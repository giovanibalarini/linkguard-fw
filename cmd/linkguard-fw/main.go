package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	linkguardfw "github.com/giovanibalarini/linkguard-fw"
	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/balancer"
	"github.com/giovanibalarini/linkguard-fw/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-fw/internal/comportamento"
	"github.com/giovanibalarini/linkguard-fw/internal/config"
	"github.com/giovanibalarini/linkguard-fw/internal/ddns"
	"github.com/giovanibalarini/linkguard-fw/internal/dnstap"
	"github.com/giovanibalarini/linkguard-fw/internal/domtargets"
	"github.com/giovanibalarini/linkguard-fw/internal/failover"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/hosts"
	"github.com/giovanibalarini/linkguard-fw/internal/hosttraffic"
	"github.com/giovanibalarini/linkguard-fw/internal/iptables"
	"github.com/giovanibalarini/linkguard-fw/internal/keaunbound"
	"github.com/giovanibalarini/linkguard-fw/internal/linkquota"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/netif"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/notify"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/sysprep"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
	"github.com/giovanibalarini/linkguard-fw/internal/tlscert"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

var version = "dev"

// pkgInstallTimeout is the deadline for a single apt-get run. Sized for a
// package download over a bad link, not for a local command: kea + unbound +
// dns-root-data are ~10 MB, and the measurement that motivated this was a
// first apply taking ~40s on a healthy office link — with a 30s executor
// underneath it.
//
// It is a ceiling for a hung apt, not an expectation. Nothing waits on it
// synchronously any more: the boot path runs it off the critical path (see
// the goroutine below) and the HTTP path runs it on a request whose context
// is deliberately detached from the client's.
const pkgInstallTimeout = 10 * time.Minute

// captureTimeout é o teto do executor da captura de pacotes: a maior janela
// que o pktcapture aceita, com folga para o processo subir e sair. Não é a
// duração da captura — essa vem do pedido do admin, limitada em
// pktcapture.MaxDurationSec.
const captureTimeout = 3 * time.Minute

func main() {
	os.Exit(run())
}

// ntpInputStateFrom lê o estado de "servir NTP para a LAN" da chave de
// settings "ntp_config" (dona: internal/api/handlers.NTPHandler) e é a ÚNICA
// leitura dela fora da camada HTTP: alimenta tanto a fonte ligada em
// nftables.SetInputChainSources quanto a reconciliação do boot, para que as
// duas nunca discordem sobre o que está configurado.
//
// NENHUM dos dois erros pode ser engolido (I-1 da revisão da Fase C2).
// db.GetSetting devolve ("", nil) só quando a chave não existe; qualquer outra
// falha (banco travado, IO) é erro de verdade, e um `_` ali transformava "não
// consegui ler" em "servir NTP está desligado" — o que faria a passada
// seguinte de ReconcileGroups dar flush na chain input e reescrevê-la só com
// os jumps, apagando do firewall vivo as duas linhas de udp/123 enquanto o
// painel continua mostrando o toggle ligado e o apply é reportado ok. JSON
// corrompido tem exatamente o mesmo efeito, e por isso também é erro.
//
// Recebe a leitura por parâmetro (e não o *storage.DB) para que o teste possa
// exercitar as quatro saídas sem inventar um banco quebrado.
func ntpInputStateFrom(getSetting func(string) (string, error)) ([]string, bool, error) {
	raw, err := getSetting("ntp_config")
	if err != nil {
		return nil, false, fmt.Errorf("ler a configuração de NTP do banco: %w", err)
	}
	if raw == "" {
		return nil, false, nil // nunca configurado: servir NTP nasce desligado
	}
	var c timesync.Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, false, fmt.Errorf("interpretar a configuração de NTP gravada: %w", err)
	}
	return c.AllowedNetworks, c.ServeLAN, nil
}

// anyWANIsDHCP diz se alguma interface gerenciada pega endereço por DHCP.
//
// Decide se a chain input precisa aceitar udp/68: a renovação unicast em T1
// passa por conntrack, mas o REBIND sai de 0.0.0.0:68 para broadcast e não casa
// a tupla de retorno. Sem a linha, a WAN nunca mais renova depois de um flap de
// link — e o sintoma aparece dias depois, como "a internet caiu sozinha".
//
// Erro de leitura devolve TRUE: emitir a linha à toa numa máquina estática não
// abre nada (ninguém manda DHCP para ela), enquanto omiti-la numa máquina que
// precisa dela derruba a internet. O lado seguro é o permissivo aqui, e só aqui.
func anyWANIsDHCP(db *storage.DB) bool {
	ifaces, err := db.ListManagedInterfaces()
	if err != nil {
		return true
	}
	for _, i := range ifaces {
		if i.AddrMode == "dhcp" {
			return true
		}
	}
	return false
}

func run() int {
	configPath := flag.String("config", "/etc/linkguard-fw/config.json", "Path to config file")
	addr := flag.String("addr", "", "Listen address override")
	port := flag.Int("port", 0, "Listen port override")
	dryRun := flag.Bool("dry-run", false, "Run in dry-run mode")
	debug := flag.Bool("debug", false, "Enable debug logs")
	showVersion := flag.Bool("version", false, "Print version and exit")
	notifyDown := flag.Bool("notify-down", false, "Send a 'service down' notification and exit (systemd OnFailure)")
	prepareSystem := flag.Bool("prepare-system", false, "Create the filesystem paths the systemd unit needs before it can start, then exit")
	prepareSystemAtStart := flag.Bool("prepare-system-at-start", false, "Same as --prepare-system plus the paths that may only be created outside a dpkg transaction (called by the unit's ExecStartPre), then exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	// Chamado pelos TRÊS caminhos de instalação (postinst do .deb,
	// deploy/install.sh, `make install`) logo depois de copiar o binário,
	// para que os três deixem a máquina no MESMO estado. Ver
	// internal/sysprep: sem isso a unidade morre em 226/NAMESPACE, em loop
	// de restart, disparando o OnFailure a cada tentativa — e sem nunca
	// executar uma linha do binário que instalaria a base.
	//
	// --prepare-system-at-start é o mesmo trabalho feito pela unidade, no
	// ExecStartPre, para os caminhos que um instalador não pode criar por
	// pertencerem a outro pacote (/etc/nftables.conf é conffile do
	// `nftables`): criá-lo dentro da transação do dpkg fazia o `apt install`
	// numa máquina pelada parar no prompt de conffile. Ver internal/sysprep,
	// tipo Stage.
	if *prepareSystem || *prepareSystemAtStart {
		stage := sysprep.StageInstall
		if *prepareSystemAtStart {
			stage = sysprep.StageServiceStart
		}
		created, err := sysprep.Prepare("", stage)
		for _, line := range created {
			fmt.Println("[INFO] criado: " + line)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "[ERRO] "+err.Error())
			return 1
		}
		return 0
	}

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "err", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("configuração inválida", "err", err)
		return 1
	}

	if setFlags["addr"] {
		cfg.ListenAddr = *addr
	}
	if setFlags["port"] {
		cfg.Port = *port
	}
	if setFlags["dry-run"] {
		cfg.DryRun = *dryRun
	}
	if setFlags["debug"] {
		cfg.Debug = *debug
	}

	level := slog.LevelInfo
	if cfg.Debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	if *notifyDown {
		return notifyDownRun(cfg.DBPath)
	}

	db, err := openStore(cfg)
	if err != nil {
		return 1
	}
	defer db.Close()

	s, err := buildServices(cfg, db)
	if err != nil {
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	wireCallbacks(ctx, s)
	writers := startBackground(ctx, s)
	return serveHTTP(ctx, s, writers)
}

// notifyDownRun é o caminho do --notify-down: avisa que o serviço caiu e sai.
// Devolve o código de saída do processo.
//
// A unidade que chama é Type=oneshot (deploy/linkguard-notify-down.service,
// disparada pelo OnFailure= da unidade principal), então este código de saída
// vira o estado da unidade — aparece no `systemctl status`, no `is-failed` e no
// journal. Ele é a única forma de quem olha a máquina depois distinguir "o aviso
// saiu" de "o aviso não saiu".
//
// O defeito que isto fecha (issue #60): o storage.Open era seguido de
// `if err == nil { … }` sem else, sem log, e a função terminava em `return 0`.
// Com o banco ilegível o processo dizia "avisei" tendo enviado nada. É o pior
// modo de falha possível — silencioso, no mecanismo que existe para avisar que
// algo deu errado, e disparado justamente quando algo deu errado. Banco
// ilegível no momento em que o serviço caiu é sinal de problema MAIOR, não
// menor.
//
// O mapeamento dos códigos:
//
//	banco não abre, chave órfã, chave não carrega → 1 (não dá para nem tentar)
//	todos os canais habilitados falharam          → 1 (o aviso não saiu)
//	ao menos um canal entregou                    → 0
//	nenhum canal habilitado                       → 0
//
// O último merece a explicação: não ter canal configurado é escolha do admin,
// não falha. Sair 1 aí deixaria uma unidade permanentemente vermelha em toda
// instalação sem notificação — e uma unidade que vive vermelha é uma que
// ninguém mais olha, o que custaria justamente o sinal que este código de saída
// existe para dar.
func notifyDownRun(dbPath string) int {
	db, err := storage.Open(dbPath)
	if err != nil {
		slog.Error("notify-down: banco inacessível, nenhum aviso foi enviado",
			"path", dbPath, "err", err)
		return 1
	}
	defer db.Close() //nolint:errcheck // processo saindo

	if orphanErr := secrets.CheckNotOrphaned(secretKeyPath, db); orphanErr != nil {
		slog.Error("notify-down: refusing to start", "err", orphanErr)
		return 1
	}
	key, keyErr := secrets.LoadOrGenerateKey(secretKeyPath)
	if keyErr != nil {
		slog.Error("notify-down: failed to load secret key", "err", keyErr)
		return 1
	}

	sec := secrets.NewService(db, key)
	errs := notify.NewService(db, sec).SendNow("critical",
		"LinkGuard caiu", "O serviço linkguard-fw parou inesperadamente no firewall.")

	// send() devolve uma entrada por canal HABILITADO: slice vazia é "nenhum
	// canal configurado", que não é o mesmo que "todos falharam".
	failed := 0
	for _, e := range errs {
		if e != nil {
			failed++
			slog.Warn("notify-down send failed", "err", e)
		}
	}
	if len(errs) > 0 && failed == len(errs) {
		slog.Error("notify-down: todos os canais falharam, nenhum aviso saiu",
			"canais", len(errs))
		return 1
	}
	if len(errs) == 0 {
		slog.Warn("notify-down: nenhum canal de notificação está habilitado; nada foi enviado")
	}
	return 0
}

// openStore abre o banco e semeia o que precisa existir antes de qualquer
// serviço: o administrador inicial e os papéis de RBAC.
//
// Os slog.Error ficam AQUI, com o mesmo texto e os mesmos campos de antes, e
// quem chama só devolve 1 sem logar de novo. Log de boot de firewall é lido em
// emergência: um refactor pode mudar de onde a linha sai, não o que ela diz.
func openStore(cfg *config.Config) (*storage.DB, error) {
	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		slog.Error("failed to open database", "path", cfg.DBPath, "err", err)
		return nil, err
	}

	// O administrador inicial vem ANTES dos papéis: é o EnsureDefaultRoles que
	// amarra o papel de admin à conta, e a conta precisa existir para a
	// foreign key aceitar. (O EnsureDefaultRoles também confere a existência,
	// então a ordem é uma garantia a mais, não a única.)
	if err := seedInitialAdmin(db); err != nil {
		slog.Error("failed to seed initial admin", "err", err)
		db.Close() //nolint:errcheck // já estamos abortando o boot
		return nil, err
	}

	if err := seedDefaultRoles(db); err != nil {
		slog.Error("failed to seed default roles", "err", err)
		db.Close() //nolint:errcheck // já estamos abortando o boot
		return nil, err
	}
	return db, nil
}

// services é tudo o que o boot monta, nomeado. Existe para que a MONTAGEM
// possa ser exercitada por um teste (boot_wiring_runtime_test.go) sem passar
// pelo main: antes disto, a única forma de perguntar "o Service saiu com a
// guarda ligada?" era ler main.go como texto.
//
// Os nomes dos campos são os nomes das variáveis locais que a montagem usa,
// para que ler buildServices e ler este struct dê a mesma imagem.
type services struct {
	cfg *config.Config
	db  *storage.DB

	// exec é o executor da aplicação (30 s). pkgExec é o dos gerenciadores de
	// pacote (10 min) — ver pkgInstallTimeout.
	exec    firewall.Executor
	pkgExec firewall.Executor

	secretsSvc   *secrets.Service
	alertSvc     *alerts.Service
	notifySvc    *notify.Service
	authSvc      *auth.Service
	linkSvc      *links.Service
	iptSvc       *iptables.Service
	routeSvc     *routes.Service
	failoverSvc  *failover.Service
	nftSvc       *nftables.Service
	frSvc        *firewallrules.Service
	balancerSvc  *balancer.Service
	keaSvc       *keaunbound.Service
	netSvc       netsvc.Provider
	trafficSvc   *hosttraffic.Service
	hostSvc      *hosts.Service
	netifSvc     *netif.Service
	sysCollector *system.Collector
	rrdSvc       *tsdb.Service
	hostSampler  *hosttraffic.Sampler
	quotaSvc     *linkquota.Service
	ddnsSvc      *ddns.Service
	aiClient     *ai.Client

	promReg          *prometheus.Registry
	appMetrics       *metrics.Metrics
	metricsCollector *monitoring.Collector
	backupSched      *backup.Scheduler
	journalSched     *monitoring.JournalScheduler
	updatesSched     *monitoring.UpdatesScheduler

	monitor   *links.Monitor
	server    *api.Server
	dnstapSvc *dnstap.Servico
	// domSvc é o alimentador de alvo por domínio (#123). Escreve no KERNEL e
	// não no banco, então não é um spawnWriter — ver startBackground.
	domSvc *domtargets.Servico

	// ntpInputState é a MESMA fonte que foi entregue a
	// nftSvc.SetInputChainSources, guardada aqui porque a reconciliação de
	// boot (em startBackground) também precisa dela — e as duas discordarem
	// sobre o que está configurado é o que a Fase C2 existe para impedir.
	ntpInputState func() ([]string, bool, error)

	// interval é a cadência do coletor de métricas; a do monitor de link é
	// outra (e mais rápida) e já está dentro do próprio monitor.
	interval time.Duration
}

// secretKeyPath é o arquivo da chave que cifra os segredos do banco.
//
// É var, e não const, por um motivo só: buildServices é exercitada por teste
// (o que esta issue existe para permitir) e o teste não pode escrever em /etc.
// Nada em produção troca este valor.
var secretKeyPath = "/etc/linkguard-fw/secret.key"

// buildServices monta os ~25 serviços do produto e devolve todos nomeados.
//
// A LIGAÇÃO ENTRE OS SERVIÇOS MORA AQUI, e não numa função de "wiring"
// separada, apesar de a issue #24 propor o contrário. O motivo é o que a
// própria issue reclama: hoje a ligação é "opcional e silenciosa", e uma
// wireCallbacks separada mantém essa propriedade — passa a existir um
// *services completo, com todos os campos preenchidos, que ninguém guardou.
// Ligando aqui, quem tem um *services tem um nftSvc com a guarda do Persist e
// com as duas fontes da chain input, porque não há outro caminho para obtê-lo.
// É a aproximação de "não compila um Service sem PersistGuard" que se
// consegue sem mexer na API de internal/nftables — ver o relatório da issue
// para por que a versão literal daquele critério esbarra num ciclo
// (nftables.Service precisa de firewallrules.Service, que precisa de
// nftables.Service).
//
// wireCallbacks fica com o que é de fato callback de evento e precisa do ctx.
//
// Os slog.Error ficam aqui pelo mesmo motivo de openStore.
func buildServices(cfg *config.Config, db *storage.DB) (*services, error) {
	if err := secrets.CheckNotOrphaned(secretKeyPath, db); err != nil {
		slog.Error("refusing to start", "err", err)
		return nil, err
	}
	secretKey, err := secrets.LoadOrGenerateKey(secretKeyPath)
	if err != nil {
		slog.Error("failed to load or generate secret key", "err", err)
		return nil, err
	}
	secretsSvc := secrets.NewService(db, secretKey)
	if err := secrets.MigrateFromSettings(db, secretsSvc); err != nil {
		slog.Error("failed to migrate legacy secrets", "err", err)
		return nil, err
	}

	var exec firewall.Executor = firewall.NewRealExecutor(30 * time.Second)
	if cfg.DryRun {
		exec = firewall.NewDryRunExecutor()
	}

	// pkgExec is the executor for anything that runs a package manager. The
	// application's `exec` has a 30s deadline — right for `nft`, `ip` or
	// `systemctl`, far too short for an apt-get fetching packages, and worse
	// than too short: when the deadline fires, the apt does NOT die with it
	// (systemd-run's transient unit finishes the transaction), so LinkGuard
	// reports a failure that is not happening. Every apt path — the base at
	// boot, the on-demand DHCP/DNS install, chrony — uses this one.
	pkgExec := exec
	if !cfg.DryRun {
		pkgExec = firewall.NewRealExecutor(pkgInstallTimeout)
	}

	// A captura de pacotes tem prazo próprio pelo mesmo motivo, ao contrário:
	// ela roda por até pktcapture.MaxDurationSec, e os 30 s do executor da
	// aplicação matariam toda captura mais longa que meio minuto reportando
	// falha que não houve. A janela real de cada captura continua sendo
	// imposta lá dentro; este prazo é só o teto que não pode ser menor que ela.
	capExec := exec
	if !cfg.DryRun {
		capExec = firewall.NewRealExecutor(captureTimeout)
	}

	alertSvc := alerts.NewService(db)
	// Close state-derived alerts left open by a previous process before any
	// watcher starts observing again: the health state that gates whether a
	// condition is "new" lives only in memory, so every restart forgets
	// what was already true. Whatever is still genuinely wrong gets
	// re-raised within the first tick or two; whatever was fixed while the
	// service was down (three alerts had to be resolved by hand on
	// 2026-08-11 for exactly this reason) stays closed. Must run before the
	// collectors/schedulers below start, so a still-true condition is
	// re-raised by the first tick rather than racing this cleanup.
	alertSvc.ResolveStaleOnStartup()
	notifySvc := notify.NewService(db, secretsSvc)
	alertSvc.SetNotifier(notifySvc)
	authSvc := auth.NewService(db, cfg.JWTSecret, secretsSvc)
	linkSvc := links.NewService(db)
	iptSvc := iptables.NewService(exec)
	routeSvc := routes.NewService(exec)
	failoverSvc := failover.NewService(failover.Config{
		Enabled:          cfg.FailoverEnabled,
		DryRun:           cfg.DryRun,
		FailThreshold:    cfg.FailThreshold,
		RecoverThreshold: cfg.RecoverThreshold,
		CooldownSecs:     cfg.FailoverCooldownSecs,
	}, db, exec, routeSvc, alertSvc)
	nftSvc := nftables.NewService(exec)
	frSvc := firewallrules.NewService(db, nftSvc)
	// Bloqueio administrativo que não está mais na lista de grupos é motivo
	// para alcançar o operador onde ele estiver, não só para deixar a faixa
	// vermelha na tela do firewall.
	frSvc.SetAlerter(alertSvc)
	// A chain input tem um renderizador só (Fase C2): ela é reconstruída
	// inteira, com a proteção do NTP E os jumps dos grupos de escopo input,
	// venha a passada de onde vier. Quem reconcilia o NTP sabe o estado do
	// NTP e precisa dos grupos; quem reconcilia os grupos sabe os grupos e
	// precisa do estado do NTP — estas duas funções são o que fecha esse
	// círculo sem internal/nftables importar internal/storage.
	//
	// Ligado aqui, junto da construção, e não perto de um dos reconciles: sem
	// isto, salvar um grupo apagaria a proteção do NTP da chain input.
	// TestMainWiresTheInputChainSources guarda essa ligação contra deriva.
	//
	// O erro de leitura viaja junto e NÃO vira "servir NTP está desligado" —
	// ver ntpInputStateFrom.
	ntpInputState := func() ([]string, bool, error) { return ntpInputStateFrom(db.GetSetting) }
	nftSvc.SetInputChainSources(frSvc.StoredGroups, ntpInputState)
	// E a guarda do /etc/nftables.conf (I-1 da revisão final da Fase C2):
	// enquanto houver uma mudança aguardando confirmação, o ruleset vivo NÃO vai
	// para o arquivo que o nftables.service carrega no boot — senão uma queda de
	// energia dentro dos 90 segundos faz a máquina voltar com a regra não
	// confirmada valendo, antes de o LinkGuard subir para reverter. Ligada aqui,
	// junto da construção, pelo mesmo motivo da linha acima; guardada contra
	// deriva por TestMainWiresThePersistGuard.
	nftSvc.SetPersistGuard(frSvc.UnconfirmedChangePending)
	balancerSvc := balancer.NewService(db, exec, linkSvc, alertSvc)
	keaSvc := keaunbound.NewService(exec)
	// O caminho sob demanda (o admin liga DHCP/DNS no painel) instala
	// kea + unbound + dns-root-data. Sem isto ele herdava o executor de 30s
	// e, ao estourar, mentia dizendo que não conseguiu instalar enquanto o
	// apt terminava a instalação com sucesso.
	keaSvc.SetInstallExecutor(pkgExec)
	var netSvc netsvc.Provider = keaSvc
	trafficSvc := hosttraffic.NewService(exec)
	hostSvc := hosts.NewService(exec, db, nftSvc, netSvc)
	netifSvc := netif.NewService(exec, db, linkSvc)
	netifSvc.SetAlertService(alertSvc)
	// Regra que cita uma interface inexistente carrega no nft SEM ERRO e nunca
	// casa — o painel mostra a regra ativa e ela não protege nada. Aconteceu em
	// produção (reshuffle de PCI, enp4s0 → enp5s0). Esta ligação é o que permite
	// ao produto AVISAR; corrigir sozinho seria adivinhar qual interface o admin
	// queria, e desativar a regra em silêncio é o mesmo defeito com outro nome.
	// A postura do firewall (issue #78). As duas fontes andam juntas: sem a de
	// acesso administrativo, uma política restritiva renderiza sem saber o que
	// manter aberto — e é assim que o admin se tranca fora. O renderizador
	// aborta nesse caso, e esta ligação é o que faz o caso não acontecer.
	nftSvc.SetInputPolicySource(frSvc.InputPolicy)
	// A decisão de fechar a gerência nas WANs é lida a cada reconciliação, e não
	// guardada em memória, pelo mesmo motivo da política: a reversão automática
	// da janela de 90 s reescreve o valor no banco, e a reconciliação seguinte
	// tem de obedecer ao que a reversão gravou — não ao que o processo lembrava.
	nftSvc.SetWANMgmtClosedSource(frSvc.WANMgmtClosed)
	// Alerta que NOMEIA aparelho só sai da caixa com escolha explícita (#117).
	// Ver tiposQueNomeiamAparelho em internal/alerts e a regra escrita em
	// internal/metrics/exposicao.go.
	alertSvc.SetNotificarAparelho(func() (bool, error) {
		return notifySvc.LoadConfig().NotificarAparelho, nil
	})
	// A contenção de tentativa repetida (#127) é opt-in e lida a cada
	// reconciliação, pelo mesmo motivo das outras: o valor pode mudar pela tela
	// e tem de valer na reconciliação seguinte, sem reiniciar nada.
	nftSvc.SetEdgeContainmentSource(frSvc.EdgeContainment)
	nftSvc.SetForwardPolicySource(frSvc.ForwardPolicy)
	nftSvc.SetAdminAccessSource(func() (nftables.AdminAccess, error) {
		netCfg := netsvc.DefaultConfig()
		if raw, _ := db.GetSetting("netsvc_config"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &netCfg)
		}
		var redes []string
		if netCfg.SubnetCIDR != "" {
			redes = append(redes, netCfg.SubnetCIDR)
		}
		// A porta do painel NÃO é fixa: 8080 é o default do binário, 9997 o do
		// .deb, e quem põe proxy usa outra. Fixá-la aqui deixaria o anti-lockout
		// mudo justamente em quem não usa o padrão.
		// A porta do SSH sai de onde o sshd está ESCUTANDO, não de um literal.
		// Fixá-la em 22 era o mesmo erro que o comentário acima denuncia para a
		// porta do painel, cometido para o outro serviço: numa caixa com
		// `Port 2222`, a regra que existe para não trancar o admin descartaria
		// exatamente a porta por onde ele entra.
		return nftables.AdminAccess{
			PanelPort:   cfg.Port,
			SSHPorts:    system.SSHPorts(context.Background(), exec),
			LANNetworks: redes,
			WANIsDHCP:   anyWANIsDHCP(db),
		}, nil
	})

	frSvc.SetIfaceLister(func() ([]string, error) {
		views, err := netifSvc.List(context.Background())
		if err != nil {
			return nil, err
		}
		nomes := make([]string, 0, len(views))
		for _, v := range views {
			nomes = append(nomes, v.Name)
		}
		return nomes, nil
	})
	sysCollector := system.NewCollector()
	// O consumo por host passa a vir dos contadores do nftables (#112), e não
	// mais das conexões vivas do conntrack — que perdiam os bytes assim que a
	// conexão fechava. Ver internal/nftables/accounting.go.
	trafficSvc.SetCounterSource(nftSvc)

	// A opção de registrar bloqueios (#122) é lida do banco a cada
	// reconciliação, e não guardada em memória: o admin pode ligá-la pelo
	// painel, e o valor tem de valer na reconciliação seguinte sem reiniciar
	// nada. Mesmo desenho da política padrão da chain input.
	nftSvc.SetBlockLogSource(func() (bool, error) { return handlers.BlockLogEnabled(db) })

	// A proteção de entrada das WANs (#119) lê a MESMA lista que o masquerade e
	// a contabilidade, e pelo mesmo motivo lê a cada reconciliação em vez de
	// guardar em memória: trocar a interface de um link tem de valer na
	// reconciliação seguinte, sem reiniciar nada.
	nftSvc.SetWANInterfacesSource(func() ([]string, error) {
		ls, err := db.GetLinks()
		if err != nil {
			return nil, err
		}
		ifaces := make([]string, 0, len(ls))
		for _, l := range ls {
			if l.Enabled && l.Interface != "" {
				ifaces = append(ifaces, l.Interface)
			}
		}
		return ifaces, nil
	})

	rrdSvc := tsdb.NewService(db)

	// A série de consumo por host (#113) usa as três peças que já existem: os
	// contadores do nftables (#112), a tabela de vizinhança para resolver o
	// MAC, e o tsdb como gravador — com o rollup e a retenção que ele já tem.
	hostSampler := hosttraffic.NewSampler(nftSvc, hostSvc, rrdSvc)

	// A franquia por link consome os MESMOS deltas de byte que alimentam as
	// séries de tráfego — ver tsdb.UsageSink. SetUsageSink tem de acontecer
	// antes de rrdSvc.Run, que é quem monta o amostrador.
	quotaSvc := linkquota.NewService(db, alertSvc)

	// DNS dinâmico por link (#129). A descoberta do endereço usa a MESMA
	// leitura de `ip addr` que o balanceador — duas leituras com parsers
	// diferentes divergiriam no primeiro formato inesperado, e o sintoma seria
	// o nome apontando para lugar nenhum.
	ddnsSvc := ddns.NewService(db, secretsSvc, func(ctx context.Context, iface string) string {
		return balancer.InterfaceIPv4(ctx, exec, iface)
	})
	rrdSvc.SetUsageSink(quotaSvc)

	// Optional AI advisory layer (BYOK): disabled by default (ai.LoadConfig's
	// Enabled defaults to false), and swallows its own failures — wiring it in
	// unconditionally here does not change failover/balance behavior.
	aiBudget := ai.NewBudgetGuard(db)
	aiClient := ai.NewClient(secretsSvc, aiBudget, func() ai.Config { return ai.LoadConfig(db) })
	balancerSvc.SetAI(aiClient, rrdSvc)

	promReg := prometheus.NewRegistry()
	appMetrics := metrics.New(promReg)
	// `linkguard_failover_events_total` era publicada em /metrics e NUNCA
	// incrementada: zero para sempre, num painel de Grafana dizendo que a rede
	// nunca teve problema nenhum. Ver recordEvent em internal/failover.
	failoverSvc.SetEventHook(appMetrics.FailoverEvents.Inc)
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec, rrdSvc)
	// O item "Regras no próximo boot" da Saúde do sistema. Sem esta linha o
	// vigia não tem como saber nada sobre o /etc/nftables.conf e o item
	// simplesmente não aparece — a falha do Persist voltaria a ser só um WARN no
	// journal, que é exatamente o que o §10 da validação em VM mediu. Guardada
	// contra deriva por TestMainWiresTheBootPersistSource.
	metricsCollector.SetBootPersistSource(nftSvc)
	backupSched := backup.NewScheduler(db, secretsSvc, notifySvc, alertSvc, version)
	journalSched := monitoring.NewJournalScheduler(metricsCollector)
	updatesSched := monitoring.NewUpdatesScheduler(metricsCollector)

	// Criado ANTES do servidor: api.New monta o roteador na mesma chamada, e as
	// rotas leem o coletor na hora do registro (#116).
	dnstapSvc := dnstap.NovoServico()
	// Alvo por domínio (#123): o alimentador ouve as respostas que o coletor já
	// extraiu, em vez de abrir um segundo consumidor do socket. Ligado AQUI,
	// antes de qualquer Run, porque o observador é lido sem lock pelas
	// goroutines de conexão — ver SetObservador.
	domSvc := domtargets.NovoServico(nftSvc)
	dnstapSvc.SetObservador(domSvc.Observar)
	// Séries por aparelho para o coletor do cliente (#118). Fora do registro
	// aberto do Prometheus de propósito — ver internal/metrics/exposicao.go.
	porHost := metrics.NovoPorHost()
	hostSampler.SetPorHost(porHost)

	server := api.New(api.Config{
		Addr:        cfg.Addr(),
		DryRun:      cfg.DryRun,
		WebFS:       linkguardfw.WebFS,
		PromReg:     promReg,
		Version:     version,
		PkgExec:     pkgExec,
		CaptureExec: capExec,
		DNSTap:      dnstapSvc,
		PorHost:     porHost,
	}, db, exec, linkSvc, iptSvc, routeSvc, failoverSvc, balancerSvc, alertSvc, authSvc, hostSvc, netifSvc, nftSvc, frSvc, netSvc, notifySvc, trafficSvc, quotaSvc, ddnsSvc, sysCollector, rrdSvc, promReg, metricsCollector, secretsSvc, aiClient, backupSched)

	interval := time.Duration(cfg.MonitorInterval) * time.Second
	// The link health probe runs on its own (faster) cadence, decoupled from the
	// metrics collector, and sends several probes per host so packet loss/latency
	// are real averages instead of a single pass/fail.
	probeInterval := time.Duration(cfg.ProbeIntervalSeconds) * time.Second
	monitor := links.NewMonitor(db, linkSvc, probeInterval, cfg.ProbeCount, rrdSvc, appMetrics)

	return &services{
		cfg:              cfg,
		db:               db,
		exec:             exec,
		pkgExec:          pkgExec,
		secretsSvc:       secretsSvc,
		alertSvc:         alertSvc,
		notifySvc:        notifySvc,
		authSvc:          authSvc,
		linkSvc:          linkSvc,
		iptSvc:           iptSvc,
		routeSvc:         routeSvc,
		failoverSvc:      failoverSvc,
		nftSvc:           nftSvc,
		frSvc:            frSvc,
		balancerSvc:      balancerSvc,
		keaSvc:           keaSvc,
		netSvc:           netSvc,
		trafficSvc:       trafficSvc,
		hostSvc:          hostSvc,
		netifSvc:         netifSvc,
		sysCollector:     sysCollector,
		rrdSvc:           rrdSvc,
		hostSampler:      hostSampler,
		quotaSvc:         quotaSvc,
		ddnsSvc:          ddnsSvc,
		aiClient:         aiClient,
		promReg:          promReg,
		appMetrics:       appMetrics,
		metricsCollector: metricsCollector,
		backupSched:      backupSched,
		journalSched:     journalSched,
		updatesSched:     updatesSched,
		monitor:          monitor,
		server:           server,
		ntpInputState:    ntpInputState,
		interval:         interval,
		dnstapSvc:        dnstapSvc,
		domSvc:           domSvc,
	}, nil
}

// wireCallbacks liga os callbacks de EVENTO — os que só podem ser ligados
// depois de existir o ctx do processo, e por isso não cabem em buildServices.
//
// É só o monitor de link: a decisão entre balanceamento e failover a cada
// mudança de estado, e a expulsão ativa do link degradado. As ligações que
// NÃO dependem do ctx (a guarda do Persist, as fontes da chain input, a fonte
// do vigia) ficam em buildServices, junto da construção — ver o doc-comment
// de lá para por que essa separação não é arbitrária.
func wireCallbacks(ctx context.Context, s *services) {
	monitor, balancerSvc, failoverSvc := s.monitor, s.balancerSvc, s.failoverSvc

	// On a link state change, balance mode rebuilds the weighted multipath
	// default route; otherwise the legacy per-table failover handles it.
	monitor.OnStatusChange(func(link *storage.Link, oldStatus, newStatus string) {
		if balancerSvc.Active() {
			balancerSvc.OnLinkChange(link, oldStatus, newStatus)
			return
		}
		failoverSvc.HandleStatusChange(link, oldStatus, newStatus)
	})
	// A link that stays degraded past the admin-configured threshold triggers
	// active flow eviction (balance mode only; itself gated by a toggle). The
	// threshold is read live so UI changes take effect without a restart.
	monitor.SustainThreshold(func() int { return balancerSvc.LoadConfig().DegradedSustainSamples })
	monitor.OnDegradedSustained(func(link *storage.Link) {
		if balancerSvc.Active() {
			balancerSvc.EvictDegraded(ctx, link)
		}
	})
}

// connMarksDe e replyRoutesDe traduzem o caminho de volta de cada WAN para o
// que cada camada entende. São duas linhas cada, e existem para a conversão
// acontecer num lugar só: o dia em que a marca deixar de ser o table_id, é aqui
// que se descobre — e não numa caixa em que a resposta some.
func connMarksDe(caminhos []links.WANPath) []nftables.WANMark {
	out := make([]nftables.WANMark, 0, len(caminhos))
	for _, c := range caminhos {
		out = append(out, nftables.WANMark{Interface: c.Interface, Mark: c.Mark})
	}
	return out
}

func replyRoutesDe(caminhos []links.WANPath) []routes.ReplyRoute {
	out := make([]routes.ReplyRoute, 0, len(caminhos))
	for _, c := range caminhos {
		out = append(out, routes.ReplyRoute{
			Interface: c.Interface, Gateway: c.Gateway, Table: c.Table, Mark: c.MarkHex(),
		})
	}
	return out
}

// startBackground sobe TUDO que roda em segundo plano: o provisionamento da
// máquina (o que o LinkGuard faz no boot que mexe em nftables/rotas/NTP), o
// timer do confirmar-ou-reverte e as goroutinas de coleta.
//
// Devolve o WaitGroup das goroutines que ESCREVEM no banco — ver o comentário
// da declaração dele. Quem chama tem que esperá-lo DEPOIS de o HTTP parar
// (serveHTTP faz isso), senão o tsdb volta a perder o balde da janela corrente
// a cada reinício.
//
// Os serviços são reapontados para variáveis locais com os MESMOS nomes que a
// montagem usa (frSvc, nftSvc, …) de propósito: a sequência abaixo é guardada
// contra deriva por testes de AST que procuram `frSvc.RevertPendingOnBoot`,
// `nftSvc.ReconcileNTPInput` e afins como chamadas em identificadores simples.
// Escrever `s.frSvc.…` aqui deixaria esses guardas cegos sem uma linha sequer
// mudar de comportamento — que é exatamente o modo de falha que eles existem
// para pegar.
func startBackground(ctx context.Context, s *services) *sync.WaitGroup {
	db := s.db
	exec, pkgExec := s.exec, s.pkgExec
	frSvc, nftSvc := s.frSvc, s.nftSvc
	linkSvc, routeSvc, balancerSvc := s.linkSvc, s.routeSvc, s.balancerSvc
	trafficSvc, keaSvc, alertSvc := s.trafficSvc, s.keaSvc, s.alertSvc
	monitor, metricsCollector, rrdSvc := s.monitor, s.metricsCollector, s.rrdSvc
	quotaSvc := s.quotaSvc
	ddnsSvc := s.ddnsSvc
	hostSampler := s.hostSampler
	backupSched, journalSched, updatesSched := s.backupSched, s.journalSched, s.updatesSched
	netifSvc, aiClient := s.netifSvc, s.aiClient
	ntpInputState := s.ntpInputState
	interval := s.interval

	// bootPendingChecked prende a verificação de boot do confirmar-ou-reverte
	// à primeira passada de provisionSystem que a tenha CONCLUÍDO.
	// provisionSystem é reexecutado quando uma tentativa posterior de instalar
	// a base finalmente dá certo — e isso pode acontecer meia hora depois da
	// subida, com o operador já no painel. Sem a trava, essa segunda passada
	// reverteria uma janela de confirmação que ele tivesse acabado de abrir,
	// como se a máquina tivesse reiniciado. "No boot" tem que querer dizer no
	// boot.
	//
	// N-4 — por que uma trava explícita e não um sync.Once. A primeira passada
	// roda mesmo quando o bootstrap FALHOU (`if done || attempt == 0`), e numa
	// máquina onde o `nft` ainda nem existe é justamente a passada em que a
	// reversão de boot não tem como se completar. Um sync.Once queimava ali, e
	// a passada que finalmente dava certo não repetia a verificação. Marcando
	// só quando ela conclui, a passada seguinte retoma o trabalho.
	//
	// O que isso custa, dito por inteiro: se a verificação falhou porque a
	// LEITURA do pendente falhou (e não havia pendente nenhum), uma passada
	// posterior pode reverter uma janela aberta no intervalo. É o caso raro de
	// um caso raro, e ele falha na direção segura — o operador mantém o acesso
	// e reaplica a alteração; o inverso (deixar de reverter) é ele trancado
	// fora de uma máquina remota. Quando a falha foi da reversão em si, repetir
	// é exatamente o certo: o pendente continua no banco e é o mesmo.
	//
	// Escrita e lida por uma goroutine só (a do laço de bootstrap, mais
	// abaixo), que é de onde provisionSystem é chamado.
	bootPendingChecked := false

	// provisionSystem é tudo o que o LinkGuard faz no boot que MEXE na
	// máquina: forwarding, policy routing, bootstrap/reconciliação do
	// nftables, accounting do conntrack, NTP e resolv.conf.
	//
	// Tudo isto depende de o `nft`/`ip` existirem, então continua vindo
	// DEPOIS de garantir a base — mas fora do caminho crítico da subida (ver
	// a goroutine logo abaixo). É idempotente de ponta a ponta, e por isso
	// pode ser chamado de novo quando uma tentativa posterior de instalar a
	// base finalmente der certo.
	provisionSystem := func() {
		// A primeira coisa DESTA função, antes de qualquer reconciliação
		// (Fase C2, spec §5.1): se ficou uma mudança de firewall aplicada e
		// não confirmada, reverta — tenha ela expirado ou não.
		//
		// A ordem é a proteção, não uma preferência de organização. Reverter
		// DEPOIS de já ter reconciliado significaria aplicar mais uma vez, na
		// máquina que acabou de voltar, exatamente a regra que pode tê-la
		// derrubado — e regra de escopo input derruba o acesso do OPERADOR
		// (SSH, painel), numa máquina remota, sem conserto local.
		//
		// m-1 — o que isto NÃO é: não é o primeiro instante do boot.
		// provisionSystem só roda depois de bootstrapdeps.Ensure, que num
		// link ruim pode levar meia hora (ver a goroutine mais abaixo). O que
		// cobre esse intervalo é frSvc.WatchPending, que já está de pé desde
		// a subida: a janela dura 90 s, então na prática é ele quem reverte
		// primeiro, e esta chamada é a rede para o caso de o processo ter
		// reiniciado com a janela ainda correndo. A garantia real é "antes de
		// o LinkGuard reconciliar", não "antes de tudo".
		//
		// Reverter mesmo dentro do prazo é decisão registrada: o operador não
		// estava lá para confirmar, e um reboot dentro da janela normalmente
		// significa que a máquina caiu por causa da mudança. Ver
		// RevertPendingOnBoot.
		//
		// Erro aqui não derruba o boot nem desarma nada: fica no journal, o
		// pendente CONTINUA no banco (a faixa do painel segue pedindo
		// confirmação ou reversão) e o WatchPending retoma a reversão. É o
		// que salva a máquina cuja tabela `inet linkguard` precisou ser
		// recriada — aqui, algumas linhas antes do EnsureTable, a
		// reconciliação da reversão falha de forma determinística. E a trava
		// só é marcada quando a verificação CONCLUI (N-4): uma passada que não
		// conseguiu terminar não gasta a única chance de "no boot".
		if !bootPendingChecked {
			if err := frSvc.RevertPendingOnBoot(ctx); err != nil {
				slog.Error("não foi possível reverter no boot a mudança de firewall não confirmada", "err", err)
			} else {
				bootPendingChecked = true
			}
		}

		// Enable IPv4 forwarding so the box can route between LAN and WAN; it
		// defaults to 0 on a fresh system and a firewall/router needs it on.
		routeSvc.EnsureForwarding()

		// Apply the WAN host-steering policy routing at startup (LinkGuard now owns
		// this; it previously came from /etc/network/linkguard-routing.sh via rc.local).
		balancerSvc.EnsureSteerRouting(ctx)

		// Bootstrap `table inet linkguard` if it doesn't exist yet — every other
		// nftables operation (block host, port forward, custom rule) assumes the
		// table is already there. On every install to date this table was created
		// by hand once; this makes a fresh install self-sufficient instead of
		// silently failing the first time an admin uses the Firewall screen.
		if configuredLinks, err := linkSvc.List(); err != nil {
			slog.Warn("could not load links for nftables bootstrap", "err", err)
		} else {
			wanInterfaces := make([]string, 0, len(configuredLinks))
			for _, l := range configuredLinks {
				wanInterfaces = append(wanInterfaces, l.Interface)
			}
			if nftSvc.EnsureTable(ctx, wanInterfaces) {
				// The table was just created empty — restore whatever was saved on
				// the last mutation (host_wan, blocklist, user rules, host blocks,
				// port forwards) so a from-scratch install with a restored database
				// comes back with the same firewall it had, not a blank one. Only
				// runs right after a bootstrap: reapplying a snapshot on every
				// ordinary restart would risk clobbering a running firewall with
				// stale state instead.
				if snapshot, _ := db.GetSetting(nftables.LiveSnapshotSettingKey); snapshot != "" {
					if _, err := nftSvc.Restore(ctx, snapshot); err != nil {
						slog.Warn("bootstrapped nftables table but could not restore the saved elements", "err", err)
					} else {
						slog.Info("restored saved nftables elements after bootstrap (host_wan/blocklist/user rules/port forwards)")
					}
				}
			}

			// Reconcile the masquerade rule on EVERY boot, not just when the table
			// had to be created. EnsureTable is a no-op on an already-provisioned
			// box, so before this the NAT rule kept whatever interface names it was
			// born with — in production a renamed NIC (enp4s0 -> enp5s0) silently
			// took WAN1's NAT down until an operator intervened by hand.
			enabledWANs := make([]string, 0, len(configuredLinks))
			for _, l := range configuredLinks {
				if l.Enabled && l.Interface != "" {
					enabledWANs = append(enabledWANs, l.Interface)
				}
			}
			if err := nftSvc.ReconcileMasquerade(ctx, enabledWANs); err != nil {
				slog.Warn("não foi possível reconciliar a regra de NAT no boot", "err", err)
			}

			// A contabilidade por host (#112) usa a MESMA lista de WANs, e pelo
			// mesmo motivo do masquerade precisa ser reconciliada em todo boot:
			// EnsureTable é no-op em máquina já provisionada, então sem isto
			// uma instalação existente nunca ganharia a chain.
			if err := nftSvc.EnsureAccounting(ctx, enabledWANs); err != nil {
				slog.Warn("não foi possível reconciliar a contabilidade por host no boot", "err", err)
			}

			// Ajuste de MSS (#130): também deriva da lista de WANs, e é no-op
			// por construção onde a MTU é 1500 — ver EnsureMSSClamp.
			if err := nftSvc.EnsureMSSClamp(ctx, enabledWANs); err != nil {
				slog.Warn("não foi possível reconciliar o ajuste de MSS no boot", "err", err)
			}

			// Bloqueio por endereço físico (#119, fase 2). O set nasce vazio,
			// então numa caixa já instalada os hosts bloqueados precisam ser
			// recolocados nele — senão o bloqueio deles continuaria valendo só
			// para IPv4, com a tela dizendo "bloqueado".
			// A set precisa existir ANTES da sincronização: quem a cria no
			// caminho normal é reconcileGroups, que só roda mais adiante neste
			// mesmo boot. Sem esta linha, no primeiro boot depois do upgrade
			// TODOS os elementos são recusados pelo nft e o erro é engolido —
			// a set fica vazia e o bloqueio volta a valer só para IPv4, sem uma
			// linha no journal dizendo por quê.
			if err := s.nftSvc.EnsureBlockedMACSet(ctx); err != nil {
				slog.Warn("não foi possível garantir a set de endereços físicos bloqueados no boot", "err", err)
			}
			s.hostSvc.SincronizaBloqueiosPorMAC(ctx)

			// Estruturas de alvo por domínio (#123): garantidas E ESVAZIADAS
			// no boot.
			//
			// O esvaziamento é incondicional de propósito. O que elas guardam é
			// cache do que o resolver respondeu, e endereço de CDN é de um site
			// hoje e de outro daqui a dez minutos. Cache que sobrevive ao
			// reboot afirma sobre endereços o que ninguém mais confirmou — a
			// mesma razão pela qual o mapa da #116 vive só em memória.
			//
			// E há um caminho pelo qual esse cache VOLTARIA sozinho: Persist
			// despeja o `nft list table` inteiro, elementos inclusive, em
			// /etc/nftables.conf, e o nftables.service recarrega esse arquivo
			// ANTES de o LinkGuard subir. Sem esta linha, endereços aprendidos
			// há semanas voltariam a valer sem ninguém para reconfirmá-los.
			if err := s.nftSvc.EnsureDomainStructures(ctx); err != nil {
				slog.Warn("não foi possível garantir as estruturas de alvo por domínio no boot", "err", err)
			} else if err := s.nftSvc.FlushDomainStructures(ctx); err != nil {
				slog.Warn("não foi possível esvaziar as estruturas de alvo por domínio no boot", "err", err)
			}

			// Controle de fuga de DNS (#124), reconciliado no boot (#153). Era
			// a única feature de firewall fora desta lista: o estado dela mora
			// no banco e a tela lê de lá, então os toggles ficavam marcados
			// mesmo quando as chains não existiam no kernel.
			if err := handlers.ReconcileDNSGuardOnBoot(ctx, db, nftSvc); err != nil {
				slog.Warn("não foi possível reconciliar o controle de fuga de DNS no boot", "err", err)
			}

			// Proteção de entrada das WANs (#119). Reconciliada em todo boot
			// pela mesma razão da contabilidade: EnsureTable é no-op em máquina
			// já provisionada, então sem isto uma instalação existente nunca
			// ganharia a proteção.
			if err := nftSvc.ReconcileInputProtection(ctx); err != nil {
				slog.Warn("não foi possível reconciliar a proteção de entrada das WANs no boot", "err", err)
			}

			// Roteamento de retorno por WAN (#120). As duas metades saem da
			// MESMA lista de caminhos, derivada num lugar só (links.WANPaths),
			// para a marca gravada na conexão e a tabela consultada pela rota
			// nunca discordarem.
			caminhos := links.WANPaths(configuredLinks)
			if err := nftSvc.EnsureConnMark(ctx, connMarksDe(caminhos)); err != nil {
				slog.Warn("não foi possível reconciliar a marcação de conexão no boot", "err", err)
			}
			if err := routeSvc.EnsureReplyRouting(ctx, replyRoutesDe(caminhos)); err != nil {
				slog.Warn("não foi possível reconciliar o roteamento de retorno no boot", "err", err)
			}

			// Reconcile the structural chain (mark_hosts) on every boot too.
			// Until this feature (2026-08-11, firewall page redesign spec §6)
			// it was only ever created once at EnsureTable/bootstrap and never
			// touched again — the gap that let a double-load of the ruleset
			// (2026-08-10 incident) leave every rule in it permanently
			// duplicated, since nothing ever flushed and rewrote it again. See
			// ReconcileStructuralChains' doc comment.
			//
			// The forward chain used to be reconciled here too; since rule
			// groups (Phase C1) it belongs to ReconcileGroups, called below via
			// frSvc.Reconcile — the only place that knows the admin's groups.
			if err := nftSvc.ReconcileStructuralChains(ctx); err != nil {
				slog.Warn("não foi possível reconciliar a chain estrutural (mark_hosts) no boot", "err", err)
			}

			// EnsureSystemGroups vem PRIMEIRO, antes de qualquer coisa que
			// reconcilie, e a ordem é o ponto: ele cria, uma única vez, as
			// duas linhas de grupo que representam os bloqueios (hosts e
			// destinos) nas posições 0 e 1, empurrando os grupos do admin
			// para depois. É a lista de grupos que passa a decidir se os
			// bloqueios existem na chain forward — e as duas migrações
			// abaixo reconciliam por dentro, então rodá-las antes desta
			// abriria uma janela em que a forward é reconstruída com a lista
			// ainda sem os bloqueios. A defesa de firewallrules recusa
			// exatamente esse estado (ver ensureSystemGroupsPresent): com a
			// ordem invertida, as duas migrações do boot de upgrade
			// falhariam em vez de migrar.
			//
			// Não depende de nenhuma das duas: só lê a própria trava e
			// insere as duas linhas, deslocando as posições existentes.
			// TestEnsureSystemGroupsRunsBeforeTheMigrationsThatReconcile
			// guarda essa ordem contra deriva.
			//
			// Um erro aqui não derruba o boot: os grupos não são criados, e
			// tudo que reconcilia a seguir se recusa a reconstruir a forward
			// (o firewall segue valendo com a última forward aplicada, que
			// tem os bloqueios dentro), com apply-status não-ok e alerta
			// crítico. A próxima inicialização tenta de novo.
			if err := frSvc.EnsureSystemGroups(ctx); err != nil {
				slog.Warn("não foi possível criar os grupos do sistema (hosts e destinos bloqueados)", "err", err)
			}

			// Phase B (firewall page redesign spec §4.1): the admin's own rules
			// now live in the DB, not just inside nft. On a box upgrading from
			// Phase A, ImportOnce brings whatever is in the live user_rules
			// chain into the DB exactly once (guarded by a settings flag, never
			// by "is the table empty" — see its doc comment for why that
			// distinction matters), preserving order; a fresh install has
			// nothing to import and just sets the guard.
			//
			// MigrateRulesIntoDefaultGroup runs right after: it adopts whatever
			// rules are still ungrouped — including whatever ImportOnce just
			// brought in — into the "Minhas regras" group, once, guarded the
			// same way. The order between these two is not arbitrary: inverting
			// them would make a box still on Phase A (nothing in the DB yet,
			// the real rules only living in the legacy user_rules chain) run
			// the group migration against an empty rule set, then have
			// ImportOnce bring the rules in afterwards as orphans nobody ever
			// adopts into a group.
			//
			// Reconcile (Fase C1) is what actually renders the forward chain
			// (blocks, then the group jumps) and every grp_ chain from the DB —
			// see its doc comment. It is called unconditionally last, on every
			// boot, same as the other reconciles above. This is not redundant
			// with the two calls above even though both of them also reconcile
			// internally when they do real work (MigrateRulesIntoDefaultGroup
			// must, to safely retire the legacy user_rules chain — see its doc
			// comment): on a box with nothing to migrate, that function returns
			// without reconciling at all, which would leave the forward chain
			// stuck on whatever was last written to /etc/nftables.conf.
			if err := frSvc.ImportOnce(ctx); err != nil {
				slog.Warn("não foi possível importar as regras existentes de user_rules para o banco", "err", err)
			}
			if err := frSvc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
				slog.Warn("não foi possível migrar as regras soltas para o grupo padrão", "err", err)
			}
			if err := frSvc.Reconcile(ctx); err != nil {
				slog.Warn("não foi possível reconciliar os grupos de regras (chain forward) a partir do banco no boot", "err", err)

				// m1 da revisão da Fase C2: frSvc.Reconcile → nftSvc.ReconcileGroups
				// já reconstrói a chain input INTEIRA (passo 3b, ver o doc-comment
				// de ReconcileGroups) a partir da mesma fonte de estado do NTP que
				// ntpInputState lê abaixo — no caminho feliz, chamar
				// nftSvc.ReconcileNTPInput de novo aqui só duplicava o trabalho.
				// Duplicar não é de graça: cada reconstrução da chain input abre uma
				// janela entre o `flush chain` e o `add rule` do bloqueio de udp/123
				// em que ela fica vazia com `policy accept` — NTP de qualquer origem
				// passaria nesse instante —, e dobrar a chamada dobra essa janela por
				// boot, além de duplicar o Persist() em /etc/nftables.conf.
				//
				// O valor que sobra é estreito mas real: se frSvc.Reconcile FALHOU
				// (por exemplo abortou em ensureSystemGroupsPresent, antes mesmo de
				// chamar ReconcileGroups), a chain input pode não ter sido tocada por
				// ele nesta passada — e é só este `if` que ainda garante que a
				// proteção do NTP suba no boot. Por isso a chamada fica presa a este
				// ramo de erro em vez de rodar solta como antes.
				// TestNTPInputIsReconciledAfterTheGroupChainsExist guarda isto.
				//
				// A ordem continua sendo o ponto (I-4 da revisão da Fase C2): desde a
				// Fase C2 a chain input carrega também um `jump` por grupo de escopo
				// input, e quem CRIA as chains grp_ é o passo 1 de ReconcileGroups,
				// chamado (com sucesso ou não) dentro de frSvc.Reconcile acima. Numa
				// máquina cujo ruleset foi recriado do zero por EnsureTable
				// (recuperação de desastre, como em 2026-08-10) e cujo banco tenha um
				// grupo de escopo input, emitir o jump antes disso falha com "No such
				// file or directory": a passada seguinte conserta, mas o log de boot
				// fica com um erro que não é erro — e log de boot de firewall é lido
				// em emergência.
				//
				// Erro de LEITURA não vira reconciliação: reconstruir a chain com
				// "servir NTP: desligado" que na verdade é "não consegui ler"
				// apagaria a proteção do serviço de hora do firewall vivo (I-1).
				if networks, serving, err := ntpInputState(); err != nil {
					slog.Warn("não foi possível ler a configuração de NTP no boot; a chain input não foi tocada nesta passada", "err", err)
				} else if err := nftSvc.ReconcileNTPInput(ctx, networks, serving); err != nil {
					slog.Warn("não foi possível reconciliar a chain de proteção do NTP no boot", "err", err)
				}
			}
		}

		// Enable conntrack byte accounting so per-host traffic (top talkers) can be
		// computed; without it /proc/net/nf_conntrack has no byte counters.
		trafficSvc.EnsureAccounting()

		// Enable NTP time sync (chrony) if it's installed — LinkGuard owns this
		// the same way it owns the three prerequisites above.
		timesync.EnsureEnabled(ctx, exec)

		// Relax /etc/kea's directory permissions so DHCP config validation/apply
		// doesn't fail under AppArmor (see EnsureKeaDirReadable's doc comment).
		keaSvc.EnsureKeaDirReadable()

		// Point /etc/resolv.conf at the local unbound and stop dhclient from
		// undoing it on lease renewal (see EnsureResolvConf's doc comment).
		keaSvc.EnsureResolvConf(ctx)
	}

	// O painel e o monitor de failover sobem PRIMEIRO; a base e o
	// provisionamento vão para segundo plano.
	//
	// Antes, bootstrapdeps.Ensure rodava síncrono aqui: com o executor de
	// pacote (10 min por comando) o pior caso era install + apt-get update +
	// install ≈ 30 minutos sem monitor de failover, sem balanceamento e sem
	// painel. E o cenário em que o apt trava devagar é justamente "a WAN
	// caiu" — exatamente quando o failover é a única coisa que importa. É o
	// padrão do incidente de 2026-07-24, em que uma migração sem transação
	// travou o boot desta aplicação por 50+ minutos numa máquina de
	// produção.
	//
	// Por que esta ordem e não simplesmente limitar o prazo total do Ensure:
	// um teto no Ensure escolhe entre "esperar menos" e "instalar a base" —
	// os dois importam, e num link ruim qualquer teto que caiba num boot
	// aceitável é curto demais para um apt honesto. Subir antes remove a
	// escolha: o painel aparece em milissegundos, o failover está de pé, e a
	// instalação tem todo o tempo de que precisa.
	//
	// Numa máquina já provisionada isto custa quatro dpkg-query e o
	// provisionamento roda igual, poucos milissegundos depois da subida.
	//
	// O laço existe porque Ensure roda uma vez por tentativa e o motivo mais
	// comum de falhar logo depois do boot é o apt-daily/unattended-upgrades
	// estar com o lock do dpkg — nada que uma segunda tentativa alguns
	// minutos depois não resolva. Sem ele, a base nunca era instalada nesse
	// boot. Cada tentativa bem-sucedida reprovisiona (é aí que o `nft`
	// finalmente existe para a reconciliação valer).
	go func() {
		for attempt := 0; ; attempt++ {
			done := bootstrapdeps.Ensure(ctx, pkgExec, alertSvc)
			if done || attempt == 0 {
				provisionSystem()
			}
			if done {
				return
			}
			delay := bootstrapdeps.RetryDelay(attempt)
			slog.Warn("base incompleta; o LinkGuard vai tentar instalar de novo", "em", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()

	// O timer em memória do confirmar-ou-reverte: enquanto o processo vive,
	// é ele que desfaz a mudança de firewall quando o prazo de 90 s termina
	// sem confirmação. A rede embaixo dele é a verificação de boot acima —
	// esta goroutine morre junto com o processo, e é justamente o processo
	// morrer dentro da janela o caso que não pode deixar a regra valendo.
	//
	// Ele sobe AQUI, fora do caminho do bootstrap, e é por isso que numa
	// máquina que ainda está instalando a base (o que pode demorar meia hora)
	// existe alguém observando o pendente desde o primeiro segundo — a
	// verificação de boot, dentro de provisionSystem, só roda depois do
	// bootstrapdeps.Ensure (m-1). É também ele quem RETOMA uma reversão que
	// não pôde ser concluída no nft: nesse caso o pendente continua no banco
	// justamente para dar a ele o que tentar de novo, com backoff.
	//
	// Cinco segundos: a contagem que o operador vê sai de expires_at (do
	// servidor), então isto é só a granularidade da reversão. Custa um SELECT
	// numa tabela de no máximo uma linha.
	go frSvc.WatchPending(ctx, 5*time.Second)

	// As goroutines que ESCREVEM no banco são esperadas no desligamento; as de
	// leitura pura, não.
	//
	// A distinção é o ponto: `httpServer.Shutdown` espera as requisições HTTP e
	// o processo sai, abandonando as goroutines onde estiverem. Para quem só lê
	// (monitor de link, leitura do journal) isso é inofensivo. Para quem tem
	// estado em memória para gravar, não é — o tsdb perdia o balde da janela
	// corrente a cada reinício, e o auto-update reinicia.
	var writers sync.WaitGroup
	spawnWriter := func(name string, fn func()) {
		writers.Add(1)
		go func() {
			defer writers.Done()
			fn()
			slog.Debug("goroutine de escrita encerrada", "nome", name)
		}()
	}

	go monitor.Run(ctx)
	spawnWriter("metrics", func() { metricsCollector.Run(ctx, interval) })
	spawnWriter("tsdb", func() { rrdSvc.Run(ctx) })
	// Escritor: o Run grava o acumulado do minuto na saída, e perder isso a
	// cada reinício abriria um buraco justamente na contagem que a franquia
	// existe para fazer.
	spawnWriter("cota", func() { quotaSvc.Run(ctx) })
	// Escritor: grava a série por host, e perder a última amostra num
	// reinício abre buraco justamente na série que o histórico existe para ter.
	spawnWriter("consumo-por-host", func() { hostSampler.Run(ctx) })
	// Detectores de comportamento (#117): cruzam o histórico por aparelho com o
	// inventário. Cadência de 5 minutos — a série é gravada a cada 10 segundos,
	// e olhar mais rápido só geraria o ruído que a issue manda evitar.
	go func() {
		comp := comportamento.NovoServico(s.db, s.alertSvc)
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				comp.Verificar()
			}
		}
	}()

	go ddnsSvc.Run(ctx)

	// Coletor de dnstap (#116). Sobe sempre; quem decide se há entrega é o
	// unbound, e ele só entrega quando o admin liga o recurso na tela.
	//
	// Falhar aqui NÃO derruba o produto — dnstap é acessório. Mas também não
	// pode falhar em silêncio: sem esta linha, o admin ligaria na tela e não
	// teria como saber por que o mapa fica vazio para sempre.
	go func() {
		if err := s.dnstapSvc.Run(ctx); err != nil {
			slog.Warn("dnstap: o coletor não subiu; o mapa endereço → nome fica vazio", "err", err)
		}
	}()
	// Alimentador de alvo por domínio (#123). NÃO é spawnWriter: ele escreve no
	// kernel, não no banco, e o que ele guarda em memória é cache de resposta de
	// DNS — perder no desligamento é o comportamento certo, porque cache que
	// sobrevive ao reboot afirma sobre endereços o que ninguém mais confirmou.
	//
	// Nesta entrega ele não muda um pacote: as estruturas que ele enche não são
	// olhadas por nenhuma chain, e todo domínio nasce em ensaio.
	go s.domSvc.Run(ctx)
	go func() {
		alvos, err := s.db.ListDomainTargets()
		if err != nil {
			slog.Warn("alvo por domínio: não consegui carregar a lista", "err", err)
			return
		}
		s.domSvc.DefinirAlvos(ctx, alvosDeDominio(alvos))
	}()

	go balancerSvc.Run(ctx)
	spawnWriter("backup", func() { backupSched.Run(ctx) })
	go journalSched.Run(ctx)
	go updatesSched.Run(ctx)
	go netifSvc.RunExpirySweep(ctx, 10*time.Second)
	go ai.RunDigest(ctx, aiClient, rrdSvc, alertSvc, db, func() []string {
		all, _ := db.GetLinks()
		names := make([]string, 0, len(all))
		for _, l := range all {
			if l.Enabled {
				names = append(names, l.Name)
			}
		}
		return names
	})

	return &writers
}

// alvosDeDominio traduz as linhas do banco para o índice do alimentador.
//
// A tradução mora aqui, no ponto de montagem, e não dentro de domtargets: o
// alimentador não conhece o banco de propósito, e é isso que deixa a parte que
// decide (o índice) ser testada sem um arquivo de SQLite por perto.
//
// Estágio que não seja exatamente "ativo" vira ensaio. É a mesma decisão que a
// coluna do banco já toma no DEFAULT, repetida aqui porque este é o último
// ponto em que um valor estranho — de um backup antigo, de uma edição à mão no
// banco — ainda pode ser recusado antes de virar escrita no firewall.
func alvosDeDominio(linhas []storage.DomainTarget) []domtargets.Alvo {
	out := make([]domtargets.Alvo, 0, len(linhas))
	for _, l := range linhas {
		a := domtargets.Alvo{
			Dominio:    l.Domain,
			Capacidade: domtargets.Barrar,
			Estagio:    domtargets.Ensaio,
			Marca:      l.Mark,
		}
		if l.Capability == storage.DomainCapDirecionar {
			a.Capacidade = domtargets.Direcionar
		}
		if l.Stage == storage.DomainStageAtivo {
			a.Estagio = domtargets.Ativo
		}
		out = append(out, a)
	}
	return out
}

// serveHTTP é o fim do boot: sobe o painel e fica nele até o processo receber
// o sinal de desligamento. Devolve o código de saída do processo.
//
// Recebe o WaitGroup das goroutines de escrita porque a ORDEM do desligamento
// é dele: primeiro o HTTP para, só depois se espera quem tem estado em memória
// para gravar — ver o comentário do WaitGroup em startBackground.
func serveHTTP(ctx context.Context, s *services, writers *sync.WaitGroup) int {
	cfg, server := s.cfg, s.server

	httpServer := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		// Carimba cada conexão com o instante do accept (issue #86).
		//
		// Sem esta linha o "Confirmar acesso" volta a aceitar a conexão que já
		// existia antes da mudança — e essa conexão responde mesmo com o acesso
		// cortado, porque uma chain que aceita `ct state established` a mantém
		// de pé. O operador testaria, confirmaria, e descobriria na próxima
		// reconexão.
		//
		// Tirar isto daqui não quebra teste nenhum e não aparece em lugar
		// nenhum: a decisão degrada para "não verificável", que é o lado seguro
		// mas silencioso. Por isso o aviso fica no ponto em que alguém mexeria.
		ConnContext: handlers.ConnContext,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown failed", "err", err)
		}
	}()

	slog.Info("linkguard-fw starting", "version", version, "addr", cfg.Addr(),
		"dry_run", cfg.DryRun, "tls", cfg.TLSEnabled)

	serve := httpServer.ListenAndServe
	if cfg.TLSEnabled {
		if err := tlscert.EnsureSelfSigned(cfg.TLSCert, cfg.TLSKey); err != nil {
			slog.Error("tls certificate setup failed", "err", err)
			return 1
		}
		serve = func() error { return httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey) }
	}
	serveErr := serve()

	// Só depois que o HTTP parou: dar às goroutines de escrita a chance de
	// gravar o que têm em memória. O teto é curto de propósito — o systemd
	// manda SIGKILL depois do TimeoutStopSec, e é melhor perder o resíduo de
	// uma delas do que atrasar o desligamento inteiro do serviço.
	if !waitTimeout(writers, 3*time.Second) {
		slog.Warn("desligando com goroutine de escrita ainda em andamento; algum dado em memória pode não ter sido gravado")
	}

	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		slog.Error("server failed", "err", serveErr)
		return 1
	}
	slog.Info("linkguard-fw stopped")
	return 0
}

// waitTimeout espera o WaitGroup, devolvendo false se o prazo estourar antes.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// seedDefaultRoles seeds the built-in RBAC roles (defined in the auth catalog)
// on first run, without overwriting any later admin customizations.
func seedDefaultRoles(db *storage.DB) error {
	seeds := make([]storage.RoleSeed, 0, len(auth.DefaultRoles))
	adminRoleID := ""
	for _, dr := range auth.DefaultRoles {
		perms := make([]string, len(dr.Permissions))
		for i, p := range dr.Permissions {
			perms[i] = string(p)
			if p == auth.PermUsersManage {
				adminRoleID = dr.ID
			}
		}
		seeds = append(seeds, storage.RoleSeed{
			ID:          dr.ID,
			Name:        dr.Name,
			Description: dr.Description,
			Permissions: perms,
			// Keep the admin role in sync with the catalog across upgrades.
			AlwaysSync: dr.ID == adminRoleID,
		})
	}
	return db.EnsureDefaultRoles(seeds, adminRoleID)
}

// initialAdminPasswordFile é onde a senha gerada na primeira instalação fica
// legível para quem instalou — e só para o root. O journal também a registra,
// mas ele rotaciona; o arquivo é o que ainda está lá no dia seguinte.
const initialAdminPasswordFile = "/etc/linkguard-fw/initial-admin-password"

// seedInitialAdmin cria o administrador da primeira instalação com uma senha
// ALEATÓRIA, e a entrega ao operador pelo log e por um arquivo 0600.
//
// Até a v1.0.82 toda instalação nascia com admin/admin — hash constante numa
// linha de INSERT — sem troca obrigatória, num painel que escuta a LAN inteira.
// Bastava alguém na rede interna conhecer o produto.
//
// Não faz nada quando já existe usuário, então instalação que já roda não é
// afetada: para essas, o caminho é POST /api/auth/change-password, que também
// passou a existir agora.
func seedInitialAdmin(db *storage.DB) error {
	pw, err := generateInitialPassword()
	if err != nil {
		return fmt.Errorf("gerar a senha inicial: %w", err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return fmt.Errorf("cifrar a senha inicial: %w", err)
	}
	created, err := db.SeedInitialAdmin(hash)
	if err != nil {
		return err
	}
	if !created {
		return nil
	}

	// 0600: a senha em claro só interessa a quem tem root, que já poderia
	// redefini-la de qualquer jeito.
	if err := os.WriteFile(initialAdminPasswordFile, []byte(pw+"\n"), 0600); err != nil {
		// Não é fatal — a senha ainda vai para o log, e sem ela a instalação
		// fica inacessível, o que seria pior do que um arquivo faltando.
		slog.Warn("não consegui gravar a senha inicial em arquivo",
			"path", initialAdminPasswordFile, "err", err)
	}
	slog.Warn("PRIMEIRA EXECUÇÃO: administrador criado",
		"usuario", "admin",
		"senha", pw,
		"arquivo", initialAdminPasswordFile,
		"acao", "entre no painel, troque a senha e apague o arquivo")
	return nil
}

// generateInitialPassword devolve 24 caracteres de um alfabeto sem os pares que
// se confundem à mão (0/O, 1/l/I) — a senha é lida de um terminal e digitada de
// novo pelo menos uma vez.
func generateInitialPassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const length = 24
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}
