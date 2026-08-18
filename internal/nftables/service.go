// Package nftables manages the firewall via the native nft tooling. It replaces
// the legacy iptables path: the system now runs a single `table inet linkguard`
// ruleset, and all management (read, backup/restore, host blocking) goes through
// nft rather than iptables.
package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Family/table the application owns.
const (
	Family = "inet"
	Table  = "linkguard"
	// BlockedSet holds individual host IPs whose forwarded traffic is dropped.
	BlockedSet = "blocked_hosts"
	// HostWanMap maps a host IP to the fwmark that steers it to a given WAN.
	HostWanMap = "host_wan"
)

// Service wraps nft operations.
type Service struct {
	exec firewall.Executor

	// groupsSource e ntpInputSource são as duas metades da chain input que
	// este pacote não conhece por si (ver SetInputChainSources).
	groupsSource   func() ([]StoredGroup, error)
	ntpInputSource func() (networks []string, serving bool, err error)
	// inputPolicySource é a política padrão da chain input (#81). Opcional por
	// natureza — nil resolve para accept, que é o comportamento de sempre. Ver
	// policy.go para a razão de ela não abortar quando ausente, ao contrário
	// das duas acima.
	inputPolicySource func() (Policy, error)

	// confPath é o arquivo que Persist grava — o ruleset de BOOT da máquina
	// (ver ConfPath e SetConfPath). Injetável no Service, e não só na variável
	// de pacote, porque Persist é a única escrita deste pacote que NÃO passa
	// pelo Executor: um executor falso intercepta tudo, menos ela. Rodar a
	// suíte como root na própria appliance chegava a sobrescrever o
	// /etc/nftables.conf de verdade com o dump do executor falso — isto é, o
	// firewall da máquina VAZIO no próximo boot. Nos testes ele aponta para
	// t.TempDir(); em produção, para /etc/nftables.conf.
	confPath string

	// unconfirmedChange responde "há uma mudança de firewall aplicada e ainda
	// NÃO confirmada?" — a única pergunta que pode impedir o Persist (ver
	// SetPersistGuard e Persist). Fonte injetada porque a janela de confirmação
	// mora no banco, em internal/firewallrules, e este pacote não pode importar
	// internal/storage (ciclo; ver o doc-comment de StoredRule).
	unconfirmedChange func() (bool, error)

	// reconcileMu serializa as reconciliações das chains compartilhadas —
	// ReconcileGroups/ReconcileGroupsFrom (forward + input) e ReconcileNTPInput
	// (input). Não protege campo nenhum deste struct: protege a SEQUÊNCIA "ler o
	// estado → flush chain → readicionar regra por regra", que não é atômica no
	// kernel. Ver ReconcileGroupsFrom para a corrida que ele fecha (I-3 da
	// revisão final).
	//
	// ORDEM DOS LOCKS, para quem for mexer: firewallrules.Service.mu é tomado
	// ANTES deste (revert → Reconcile → aqui) e nunca depois. Nada que este lock
	// alcança pode tomar aquele — em particular as fontes de
	// SetInputChainSources e a guarda de SetPersistGuard, que por isso são
	// SELECTs soltos, sem mutex nenhum do serviço de firewallrules.
	//
	// Não é reentrante: nenhuma função que o segura pode chamar outra que o
	// tome. É por isso que ReconcileGroups/ReconcileGroupsFrom compartilham um
	// corpo interno (reconcileGroups) em vez de uma chamar a outra.
	reconcileMu sync.Mutex

	// persistMu protege persistState, lido de fora (o vigia, o apply status)
	// enquanto qualquer caminho de reconciliação pode estar escrevendo.
	persistMu sync.Mutex
	// persistState é o resultado da ÚLTIMA tentativa REAL de gravar o arquivo
	// de boot — a memória que faltava para a falha do Persist deixar de ser só
	// um WARN no journal (§10 da validação em VM). Ver PersistState.
	persistState PersistState
}

// PersistState é o que o produto sabe sobre o arquivo de boot: a última vez
// que o Persist tentou MESMO gravá-lo, e com que resultado.
//
// Existe porque o Persist é o ponto em que os cinco chamadores convergem e
// nenhum deles carregava a falha para lugar nenhum além do journal: as regras
// entravam no kernel, o painel dizia `apply_status: {"ok": true}` e a máquina
// voltaria de um reboot com um firewall diferente do que a tela mostrava.
// Gravar o resultado AQUI, e não em cada chamador, é o que torna a falha
// visível independentemente de qual caminho a disparou.
//
// "Tentativa REAL" exclui de propósito os dois casos em que o Persist decide
// não escrever e devolve nil:
//
//   - dry-run: nada neste binário toca no firewall, então não há nada a dizer
//     sobre o arquivo de boot;
//   - a guarda da janela de confirmação (SetPersistGuard): não gravar ali é a
//     decisão certa, dura no máximo os 90 segundos da janela e o painel já
//     mostra a faixa da mudança pendente. Registrá-la como falha faria o vigia
//     acender um item vermelho em toda mutação de escopo input de uma máquina
//     saudável — exatamente o alarme falso que este projeto acabou de corrigir
//     em outro vigia.
//
// Attempted falso significa "ainda não sei", nunca "está tudo bem": quem
// consome isto (monitoring.Collector.checkBootPersist) fica em silêncio em vez
// de inventar um veredito.
type PersistState struct {
	// Attempted é falso até o Persist chegar de fato à gravação uma vez.
	Attempted bool
	// OK diz se a última tentativa gravou o arquivo de boot.
	OK bool
	// Err é a mensagem da falha (vazia quando OK).
	Err string
	// At é o instante (unix) da última tentativa.
	At int64
}

// recordPersist guarda o resultado de uma tentativa real de gravação.
func (s *Service) recordPersist(err error) {
	st := PersistState{Attempted: true, OK: err == nil, At: time.Now().Unix()}
	if err != nil {
		st.Err = err.Error()
	}
	s.persistMu.Lock()
	s.persistState = st
	s.persistMu.Unlock()
}

// PersistState devolve o resultado da última tentativa real de gravar o
// arquivo de boot. Ver o tipo PersistState para o que "real" exclui.
func (s *Service) PersistState() PersistState {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	return s.persistState
}

// NewService creates an nftables Service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec, confPath: ConfPath}
}

// SetConfPath aponta o Persist para outro arquivo. Existe para os testes
// escreverem em t.TempDir() (ver o campo confPath); em produção o valor vem de
// NewService e é /etc/nftables.conf.
func (s *Service) SetConfPath(path string) { s.confPath = path }

// SetPersistGuard liga o Persist à janela de confirmação (Fase C2, I-1 da
// revisão final): enquanto houver uma mudança de firewall aplicada e ainda não
// confirmada, o ruleset vivo NÃO vai para o arquivo de boot.
//
// O buraco que isto fecha é o único que a revisão achou em que o operador fica
// trancado sem o LinkGuard poder ajudá-lo. A sequência: o operador cria um
// grupo de escopo input que dropa `tcp dport 22`; a reconciliação aplica e
// persiste; aos 30 segundos cai a energia. O nftables.service do systemd carrega
// /etc/nftables.conf ANTES de o LinkGuard subir, então a máquina volta com a
// regra valendo — SSH bloqueado. Quem devolveria o acesso é
// firewallrules.RevertPendingOnBoot, mas ele só roda depois do
// bootstrapdeps.Ensure e só se o LinkGuard subir; este projeto já teve um boot
// da aplicação travado por mais de 50 minutos (incidente de 2026-07-24), e
// nesse intervalo o operador fica sem SSH e sem painel, sem conserto remoto.
//
// O custo, dito por inteiro: um boot em que a regra CONFIRMADA ainda não está
// no arquivo (porque o confirmar-ou-reverte é o que dispara a persistência dela)
// sobe sem ela até a reconciliação do LinkGuard. É fail-open — a máquina volta
// com o firewall de antes da mudança arriscada, não com uma regra que pode
// trancar quem precisa consertá-la —, que é a direção certa para este caso.
//
// A fonte NÃO PODE tomar mutex nenhum do chamador: Persist é alcançado de
// dentro de firewallrules.revert, que já segura o mutex do serviço. É por isso
// que a implementação de produção (firewallrules.UnconfirmedChangePending) é um
// SELECT solto.
//
// Erro na fonte também impede o Persist, pela mesma razão de tudo mais neste
// mecanismo: quem não consegue PROVAR que não há janela aberta não pode gravar
// o arquivo de boot por otimismo.
func (s *Service) SetPersistGuard(pending func() (bool, error)) { s.unconfirmedChange = pending }

// persistBlocked diz se o Persist deve parar antes de escrever, e já registra
// o motivo. Sem guarda ligada (testes, binários que não têm banco), nada bloqueia
// — a ausência de guarda é o comportamento anterior à Fase C2, e ligá-la em
// produção é obrigação do main (guardado por TestMainWiresThePersistGuard).
func (s *Service) persistBlocked() bool {
	if s.unconfirmedChange == nil {
		return false
	}
	pending, err := s.unconfirmedChange()
	if err != nil {
		slog.Error("o ruleset NÃO foi persistido para o próximo boot: não foi possível saber se há uma mudança de firewall aguardando confirmação, e gravar o arquivo de boot sem essa resposta pode congelar nele uma regra não confirmada", "err", err)
		return true
	}
	if pending {
		slog.Info("o ruleset não foi persistido para o próximo boot: há uma mudança de firewall aguardando confirmação; a persistência acontece quando ela for confirmada ou revertida")
		return true
	}
	return false
}

// PersistPath é o arquivo que Persist grava. O fallback para a variável de
// pacote cobre os Service montados por literal (`&Service{exec: …}`, comum nos
// testes deste pacote), que nunca passaram por NewService.
//
// Exportado porque o vigia precisa perguntar por ele: checkBootPersist confere
// a EXISTÊNCIA deste arquivo, e um caminho fixo no vigia divergiria em silêncio
// de um Service redirecionado por SetConfPath (o que a suíte inteira faz).
func (s *Service) PersistPath() string {
	if s.confPath != "" {
		return s.confPath
	}
	return ConfPath
}

// SetInputChainSources liga o Service às duas coisas que dividem a chain
// input e que ele não tem como conhecer sozinho — o banco mora em
// internal/storage, que este pacote não pode importar (ciclo; ver o
// doc-comment de StoredRule).
//
// Desde a Fase C2 a chain input é reconstruída INTEIRA a cada passada, por um
// renderizador só (inputChainRules). Cada chamador sabe explicitamente uma
// das metades e precisa da outra para não apagá-la:
//
//   - ReconcileNTPInput recebe o estado do NTP por parâmetro e lê os GRUPOS
//     daqui;
//   - ReconcileGroups recebe os grupos por parâmetro e lê o ESTADO DO NTP
//     daqui.
//
// Ligar isto é obrigatório em produção, e cmd/linkguard-fw/main.go o faz
// junto da construção dos serviços (guardado por
// TestMainWiresTheInputChainSources). Sem a fonte do NTP, ntpInputState
// devolve erro (m3 da revisão) — não mais um slog.Error e um silêncio que
// deixava ReconcileGroups seguir como se "servir NTP" fosse desligado.
//
// AS DUAS FONTES DEVOLVEM ERRO, e pela mesma razão (I-1 e m3 da revisão da
// Fase C2): quem lê "não consegui ler" NÃO pode tratar isso como "está
// desligado"/"não existe" — nem quando o motivo é a leitura em si falhar,
// nem quando o motivo é a fonte nunca ter sido ligada. Uma leitura de
// settings que falha (banco travado, IO, JSON corrompido) ou uma fonte
// ausente devolvendo "servir NTP: não" faria ReconcileGroups dar flush na
// chain input e reescrevê-la só com os jumps — as duas linhas de udp/123
// sumiriam do firewall vivo, o painel continuaria mostrando o toggle ligado,
// e o apply seria reportado ok. Fail-open silencioso. Com o erro explícito
// nos dois casos, quem reconcilia ABORTA sem tocar na chain, exatamente
// como já fazia do lado dos grupos.
func (s *Service) SetInputChainSources(groups func() ([]StoredGroup, error), ntpInput func() ([]string, bool, error)) {
	s.groupsSource = groups
	s.ntpInputSource = ntpInput
}

// inputChainGroups devolve os grupos gravados para quem vai reconstruir a
// chain input sem tê-los recebido por parâmetro. Erro é propagado (o chamador
// aborta sem tocar na chain); fonte não ligada devolve lista vazia com aviso.
func (s *Service) inputChainGroups() ([]StoredGroup, error) {
	if s.groupsSource == nil {
		slog.Warn("nenhuma fonte de grupos ligada ao serviço de nftables: a chain input será reconstruída só com as regras do NTP (ver SetInputChainSources)")
		return nil, nil
	}
	return s.groupsSource()
}

// ntpInputState devolve o estado de "servir NTP para a LAN" para quem vai
// reconstruir a chain input sem tê-lo recebido por parâmetro. As duas formas
// de não conseguir responder — ERRO DE LEITURA e fonte NÃO LIGADA — levam ao
// mesmo tratamento: erro propagado, chamador aborta sem tocar na chain.
//
// Antes desta correção (achado m3 da revisão) as duas eram tratadas de forma
// diferente: erro de leitura virava erro, fonte não ligada virava
// (nil, false, nil) com só um slog.Error de aviso. Essa segunda forma é
// exatamente o fail-open que a primeira existe para fechar (I-1) — só que
// pelo lado da "fonte nunca foi ligada" em vez do lado "SELECT falhou": os
// dois casos fazem ReconcileGroups/ReconcileNTPInput dar flush na chain input
// vivendo e reescrevê-la só com os jumps, apagando as duas linhas de udp/123
// do firewall vivo enquanto o painel continua mostrando o toggle ligado e o
// apply é reportado ok. Fonte não ligada é bug de binário mal montado (falta
// a chamada a SetInputChainSources, guardada por
// TestMainWiresTheInputChainSources em cmd/linkguard-fw), não estado de
// produção — mas um guarda de deriva na AST é defesa fraca sozinha para um
// firewall: se o binário de produção algum dia rodar sem essa ligação (build
// alternativo, teste que constrói Service direto, refactor que remove a
// chamada sem que o teste de deriva pegue), o silêncio anterior apagava a
// proteção do NTP sem avisar. Agora aborta, como o erro de leitura já fazia.
func (s *Service) ntpInputState() ([]string, bool, error) {
	if s.ntpInputSource == nil {
		err := fmt.Errorf("nenhuma fonte de configuração do NTP ligada ao serviço de nftables (SetInputChainSources nunca foi chamado)")
		slog.Error("a chain input NÃO será tocada: " + err.Error())
		return nil, false, err
	}
	return s.ntpInputSource()
}

// Ruleset returns the full live nftables ruleset (`nft list ruleset`).
func (s *Service) Ruleset(ctx context.Context) (string, error) {
	return s.exec.ExecuteRead(ctx, "nft", "list", "ruleset")
}

// Save returns the current ruleset for storage as a backup (same as Ruleset).
func (s *Service) Save(ctx context.Context) (string, error) {
	return s.Ruleset(ctx)
}

// ErrNoLinkguardTable é a recusa de restaurar um snapshot que não contém a
// tabela que o LinkGuard possui — ver LinkguardTableBlock e Restore.
var ErrNoLinkguardTable = fmt.Errorf("o snapshot não contém a tabela %s %s", Family, Table)

// LinkguardTableBlock extrai de um dump de `nft list ruleset` APENAS o bloco
// `table inet linkguard { … }`. É o que torna o Restore escopado (ver lá).
//
// O reconhecimento é ancorado no formato que o próprio nft emite, e não numa
// contagem de chaves: o dump abre a tabela com `table inet linkguard {` na
// coluna 0 e a fecha com um `}` sozinho, também na coluna 0, enquanto TODA
// linha do corpo — chain, set, map, elemento de lista quebrada em várias
// linhas, comentário — começa com tabulação. Medido contra o nft 1.1.3 de
// verdade (v. .superpowers/sdd/rollback-trava-e-flush.md): nem um comentário
// contendo `}` (`comment "chave } com chave"`), nem uma lista de elementos
// longa o bastante para o nft quebrar em várias linhas produzem `}` na coluna
// 0. Contar chaves, ao contrário, se perderia justamente nesse comentário e
// devolveria um bloco TRUNCADO — que é o pior desfecho possível aqui, porque
// um bloco truncado ainda pode ser um ruleset válido e seria aplicado
// atomicamente como se fosse o snapshot inteiro.
//
// Um dump sem a nossa tabela devolve ErrNoLinkguardTable, nunca string vazia:
// um snapshot antigo, ou de uma máquina onde a tabela ainda não existia, tem
// que virar recusa VISÍVEL, não um restore que não restaura nada e responde
// "pronto".
func LinkguardTableBlock(dump string) (string, error) {
	header := fmt.Sprintf("table %s %s {", Family, Table)
	lines := strings.Split(dump, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimRight(l, " \t\r") == header {
			start = i
			break
		}
	}
	if start < 0 {
		return "", ErrNoLinkguardTable
	}
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], " \t\r") == "}" {
			return strings.Join(lines[start:i+1], "\n"), nil
		}
	}
	return "", fmt.Errorf("o bloco de `table %s %s` do snapshot não está fechado (dump truncado?)", Family, Table)
}

// ErrInputPolicyNotAccept é a recusa de restaurar um snapshot cuja chain
// `input` traz uma política restritiva. Ver refuseRestrictiveInputPolicy.
var ErrInputPolicyNotAccept = fmt.Errorf("a chain `input` do snapshot não tem `policy accept`")

// inputChainPolicyRe casa a linha de declaração de uma chain base como o nft
// 1.1.3 a IMPRIME — medido, não imaginado (`unshare -rn` + `nft list ruleset`,
// nftables v1.1.3):
//
//	\t\ttype filter hook input priority filter; policy drop;
//
// Duas coisas que a medição fixou e que uma fixture inventada erraria:
//
//   - o nft SEMPRE imprime `policy <x>;` numa chain base, mesmo quando o
//     arquivo de entrada não trazia política nenhuma (o default `accept` é
//     materializado na saída). Ou seja: ausência da linha `type … hook …` numa
//     chain chamada `input` significa "não é chain base", não "política oculta";
//   - `priority` sai por NOME quando existe um nome (`filter`, `mangle`), não
//     pelo número que entrou — daí o `[^;]+` em vez de algo mais específico.
//
// A âncora é `type … hook …`, e não a substring `policy`: o comentário de uma
// REGRA pode conter a palavra (medido: `comment "policy drop dentro de
// comentario"` é impresso literalmente), e uma busca solta recusaria um snapshot
// perfeitamente legítimo — o que seria pior que o defeito, porque tiraria do
// operador a única ferramenta de recuperação que ele tem.
var inputChainPolicyRe = regexp.MustCompile(`^type\s+\S+\s+hook\s+\S+\s+priority\s+[^;]+;\s*policy\s+([A-Za-z_]+)\s*;`)

// refuseRestrictiveInputPolicy recusa um bloco de tabela cuja chain `input`
// venha com política diferente de `accept`.
//
// POR QUE ISTO EXISTE. A invariante mais dura deste projeto é que a chain
// `input` nasce e permanece com `policy accept`; bloqueio se faz por REGRA
// explícita, nunca por política. A razão é textual e operacional: uma política
// restritiva trancaria o operador para fora de um firewall em produção,
// possivelmente de madrugada e sem acesso físico — não há regra de SSH que
// sobreviva a um `policy drop` que casou antes dela em outra passada, e não há
// como voltar atrás pela rede depois que ela vale.
//
// O produto nunca EMITE `policy drop` (há teste garantindo), então este caminho
// não é alcançável por um snapshot gerado por nós. Mas o Restore é o único lugar
// que aplica texto de firewall que o produto não gerou: a linha
// `iptables_backups` pode ter sido editada à mão, vir de outra máquina, ou ter
// sido capturada quando alguém estava mexendo no ruleset por fora. É a única
// porta pela qual um `policy drop` editado à mão entra no kernel.
//
// POR QUE AQUI, E NÃO EM LinkguardTableBlock. A recusa mora no Restore (que a
// chama), não no recorte, por três motivos:
//
//  1. LinkguardTableBlock é um extrator PURO e o nome promete só isso. Um
//     futuro leitor legítimo — mostrar o diff de um snapshot na tela, comparar
//     dois backups, um relatório — precisa conseguir LER um snapshot ruim
//     justamente para explicar por que ele é ruim. Recusar na leitura tiraria
//     essa possibilidade e transformaria "não posso aplicar" em "não posso nem
//     olhar";
//  2. a invariante é sobre APLICAR, não sobre parsear. Quem viola a regra de
//     ouro é quem escreve no kernel, e é lá que a guarda tem valor de fato;
//  3. o Restore é o único chamador que escreve. Colocar a guarda nele mantém
//     "toda escrita passa por esta verificação" verdadeiro sem precisar
//     depender de o próximo chamador lembrar.
//
// A verificação roda ANTES de qualquer efeito: antes do arquivo temporário,
// antes do pré-voo `nft -c -f` e antes do `nft -f`. Nada é alterado no firewall.
//
// O que NÃO é recusado, de propósito: um bloco sem chain `input` nenhuma, e um
// bloco cuja `input` não é chain base (sem `type … hook …`). Nos dois casos não
// existe política de input a valer — não há hook —, logo não há tranca. Recusar
// aí seria recusar um snapshot legítimo, e este projeto prefere o falso negativo
// ao falso positivo quando o falso positivo tira do operador o botão de
// recuperação.
func refuseRestrictiveInputPolicy(block string) error {
	inInput := false
	for _, l := range strings.Split(block, "\n") {
		t := strings.TrimSpace(l)
		if !inInput {
			if t == "chain input {" {
				inInput = true
			}
			continue
		}
		if t == "}" { // fim da chain input
			return nil
		}
		m := inputChainPolicyRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		if policy := m[1]; policy != "accept" {
			return fmt.Errorf("%w (veio `policy %s`): uma política restritiva na chain `input` trancaria o operador para fora deste firewall — sem acesso físico e sem como desfazer pela rede. O LinkGuard bloqueia por regra explícita, nunca por política, e por isso nunca gera um snapshot assim; este foi editado à mão ou veio de outra máquina. Nada foi alterado no firewall",
				ErrInputPolicyNotAccept, policy)
		}
		return nil
	}
	return nil
}

// Restore reaplica um snapshot de ruleset — ESCOPADO à tabela `inet linkguard`.
//
// O que ele NÃO faz mais: `flush ruleset`. A versão anterior mandava ao `nft -f`
// um arquivo que começava por `flush ruleset` e seguia com o dump inteiro que o
// Save guardou. Isso viola a regra de ouro do produto ("o LinkGuard só mexe na
// tabela dele") de duas formas, as duas medidas contra o nft real:
//
//   - toda tabela de terceiro criada DEPOIS do snapshot (docker, libvirt,
//     tailscale, ou uma do próprio admin) desaparecia, e nenhum desses
//     programas a recria sozinho: quem cria a tabela do Docker é o daemon, na
//     inicialização dele;
//   - as que existiam no instante do snapshot voltavam ao conteúdo ANTIGO
//     delas, o que é pior do que sumir — a máquina fica com regras de terceiro
//     ressuscitadas que ninguém pediu de volta, e foi assim que uma
//     `iptables -t nat -A POSTROUTING -j MASQUERADE` capturada por engano
//     sobreviveu à própria remoção nesta produção (ver Persist).
//
// O que ele faz agora é o mesmo idioma já provado em produção pelo Persist: um
// `table inet linkguard` (cria se não existir, então a linha nunca falha),
// seguido de `delete table inet linkguard` (agora garantidamente seguro) e da
// definição inteira vinda do snapshot. O resultado é EXATAMENTE a tabela do
// snapshot — nada da tabela antiga sobrevive, o que uma reconstrução chain a
// chain não conseguiria garantir sem reimplementar um diff — e nenhuma outra
// tabela da máquina é tocada. `nft -f` é uma transação: ou entra tudo, ou não
// entra nada.
//
// O pré-voo `nft -c -f` roda antes do apply de verdade pelo motivo de sempre
// neste projeto: separar "o snapshot não compila" (backup ruim, e nada foi
// aplicado) de "o kernel recusou".
//
// EM DRY-RUN O PRÉ-VOO RODA DE VERDADE. `DryRunExecutor.ExecuteRead` executa o
// comando mesmo em dry-run (é leitura; a inspeção do firewall tem que continuar
// funcionando), e `nft -c -f` precisa de CAP_NET_ADMIN mesmo com o `-c`, porque
// ele valida contra o kernel. Em produção isso é inócuo: o serviço roda como
// root e o `-c` não commita nada — nenhuma linha do snapshot entra no firewall.
// Mas quem rodar o binário em dry-run FORA da appliance (na estação de
// desenvolvimento, sem privilégio) vai ver este Restore falhar aqui, no pré-voo,
// e não no apply. É comportamento esperado, não defeito: o dry-run cobre a
// escrita, não a leitura. Se algum dia isso incomodar, o conserto é pular o
// pré-voo quando `s.exec.IsDryRun()` — deliberadamente NÃO feito agora, porque
// pular a validação é exatamente o que faria um snapshot ruim chegar ao `nft -f`
// sem ninguém ter conferido.
func (s *Service) Restore(ctx context.Context, ruleset string) (string, error) {
	block, err := LinkguardTableBlock(ruleset)
	if err != nil {
		return "", err
	}
	// Antes do arquivo temporário, do pré-voo e do apply: um snapshot com a
	// chain `input` trancada nunca chega a ser escrito em lugar nenhum.
	if err := refuseRestrictiveInputPolicy(block); err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "linkguard-nft-*.conf")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	body := fmt.Sprintf("table %s %s\ndelete table %s %s\n\n%s\n", Family, Table, Family, Table, block)
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		return "", fmt.Errorf("write ruleset: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	if out, err := s.exec.ExecuteRead(ctx, "nft", "-c", "-f", f.Name()); err != nil {
		return out, fmt.Errorf("o snapshot não passou na validação do nft (`nft -c -f`), nada foi aplicado: %w", err)
	}
	return s.exec.Execute(ctx, "nft", "-f", f.Name())
}

// BlockHost drops a host's forwarded traffic by adding its IP to the blocked set.
func (s *Service) BlockHost(ctx context.Context, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, BlockedSet, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// UnblockHost removes a host's IP from the blocked set.
func (s *Service) UnblockHost(ctx context.Context, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, BlockedSet, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// ─── Managed view & editing (sets / map elements) ────────────────────────────

// ConfPath is the persisted ruleset loaded by nftables.service at boot — the
// DEFAULT for a Service built by NewService, and the fallback for one built by
// literal.
//
// Ainda é var (não const) porque os testes deste pacote montam Service por
// literal; o caminho de verdade a partir de agora é o campo confPath do
// Service (ver SetConfPath). Persist é a única escrita em disco deste pacote
// que não passa pelo Executor — ou seja, a única que um executor falso NÃO
// intercepta —, e o arquivo que ela grava é o firewall com que a máquina
// volta em todo boot.
var ConfPath = defaultConfPath

// defaultConfPath é o caminho de PRODUÇÃO — o arquivo que o nftables.service
// do systemd carrega no boot, antes de o LinkGuard subir. Constante, para que
// um teste possa afirmar que ele não mudou mesmo com ConfPath redirecionado
// para um temporário durante a suíte.
const defaultConfPath = "/etc/nftables.conf"

// DefaultWanMark steers a host to the secondary WAN (sumicity).
const DefaultWanMark = "0x12c"

// WanHost is one entry of the host_wan map (a host steered to a WAN by fwmark).
type WanHost struct {
	IP   string `json:"ip"`
	Mark string `json:"mark"`
}

// Managed is the editable, element-level view of the linkguard ruleset.
type Managed struct {
	WanHosts     []WanHost `json:"wan_hosts"`
	Blocklist    []string  `json:"blocklist"`
	BlockedHosts []string  `json:"blocked_hosts"`
}

// Managed returns the current elements of the host_wan map and the sets.
func (s *Service) Managed(ctx context.Context) (*Managed, error) {
	m := &Managed{WanHosts: []WanHost{}, Blocklist: []string{}, BlockedHosts: []string{}}

	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "map", Family, Table, HostWanMap); err == nil {
		for _, e := range parseElements(out) {
			parts := strings.SplitN(e, ":", 2)
			h := WanHost{IP: strings.TrimSpace(parts[0])}
			if len(parts) == 2 {
				h.Mark = strings.TrimSpace(parts[1])
			}
			m.WanHosts = append(m.WanHosts, h)
		}
	}
	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "set", Family, Table, "blocklist"); err == nil {
		m.Blocklist = parseElements(out)
	}
	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "set", Family, Table, BlockedSet); err == nil {
		m.BlockedHosts = parseElements(out)
	}
	return m, nil
}

// AddWanHost steers a host IP to a WAN by adding it to the host_wan map.
func (s *Service) AddWanHost(ctx context.Context, ip, mark string) (string, error) {
	if mark == "" {
		mark = DefaultWanMark
	}
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip inválido")
	}
	if !ValidMark(mark) {
		return "", fmt.Errorf("marca inválida")
	}
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, HostWanMap, "{", ip, ":", mark, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// DelWanHost removes a host from the host_wan map (reverts it to the primary WAN).
func (s *Service) DelWanHost(ctx context.Context, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, HostWanMap, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// AddBlocklist blocks a destination CIDR by adding it to the blocklist set.
func (s *Service) AddBlocklist(ctx context.Context, cidr string) (string, error) {
	cidr = strings.TrimSpace(cidr)
	if !validIPOrCIDR(cidr) {
		return "", fmt.Errorf("CIDR/IP inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, "blocklist", "{", cidr, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// DelBlocklist removes a destination CIDR from the blocklist set.
func (s *Service) DelBlocklist(ctx context.Context, cidr string) (string, error) {
	cidr = strings.TrimSpace(cidr)
	if !validIPOrCIDR(cidr) {
		return "", fmt.Errorf("CIDR/IP inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, "blocklist", "{", cidr, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// Persist writes ConfPath — reloaded by nftables.service at boot — so element
// edits (host_wan, blocklist, user rules, port forwards, ...) survive a
// reboot. Skipped in dry-run.
//
// Two hard-won constraints, both from a production incident (see
// docs/incidents or ask before "simplifying" this):
//
//  1. It serializes ONLY `table Family Table` (the table LinkGuard owns) via
//     `nft list table <family> <table>`, never `nft list ruleset` (the whole
//     kernel ruleset). During an incident an operator manually added a
//     blanket `iptables -t nat -A POSTROUTING -j MASQUERADE`, which lives in
//     `table ip nat` — a table LinkGuard does not own. A prior version of
//     this function dumped the entire ruleset into ConfPath, so it captured
//     that foreign rule and nftables.service recreated it on every boot, even
//     after it was deleted from the live ruleset. That rule had no interface
//     filter, so it masqueraded loopback traffic too: the box's own DNS
//     queries to 127.0.0.1 arrived at unbound with the WAN's source address
//     and were refused, chrony then had no working DNS to resolve its NTP
//     pool, and the clock silently drifted unsynchronized. LAN clients kept
//     working throughout, so the panel looked healthy — the failure was
//     invisible until directly investigated. Scoping to `table Family Table`
//     means a foreign table can never be captured here again.
//  2. The written file leads with the standard nft idempotent-reload
//     preamble — a bare `table <family> <table>` (creates it if absent, so
//     this line can never fail) followed by `delete table <family> <table>`
//     (now safe to delete, since it's guaranteed to exist) — before the full
//     table definition. Without this, `nft -f` on a box where the table
//     already exists in the kernel *appends* the definition instead of
//     replacing it, which is exactly how the same production box ended up
//     with two `oifname { ... } masquerade` rules in the postrouting chain,
//     one of them referencing an interface that no longer existed. This is
//     deliberately NOT `flush ruleset`: that would delete every foreign
//     table (including whatever else the box's operator or another tool set
//     up) on every boot, which is the opposite of what this fix is about —
//     LinkGuard resets only the table it owns.
//
// Uma terceira condição, da Fase C2 (I-1 da revisão final): com uma mudança
// aguardando confirmação, isto NÃO grava nada e devolve nil. O arquivo de boot
// não pode receber uma regra que ainda não se provou boa — ver SetPersistGuard
// para o cenário inteiro. Devolve nil, e não erro, porque não é falha: é a
// decisão de não gravar. Todo chamador trata o erro daqui como "não consegui
// persistir" e o registra em WARN; um erro sintético encheria o journal de
// alarme falso a cada reconciliação dos 90 segundos.
//
// A FALHA DAQUI NÃO É MAIS MUDA NA TELA (§10 da validação final em VM,
// 2026-08-13). O que ela era: os cinco chamadores logavam um WARN e seguiam em
// frente, e mais nada. Medido com /etc/nftables.conf ausente e /etc imutável,
// de modo que o ExecStartPre (que tem o prefixo `-`) não conseguisse criar o
// arquivo — o serviço sobe, o painel responde 200, o apply CHEGA ao kernel e as
// regras valem, e o painel dizia `apply_status: {"ok": true}`, sem alerta e sem
// item de saúde depois de 2 ciclos do vigia. A única evidência era o journal, e
// as regras não sobreviveriam ao reboot: a máquina voltaria com um firewall
// diferente do que a tela mostrava. É o modo de falha que o prefixo `-`
// introduziu — o `-` funciona como projetado (antes dele a máquina não subia),
// mas o preço era esse estado silencioso, contra a regra do projeto de que
// "configurado ≠ funcionando" tem que ser visível na tela.
//
// O conserto ficou AQUI, e não nos cinco chamadores, porque aqui é onde eles
// convergem: recordPersist grava o resultado de toda tentativa real em
// PersistState, e as duas superfícies leem de lá —
//
//   - firewallrules.Service.recordApplyStatus, que deixa de dizer `ok: true` e
//     nomeia o que não aconteceu em `boot_persist_error` (sem virar erro do
//     apply: as regras ENTRARAM no kernel, e reportar erro faria o operador
//     desfazer um trabalho que funcionou);
//   - monitoring.Collector.checkBootPersist, o item "Regras no próximo boot" da
//     Saúde do sistema, que é a superfície certa para uma CONDIÇÃO contínua e
//     some sozinha quando o arquivo volta a ser gravado.
//
// COMO A CONDIÇÃO SE RESOLVE, MEDIDO (validação em VM de 2026-08-13, cenário 5):
// **reiniciando o serviço** — `systemctl restart linkguard-fw` — depois de
// devolver a permissão de escrita no host. Uma mutação nova NÃO resolve, e esta
// é a metade que a documentação anterior errava (dizia "até a próxima mutação ou
// o próximo boot"). O motivo é a armadilha de namespace do systemd que este
// projeto já pisou duas vezes: a unidade tem `ProtectSystem=strict` com
// `ReadWritePaths=-/etc/nftables.conf`, e um caminho que NÃO EXISTIA no start do
// serviço não entra gravável no namespace. Devolver a permissão ao /etc do host
// não remonta nada — o processo já rodando continua vendo o caminho como
// somente leitura, então a mutação seguinte falha exatamente igual, o
// apply_status continua `ok: false` e o arquivo continua ausente. Só um start
// novo monta o namespace de novo. É por isso que as duas superfícies de tela (a
// faixa âmbar e o item de saúde) mandam reiniciar o serviço, e não mexer numa
// regra: mandar o operador tentar a mutação primeiro é mandá-lo concluir que o
// produto está quebrado.
//
// Continua devolvendo o erro ao chamador, e todo chamador continua tratando-o
// como WARN e seguindo em frente: as regras estão valendo, e abortar por causa
// do arquivo de boot seria trocar um problema futuro por um presente.
func (s *Service) Persist(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if s.persistBlocked() {
		return nil
	}
	// Daqui para baixo é uma tentativa REAL de gravar: todo caminho de saída
	// passa por recordPersist. A recusa do `nft list table` conta como falha de
	// persistência porque a consequência é a mesma — o arquivo de boot fica com
	// o conteúdo antigo (ou não existe) enquanto o kernel tem outro.
	tbl, err := s.exec.ExecuteRead(ctx, "nft", "list", "table", Family, Table)
	if err != nil {
		s.recordPersist(err)
		return err
	}
	body := fmt.Sprintf(
		"#!/usr/sbin/nft -f\n\ntable %s %s\ndelete table %s %s\n\n%s\n",
		Family, Table, Family, Table, tbl,
	)
	err = os.WriteFile(s.PersistPath(), []byte(body), 0o644)
	s.recordPersist(err)
	return err
}

// ─── Port forwarding (DNAT) ──────────────────────────────────────────────────

// DNATChain is the prerouting nat chain that holds port-forward rules. It is
// created on demand and fully rebuilt on every apply, so it is always an exact
// reflection of the stored forwards.
const DNATChain = "prerouting_dnat"

// PortForward describes a single external-port → internal-host:port mapping.
type PortForward struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Proto     string `json:"proto"`     // tcp | udp
	Interface string `json:"interface"` // WAN iif; empty = any
	ExtPort   int    `json:"ext_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
}

// ApplyPortForwards rebuilds the DNAT chain from the given forwards atomically
// (`nft -f` with flush + re-add) and persists the ruleset. Only enabled,
// well-formed entries are emitted.
func (s *Service) ApplyPortForwards(ctx context.Context, fwds []PortForward) error {
	var b strings.Builder
	// Idempotent chain create, then flush + re-add inside one atomic load.
	fmt.Fprintf(&b, "add chain %s %s %s { type nat hook prerouting priority dstnat ; policy accept ; }\n",
		Family, Table, DNATChain)
	fmt.Fprintf(&b, "flush chain %s %s %s\n", Family, Table, DNATChain)
	for _, f := range fwds {
		if !f.Enabled {
			continue
		}
		rule, err := dnatRule(f)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "add rule %s %s %s %s\n", Family, Table, DNATChain, rule)
	}

	f, err := os.CreateTemp("", "linkguard-dnat-*.conf")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return fmt.Errorf("write dnat: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if _, err := s.exec.Execute(ctx, "nft", "-f", f.Name()); err != nil {
		return fmt.Errorf("apply port forwards: %w", err)
	}
	return s.Persist(ctx)
}

// dnatRule renders one PortForward into an nft rule body (inet family DNAT to an
// IPv4 destination requires the `dnat ip to` form).
func dnatRule(f PortForward) (string, error) {
	proto := strings.ToLower(strings.TrimSpace(f.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", fmt.Errorf("protocolo inválido: %q (use tcp ou udp)", f.Proto)
	}
	if f.ExtPort < 1 || f.ExtPort > 65535 || f.DestPort < 1 || f.DestPort > 65535 {
		return "", fmt.Errorf("porta fora do intervalo 1-65535")
	}
	if net.ParseIP(f.DestIP) == nil || strings.Contains(f.DestIP, ":") {
		return "", fmt.Errorf("IP de destino inválido: %q", f.DestIP)
	}
	var parts []string
	if iif := strings.TrimSpace(f.Interface); iif != "" {
		if !reIface.MatchString(iif) {
			return "", fmt.Errorf("interface inválida: %q", iif)
		}
		parts = append(parts, fmt.Sprintf("iifname %q", iif))
	}
	parts = append(parts,
		fmt.Sprintf("%s dport %d", proto, f.ExtPort),
		fmt.Sprintf("dnat ip to %s:%d", f.DestIP, f.DestPort),
	)
	return strings.Join(parts, " "), nil
}

// ─── User rules (custom allow/block, ordered, edited via modal) ──────────────

// UserChain is the admin-managed chain. It is NO LONGER reached from
// `forward`: since rule groups (Phase C1) the admin's rules live inside a
// group chain, and the one-off migration moves the old ones into the group
// "Minhas regras". The chain and its contents stay put — it is still
// reconciled from the DB (ReconcileUserRules) and still read by the panel —
// but nothing jumps into it, so nothing in it is evaluated by the kernel.
const UserChain = "user_rules"

// RuleFields is the structured, UX-friendly description of a custom rule. The
// admin fills these in a modal; the spec is built server-side so they never see
// raw nft syntax.
type RuleFields struct {
	Action string `json:"action"` // accept | drop | reject
	Iif    string `json:"iif"`    // input interface
	Oif    string `json:"oif"`    // output interface
	Saddr  string `json:"saddr"`  // source IP/CIDR
	Daddr  string `json:"daddr"`  // destination IP/CIDR
	Proto  string `json:"proto"`  // tcp | udp | icmp | ""
	Dport  string `json:"dport"`  // destination port (tcp/udp)
}

// UserRule is a stored custom rule with its nft handle (stable id) and the
// parsed fields so the modal can pre-fill on edit.
type UserRule struct {
	Handle int    `json:"handle"`
	Raw    string `json:"raw"`
	RuleFields
}

var (
	reHandle  = regexp.MustCompile(`# handle (\d+)`)
	reCounter = regexp.MustCompile(`counter packets \d+ bytes \d+`)
)

// ListUserRules returns the custom rules in order, with handles and fields.
// Read-only by design: the admin's rules are now DB-authoritative (design
// spec §4.1) and rendered into nft by ReconcileUserRules, not edited
// directly by handle — the handle-based AddUserRule/UpdateUserRule/
// DeleteUserRule/MoveUserRule this function used to support were removed
// once every caller moved to the DB (internal/firewallrules,
// internal/api/handlers/nftables.go); keeping a handle-based mutation path
// alongside a DB-authoritative reconcile would only invite a future caller
// that writes straight to nft and drifts from the DB the same way the
// pre-Phase-B code did. ListUserRules itself stays: the one-time import
// (firewallrules.Service.ImportOnce) still needs to read the pre-existing
// live chain.
func (s *Service) ListUserRules(ctx context.Context) ([]UserRule, error) {
	out, err := s.exec.ExecuteRead(ctx, "nft", "-a", "list", "chain", Family, Table, UserChain)
	if err != nil {
		return nil, err
	}
	rules := []UserRule{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Skip the chain header (`chain user_rules { # handle N`) and any block
		// delimiters — only actual rule lines carry a handle here.
		if strings.HasPrefix(line, "chain ") || strings.Contains(line, "{") || strings.HasPrefix(line, "}") {
			continue
		}
		m := reHandle.FindStringSubmatch(line)
		if m == nil {
			continue // not a rule line
		}
		handle, _ := strconv.Atoi(m[1])
		clean := reHandle.ReplaceAllString(line, "")
		clean = reCounter.ReplaceAllString(clean, "")
		clean = strings.Join(strings.Fields(clean), " ")
		rules = append(rules, UserRule{Handle: handle, Raw: clean, RuleFields: parseRuleFields(clean)})
	}
	return rules, nil
}

// buildRuleTokens turns structured fields into nft rule tokens (validated).
// Input validators. nft parses its argv joined by spaces, so an unvalidated
// token containing spaces/";" could inject extra nft commands (e.g. flush
// ruleset). Every user-supplied token below is constrained to a safe charset.
var (
	reIface = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)
	reMark  = regexp.MustCompile(`^(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})$`)
	rePort  = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)
)

// ValidMark reports whether a fwmark string is a plain hex/decimal number.
func ValidMark(s string) bool { return reMark.MatchString(strings.TrimSpace(s)) }

func validIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// validIPv4OrCIDR is validIPOrCIDR narrowed to what `ip saddr`/`ip daddr`
// actually match. Those tokens are IPv4-only even inside the `inet` family
// (IPv6 needs the separate `ip6 saddr`/`ip6 daddr` keywords, which this
// package never emits) — but net.ParseIP/net.ParseCIDR happily accept an
// IPv6 literal or CIDR, so validIPOrCIDR alone let one straight into the nft
// argv (C-1). At that point nft rejects the rule outright, and — before the
// rest of C-1's fix — that single bad row used to truncate every rule after
// it in the chain, permanently (the same bad DB row re-renders and re-fails
// on every subsequent boot). Rejecting here, before the value ever reaches
// buildRuleTokens' caller, is cheaper and gives the admin an immediate,
// specific reason instead of a a later nft failure.
func validIPv4OrCIDR(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	return ipnet.IP.To4() != nil
}

// validPort reports whether s is a single TCP/UDP port or a range, both
// ends within the protocol's actual 1-65535 range, and — for a range — the
// start no greater than the end. rePort's charset check alone accepted
// `99999` (five digits, but out of range) and inverted ranges like
// `8080-80`, both of which nft rejects at rule-add time; by then (before
// this fix) the whole chain had already been flushed, so nft's rejection
// truncated everything after that rule (C-1). Every one of these is
// reachable with ordinary typing into the rule modal, not just a
// hand-crafted API request.
func validPort(s string) bool {
	if !rePort.MatchString(s) {
		return false
	}
	parts := strings.SplitN(s, "-", 2)
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 1 || start > 65535 {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil || end < 1 || end > 65535 {
		return false
	}
	return start <= end
}

func buildRuleTokens(f RuleFields) ([]string, error) {
	action := strings.ToLower(strings.TrimSpace(f.Action))
	if action != "accept" && action != "drop" && action != "reject" {
		return nil, fmt.Errorf("ação inválida (use accept, drop ou reject)")
	}
	var t []string
	if f.Iif != "" {
		if !reIface.MatchString(f.Iif) {
			return nil, fmt.Errorf("interface de entrada inválida")
		}
		t = append(t, "iifname", f.Iif)
	}
	if f.Oif != "" {
		if !reIface.MatchString(f.Oif) {
			return nil, fmt.Errorf("interface de saída inválida")
		}
		t = append(t, "oifname", f.Oif)
	}
	if f.Saddr != "" {
		if !validIPv4OrCIDR(f.Saddr) {
			return nil, fmt.Errorf("origem inválida: use um IP/CIDR IPv4 (IPv6 ainda não é suportado nas regras personalizadas)")
		}
		t = append(t, "ip", "saddr", f.Saddr)
	}
	if f.Daddr != "" {
		if !validIPv4OrCIDR(f.Daddr) {
			return nil, fmt.Errorf("destino inválido: use um IP/CIDR IPv4 (IPv6 ainda não é suportado nas regras personalizadas)")
		}
		t = append(t, "ip", "daddr", f.Daddr)
	}
	proto := strings.ToLower(strings.TrimSpace(f.Proto))
	switch proto {
	case "tcp", "udp":
		if f.Dport != "" {
			if !validPort(f.Dport) {
				return nil, fmt.Errorf("porta inválida: use um valor entre 1 e 65535, ou um intervalo início-fim válido (ex.: 8000-8080)")
			}
			t = append(t, proto, "dport", f.Dport)
		} else {
			t = append(t, "ip", "protocol", proto)
		}
	case "icmp":
		t = append(t, "ip", "protocol", "icmp")
	case "", "all", "any":
		// no L4 match
	default:
		return nil, fmt.Errorf("protocolo inválido")
	}
	t = append(t, "counter", action)
	return t, nil
}

// expressionTokens renders f into the exact token sequence buildRuleTokens
// would hand to nft, minus the literal "counter" keyword. Every rule this
// package builds always carries it, so on its own it carries no identifying
// information — and ListUserRules/ListRuleset strip the whole "counter
// packets N bytes M" runtime clause, keyword included, out of a live rule's
// text (packet/byte counts are instance state, not part of what the rule
// means). Stripping it here the same way lets the two be compared, word for
// word, as the identical rule they claim to be.
func expressionTokens(f RuleFields) (string, error) {
	tokens, err := buildRuleTokens(f)
	if err != nil {
		return "", err
	}
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if tok == "counter" {
			continue
		}
		out = append(out, tok)
	}
	return strings.Join(out, " "), nil
}

// ExpressionMatches reports whether f, once rendered and normalized exactly
// like a live rule's own text already is (see expressionTokens), equals
// live word for word. This is the single building block behind two
// independent honesty checks that both boil down to the same question —
// "does this structured RuleFields really mean what this raw nft text
// says" — and where a false positive was a documented production risk:
//
//   - C-2 (internal/firewallrules.ImportOnce's round-trip check): a rule
//     richer than the 7-field model (e.g. `ct state established,related
//     counter accept`) best-effort-parses into whatever survived (here,
//     just {Action: accept}) — which then silently means "accept
//     everything" once re-rendered, not what the live rule actually said.
//   - I-4 (MergeUserRules' live-rule identity check): pairing a DB row to
//     a live nft rule by position alone attributes one rule's handle and
//     counters to a different rule the moment the two lists diverge.
//
// A mismatch in either case must fall back to an honest "could not verify"
// state rather than silently treating the parsed fields as equivalent.
//
// Both sides go through normalizeExpression first: nft does not echo back
// the rule it was given, it re-prints its own parsed form of it, and that
// form differs from what buildRuleTokens emits in ways that say nothing
// about whether the two rules mean the same thing (quoted interface
// operands, addresses re-printed in canonical form). Comparing raw text
// made every rule carrying an interface or a /32 mismatch forever — the
// rule got imported disabled and then reconciled away, and MergeUserRules
// marked it Applied=false and (never advancing past the unmatched live
// entry) dragged every rule after it into the same fate, duplicating the
// whole live chain at the end of the panel's list.
func ExpressionMatches(f RuleFields, live string) bool {
	expected, err := expressionTokens(f)
	if err != nil {
		return false
	}
	return normalizeExpression(expected) == normalizeExpression(live)
}

// normalizeExpression rewrites an nft rule expression — ours or the
// kernel's — into the one shape both can be compared in. It is deliberately
// narrow: it only touches the operands whose printed form nft is known,
// empirically, to differ on, and leaves every other token byte for byte so
// a genuinely different rule still reads as different.
//
//   - iifname/oifname (and the iif/oif variants parseRuleFields accepts):
//     nft quotes the operand (`iifname "enp5s0"`), buildRuleTokens does
//     not. The quotes are stripped here rather than emitted by
//     buildRuleTokens — unlike dnatRule, which builds a single rule string
//     and quotes for the same reason — because buildRuleTokens' output is
//     also the text the panel shows for a rule nft has never seen
//     (syntheticUserRule), and because quoting alone would not fix the
//     address case below: a normalizer on both sides is needed regardless,
//     so there is exactly one of them instead of two half-measures.
//   - ip saddr/ip daddr: nft re-prints addresses canonically — a host
//     mask is dropped (`10.0.0.1/32` → `10.0.0.1`) and any other prefix is
//     reduced to its network address (`10.0.0.5/24` → `10.0.0.0/24`).
//     canonicalAddr does the same to both sides.
func normalizeExpression(expr string) string {
	toks := strings.Fields(expr)
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "iifname", "oifname", "iif", "oif":
			if i+1 < len(toks) {
				toks[i+1] = strings.Trim(toks[i+1], `"`)
				i++
			}
		case "ip":
			if i+2 < len(toks) && (toks[i+1] == "saddr" || toks[i+1] == "daddr") {
				toks[i+2] = canonicalAddr(toks[i+2])
				i += 2
			}
		}
	}
	return strings.Join(toks, " ")
}

// canonicalAddr renders an address operand the way nft prints it back:
// a full-mask CIDR as the bare address, any other CIDR as its network
// address plus prefix. Anything that is not an address literal (a set
// reference like `@blocklist`, an anonymous set, a range) is returned
// untouched — normalizing what we don't understand would be inventing
// equality.
func canonicalAddr(s string) string {
	if strings.Contains(s, "/") {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return s
		}
		if ones, bits := ipnet.Mask.Size(); ones == bits {
			return ip.String()
		}
		return ipnet.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// parseRuleFields best-effort parses our generated rule text back into fields
// (so the edit modal can pre-fill). Unknown tokens are ignored.
func parseRuleFields(clean string) RuleFields {
	f := RuleFields{}
	toks := strings.Fields(clean)
	unq := func(s string) string { return strings.Trim(s, `"`) }
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "iif", "iifname":
			if i+1 < len(toks) {
				f.Iif = unq(toks[i+1])
				i++
			}
		case "oif", "oifname":
			if i+1 < len(toks) {
				f.Oif = unq(toks[i+1])
				i++
			}
		case "ip":
			if i+2 < len(toks) {
				switch toks[i+1] {
				case "saddr":
					f.Saddr = toks[i+2]
				case "daddr":
					f.Daddr = toks[i+2]
				case "protocol":
					f.Proto = toks[i+2]
				}
				i += 2
			}
		case "tcp", "udp":
			f.Proto = toks[i]
			if i+2 < len(toks) && toks[i+1] == "dport" {
				f.Dport = toks[i+2]
				i += 2
			}
		case "accept", "drop", "reject":
			f.Action = toks[i]
		}
	}
	return f
}

// parseElements extracts the comma-separated tokens inside an `elements = { ... }`
// block from `nft list set/map` output (the block may span multiple lines).
func parseElements(out string) []string {
	res := []string{}
	i := strings.Index(out, "elements = {")
	if i < 0 {
		return res
	}
	rest := out[i+len("elements = {"):]
	j := strings.Index(rest, "}")
	if j < 0 {
		return res
	}
	for _, tok := range strings.Split(rest[:j], ",") {
		t := strings.Join(strings.Fields(tok), " ")
		if t != "" {
			res = append(res, t)
		}
	}
	return res
}

// RenderRule devolve a linha nft exata que esta regra vira no kernel —
// incluindo o `counter`, ao contrário de expressionTokens, que o remove porque
// existe para COMPARAR com uma regra viva (a saída do nft traz "counter packets
// N bytes M", que é estado de instância, não parte do que a regra significa).
//
// Existe para que a pré-visualização da tela seja a linha, e não uma paráfrase
// dela. Antes, o frontend remontava esses tokens em TypeScript, à mão, e nada
// verificava que as duas versões continuavam iguais — num painel onde uma regra
// errada corta o SSH do operador, a tela podia afirmar uma coisa e o kernel
// receber outra, sem teste, sem log e sem apply falhando.
func RenderRule(f RuleFields) (string, error) {
	tokens, err := buildRuleTokens(f)
	if err != nil {
		return "", err
	}
	return strings.Join(tokens, " "), nil
}

// RenderGroupJump devolve a linha de jump que o grupo põe na chain hospedeira:
// a condição de entrada, o estado de conexão quando houver, e o salto.
func RenderGroupJump(g StoredGroup) (string, error) {
	tokens, err := groupJumpTokens(g)
	if err != nil {
		return "", err
	}
	return strings.Join(tokens, " "), nil
}
