// Package hostquota mede quanto cada aparelho da LAN já consumiu no ciclo
// vigente e avisa quando ele passa do que foi declarado para ele.
//
// É o gêmeo de internal/linkquota um andar abaixo: lá a pergunta é "quanto
// deste link já foi embora"; aqui é "quem gastou". As duas metades estão
// na issue #126, e a de link foi entregue primeiro porque não dependia de nada.
//
// ─── O QUE ELE NÃO FAZ, E POR QUÊ ────────────────────────────────────────────
//
// ELE NÃO CORTA NADA. Não bloqueia o aparelho que estourou, não escreve regra
// no ruleset vivo, não limita banda. Mede e avisa.
//
// Isso não é uma etapa que faltou: é a decisão de produto desta entrega. E não
// é só prosa: boundary_test.go, neste mesmo pacote, RECUSA A COMPILAR se algum
// import de corte aparecer aqui. Comentário convence; teste impede.
//
//  1. CORTAR POR COTA É A TRANCA. O aparelho que estourou pode ser o do
//     próprio admin — e costuma ser, porque é o que mais usa a rede. Um corte
//     automático tira a internet de quem estava resolvendo o problema, no
//     momento em que ele estava resolvendo. hosts.SetBlocked é forward-only,
//     então o painel na LAN continua alcançável; o acesso ao mundo, não.
//
//  2. O BLOQUEIO AUTOMÁTICO VIRA ESTADO PERSISTIDO. hosts.SetBlocked grava o
//     ruleset vivo em nftables.LiveSnapshotSettingKey. Um bloqueio disparado
//     por software, e não por um admin, sobrevive a reinstalação e volta
//     sozinho — e ninguém sabe de onde ele veio.
//
//  3. A CHAVE ERRADA BLOQUEIA O VIZINHO. O bloqueio vale por MAC e por IP; um
//     aparelho que herdou o endereço de outro leva o corte do outro.
//
//  4. É EXATAMENTE A CLASSE DE MUDANÇA QUE internal/nftables/survival.go
//     descreve: a que quebra DIAS depois, sem relação visível com a mudança.
//     Este produto já produziu três travamentos assim.
//
// Avisar é reversível; cortar não é. Se alguém "aproveitar" este pacote
// para ligar o corte, o resultado não é uma feature a mais: é um defeito de
// segurança com uma tela bonita na frente.
//
// Limitar banda também fica de fora, e não por falta de tempo. O limit rate do
// nft não é shaping — é policer com descarte de cauda, sem fila e sem
// backpressure —, e aplicado ao TCP de um host produz throughput serrilhado, e
// não "5 Mbit/s". Além disso, em nft limit é CASAMENTO e não modificador: a
// armadilha está escrita em internal/nftables/groups.go (lição da #122), e
// escrita ao contrário a regra descarta quem se comporta e libera quem abusa.
// Shaping honesto é cake/HTB, que é a issue #121.
//
// ─── DE ONDE VEM O NÚMERO ────────────────────────────────────────────────────
//
// Dos contadores por endereço que o nftables mantém
// (internal/nftables/accounting.go, sobre o nf_conntrack_acct), pelo MESMO
// delta que já desenha as séries por aparelho — ver hosttraffic.UsageSink. Não
// é integração de taxa: integrar host.rx_bps daria um número errado por ordens
// de grandeza, e o porquê está no comentário daquela interface.
//
// O que ele mede é IPv4 apenas, porque os sets da contabilidade são ipv4_addr,
// e conta TUDO o que o firewall encaminha — inclusive de uma sub-rede interna
// para outra. A tela diz as duas coisas com todas as letras: um número que
// subconta em silêncio é pior que nenhum número, e um que sobreconta em
// silêncio também.
//
// ─── O TEMPO ─────────────────────────────────────────────────────────────────
//
// O INSTANTE DA MEDIÇÃO VIAJA COM O BYTE. O amostrador entrega deltas a cada
// dez segundos e o flush roda a cada minuto; se o ciclo fosse decidido no
// instante do FLUSH, tudo o que foi medido no último minuto do ciclo cairia no
// ciclo seguinte. No mensal isso é um minuto por mês; no diário é um minuto por
// dia, e um minuto a 300 Mbit/s são 2,25 GB — mais que a cota diária inteira de
// um tablet. O ciclo novo nasceria estourado, com alerta crítico sobre tráfego
// que o aparelho não fez naquele dia, e o dia real ficaria mudo.
package hostquota

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/linkquota"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// Tipos de alerta desta feature. Vêm de internal/alerts, e não daqui, porque
// precisam estar em tiposQueNomeiamAparelho — o portão que impede identidade
// de aparelho de sair da caixa sem escolha explícita (internal/metrics/
// exposicao.go, regra 4).
const (
	TypeQuotaWarning  = alerts.TypeHostQuotaWarning
	TypeQuotaExceeded = alerts.TypeHostQuotaExceeded
)

const (
	// bytesPerGB é DECIMAL (10^9), como em linkquota e como na fatura.
	bytesPerGB = 1_000_000_000.0

	// flushInterval é de quanto em quanto tempo o acumulado em memória vira
	// linha no banco.
	//
	// UM MINUTO, e não a cadência de dez segundos do amostrador: aqui são
	// dezenas de aparelhos por rodada, e não dois ou três links. Gravar a cada
	// amostra seriam da ordem de 700 mil UPDATEs por dia no mesmo SSD que
	// guarda metric_samples. Perder até um minuto de contagem num desligamento
	// abrupto não muda nenhuma decisão que esta feature exista para apoiar.
	flushInterval = time.Minute

	// retencaoSemCota é por quanto tempo o consumo de um aparelho SEM cota
	// declarada fica no banco.
	//
	// Existe porque host_usage não tem outra poda: uma linha cujo MAC não está
	// no inventário nem em host_quota é invisível na tela e imortal no banco.
	// Telefone moderno rotaciona o endereço físico a cada associação; com ciclo
	// diário, cada um deixa uma linha por dia, para sempre.
	//
	// Quem TEM cota declarada não é podado: aquele histórico é o que responde
	// "o teto está no lugar certo?".
	retencaoSemCota = 90 * 24 * time.Hour

	// intervaloDePoda é de quanto em quanto tempo a poda roda. Uma vez por dia,
	// e não a cada flush: é um DELETE com subconsulta, e rodá-lo por minuto
	// poria o acumulador para disputar o banco com metric_samples sem ganhar
	// nada.
	intervaloDePoda = 24 * time.Hour
)

// Alerter é o pedaço do alerts.Service que esta feature usa. Interface local
// para o serviço ser testável sem banco de alerta — mesmo padrão do linkquota.
//
// O último parâmetro se chama linkID no alerts.Service por herança; o que ele
// carrega é "sobre O QUE é este alerta". Aqui é o MAC do aparelho, que é a
// identidade certa: dois aparelhos estourando a cota ao mesmo tempo precisam
// de dois alertas, e resolver um não pode fechar o do outro.
type Alerter interface {
	Create(alertType, severity, title, message, key string) error
	AutoResolve(alertType, key string)
}

// Status é o que o painel mostra por aparelho.
type Status struct {
	MAC string `json:"mac"`
	// Name é o apelido do aparelho, com queda para nome de host, endereço e
	// MAC. É o que vai na tela e no texto do alerta: um alerta que diz
	// "aa:bb:cc:dd:ee:ff estourou a cota" obriga o admin a ir procurar de
	// quem é aquele aparelho, que é justamente o trabalho que o apelido existe
	// para poupar.
	Name         string  `json:"name"`
	IP           string  `json:"ip"`
	Configured   bool    `json:"configured"`
	AlertEnabled bool    `json:"alert_enabled"`
	LimitGB      float64 `json:"limit_gb"`
	Period       string  `json:"period"`
	CycleDay     int     `json:"cycle_day"`
	AlertPct     int     `json:"alert_pct"`
	CycleStart   int64   `json:"cycle_start"`
	CycleEnd     int64   `json:"cycle_end"`
	RxBytes      uint64  `json:"rx_bytes"`
	TxBytes      uint64  `json:"tx_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	UsedPct      float64 `json:"used_pct"` // 0 quando não há cota declarada
	// Present diz se o aparelho ainda está no inventário. Falso é a cota sem
	// dono conhecido — um endereço digitado à mão que nunca apareceu na rede.
	// Ela aparece na tela de propósito, porque uma cota que ninguém consegue
	// ver é uma cota que ninguém consegue remover.
	//
	// PRESENT NÃO É "O APARELHO AINDA EXISTE", e é importante não ler
	// assim: host_metadata guarda a linha para sempre depois do primeiro
	// avistamento, então o MAC de privacidade que um celular rotacionou ontem
	// continua "presente" hoje. Quem responde a essa pergunta são os dois
	// campos abaixo.
	Present bool `json:"present"`
	// LastSeen é quando o inventário viu o aparelho pela última vez, e
	// MeasuredAt é quando a MEDIÇÃO deste ciclo foi atualizada pela última vez
	// (zero = nada medido neste ciclo).
	//
	// POR QUE OS DOIS ESTÃO AQUI. Sem eles, "aparelho comportado, 0% da
	// cota" e "aparelho que sumiu e a medição morreu" desenham a MESMA
	// barra verde. A tela não tinha como distinguir os dois, e uma cota morta
	// que parece saudável é a cota-fantasma com outro nome.
	LastSeen   int64 `json:"last_seen"`
	MeasuredAt int64 `json:"measured_at"`
}

type delta struct{ rx, tx uint64 }

// ciclo é a chave de um ciclo: período E instante de início.
//
// OS DOIS JUNTOS, e não só o instante: o início de um ciclo diário no dia 1 e o
// de um ciclo mensal que fecha no dia 1 são o mesmo inteiro. Sem o período, a
// virada de ciclo não seria detectada numa troca de período no dia 1, e o
// histórico misturaria dia com mês.
type ciclo struct {
	period string
	start  int64
}

// Service acumula bytes por aparelho e os converte em consumo por ciclo.
type Service struct {
	db       *storage.DB
	alertSvc Alerter

	mu sync.Mutex
	// pending guarda o delta por APARELHO e por INSTANTE DE AMOSTRA.
	//
	// O instante é a chave interna porque o ciclo a que um byte pertence é uma
	// função do MOMENTO EM QUE ELE FOI MEDIDO, e não do momento em que o flush
	// acontece. São no máximo seis baldes por aparelho por flush (amostra de
	// dez segundos, flush de um minuto).
	pending map[string]map[int64]delta
	// lastCycle guarda o ciclo em que cada aparelho estava no flush anterior,
	// para detectar a virada e reabrir a possibilidade de alertar.
	lastCycle map[string]ciclo

	// ultimaPoda é quando a retenção rodou pela última vez.
	ultimaPoda time.Time

	nowFn func() time.Time
}

// NewService cria o serviço. alertSvc pode ser nil (o consumo continua sendo
// medido; só não há aviso).
func NewService(db *storage.DB, alertSvc Alerter) *Service {
	return &Service{
		db:        db,
		alertSvc:  alertSvc,
		pending:   map[string]map[int64]delta{},
		lastCycle: map[string]ciclo{},
		nowFn:     time.Now,
	}
}

// AddHostBytes recebe o delta de bytes de um aparelho, com o INSTANTE em que
// ele foi medido. Implementa hosttraffic.UsageSink: é chamado a cada dez
// segundos pelo amostrador, com os MESMOS deltas que alimentam as séries — de
// propósito, porque dois caminhos de medição divergiriam e aí o gráfico e a
// cota contariam coisas diferentes.
//
// O ts não é decoração: ver o cabeçalho deste arquivo, seção O TEMPO.
func (s *Service) AddHostBytes(mac string, ts int64, rx, tx uint64) {
	if mac == "" || (rx == 0 && tx == 0) {
		return
	}
	s.mu.Lock()
	porInstante := s.pending[mac]
	if porInstante == nil {
		porInstante = map[int64]delta{}
		s.pending[mac] = porInstante
	}
	d := porInstante[ts]
	d.rx += rx
	d.tx += tx
	porInstante[ts] = d
	s.mu.Unlock()
}

// devolver põe de volta na fila o que não conseguiu ser gravado.
//
// SOMANDO, e não substituindo: entre o dreno e a devolução o amostrador pode
// ter entregue delta novo para o mesmo aparelho e o mesmo instante. Sem isto,
// um "database is locked" — que não é hipótese remota, porque o mesmo
// SQLite recebe as escritas de metric_samples — apagaria permanentemente o
// minuto que já tinha saído da fila.
func (s *Service) devolver(pendente map[string]map[int64]delta) {
	if len(pendente) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for mac, porInstante := range pendente {
		alvo := s.pending[mac]
		if alvo == nil {
			alvo = map[int64]delta{}
			s.pending[mac] = alvo
		}
		for ts, d := range porInstante {
			j := alvo[ts]
			j.rx += d.rx
			j.tx += d.tx
			alvo[ts] = j
		}
	}
}

// Run grava o acumulado periodicamente e avalia as cotas.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	slog.Info("cota por aparelho iniciada", "flush", flushInterval)
	for {
		select {
		case <-ctx.Done():
			// Último flush na saída: o que estava em memória é medição real
			// que ainda não virou linha no banco.
			s.Flush()
			return
		case <-t.C:
			s.Flush()
		}
	}
}

// Flush grava o acumulado e avalia as cotas. Idempotente e seguro de chamar
// fora do ticker (o desligamento faz isso).
func (s *Service) Flush() {
	s.mu.Lock()
	pendente := s.pending
	s.pending = map[string]map[int64]delta{}
	s.mu.Unlock()

	quotas, err := s.db.GetHostQuotas()
	if err != nil {
		// O acumulado JÁ SAIU da fila. Devolvê-lo transforma uma perda
		// permanente numa retentativa em sessenta segundos.
		slog.Warn("cota por aparelho: não consegui ler as cotas; o acumulado deste minuto volta para a fila", "err", err)
		s.devolver(pendente)
		return
	}

	// O universo desta rodada é quem CONSUMIU mais quem tem cota DECLARADA.
	//
	// Não é o inventário inteiro de propósito: um aparelho parado não gera
	// linha em host_usage, e é isso que mantém a escrita proporcional a quem
	// está usando a rede, e não ao tamanho do inventário. E não é só quem tem
	// cota, também de propósito: medir quem não declarou nada é o que permite
	// ao admin descobrir ONDE declarar — a mesma escolha do link.
	macs := make([]string, 0, len(pendente)+len(quotas))
	visto := map[string]bool{}
	for mac := range pendente {
		macs = append(macs, mac)
		visto[mac] = true
	}
	for mac := range quotas {
		if !visto[mac] {
			macs = append(macs, mac)
		}
	}
	sort.Strings(macs) // ordem estável: o log e os testes agradecem

	now := s.nowFn()
	loc := now.Location()
	atual := make(map[string]ciclo, len(macs))
	naoGravado := map[string]map[int64]delta{}

	// ─── PASSO 1: gravar ─────────────────────────────────────────────────────
	//
	// TODA a escrita acontece antes de QUALQUER leitura. O passo 2 lê o consumo
	// do ciclo em lote (uma consulta por ciclo, não uma por aparelho); se as
	// duas coisas estivessem no mesmo laço, o lote seria carregado no primeiro
	// aparelho que precisasse dele e sairia desatualizado para todos os que
	// gravassem depois.
	for _, mac := range macs {
		q := quotas[mac]
		period, dia := periodoDe(q), diaDe(q)
		atual[mac] = ciclo{period, CycleStart(now, period, dia).Unix()}

		for ts, d := range pendente[mac] {
			// O CICLO SAI DO INSTANTE DA MEDIÇÃO, e não do instante do flush.
			// Ver o cabeçalho deste arquivo, seção O TEMPO.
			inicio := CycleStart(time.Unix(ts, 0).In(loc), period, dia).Unix()
			if err := s.db.AddHostUsage(mac, period, inicio, d.rx, d.tx); err != nil {
				slog.Warn("cota por aparelho: não consegui acumular o consumo; volta para a fila", "mac", mac, "err", err)
				if naoGravado[mac] == nil {
					naoGravado[mac] = map[int64]delta{}
				}
				naoGravado[mac][ts] = d
			}
		}
	}
	s.devolver(naoGravado)

	// ─── PASSO 2: virada de ciclo e avaliação ────────────────────────────────
	novoLastCycle := make(map[string]ciclo, len(macs))
	usoPorCiclo := map[ciclo]map[string]storage.HostUsage{}
	var nomes map[string]string

	for _, mac := range macs {
		c := atual[mac]

		// Virada de ciclo: o consumo volta a zero, então os avisos do ciclo
		// anterior deixam de ser verdade. Resolvê-los é o que permite o ciclo
		// seguinte avisar de novo — o alerts.Service deduplica por (tipo,
		// chave) enquanto o alerta estiver aberto.
		//
		// COM CICLO DIÁRIO ISSO É A DIFERENÇA ENTRE A FEATURE FUNCIONAR E NÃO
		// FUNCIONAR. No mensal, um alerta preso mataria o aviso a partir do
		// segundo MÊS; no diário, a partir do segundo DIA.
		prev, conhecido := s.lastCycle[mac]
		if !conhecido {
			prev, conhecido = s.cicloNoDisco(mac)
		}
		if conhecido && prev != c && s.alertSvc != nil {
			s.alertSvc.AutoResolve(TypeQuotaWarning, mac)
			s.alertSvc.AutoResolve(TypeQuotaExceeded, mac)
		}
		// SEMPRE, inclusive quando a gravação do passo 1 falhou para este
		// aparelho: se ele saísse do mapa, o flush seguinte o veria como
		// desconhecido e a virada de ciclo dele não resolveria alerta nenhum.
		novoLastCycle[mac] = c

		q, temCota := quotas[mac]
		if !temCota || !q.AlertEnabled || q.LimitGB <= 0 {
			continue
		}
		uso, carregado := usoPorCiclo[c]
		if !carregado {
			uso, err = s.db.GetHostUsageAll(c.period, c.start)
			if err != nil {
				slog.Warn("cota por aparelho: não consegui ler o consumo do ciclo", "mac", mac, "err", err)
				continue
			}
			usoPorCiclo[c] = uso
		}
		if nomes == nil {
			nomes = s.nomes()
		}
		nome := nomes[mac]
		if nome == "" {
			nome = mac
		}
		u := uso[mac]
		s.evaluate(nome, mac, q, u.RxBytes+u.TxBytes)
	}

	// lastCycle guarda só quem foi processado nesta rodada. Sem a poda, o mapa
	// cresceria com todo MAC que já passou pela rede — inclusive os aleatórios
	// que telefone moderno gera a cada associação.
	s.lastCycle = novoLastCycle
	s.podar(now)
}

// cicloNoDisco recupera do BANCO o último ciclo em que este aparelho teve
// consumo medido.
//
// POR QUE ISTO EXISTE. lastCycle é memória, e nasce vazio a cada processo. Se o
// daemon reinicia DEPOIS da virada — upgrade noturno, reboot, crash —, o
// primeiro flush apenas semearia o mapa e nunca resolveria os alertas do ciclo
// que acabou. E alerts.Create deduplica por (tipo, chave) enquanto o alerta
// estiver aberto: o aviso do ciclo seguinte, e do seguinte, e do seguinte,
// nunca seria criado. A feature morre em silêncio, com a suíte verde e um
// alerta vermelho perpétuo sobre um ciclo que já acabou.
//
// No mensal, a chance de um reinício cair em cima da virada é pequena. No
// DIÁRIO, é rotina.
func (s *Service) cicloNoDisco(mac string) (ciclo, bool) {
	hist, err := s.db.GetHostUsageHistory(mac, 1)
	if err != nil || len(hist) == 0 {
		return ciclo{}, false
	}
	return ciclo{hist[0].Period, hist[0].CycleStart}, true
}

// podar aplica a retenção de host_usage, no máximo uma vez por dia.
func (s *Service) podar(now time.Time) {
	if !s.ultimaPoda.IsZero() && now.Sub(s.ultimaPoda) < intervaloDePoda {
		return
	}
	s.ultimaPoda = now
	n, err := s.db.PurgeHostUsage(now.Add(-retencaoSemCota).Unix())
	if err != nil {
		slog.Warn("cota por aparelho: não consegui podar o consumo antigo", "err", err)
		return
	}
	if n > 0 {
		slog.Info("cota por aparelho: consumo antigo podado", "linhas", n)
	}
}

// periodoDe e diaDe normalizam a cota (ou a ausência dela) para os valores que
// o calendário entende. Existem para o Flush e o Snapshot calcularem o MESMO
// ciclo para o mesmo aparelho: se divergissem, a tela leria uma chave e o
// acumulador escreveria noutra.
func periodoDe(q storage.HostQuota) string {
	if q.Period == "" {
		return storage.HostPeriodMonthly
	}
	return q.Period
}

func diaDe(q storage.HostQuota) int {
	if q.CycleDay < 1 {
		return 1
	}
	return q.CycleDay
}

// nomes devolve o nome legível de cada aparelho conhecido, indexado por MAC.
//
// Lê host_metadata, e não o inventário vivo (hosts.Service.List), porque o
// inventário vivo executa "ip neigh" e este código roda num ticker de um
// minuto: acoplar o acumulador a um comando externo faria a contagem depender
// de algo que pode demorar ou falhar. O apelido está no banco de qualquer
// forma — é o próprio hosts.Service quem o grava.
func (s *Service) nomes() map[string]string {
	metaList, err := s.db.ListHostMetadata()
	if err != nil {
		slog.Warn("cota por aparelho: não consegui ler o inventário; o alerta vai sair com o endereço físico", "err", err)
		return map[string]string{}
	}
	out := make(map[string]string, len(metaList))
	for _, m := range metaList {
		out[m.MAC] = NomeDe(m)
	}
	return out
}

// NomeDe escolhe como o aparelho é chamado na tela e no alerta.
func NomeDe(m storage.HostMetadata) string {
	switch {
	case m.Alias != "":
		return m.Alias
	case m.Hostname != "":
		return m.Hostname
	case m.IP != "":
		return m.IP
	default:
		return m.MAC
	}
}

// evaluate dispara o aviso quando o consumo cruza o limiar. Não guarda estado
// de "já avisei": quem faz isso é o alerts.Service, que suprime um alerta
// aberto do mesmo (tipo, chave). Duplicar esse controle aqui criaria duas
// fontes de verdade sobre o que já foi avisado.
//
// Os textos usam linkquota.HumanBytes/HumanGB, e não "%.1f GB": uma cota de
// 500 MB — que é exatamente o tamanho que se declara para uma câmera ou um
// tablet — sairia como "0.0 GB de 0 GB", o defeito que a metade de link
// deste mesmo recurso já pagou numa validação em máquina real.
func (s *Service) evaluate(nome, mac string, q storage.HostQuota, used uint64) {
	if s.alertSvc == nil {
		return
	}
	limit := q.LimitGB * bytesPerGB
	if limit <= 0 {
		return
	}
	pct := float64(used) / limit * 100
	janela := janelaDe(q.Period)

	switch {
	case pct >= 100:
		// O aviso de "chegando lá" deixa de ser verdade quando a cota
		// acaba: mantê-lo aberto ao lado do crítico põe dois alertas do mesmo
		// aparelho na tela dizendo coisas diferentes sobre o mesmo fato.
		s.alertSvc.AutoResolve(TypeQuotaWarning, mac)
		_ = s.alertSvc.Create(TypeQuotaExceeded, alerts.SeverityCritical,
			fmt.Sprintf("Cota estourada: %s", nome),
			fmt.Sprintf("O aparelho %s já consumiu %s dos %s %s (%.0f%%). "+
				"O LinkGuard NÃO corta nem limita a banda dele — este alerta é um aviso.",
				nome, linkquota.HumanBytes(float64(used)), linkquota.HumanGB(q.LimitGB), janela, pct),
			mac)
	case pct >= float64(q.AlertPct):
		_ = s.alertSvc.Create(TypeQuotaWarning, alerts.SeverityWarning,
			fmt.Sprintf("Cota em %.0f%%: %s", pct, nome),
			fmt.Sprintf("O aparelho %s consumiu %s dos %s %s.",
				nome, linkquota.HumanBytes(float64(used)), linkquota.HumanGB(q.LimitGB), janela),
			mac)
	}
}

// janelaDe é o pedaço de frase que diz de que ciclo o número fala. Sem ele,
// "consumiu 900 MB de 1.0 GB" não distingue um teto diário de um mensal — e
// as duas leituras pedem reações opostas.
func janelaDe(period string) string {
	if period == storage.HostPeriodDaily {
		return "de hoje"
	}
	return "do ciclo"
}

// Snapshot devolve o estado de cota e consumo de cada aparelho, para o painel.
//
// LÊ O QUE FOI MEDIDO, e não o que está no acumulador em memória: o que ainda
// não passou pelo flush não é dado, é intenção. Mostrar os dois somados faria a
// tela e o alerta discordarem por até um minuto, e o admin não teria como saber
// qual dos dois olhar.
func (s *Service) Snapshot() ([]Status, error) {
	quotas, err := s.db.GetHostQuotas()
	if err != nil {
		return nil, err
	}
	metaList, err := s.db.ListHostMetadata()
	if err != nil {
		return nil, err
	}
	meta := make(map[string]storage.HostMetadata, len(metaList))
	for _, m := range metaList {
		meta[m.MAC] = m
	}

	macs := make([]string, 0, len(meta)+len(quotas))
	for mac := range meta {
		macs = append(macs, mac)
	}
	for mac := range quotas {
		if _, ok := meta[mac]; !ok {
			macs = append(macs, mac)
		}
	}

	now := s.nowFn()
	// Uma consulta por CICLO, e não por aparelho. Quase todo mundo cai no ciclo
	// mensal padrão, então na prática são uma ou duas leituras para a tela
	// inteira, em vez de uma por linha.
	usoPorCiclo := map[ciclo]map[string]storage.HostUsage{}

	out := make([]Status, 0, len(macs))
	for _, mac := range macs {
		q, hasQuota := quotas[mac]
		period, cycleDay := periodoDe(q), diaDe(q)
		start := CycleStart(now, period, cycleDay)
		c := ciclo{period, start.Unix()}
		uso, ok := usoPorCiclo[c]
		if !ok {
			uso, err = s.db.GetHostUsageAll(c.period, c.start)
			if err != nil {
				return nil, err
			}
			usoPorCiclo[c] = uso
		}
		u := uso[mac]
		m, present := meta[mac]

		nome := mac
		var lastSeen int64
		if present {
			nome = NomeDe(m)
			if !m.LastSeen.IsZero() {
				lastSeen = m.LastSeen.Unix()
			}
		}
		// Configured é "tem cota DECLARADA", e não "tem linha no
		// banco": a linha sobrevive à remoção da cota justamente para
		// preservar o ciclo (ver Delete), com limite zero.
		st := Status{
			MAC:          mac,
			Name:         nome,
			IP:           m.IP,
			Configured:   hasQuota && q.LimitGB > 0,
			AlertEnabled: hasQuota && q.AlertEnabled && q.LimitGB > 0,
			LimitGB:      q.LimitGB,
			Period:       period,
			CycleDay:     cycleDay,
			AlertPct:     q.AlertPct,
			CycleStart:   c.start,
			CycleEnd:     CycleEnd(start, period).Unix(),
			RxBytes:      u.RxBytes,
			TxBytes:      u.TxBytes,
			UsedBytes:    u.RxBytes + u.TxBytes,
			Present:      present,
			LastSeen:     lastSeen,
			MeasuredAt:   u.UpdatedAt,
		}
		if st.Configured {
			st.UsedPct = float64(st.UsedBytes) / (q.LimitGB * bytesPerGB) * 100
		}
		out = append(out, st)
	}

	// Quem mais consumiu primeiro: é a ordem em que a pergunta "quem gastou"
	// se responde. Desempate por nome para a tela não dançar entre recargas.
	sort.Slice(out, func(i, j int) bool {
		if out[i].UsedBytes != out[j].UsedBytes {
			return out[i].UsedBytes > out[j].UsedBytes
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Save valida e grava a cota de um aparelho.
func (s *Service) Save(q storage.HostQuota) error {
	// O endereço físico é normalizado para a ÚNICA grafia que o resto do
	// produto usa. Sem isso, "AA-BB-CC-DD-EE-FF" viraria uma segunda linha
	// para o mesmo aparelho: a cota ficaria numa chave e o consumo medido
	// noutra, e a tela mostraria uma cota que nunca enche.
	mac := validate.MACCanonico(q.MAC)
	if mac == "" {
		return fmt.Errorf("endereço físico inválido")
	}
	q.MAC = mac
	if q.LimitGB < 0 {
		return fmt.Errorf("cota inválida")
	}
	switch q.Period {
	case "":
		q.Period = storage.HostPeriodMonthly
	case storage.HostPeriodMonthly, storage.HostPeriodDaily:
	default:
		return fmt.Errorf("período deve ser %q ou %q", storage.HostPeriodMonthly, storage.HostPeriodDaily)
	}
	if q.Period == storage.HostPeriodDaily {
		// No ciclo diário o dia de fechamento não quer dizer nada: o ciclo vira
		// à meia-noite. Gravar o que o admin digitou faria a tela mostrar um
		// campo que não governa nada — e ele voltaria a governar se o período
		// mudasse depois para mensal, com um valor que ninguém escolheu para
		// esse fim.
		q.CycleDay = 1
	}
	if q.CycleDay < 1 || q.CycleDay > linkquota.MaxCycleDay {
		return fmt.Errorf("dia de fechamento deve estar entre 1 e %d", linkquota.MaxCycleDay)
	}
	if q.AlertPct < 1 || q.AlertPct > 100 {
		return fmt.Errorf("o aviso deve estar entre 1%% e 100%%")
	}
	// O AVISO É DECIDIDO AQUI, e não herdado do corpo do PUT.
	//
	// Antes, AlertEnabled vinha do JSON decodificado cru: um PUT sem o campo
	// gravava false por zero-value, e o resultado era uma cota que a tela
	// desenha, cuja barra enche, que cruza 100% — e que o flush pula para
	// sempre. Ativa aos olhos, morta na prática, sem nada na interface que
	// permitisse perceber. Delete é o ÚNICO caminho que desliga o aviso.
	q.AlertEnabled = q.LimitGB > 0

	quotas, err := s.db.GetHostQuotas()
	if err != nil {
		return err
	}
	if antiga, existia := quotas[mac]; existia {
		antigoPeriodo, antigoDia := periodoDe(antiga), diaDe(antiga)
		if antigoPeriodo != q.Period || antigoDia != q.CycleDay {
			// TROCAR O PERÍODO OU O DIA DE FECHAMENTO MOVE A CHAVE DO CICLO.
			//
			// É o mesmo defeito que Delete foi escrito para não cometer (ver o
			// comentário lá), entrando por esta porta: o consumo já medido
			// ficaria sob a chave antiga, a tela passaria a ler a nova, e a
			// barra voltaria a 0% enquanto o alerta de "cota em 95%"
			// continuasse aberto no painel. Tela e alerta discordando sobre o
			// mesmo aparelho é o pior estado possível para quem está tentando
			// decidir alguma coisa.
			//
			// Então: o consumo do ciclo vigente MUDA de chave junto, numa
			// transação, e os alertas do aparelho são resolvidos — o ciclo foi
			// redefinido, e o que eles diziam já não é sobre o mesmo recorte.
			now := s.nowFn()
			de := CycleStart(now, antigoPeriodo, antigoDia).Unix()
			para := CycleStart(now, q.Period, q.CycleDay).Unix()
			if err := s.db.MoveHostUsage(mac, antigoPeriodo, de, q.Period, para); err != nil {
				return err
			}
			if s.alertSvc != nil {
				s.alertSvc.AutoResolve(TypeQuotaWarning, mac)
				s.alertSvc.AutoResolve(TypeQuotaExceeded, mac)
			}
		}
	}
	return s.db.SaveHostQuota(q)
}

// Delete remove a cota declarada — mas PRESERVA a linha, com limite zero.
//
// POR QUE ASSIM, e não um DELETE de verdade: o consumo é gravado com a chave
// (aparelho, período, início do ciclo), e os dois últimos saem do período e do
// dia de fechamento. Apagar a linha faz os dois voltarem ao padrão, o que muda
// a chave e faz a tela procurar um ciclo diferente daquele em que o consumo foi
// medido: o dado continua no banco e some da tela.
//
// Isso não é teoria. Na metade de link deste mesmo recurso, numa validação em
// máquina real (2026-08-20), remover uma franquia de fechamento 28 fez o
// consumo exibido cair de 2,6 MB para 35 KB sozinho. Aqui o estrago seria
// maior: com período diário, apagar a linha move o ciclo de "hoje" para
// "desde o dia 1", e o número exibido daria um salto para cima, não para
// baixo.
func (s *Service) Delete(mac string) error {
	mac = validate.MACCanonico(mac)
	if mac == "" {
		return fmt.Errorf("endereço físico inválido")
	}
	if s.alertSvc != nil {
		s.alertSvc.AutoResolve(TypeQuotaWarning, mac)
		s.alertSvc.AutoResolve(TypeQuotaExceeded, mac)
	}
	quotas, err := s.db.GetHostQuotas()
	if err != nil {
		return err
	}
	q, ok := quotas[mac]
	if !ok {
		return nil // nunca teve cota: nada a remover
	}
	q.LimitGB = 0
	q.AlertEnabled = false
	return s.db.SaveHostQuota(q)
}

// History devolve os ciclos anteriores de um aparelho.
func (s *Service) History(mac string, limit int) ([]storage.HostUsage, error) {
	mac = validate.MACCanonico(mac)
	if mac == "" {
		return nil, fmt.Errorf("endereço físico inválido")
	}
	return s.db.GetHostUsageHistory(mac, limit)
}

// ─── ciclo ───────────────────────────────────────────────────────────────────

// CycleStart devolve o instante em que começou o ciclo vigente.
//
// O caso mensal é o de linkquota, reaproveitado e não copiado: o dia de
// fechamento vai até 28 porque todo mês tem dia 28, e a razão inteira está
// escrita lá. Duas implementações do mesmo calendário divergiriam no primeiro
// fevereiro.
//
// O caso diário é meia-noite LOCAL, e não UTC, pelo mesmo motivo pelo qual o
// mensal é local: o "dia" que o admin quer limitar é o dele. Num fuso a
// oeste de Greenwich, um ciclo diário em UTC viraria às 21h e o aparelho
// ganharia cota nova no meio da noite de filme.
func CycleStart(now time.Time, period string, day int) time.Time {
	if period == storage.HostPeriodDaily {
		y, m, d := now.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	}
	return linkquota.CycleStart(now, day)
}

// CycleEnd é o começo do ciclo seguinte.
func CycleEnd(start time.Time, period string) time.Time {
	if period == storage.HostPeriodDaily {
		return start.AddDate(0, 0, 1)
	}
	return linkquota.CycleEnd(start)
}
