// Package hostquota mede quanto cada aparelho da LAN já consumiu no ciclo
// vigente e avisa quando ele passa do que foi declarado para ele.
//
// É o gêmeo de internal/linkquota um andar abaixo: lá a pergunta é "quanto
// deste link já foi embora"; aqui é "quem gastou". As duas metades estão na
// issue #126, e a de link foi entregue primeiro porque não dependia de nada.
//
// ─── O QUE ELE NÃO FAZ, E POR QUÊ ────────────────────────────────────────────
//
// ELE NÃO CORTA NADA. Não bloqueia o aparelho que estourou, não escreve regra
// no ruleset vivo, não limita banda. Mede e avisa.
//
// Isso não é uma etapa que faltou: é a decisão de produto desta entrega.
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
// Avisar é reversível; cortar não é. Se alguém "aproveitar" este pacote para
// ligar o corte, o resultado não é uma feature a mais: é um defeito de
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
// O que ele mede é IPv4 apenas, porque os sets da contabilidade são ipv4_addr.
// A tela diz isso com todas as letras: um número que subconta em silêncio é
// pior que nenhum número.
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
	// "aa:bb:cc:dd:ee:ff estourou a cota" obriga o admin a ir procurar de quem
	// é aquele aparelho, que é justamente o trabalho que o apelido existe para
	// poupar.
	Name       string  `json:"name"`
	IP         string  `json:"ip"`
	Configured bool    `json:"configured"`
	Enabled    bool    `json:"enabled"`
	LimitGB    float64 `json:"limit_gb"`
	Period     string  `json:"period"`
	CycleDay   int     `json:"cycle_day"`
	AlertPct   int     `json:"alert_pct"`
	CycleStart int64   `json:"cycle_start"`
	CycleEnd   int64   `json:"cycle_end"`
	RxBytes    uint64  `json:"rx_bytes"`
	TxBytes    uint64  `json:"tx_bytes"`
	UsedBytes  uint64  `json:"used_bytes"`
	UsedPct    float64 `json:"used_pct"` // 0 quando não há cota declarada
	// Present diz se o aparelho ainda está no inventário. Falso é a cota
	// órfã — o aparelho trocou de MAC, saiu da rede ou nunca mais voltou. Ela
	// aparece na tela de propósito, porque uma cota que ninguém consegue ver é
	// uma cota que ninguém consegue remover.
	Present bool `json:"present"`
}

type delta struct{ rx, tx uint64 }

// Service acumula bytes por aparelho e os converte em consumo por ciclo.
type Service struct {
	db       *storage.DB
	alertSvc Alerter

	mu      sync.Mutex
	pending map[string]delta // por MAC, entre flushes
	// lastCycle guarda o ciclo em que cada aparelho estava no flush anterior,
	// para detectar a virada e reabrir a possibilidade de alertar.
	lastCycle map[string]int64

	nowFn func() time.Time
}

// NewService cria o serviço. alertSvc pode ser nil (o consumo continua sendo
// medido; só não há aviso).
func NewService(db *storage.DB, alertSvc Alerter) *Service {
	return &Service{
		db:        db,
		alertSvc:  alertSvc,
		pending:   map[string]delta{},
		lastCycle: map[string]int64{},
		nowFn:     time.Now,
	}
}

// AddHostBytes recebe o delta de bytes de um aparelho. Implementa
// hosttraffic.UsageSink: é chamado a cada dez segundos pelo amostrador, com os
// MESMOS deltas que alimentam as séries — de propósito, porque dois caminhos de
// medição divergiriam e aí o gráfico e a cota contariam coisas diferentes.
func (s *Service) AddHostBytes(mac string, rx, tx uint64) {
	if mac == "" || (rx == 0 && tx == 0) {
		return
	}
	s.mu.Lock()
	d := s.pending[mac]
	d.rx += rx
	d.tx += tx
	s.pending[mac] = d
	s.mu.Unlock()
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
	pending := s.pending
	s.pending = map[string]delta{}
	s.mu.Unlock()

	quotas, err := s.db.GetHostQuotas()
	if err != nil {
		slog.Warn("cota por aparelho: não consegui ler as cotas; o acumulado deste minuto foi perdido", "err", err)
		return
	}

	// O universo desta rodada é quem CONSUMIU mais quem tem cota DECLARADA.
	//
	// Não é o inventário inteiro de propósito: um aparelho parado não gera
	// linha em host_usage, e é isso que mantém a escrita proporcional a quem
	// está usando a rede, e não ao tamanho do inventário. E não é só quem tem
	// cota, também de propósito: medir quem não declarou nada é o que permite
	// ao admin descobrir ONDE declarar — a mesma escolha do link.
	macs := make([]string, 0, len(pending)+len(quotas))
	visto := map[string]bool{}
	for mac := range pending {
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
	novoLastCycle := make(map[string]int64, len(macs))
	var nomes map[string]string

	for _, mac := range macs {
		q, hasQuota := quotas[mac]
		cycle := CycleStart(now, q.Period, q.CycleDay).Unix()

		if d, ok := pending[mac]; ok && (d.rx > 0 || d.tx > 0) {
			if err := s.db.AddHostUsage(mac, cycle, d.rx, d.tx); err != nil {
				slog.Warn("cota por aparelho: não consegui acumular o consumo", "mac", mac, "err", err)
				continue
			}
		}

		// Virada de ciclo: o consumo volta a zero, então os avisos do ciclo
		// anterior deixam de ser verdade. Resolvê-los é o que permite o ciclo
		// seguinte avisar de novo — o alerts.Service deduplica por (tipo,
		// chave) enquanto o alerta estiver aberto.
		//
		// COM CICLO DIÁRIO ISSO É A DIFERENÇA ENTRE A FEATURE FUNCIONAR E NÃO
		// FUNCIONAR. No mensal, um alerta preso mataria o aviso a partir do
		// segundo MÊS; no diário, a partir do segundo DIA.
		if prev, seen := s.lastCycle[mac]; seen && prev != cycle && s.alertSvc != nil {
			s.alertSvc.AutoResolve(TypeQuotaWarning, mac)
			s.alertSvc.AutoResolve(TypeQuotaExceeded, mac)
		}
		novoLastCycle[mac] = cycle

		if !hasQuota || !q.Enabled || q.LimitGB <= 0 {
			continue
		}
		usage, err := s.db.GetHostUsage(mac, cycle)
		if err != nil {
			slog.Warn("cota por aparelho: não consegui ler o consumo do ciclo", "mac", mac, "err", err)
			continue
		}
		if nomes == nil {
			nomes = s.nomes()
		}
		nome := nomes[mac]
		if nome == "" {
			nome = mac
		}
		s.evaluate(nome, mac, q, usage.RxBytes+usage.TxBytes)
	}

	// lastCycle guarda só quem foi processado nesta rodada. Sem a poda, o mapa
	// cresceria com todo MAC que já passou pela rede — inclusive os aleatórios
	// que telefone moderno gera a cada associação.
	s.lastCycle = novoLastCycle
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
// tablet — sairia como "0.0 GB de 0 GB", o defeito que a metade de link deste
// mesmo recurso já pagou numa validação em máquina real.
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
		// O aviso de "chegando lá" deixa de ser verdade quando a cota acaba:
		// mantê-lo aberto ao lado do crítico põe dois alertas do mesmo
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
// "consumiu 900 MB de 1.0 GB" não distingue um teto diário de um mensal — e as
// duas leituras pedem reações opostas.
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
	usoPorCiclo := map[int64]map[string]storage.HostUsage{}

	out := make([]Status, 0, len(macs))
	for _, mac := range macs {
		q, hasQuota := quotas[mac]
		start := CycleStart(now, q.Period, q.CycleDay)
		cycle := start.Unix()
		uso, ok := usoPorCiclo[cycle]
		if !ok {
			uso, err = s.db.GetHostUsageAll(cycle)
			if err != nil {
				return nil, err
			}
			usoPorCiclo[cycle] = uso
		}
		u := uso[mac]
		m, present := meta[mac]

		period := q.Period
		if period == "" {
			period = storage.HostPeriodMonthly
		}
		cycleDay := q.CycleDay
		if cycleDay < 1 {
			cycleDay = 1
		}
		nome := mac
		if present {
			nome = NomeDe(m)
		}
		// Configured é "tem cota DECLARADA", e não "tem linha no banco": a
		// linha sobrevive à remoção da cota justamente para preservar o ciclo
		// (ver Delete), com limite zero.
		st := Status{
			MAC:        mac,
			Name:       nome,
			IP:         m.IP,
			Configured: hasQuota && q.LimitGB > 0,
			Enabled:    hasQuota && q.Enabled && q.LimitGB > 0,
			LimitGB:    q.LimitGB,
			Period:     period,
			CycleDay:   cycleDay,
			AlertPct:   q.AlertPct,
			CycleStart: cycle,
			CycleEnd:   CycleEnd(start, period).Unix(),
			RxBytes:    u.RxBytes,
			TxBytes:    u.TxBytes,
			UsedBytes:  u.RxBytes + u.TxBytes,
			Present:    present,
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
	return s.db.SaveHostQuota(q)
}

// Delete remove a cota declarada — mas PRESERVA a linha, com limite zero.
//
// POR QUE ASSIM, e não um DELETE de verdade: o consumo é gravado com a chave
// (aparelho, início do ciclo), e o início do ciclo sai do período e do dia de
// fechamento. Apagar a linha faz os dois voltarem ao padrão, o que muda a chave
// e faz a tela procurar um ciclo diferente daquele em que o consumo foi medido:
// o dado continua no banco e some da tela.
//
// Isso não é teoria. Na metade de link deste mesmo recurso, numa validação em
// máquina real (2026-08-20), remover uma franquia de fechamento 28 fez o
// consumo exibido cair de 2,6 MB para 35 KB sozinho. Aqui o estrago seria
// maior: com período diário, apagar a linha move o ciclo de "hoje" para "desde
// o dia 1", e o número exibido daria um salto para cima, não para baixo.
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
	q.Enabled = false
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
// mensal é local: o "dia" que o admin quer limitar é o dele. Num fuso a oeste
// de Greenwich, um ciclo diário em UTC viraria às 21h e o aparelho ganharia
// cota nova no meio da noite de filme.
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
