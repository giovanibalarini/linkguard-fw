// Package linkquota mede quanto cada link WAN já consumiu no ciclo vigente e
// avisa antes de a franquia acabar.
//
// POR QUE EXISTE. O produto nasceu de uma casa com dois links, um deles móvel
// (README, "Motivação"). Link móvel tem franquia. Hoje, quando o principal cai
// e o failover joga tudo no 4G, NADA avisa que a franquia está indo embora —
// nem quando ela acaba, nem quem gastou. O admin descobre pela fatura ou pela
// velocidade despencando, que são as duas piores formas de descobrir.
//
// O QUE ELE NÃO FAZ, E POR QUÊ. Ele não restringe tráfego ao estourar a
// franquia. Cortar exige regra no ruleset vivo, e é decisão de outra ordem —
// avisar é reversível, cortar não é. A parte de restringir está na issue #126
// como etapa seguinte, deliberadamente separada desta.
//
// DE ONDE VEM O NÚMERO. Dos contadores de byte da própria interface, os mesmos
// que alimentam os gráficos (internal/tsdb.TrafficSampler), acumulados por
// ciclo. Não é estimativa por integração de taxa: é o delta do contador, com a
// mesma proteção contra reset que o amostrador já tem. O que a operadora conta
// pode divergir um pouco (ela conta no lado dela, e cabeçalho de enlace não
// entra aqui), então a tela chama isso de "medido pelo firewall" e não de
// "consumo da operadora".
package linkquota

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Tipos de alerta desta feature. Nomes estáveis: viram linha no banco.
const (
	TypeQuotaWarning  = "link_quota_warning"
	TypeQuotaExceeded = "link_quota_exceeded"
)

const (
	// bytesPerGB/bytesPerMB são DECIMAIS (10^9, 10^6). Ver o comentário de
	// storage.LinkQuota.
	bytesPerGB = 1_000_000_000.0
	bytesPerMB = 1_000_000.0

	// flushInterval é de quanto em quanto tempo o acumulado em memória vai
	// para o banco. Um minuto: gravar a cada segundo seria 86.400 UPDATEs por
	// dia por link num SSD que também guarda o banco inteiro, e perder até um
	// minuto de contagem num desligamento abrupto não muda nenhuma decisão que
	// esta feature exista para apoiar.
	flushInterval = time.Minute

	// MaxCycleDay é 28 porque todo mês tem dia 28. Fechamento em 29, 30 ou 31
	// simplesmente não existe em fevereiro, e a alternativa (deslizar para o
	// último dia do mês) faria o ciclo mudar de tamanho e o admin não
	// conseguir prever quando ele vira.
	MaxCycleDay = 28
)

// Alerter é o pedaço do alerts.Service que esta feature usa. Interface local
// para o serviço ser testável sem banco de alerta — mesmo padrão do
// bootstrapdeps.Alerter.
type Alerter interface {
	Create(alertType, severity, title, message, linkID string) error
	AutoResolve(alertType, linkID string)
}

// Status é o que o painel mostra por link.
type Status struct {
	LinkID     string  `json:"link_id"`
	LinkName   string  `json:"link_name"`
	Interface  string  `json:"interface"`
	Configured bool    `json:"configured"`
	Enabled    bool    `json:"enabled"`
	LimitGB    float64 `json:"limit_gb"`
	CycleDay   int     `json:"cycle_day"`
	AlertPct   int     `json:"alert_pct"`
	CycleStart int64   `json:"cycle_start"`
	CycleEnd   int64   `json:"cycle_end"`
	RxBytes    uint64  `json:"rx_bytes"`
	TxBytes    uint64  `json:"tx_bytes"`
	UsedBytes  uint64  `json:"used_bytes"`
	UsedPct    float64 `json:"used_pct"` // 0 quando não há franquia declarada
}

type delta struct{ rx, tx uint64 }

// Service acumula bytes por interface e os converte em consumo por ciclo.
type Service struct {
	db       *storage.DB
	alertSvc Alerter

	mu      sync.Mutex
	pending map[string]delta // por nome de interface, entre flushes
	// lastCycle guarda o ciclo em que cada link estava no flush anterior, para
	// detectar a virada e reabrir a possibilidade de alertar.
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

// AddInterfaceBytes recebe o delta de bytes de uma interface. É chamado uma
// vez por segundo pelo amostrador de tráfego, com os MESMOS deltas que
// alimentam os gráficos — de propósito: dois caminhos de medição divergiriam,
// e aí o gráfico e a franquia contariam coisas diferentes.
func (s *Service) AddInterfaceBytes(iface string, rx, tx uint64) {
	if rx == 0 && tx == 0 {
		return
	}
	s.mu.Lock()
	d := s.pending[iface]
	d.rx += rx
	d.tx += tx
	s.pending[iface] = d
	s.mu.Unlock()
}

// Run grava o acumulado periodicamente e avalia os limiares.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
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

// Flush grava o acumulado e avalia franquias. Idempotente e seguro de chamar
// fora do ticker (o desligamento faz isso).
func (s *Service) Flush() {
	s.mu.Lock()
	pending := s.pending
	s.pending = map[string]delta{}
	s.mu.Unlock()

	links, err := s.db.GetLinks()
	if err != nil {
		slog.Warn("cota: não consegui ler os links; o acumulado deste minuto foi perdido", "err", err)
		return
	}
	quotas, err := s.db.GetLinkQuotas()
	if err != nil {
		slog.Warn("cota: não consegui ler as franquias", "err", err)
		return
	}

	now := s.nowFn()
	for _, l := range links {
		if l.Interface == "" {
			continue
		}
		q, hasQuota := quotas[l.ID]
		cycleDay := 1
		if hasQuota {
			cycleDay = q.CycleDay
		}
		cycle := CycleStart(now, cycleDay).Unix()

		if d, ok := pending[l.Interface]; ok && (d.rx > 0 || d.tx > 0) {
			if err := s.db.AddLinkUsage(l.ID, cycle, d.rx, d.tx); err != nil {
				slog.Warn("cota: não consegui acumular o consumo", "link", l.Name, "err", err)
				continue
			}
		}

		// Virada de ciclo: o consumo volta a zero, então os avisos do ciclo
		// anterior deixam de ser verdade. Resolvê-los é o que permite o
		// próximo ciclo avisar de novo — o alerts.Service deduplica por
		// (tipo, link) enquanto o alerta estiver aberto.
		if prev, seen := s.lastCycle[l.ID]; seen && prev != cycle && s.alertSvc != nil {
			s.alertSvc.AutoResolve(TypeQuotaWarning, l.ID)
			s.alertSvc.AutoResolve(TypeQuotaExceeded, l.ID)
		}
		s.lastCycle[l.ID] = cycle

		if !hasQuota || !q.Enabled || q.LimitGB <= 0 {
			continue
		}
		usage, err := s.db.GetLinkUsage(l.ID, cycle)
		if err != nil {
			slog.Warn("cota: não consegui ler o consumo do ciclo", "link", l.Name, "err", err)
			continue
		}
		s.evaluate(l.Name, l.ID, q, usage.RxBytes+usage.TxBytes)
	}
}

// evaluate dispara o aviso quando o consumo cruza o limiar. Não guarda estado
// de "já avisei": quem faz isso é o alerts.Service, que suprime um alerta
// aberto do mesmo (tipo, link). Duplicar esse controle aqui criaria duas
// fontes de verdade sobre o que já foi avisado.
func (s *Service) evaluate(linkName, linkID string, q storage.LinkQuota, used uint64) {
	if s.alertSvc == nil {
		return
	}
	limit := q.LimitGB * bytesPerGB
	if limit <= 0 {
		return
	}
	pct := float64(used) / limit * 100

	switch {
	case pct >= 100:
		// O aviso de "chegando lá" deixa de ser verdade quando a franquia
		// acaba: mantê-lo aberto ao lado do crítico põe dois alertas do mesmo
		// link na tela dizendo coisas diferentes sobre o mesmo fato.
		s.alertSvc.AutoResolve(TypeQuotaWarning, linkID)
		_ = s.alertSvc.Create(TypeQuotaExceeded, "critical",
			fmt.Sprintf("Franquia esgotada: %s", linkName),
			fmt.Sprintf("O link %s já consumiu %s dos %s do ciclo (%.0f%%). "+
				"O que acontece a partir daqui é com a operadora — o LinkGuard não corta tráfego.",
				linkName, HumanBytes(float64(used)), HumanGB(q.LimitGB), pct),
			linkID)
	case pct >= float64(q.AlertPct):
		_ = s.alertSvc.Create(TypeQuotaWarning, "warning",
			fmt.Sprintf("Franquia em %.0f%%: %s", pct, linkName),
			fmt.Sprintf("O link %s consumiu %s dos %s do ciclo.",
				linkName, HumanBytes(float64(used)), HumanGB(q.LimitGB)),
			linkID)
	}
}

// HumanBytes e HumanGB existem porque a primeira versão formatava tudo em
// "%.1f GB" e "%.0f GB", e numa validação em máquina real o alerta saiu como
// "consumiu 0.0 GB dos 0 GB do ciclo" — franquia de 20 MB, consumo de 18 MB.
// Um plano de 500 MB (existe, e é justamente o tipo de plano de backup móvel
// que esta feature atende) receberia um alerta que não informa nada.
//
// A unidade acompanha a grandeza e continua DECIMAL: MB é 10^6, GB é 10^9 — o
// que a operadora usa. Ver storage.LinkQuota.
//
// SÃO EXPORTADAS porque a cota por aparelho (internal/hostquota, #126) escreve
// a mesma frase um andar abaixo. Duplicar dez linhas de formatação faria os
// dois alertas do produto divergirem na unidade — e o defeito que essas
// funções existem para impedir voltaria só na metade nova.
func HumanBytes(b float64) string {
	switch {
	case b >= bytesPerGB:
		return fmt.Sprintf("%.1f GB", b/bytesPerGB)
	case b >= bytesPerMB:
		return fmt.Sprintf("%.1f MB", b/bytesPerMB)
	default:
		return fmt.Sprintf("%.0f KB", b/1000)
	}
}

// HumanGB formata a franquia declarada, que vem em GB decimais e pode ser
// fracionária (0,5 GB = 500 MB).
func HumanGB(gb float64) string {
	return HumanBytes(gb * bytesPerGB)
}

// Snapshot devolve o estado de todos os links para o painel.
func (s *Service) Snapshot() ([]Status, error) {
	links, err := s.db.GetLinks()
	if err != nil {
		return nil, err
	}
	quotas, err := s.db.GetLinkQuotas()
	if err != nil {
		return nil, err
	}

	now := s.nowFn()
	out := make([]Status, 0, len(links))
	for _, l := range links {
		q, hasQuota := quotas[l.ID]
		cycleDay := 1
		if hasQuota {
			cycleDay = q.CycleDay
		}
		start := CycleStart(now, cycleDay)
		usage, err := s.db.GetLinkUsage(l.ID, start.Unix())
		if err != nil {
			return nil, err
		}
		// Configured é "tem franquia DECLARADA", e não "tem linha no banco": a
		// linha sobrevive à remoção da franquia justamente para preservar o
		// dia de fechamento (ver Delete), com limite zero.
		st := Status{
			LinkID:     l.ID,
			LinkName:   l.Name,
			Interface:  l.Interface,
			Configured: hasQuota && q.LimitGB > 0,
			Enabled:    hasQuota && q.Enabled && q.LimitGB > 0,
			LimitGB:    q.LimitGB,
			CycleDay:   cycleDay,
			AlertPct:   q.AlertPct,
			CycleStart: start.Unix(),
			CycleEnd:   CycleEnd(start).Unix(),
			RxBytes:    usage.RxBytes,
			TxBytes:    usage.TxBytes,
			UsedBytes:  usage.RxBytes + usage.TxBytes,
		}
		if hasQuota && q.LimitGB > 0 {
			st.UsedPct = float64(st.UsedBytes) / (q.LimitGB * bytesPerGB) * 100
		}
		out = append(out, st)
	}
	return out, nil
}

// Save valida e grava a franquia de um link.
func (s *Service) Save(q storage.LinkQuota) error {
	if q.LinkID == "" {
		return fmt.Errorf("link não informado")
	}
	if q.LimitGB < 0 {
		return fmt.Errorf("franquia inválida")
	}
	if q.CycleDay < 1 || q.CycleDay > MaxCycleDay {
		return fmt.Errorf("dia de fechamento deve estar entre 1 e %d", MaxCycleDay)
	}
	if q.AlertPct < 1 || q.AlertPct > 100 {
		return fmt.Errorf("o aviso deve estar entre 1%% e 100%%")
	}
	return s.db.SaveLinkQuota(q)
}

// Delete remove a franquia declarada — mas PRESERVA o dia de fechamento, e não
// apaga a linha.
//
// POR QUE ASSIM, e não um DELETE de verdade: o consumo é gravado com a chave
// (link, início do ciclo), e o início do ciclo sai do dia de fechamento. Apagar
// a linha faz o dia voltar ao padrão (1), o que muda a chave e faz o painel
// procurar um ciclo diferente daquele em que o consumo foi medido. O dado
// continua no banco e some da tela.
//
// Isso não é teoria: numa validação em máquina real (2026-08-20), remover uma
// franquia de fechamento 28 fez o consumo exibido cair de 2,6 MB para 35 KB
// sozinho, porque a leitura passou a olhar o ciclo que começa no dia 1. O
// histórico mostrava as duas linhas, e a tela mostrava a errada.
//
// Guardar a linha com limite zero mantém o ciclo estável e faz "sem franquia"
// ser um estado explícito, em vez da ausência de informação.
func (s *Service) Delete(linkID string) error {
	if s.alertSvc != nil {
		s.alertSvc.AutoResolve(TypeQuotaWarning, linkID)
		s.alertSvc.AutoResolve(TypeQuotaExceeded, linkID)
	}
	quotas, err := s.db.GetLinkQuotas()
	if err != nil {
		return err
	}
	q, ok := quotas[linkID]
	if !ok {
		return nil // nunca teve franquia: nada a remover
	}
	q.LimitGB = 0
	q.Enabled = false
	return s.db.SaveLinkQuota(q)
}

// History devolve os ciclos anteriores de um link.
func (s *Service) History(linkID string, limit int) ([]storage.LinkUsage, error) {
	return s.db.GetLinkUsageHistory(linkID, limit)
}

// ─── ciclo ───────────────────────────────────────────────────────────────────

// CycleStart devolve o instante em que começou o ciclo vigente, dado o dia de
// fechamento. Meia-noite local do dia `day` deste mês, se já passou; do mês
// anterior, se ainda não.
//
// Hora LOCAL, e não UTC, porque o ciclo que o admin lê na fatura é o do fuso
// dele — e o produto já gerencia o fuso da máquina (tela de NTP).
func CycleStart(now time.Time, day int) time.Time {
	if day < 1 {
		day = 1
	}
	if day > MaxCycleDay {
		day = MaxCycleDay
	}
	loc := now.Location()
	start := time.Date(now.Year(), now.Month(), day, 0, 0, 0, 0, loc)
	if now.Before(start) {
		start = start.AddDate(0, -1, 0)
	}
	return start
}

// CycleEnd é o começo do ciclo seguinte.
func CycleEnd(start time.Time) time.Time {
	return start.AddDate(0, 1, 0)
}
