package tsdb

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/system"
)

// UsageSink recebe os MESMOS deltas de byte que viram taxa nas séries.
//
// Existe para a franquia por link (internal/linkquota) contar consumo sem
// abrir um segundo caminho de medição: dois leitores independentes dos
// contadores divergiriam — cada um com seu instante de leitura e seu próprio
// tratamento de reset —, e aí o gráfico e a franquia contariam coisas
// diferentes sobre o mesmo link. Um sink só, alimentado de onde o delta já é
// calculado e já é protegido contra reset de contador.
type UsageSink interface {
	AddInterfaceBytes(iface string, rx, tx uint64)
}

// TrafficSampler feeds the "if.rx_bps"/"if.tx_bps" series once a second from
// interface byte counters, mirroring what internal/trafficrrd used to do
// directly against the database — the difference is it now calls Gauge()
// instead of writing SQL itself.
type TrafficSampler struct {
	sysCol *system.Collector
	rec    Recorder
	usage  UsageSink

	prevCounters map[string]struct {
		ts int64
		rx uint64
		tx uint64
	}
}

// NewTrafficSampler creates a sampler that reports into rec (normally the
// same *Service — pass it as a Recorder).
func NewTrafficSampler(rec Recorder) *TrafficSampler {
	return &TrafficSampler{
		sysCol: system.NewCollector(),
		rec:    rec,
		prevCounters: make(map[string]struct {
			ts int64
			rx uint64
			tx uint64
		}),
	}
}

// SetUsageSink liga (opcionalmente) um consumidor dos deltas de byte. Nil —
// o padrão — mantém o amostrador exatamente como era.
func (t *TrafficSampler) SetUsageSink(u UsageSink) { t.usage = u }

// SampleOnce reads current interface counters and reports the delta-derived
// rate for each interface. Call once per second.
func (t *TrafficSampler) SampleOnce(now int64) {
	snap, err := t.sysCol.Collect()
	if err != nil {
		return
	}
	t.sampleInterfaces(snap.Interfaces, now)
}

// SampleInterfacesForTest exercises the same delta/rate logic as SampleOnce
// against caller-supplied interface counters instead of a real
// system.Collector.Collect() snapshot, so tests can deterministically drive
// first-call seeding, rate computation, and negative-delta clamping without
// depending on /proc. Test-only — mirrors the *ForTest seam pattern already
// used by Service (FlushForTest, StateForTest, GaugeForTest).
func (t *TrafficSampler) SampleInterfacesForTest(interfaces []system.InterfaceMetrics, now int64) {
	t.sampleInterfaces(interfaces, now)
}

func (t *TrafficSampler) sampleInterfaces(interfaces []system.InterfaceMetrics, now int64) {
	for _, iface := range interfaces {
		if iface.Name == "lo" {
			continue
		}
		prev, ok := t.prevCounters[iface.Name]
		t.prevCounters[iface.Name] = struct {
			ts int64
			rx uint64
			tx uint64
		}{ts: now, rx: iface.RxBytes, tx: iface.TxBytes}
		if !ok {
			continue
		}
		dt := float64(now - prev.ts)
		if dt <= 0 {
			continue
		}
		// Counters are uint64: on a reset/wrap, current can be < prev, and
		// subtracting unsigned integers in that case underflows to a huge
		// positive number instead of going negative — casting that to
		// float64 before checking the sign would defeat the clamp entirely
		// (a reset would report a bogus multi-exabyte/s spike instead of 0).
		// Comparing before subtracting avoids ever forming the underflowed
		// value.
		var rxDelta, txDelta float64
		if iface.RxBytes >= prev.rx {
			rxDelta = float64(iface.RxBytes - prev.rx)
		}
		if iface.TxBytes >= prev.tx {
			txDelta = float64(iface.TxBytes - prev.tx)
		}
		t.rec.Gauge("if.rx_bps", iface.Name, rxDelta/dt)
		t.rec.Gauge("if.tx_bps", iface.Name, txDelta/dt)
		if t.usage != nil {
			// Os deltas já vêm zerados quando o contador resetou (ver acima),
			// então o sink nunca recebe o salto falso de um reboot.
			t.usage.AddInterfaceBytes(iface.Name, uint64(rxDelta), uint64(txDelta))
		}
	}
}

// HistoryPoint is one bucket of the traffic history response.
//
// RxBps/TxBps são ponteiros porque **ausência não é zero**: as duas direções
// são séries separadas (if.rx_bps e if.tx_bps), e um instante pode ter bucket
// de uma e não da outra. Preencher a que falta com 0 entrega à UI uma medição
// que nunca existiu — e um zero medido é indistinguível, no gráfico, de um
// link fora do ar. `null` no JSON é o "não medido" que a tela sabe não
// desenhar (web/src/lib/series.ts trata `null` como buraco na linha).
//
// Os nomes dos campos JSON são exatamente os da antiga
// storage.TrafficSample (interface/step_seconds/timestamp/rx_bps/tx_bps),
// que este tipo substitui só nesta resposta — o formato do ponto não muda,
// muda apenas o domínio do valor, que agora inclui null.
//
// Apesar do sufixo _bps, o valor é em BYTES por segundo (TrafficSampler faz
// rxDelta/dt com os bytes de /proc/net/dev). A conversão para bits mora numa
// função só, no frontend, de propósito.
type HistoryPoint struct {
	Interface   string   `json:"interface"`
	StepSeconds int      `json:"step_seconds"`
	Timestamp   int64    `json:"timestamp"`
	RxBps       *float64 `json:"rx_bps"`
	TxBps       *float64 `json:"tx_bps"`
}

// HistoryResponse is returned by the /api/system/traffic-history and
// /api/monitoring/timeline handlers for chart rendering — same shape the
// frontend already consumes from the old trafficrrd.HistoryResponse. This
// endpoint has always been average-only, so there's no min/max to carry here
// even though tsdb tracks it internally.
type HistoryResponse struct {
	Interface string         `json:"interface"`
	Range     string         `json:"range"`
	Step      int            `json:"step_seconds"`
	Points    []HistoryPoint `json:"points"`
}

// GetHistory returns rx/tx history for one interface — drop-in replacement
// for the old trafficrrd.Service.GetHistory. It queries both the if.rx_bps
// and if.tx_bps series and merges them by timestamp so each returned point
// carries both rx_bps and tx_bps, matching the contract the frontend already
// relies on (it reads both fields off the same point).
func (s *Service) GetHistory(iface, rangeID string) (*HistoryResponse, error) {
	return s.history("if.rx_bps", "if.tx_bps", iface, rangeID)
}

// GetHostHistory devolve o histórico de consumo de UM host da LAN (issue
// #113), identificado pelo MAC.
//
// O MAC, e não o IP, porque é a identidade que o resto do produto já usa —
// alias, bloqueio e o próprio inventário são todos indexados por MAC
// (internal/hosts). Indexar a série pelo IP faria o histórico de um aparelho
// se partir em dois toda vez que o lease do DHCP mudasse, que é exatamente a
// fragilidade que a Fase 3 do FEATURES.md aponta.
func (s *Service) GetHostHistory(mac, rangeID string) (*HistoryResponse, error) {
	return s.historyStep("host.rx_bps", "host.tx_bps", mac, rangeID, hostStepFor)
}

// hostStepFor corrige o passo pedido para o que a série por host REALMENTE
// tem.
//
// As janelas curtas (5m, 30m) resolvem para passo de 1 segundo, que é o passo
// nativo das interfaces. A série por host é amostrada a cada 10s (ver
// nativeSteps), então não existe balde de 1s para ela: a consulta voltaria
// vazia e o gráfico do aparelho ficaria em branco justamente na janela que a
// tela abre por padrão. Elevar o piso para 10 devolve o balde que existe.
func hostStepFor(rangeID string) (int, time.Duration) {
	step, dur := rangeToStepDuration(rangeID)
	if step < 10 {
		step = 10
	}
	return step, dur
}

// history é o corpo comum: mesma janela, mesmo merge por timestamp, mudando só
// quais séries são lidas e sob qual rótulo.
func (s *Service) history(rxSeries, txSeries, label, rangeID string) (*HistoryResponse, error) {
	return s.historyStep(rxSeries, txSeries, label, rangeID, rangeToStepDuration)
}

func (s *Service) historyStep(rxSeries, txSeries, label, rangeID string,
	passo func(string) (int, time.Duration)) (*HistoryResponse, error) {
	iface := strings.TrimSpace(label)
	if iface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	step, dur := passo(rangeID)
	toUnix := time.Now().Unix()
	fromUnix := toUnix - int64(dur.Seconds())

	rxSamples, err := s.db.GetMetricSamples(rxSeries, iface, step, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	txSamples, err := s.db.GetMetricSamples(txSeries, iface, step, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}

	rxByTs := make(map[int64]float64, len(rxSamples))
	for _, sample := range rxSamples {
		rxByTs[sample.TsUnix] = sample.VAvg
	}
	txByTs := make(map[int64]float64, len(txSamples))
	for _, sample := range txSamples {
		txByTs[sample.TsUnix] = sample.VAvg
	}

	// Union of timestamps present in either series — an interface can have a
	// bucket for one direction but not the other (e.g. a brief gap), and the
	// frontend still expects one point per distinct timestamp.
	tsSet := make(map[int64]struct{}, len(rxSamples)+len(txSamples))
	for ts := range rxByTs {
		tsSet[ts] = struct{}{}
	}
	for ts := range txByTs {
		tsSet[ts] = struct{}{}
	}
	timestamps := make([]int64, 0, len(tsSet))
	for ts := range tsSet {
		timestamps = append(timestamps, ts)
	}
	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

	points := make([]HistoryPoint, 0, len(timestamps))
	for _, ts := range timestamps {
		// Presença vem do comma-ok, nunca do valor: ler o mapa direto
		// devolveria 0 para a chave ausente, e esse 0 sairia no JSON como
		// medição real. Sem bucket, o lado vai como null.
		p := HistoryPoint{Interface: iface, StepSeconds: step, Timestamp: ts}
		if v, ok := rxByTs[ts]; ok {
			p.RxBps = &v
		}
		if v, ok := txByTs[ts]; ok {
			p.TxBps = &v
		}
		points = append(points, p)
	}

	return &HistoryResponse{Interface: iface, Range: rangeID, Step: step, Points: points}, nil
}

func rangeToStepDuration(rangeID string) (int, time.Duration) {
	switch strings.ToLower(strings.TrimSpace(rangeID)) {
	case "5m":
		return 1, 5 * time.Minute
	case "30m":
		return 1, 30 * time.Minute
	case "12h":
		return 60, 12 * time.Hour
	case "30d":
		return 900, 30 * 24 * time.Hour
	case "1y":
		return 3600, 365 * 24 * time.Hour
	case "5y":
		return 3600, 5 * 365 * 24 * time.Hour
	default:
		return 60, 12 * time.Hour
	}
}

// TimelinePoint is one bucket of one series in a timeline response.
type TimelinePoint struct {
	Ts  int64   `json:"ts"`
	Min float64 `json:"min"`
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
}

// TimelineSeries is one series+label's points for a timeline response.
type TimelineSeries struct {
	Name   string          `json:"name"`
	Label  string          `json:"label"`
	Points []TimelinePoint `json:"points"`
}

// TimelineState is one interval for the states section of a timeline response.
type TimelineState struct {
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	State     string `json:"state"`
	StartedAt int64  `json:"started_at"`
	EndedAt   *int64 `json:"ended_at,omitempty"`
}

// TimelineRequest names which series+label pairs and which state kind+label
// pairs to include.
type TimelineRequest struct {
	FromUnix, ToUnix int64
	Series           []SeriesLabel // exported alias of the internal seriesLabel key
	States           []StateKindLabel
}

// SeriesLabel and StateKindLabel are exported so callers outside the package
// (the API handler) can name what they want without reaching into internals.
type SeriesLabel struct{ Series, Label string }
type StateKindLabel struct{ Kind, Label string }

// Timeline answers a correlated multi-series, multi-state query for the
// diagnostic timeline. It picks the bucket step from the window width, the
// same rule GetHistory uses for a single series.
func (s *Service) Timeline(req TimelineRequest) (step int, series []TimelineSeries, states []TimelineState, err error) {
	dur := time.Duration(req.ToUnix-req.FromUnix) * time.Second
	step, _ = stepForDuration(dur)

	for _, sl := range req.Series {
		samples, err := s.db.GetMetricSamples(sl.Series, sl.Label, step, req.FromUnix, req.ToUnix)
		if err != nil {
			return 0, nil, nil, err
		}
		points := make([]TimelinePoint, len(samples))
		for i, sm := range samples {
			points[i] = TimelinePoint{Ts: sm.TsUnix, Min: sm.VMin, Avg: sm.VAvg, Max: sm.VMax}
		}
		series = append(series, TimelineSeries{Name: sl.Series, Label: sl.Label, Points: points})
	}

	for _, kl := range req.States {
		intervals, err := s.db.GetStateIntervals(kl.Kind, kl.Label, req.FromUnix, req.ToUnix)
		if err != nil {
			return 0, nil, nil, err
		}
		for _, iv := range intervals {
			states = append(states, TimelineState{
				Kind: iv.Kind, Label: iv.Label, State: iv.State,
				StartedAt: iv.StartedAt, EndedAt: iv.EndedAt,
			})
		}
	}

	return step, series, states, nil
}

// stepForDuration picks a bucket step by window width, same thresholds as
// rangeToStepDuration but keyed by an actual duration instead of a named range
// (the timeline endpoint takes from/to timestamps, not a preset range name).
func stepForDuration(d time.Duration) (int, error) {
	switch {
	case d <= 30*time.Minute:
		return 1, nil
	case d <= 12*time.Hour:
		return 60, nil
	case d <= 30*24*time.Hour:
		return 900, nil
	default:
		return 3600, nil
	}
}

// HostStepForTest expõe hostStepFor para o teste do pacote externo. Mesmo
// padrão dos outros seams *ForTest deste pacote.
func HostStepForTest(rangeID string) (int, time.Duration) { return hostStepFor(rangeID) }
