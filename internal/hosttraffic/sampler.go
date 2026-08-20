package hosttraffic

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// Amostragem da série de consumo por host (issue #113).
//
// POR QUE ISTO EXISTE. O contador do nftables (#112) diz quanto um aparelho já
// consumiu DESDE QUE O CONTADOR EXISTE — um acumulado, sem janela de tempo. Com
// ele dá para responder "quem consome mais agora", e não "quanto o tablet
// gastou ontem", nem "esse aparelho está fora do normal para uma terça-feira".
// O FEATURES.md dava esse rollup por host como pronto desde a Fase 2; não
// estava.
//
// O QUE ELE FAZ. A cada dez segundos lê os contadores, tira a diferença para a
// leitura anterior e grava a TAXA nas séries host.rx_bps/host.tx_bps do tsdb —
// que já tem rollup (10s → 1min → 15min → 1h) e retenção por perfil. Nenhuma
// tabela nova: a mesma máquina que guarda o histórico das interfaces.
//
// O RÓTULO É O MAC, e não o IP. É a identidade que o produto usa em todo o
// resto (alias, bloqueio, inventário são indexados por MAC), e é o que faz o
// histórico de um aparelho sobreviver a uma troca de lease do DHCP — a
// fragilidade que a Fase 3 do FEATURES.md aponta.

const (
	// sampleInterval é a cadência da amostragem, e tem de casar com o passo
	// nativo de "host." em internal/tsdb/schema.go. Se divergirem, o tsdb
	// fecha baldes com um número de amostras diferente do esperado e a média
	// sai enviesada.
	sampleInterval = 10 * time.Second

	// maxHosts limita quantos aparelhos ganham série própria numa amostra. O
	// custo do histórico é (hosts × 2 séries × passos), e uma rede de
	// visitantes com centenas de aparelhos multiplicaria a escrita sem que
	// ninguém fosse olhar aquelas linhas. Os que ficam de fora não são
	// descartados em silêncio: entram somados no rótulo "outros".
	maxHosts = 50

	// OtherLabel é onde vai o consumo dos aparelhos além do teto. Existe para
	// o total continuar verdadeiro: sem ele, a soma das séries seria menor que
	// o tráfego real e ninguém saberia por quê.
	OtherLabel = "outros"
)

// Recorder é o pedaço do tsdb que o amostrador usa. Interface local para este
// pacote não depender do tsdb inteiro.
type Recorder interface {
	Gauge(series, label string, v float64)
}

// MACSource resolve IP → MAC (a tabela de vizinhança do kernel).
type MACSource interface {
	MACByIP(ctx context.Context) (map[string]string, error)
}

type leitura struct {
	rx, tx uint64
	ts     int64
}

// Sampler transforma o acumulado dos contadores em taxa, e a taxa em série.
type Sampler struct {
	counters CounterSource
	macs     MACSource
	rec      Recorder

	// anterior guarda a última leitura POR IP (que é a chave do contador), e
	// não por MAC: o contador do kernel é indexado por endereço, e é entre
	// duas leituras do mesmo endereço que a diferença faz sentido.
	anterior map[string]leitura
}

// NewSampler cria o amostrador.
func NewSampler(counters CounterSource, macs MACSource, rec Recorder) *Sampler {
	return &Sampler{counters: counters, macs: macs, rec: rec, anterior: map[string]leitura{}}
}

// Run amostra até o contexto acabar.
func (s *Sampler) Run(ctx context.Context) {
	t := time.NewTicker(sampleInterval)
	defer t.Stop()
	slog.Info("amostragem de consumo por host iniciada", "cadencia", sampleInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SampleOnce(ctx, time.Now().Unix())
		}
	}
}

// SampleOnce faz uma amostra. Exportado para o teste exercitar exatamente o
// que o laço exercita, sem esperar dez segundos.
func (s *Sampler) SampleOnce(ctx context.Context, now int64) {
	contadores, err := s.counters.HostCounters(ctx)
	if err != nil {
		// Sem contador não há o que gravar. Buraco na série é honesto; gravar
		// zero seria inventar um minuto de silêncio que não houve.
		slog.Debug("amostragem por host: contadores indisponíveis", "err", err)
		return
	}
	macs, err := s.macs.MACByIP(ctx)
	if err != nil {
		slog.Debug("amostragem por host: tabela de vizinhança indisponível", "err", err)
		macs = map[string]string{}
	}

	type taxa struct {
		mac    string
		rx, tx float64
	}
	var taxas []taxa

	for ip, c := range contadores {
		ant, tinha := s.anterior[ip]
		s.anterior[ip] = leitura{rx: c.RxBytes, tx: c.TxBytes, ts: now}
		if !tinha {
			// Primeira leitura só semeia: o acumulado até aqui não pertence a
			// esta janela de tempo, e gravá-lo como taxa daria um pico que
			// nunca existiu.
			continue
		}
		dt := float64(now - ant.ts)
		if dt <= 0 {
			continue
		}
		// Contador do kernel é uint64 e zera quando o set é recriado. Comparar
		// ANTES de subtrair evita formar o número gigante do underflow — mesma
		// proteção do amostrador de interfaces.
		var drx, dtx float64
		if c.RxBytes >= ant.rx {
			drx = float64(c.RxBytes - ant.rx)
		}
		if c.TxBytes >= ant.tx {
			dtx = float64(c.TxBytes - ant.tx)
		}
		if drx == 0 && dtx == 0 {
			continue
		}
		mac := macs[ip]
		if mac == "" {
			// Sem MAC não é host da LAN no modelo do produto (ver
			// hosts.Service.List). Vai para "outros" em vez de sumir.
			mac = OtherLabel
		}
		taxas = append(taxas, taxa{mac: mac, rx: drx / dt, tx: dtx / dt})
	}

	s.podarAusentes(contadores)

	// Junta o que caiu no mesmo MAC (um aparelho pode ter mais de um IP).
	juntos := map[string]*taxa{}
	for i := range taxas {
		t := taxas[i]
		j, ok := juntos[t.mac]
		if !ok {
			cp := t
			juntos[t.mac] = &cp
			continue
		}
		j.rx += t.rx
		j.tx += t.tx
	}

	lista := make([]taxa, 0, len(juntos))
	for _, t := range juntos {
		lista = append(lista, *t)
	}
	// Maiores primeiro, desempate por rótulo para o corte ser determinístico.
	sort.Slice(lista, func(i, j int) bool {
		if lista[i].rx+lista[i].tx != lista[j].rx+lista[j].tx {
			return lista[i].rx+lista[i].tx > lista[j].rx+lista[j].tx
		}
		return lista[i].mac < lista[j].mac
	})

	var sobraRx, sobraTx float64
	for i, t := range lista {
		if i >= maxHosts && t.mac != OtherLabel {
			sobraRx += t.rx
			sobraTx += t.tx
			continue
		}
		if t.mac == OtherLabel {
			sobraRx += t.rx
			sobraTx += t.tx
			continue
		}
		s.rec.Gauge("host.rx_bps", t.mac, t.rx)
		s.rec.Gauge("host.tx_bps", t.mac, t.tx)
	}
	if sobraRx > 0 || sobraTx > 0 {
		s.rec.Gauge("host.rx_bps", OtherLabel, sobraRx)
		s.rec.Gauge("host.tx_bps", OtherLabel, sobraTx)
	}
}

// podarAusentes esquece o estado de endereços que sumiram dos contadores. Sem
// isto o mapa cresce para sempre, e um endereço reaproveitado depois de horas
// seria comparado com uma leitura velha — produzindo um pico falso.
func (s *Sampler) podarAusentes(contadores map[string]nftables.HostCounter) {
	for ip := range s.anterior {
		if _, ainda := contadores[ip]; !ainda {
			delete(s.anterior, ip)
		}
	}
}
