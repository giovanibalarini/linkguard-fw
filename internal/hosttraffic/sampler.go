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

// leitura é a última amostra de um endereço.
//
// mac guarda QUEM era o dono daquele endereço na amostra anterior, e existe por
// dois motivos que só aparecem em rede de verdade:
//
//  1. MEMÓRIA. Quando "ip neigh" falha ou estoura o timeout, macs vem
//     vazio e TODO delta desta amostra ficaria sem dono — dez segundos de cota
//     de toda a rede evaporando num slog.Debug que ninguém lê. Com a memória, o
//     último MAC conhecido do endereço continua valendo.
//
//  2. HANDOVER. Quando o DHCP entrega .50 para outro aparelho, o elemento do
//     set acct continua vivo (timeout 1d) e a entrada de vizinhança pode levar
//     dezenas de segundos para trocar. Nessa janela o delta é do aparelho novo
//     e o MAC lido ainda é o do antigo: a cota de quem saiu da rede subiria
//     sozinha. Quando o MAC muda entre duas amostras, o delta é DESCARTADO e o
//     endereço é re-semeado. Perde-se uma amostra; não se inventa consumo.
type leitura struct {
	rx, tx uint64
	ts     int64
	mac    string
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

	// porHost é o segundo consumidor da mesma medição (#118): as séries por
	// aparelho servidas ao coletor do cliente. Opcional — sem ele o amostrador
	// grava só no histórico, como sempre fez.
	//
	// Interface local, e não o tipo de internal/metrics, para este pacote não
	// depender daquele: o amostrador é medição, e medição não deve saber quem
	// consome.
	porHost RegistroPorHost

	// usage é o terceiro consumidor da MESMA medição (#126): a cota por
	// aparelho. Opcional, como o porHost.
	usage UsageSink
}

// RegistroPorHost é o que o amostrador precisa do registro de métricas por
// aparelho.
type RegistroPorHost interface {
	Registrar(mac, rotulo string, rx, tx float64)
	Limpar(vivos map[string]bool)
}

// SetPorHost liga o registro de métricas por aparelho (#118).
func (s *Sampler) SetPorHost(r RegistroPorHost) { s.porHost = r }

// UsageSink recebe os bytes medidos por aparelho, em bruto — gêmeo do
// tsdb.UsageSink que alimenta a franquia por link (#132).
//
// POR QUE BYTES, E NÃO A TAXA QUE O AMOSTRADOR JÁ GRAVA. A série host.rx_bps
// não pode ser integrada para virar consumo: o tsdb fecha o balde com a média
// das amostras PRESENTES (internal/tsdb/service.go), e este amostrador pula o
// aparelho parado. Um aparelho que transmitiu dez segundos dentro de uma hora
// deixa uma amostra só, com taxa alta, e o balde de 3600 s guarda essa taxa
// como média da hora inteira: multiplicar por 3600 superestima em cerca de
// 360 vezes. Somado ao teto de maxHosts e ao rótulo "outros", a integração
// seria um número errado com cara de número certo.
//
// POR QUE O INSTANTE VIAJA JUNTO. O ciclo a que um byte pertence é função do
// momento em que ele foi MEDIDO, não do momento em que o consumidor resolve
// gravá-lo. O acumulador da cota grava a cada minuto; sem o ts, tudo o que foi
// medido no último minuto do ciclo seria cobrado do ciclo SEGUINTE — um minuto
// por mês no ciclo mensal, um minuto por DIA no diário. Ver internal/hostquota,
// seção O TEMPO.
type UsageSink interface {
	AddHostBytes(mac string, ts int64, rx, tx uint64)
}

// SetUsageSink liga o acumulador de consumo por aparelho (#126). Nil mantém o
// comportamento de hoje, byte por byte — mesma promessa do UsageSink do tsdb.
func (s *Sampler) SetUsageSink(u UsageSink) { s.usage = u }

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

		// Quem é o dono deste endereço agora. Vazio quer dizer que a tabela de
		// vizinhança não respondeu, ou que a entrada está em FAILED/INCOMPLETE
		// e não tem lladdr — não quer dizer que o aparelho sumiu. Nesse caso
		// vale o último dono conhecido: ver o comentário de leitura.mac.
		macLido := macs[ip]
		mac := macLido
		if mac == "" {
			mac = ant.mac
		}
		s.anterior[ip] = leitura{rx: c.RxBytes, tx: c.TxBytes, ts: now, mac: mac}

		if !tinha {
			// Primeira leitura só semeia: o acumulado até aqui não pertence a
			// esta janela de tempo, e gravá-lo como taxa daria um pico que
			// nunca existiu.
			continue
		}
		if macLido != "" && ant.mac != "" && macLido != ant.mac {
			// O endereço trocou de dono entre duas amostras. O delta é do
			// aparelho novo e não há como reparti-lo; creditá-lo a qualquer um
			// dos dois inventaria consumo. Re-semeia e segue.
			continue
		}

		// Contador do kernel é uint64 e zera quando o set é recriado. Comparar
		// ANTES de subtrair evita formar o número gigante do underflow — mesma
		// proteção do amostrador de interfaces.
		var brx, btx uint64
		if c.RxBytes >= ant.rx {
			brx = c.RxBytes - ant.rx
		}
		if c.TxBytes >= ant.tx {
			btx = c.TxBytes - ant.tx
		}
		if brx == 0 && btx == 0 {
			continue
		}

		// A COTA RECEBE OS BYTES AQUI, no mesmo ponto em que o delta existe, e
		// NÃO depois do corte de maxHosts logo abaixo.
		//
		// O corte é do RANKING da amostra: os aparelhos além do quinquagésimo
		// viram o rótulo "outros" para o histórico não multiplicar séries.
		// Se a cota lesse dali, o aparelho com cota declarada ficaria mudo
		// exatamente na hora em que outros cinquenta estão consumindo — que é
		// a hora em que a cota importa.
		//
		// E ANTES DA GUARDA DE dt, logo abaixo. dt<=0 é preocupação de TAXA
		// (dividir por zero, ou por um número negativo depois de um passo de
		// NTP para trás — corriqueiro numa caixa sem RTC logo depois do boot).
		// A contabilidade de BYTES não precisa de dt para nada, e descartar o
		// intervalo inteiro por causa dele apagaria a cota de todos os
		// endereços de uma vez.
		//
		// Sem MAC não vai nada: "outros" é um rótulo de gráfico, não um
		// aparelho, e acumular cota nele criaria uma linha no banco que nenhum
		// aparelho pode reivindicar nem remover.
		if mac != "" && s.usage != nil {
			s.usage.AddHostBytes(mac, now, brx, btx)
		}

		dt := float64(now - ant.ts)
		if dt <= 0 {
			continue
		}
		drx, dtx := float64(brx), float64(btx)
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
	vivos := map[string]bool{}
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
		// Segundo consumidor da MESMA medição (#118), e não uma medição nova:
		// duplicar a coleta daria dois números para a mesma pergunta, que é como
		// dois painéis passam a discordar sobre a mesma rede.
		if s.porHost != nil {
			s.porHost.Registrar(t.mac, t.mac, t.rx, t.tx)
			vivos[t.mac] = true
		}
	}
	if s.porHost != nil {
		// Aparelho que saiu da rede precisa PARAR de publicar. Sem isto, o
		// Grafana mostraria uma linha reta perpétua no último valor, onde
		// deveria haver uma série que acaba — métrica que não morre é métrica
		// que mente.
		s.porHost.Limpar(vivos)
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
