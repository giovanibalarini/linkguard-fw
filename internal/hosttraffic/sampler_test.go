package hosttraffic

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

type gravacao struct {
	series, label string
	v             float64
}

type gravadorFalso struct{ gravou []gravacao }

func (g *gravadorFalso) Gauge(series, label string, v float64) {
	g.gravou = append(g.gravou, gravacao{series, label, v})
}

func (g *gravadorFalso) valor(series, label string) (float64, bool) {
	for i := len(g.gravou) - 1; i >= 0; i-- {
		if g.gravou[i].series == series && g.gravou[i].label == label {
			return g.gravou[i].v, true
		}
	}
	return 0, false
}

type macsFalso struct {
	mapa map[string]string
	err  error
}

func (m *macsFalso) MACByIP(context.Context) (map[string]string, error) { return m.mapa, m.err }

type contadoresFalso struct {
	dados map[string]nftables.HostCounter
	err   error
}

func (c *contadoresFalso) HostCounters(context.Context) (map[string]nftables.HostCounter, error) {
	return c.dados, c.err
}

func novoSampler(dados map[string]nftables.HostCounter, macs map[string]string) (*Sampler, *contadoresFalso, *gravadorFalso) {
	c := &contadoresFalso{dados: dados}
	g := &gravadorFalso{}
	return NewSampler(c, &macsFalso{mapa: macs}, g), c, g
}

func TestPrimeiraAmostraApenasSemeia(t *testing.T) {
	// O contador é acumulado desde que existe. Gravar a primeira leitura como
	// taxa daria um pico gigante que nunca aconteceu — e ele entraria no
	// rollup, contaminando a média da hora.
	s, _, g := novoSampler(
		map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 1_000_000, TxBytes: 500_000}},
		map[string]string{"192.168.3.50": "aa:bb:cc:dd:ee:ff"},
	)
	s.SampleOnce(context.Background(), 100)
	if len(g.gravou) != 0 {
		t.Errorf("a primeira amostra gravou: %+v", g.gravou)
	}
}

func TestTaxaEhADiferencaDivididaPeloTempo(t *testing.T) {
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000, TxBytes: 500},
	}}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{mapa: map[string]string{"192.168.3.50": "aa:bb:cc:dd:ee:ff"}}, g)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 11000, TxBytes: 1500}}
	s.SampleOnce(context.Background(), 110) // 10s depois

	rx, ok := g.valor("host.rx_bps", "aa:bb:cc:dd:ee:ff")
	if !ok || rx != 1000 {
		t.Errorf("rx = %v (ok=%v), queria 1000 B/s (10000 bytes em 10s)", rx, ok)
	}
	tx, _ := g.valor("host.tx_bps", "aa:bb:cc:dd:ee:ff")
	if tx != 100 {
		t.Errorf("tx = %v, queria 100 B/s", tx)
	}
}

func TestResetDoContadorNaoViraPico(t *testing.T) {
	// O set é recriado quando a tabela é reconstruída, e o contador volta a
	// zero. Subtrair uint64 sem checar daria um número perto de 2^64 — e a
	// série do host mostraria exabytes por segundo, para sempre no rollup.
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 9_000_000, TxBytes: 9_000_000},
	}}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{mapa: map[string]string{"192.168.3.50": "aa:bb:cc:dd:ee:ff"}}, g)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 10, TxBytes: 10}}
	s.SampleOnce(context.Background(), 110)

	if rx, ok := g.valor("host.rx_bps", "aa:bb:cc:dd:ee:ff"); ok && rx > 100 {
		t.Errorf("reset virou taxa de %v B/s", rx)
	}
}

func TestVariosIPsDoMesmoAparelhoSomamNumaSerieSo(t *testing.T) {
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 0},
		"192.168.3.60": {RxBytes: 0},
	}}
	g := &gravadorFalso{}
	macs := map[string]string{
		"192.168.3.50": "aa:bb:cc:dd:ee:ff",
		"192.168.3.60": "aa:bb:cc:dd:ee:ff", // mesmo aparelho, dois endereços
	}
	s := NewSampler(c, &macsFalso{mapa: macs}, g)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000},
		"192.168.3.60": {RxBytes: 2000},
	}
	s.SampleOnce(context.Background(), 110)

	rx, _ := g.valor("host.rx_bps", "aa:bb:cc:dd:ee:ff")
	if rx != 300 {
		t.Errorf("rx = %v, queria 300 B/s (1000+2000 em 10s)", rx)
	}
}

func TestEnderecoSemMACVaiParaOutros(t *testing.T) {
	// Host da LAN, no modelo do produto, é host com MAC. O que atravessa sem
	// aparecer na vizinhança não some: entra em "outros", para o total
	// continuar verdadeiro.
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{"10.9.9.9": {RxBytes: 0}}}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{mapa: map[string]string{}}, g)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"10.9.9.9": {RxBytes: 5000}}
	s.SampleOnce(context.Background(), 110)

	if v, ok := g.valor("host.rx_bps", OtherLabel); !ok || v != 500 {
		t.Errorf("outros = %v (ok=%v), queria 500 B/s", v, ok)
	}
}

func TestTetoDeHostsSomaOResto(t *testing.T) {
	// Rede de visitantes com centenas de aparelhos não pode multiplicar a
	// escrita do banco. Mas o que fica de fora tem de continuar somando em
	// algum lugar, ou o total mente.
	dados := map[string]nftables.HostCounter{}
	macs := map[string]string{}
	for i := 0; i < maxHosts+20; i++ {
		ip := "192.168.3." + strconv.Itoa(i+1)
		dados[ip] = nftables.HostCounter{}
		macs[ip] = "aa:bb:cc:00:00:" + strconv.FormatInt(int64(i), 16)
	}
	c := &contadoresFalso{dados: dados}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{mapa: macs}, g)
	s.SampleOnce(context.Background(), 100)

	// Todo mundo consome, mas em quantidades diferentes: os 20 menores caem
	// no corte.
	novo := map[string]nftables.HostCounter{}
	for i := 0; i < maxHosts+20; i++ {
		ip := "192.168.3." + strconv.Itoa(i+1)
		novo[ip] = nftables.HostCounter{RxBytes: uint64((i + 1) * 100)}
	}
	c.dados = novo
	s.SampleOnce(context.Background(), 110)

	var comSerie int
	for _, gr := range g.gravou {
		if gr.series == "host.rx_bps" && gr.label != OtherLabel {
			comSerie++
		}
	}
	if comSerie > maxHosts {
		t.Errorf("%d hosts ganharam série; o teto é %d", comSerie, maxHosts)
	}
	if _, ok := g.valor("host.rx_bps", OtherLabel); !ok {
		t.Error("os hosts além do teto sumiram em vez de somar em 'outros'")
	}
}

func TestEnderecoQueSumiuEhEsquecido(t *testing.T) {
	// Endereço reaproveitado depois de horas seria comparado com uma leitura
	// velha e produziria um pico falso.
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 1000}}}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{mapa: map[string]string{"192.168.3.50": "aa:bb:cc:dd:ee:ff"}}, g)
	s.SampleOnce(context.Background(), 100)

	c.dados = map[string]nftables.HostCounter{} // sumiu do set (timeout)
	s.SampleOnce(context.Background(), 110)

	if _, ainda := s.anterior["192.168.3.50"]; ainda {
		t.Error("o estado do endereço que sumiu não foi esquecido")
	}
}

func TestSemContadoresNaoGravaNada(t *testing.T) {
	// Buraco na série é honesto; zero seria inventar silêncio que não houve.
	c := &contadoresFalso{err: errors.New("nft fora do ar")}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{}, g)
	s.SampleOnce(context.Background(), 100)
	if len(g.gravou) != 0 {
		t.Errorf("gravou sem contadores: %+v", g.gravou)
	}
}

// ─── sink de bytes para a cota por aparelho (#126) ───────────────────────────

type sinkFalso struct {
	bytes     map[string][2]uint64
	instantes map[string][]int64
}

func novoSink() *sinkFalso {
	return &sinkFalso{bytes: map[string][2]uint64{}, instantes: map[string][]int64{}}
}

func (s *sinkFalso) AddHostBytes(mac string, ts int64, rx, tx uint64) {
	v := s.bytes[mac]
	s.bytes[mac] = [2]uint64{v[0] + rx, v[1] + tx}
	s.instantes[mac] = append(s.instantes[mac], ts)
}

func TestSinkRecebeBytesENaoTaxa(t *testing.T) {
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000, TxBytes: 500},
	}}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{mapa: map[string]string{"192.168.3.50": "aa:bb:cc:dd:ee:ff"}}, g)
	sink := novoSink()
	s.SetUsageSink(sink)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 11000, TxBytes: 1500}}
	s.SampleOnce(context.Background(), 110) // 10 s depois

	got := sink.bytes["aa:bb:cc:dd:ee:ff"]
	// 10.000 bytes em 10 s. A série grava 1000 bps; a cota tem de receber os
	// 10.000 bytes. Se aqui chegasse a taxa, a cota erraria por um fator igual
	// ao intervalo de amostragem.
	if got[0] != 10000 || got[1] != 1000 {
		t.Errorf("sink recebeu rx=%d tx=%d, queria 10000/1000", got[0], got[1])
	}
	if rx, _ := g.valor("host.rx_bps", "aa:bb:cc:dd:ee:ff"); rx != 1000 {
		t.Errorf("a série mudou de valor: %v", rx)
	}
}

func TestAPrimeiraAmostraNaoAlimentaOSink(t *testing.T) {
	// O contador é acumulado desde que existe. Se a semeadura fosse para o sink,
	// todo reinício do serviço somaria de novo tudo o que já tinha passado — o
	// aparelho estouraria a cota no boot, sem ter transmitido nada.
	s, _, _ := novoSampler(
		map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 5_000_000_000}},
		map[string]string{"192.168.3.50": "aa:bb:cc:dd:ee:ff"},
	)
	sink := novoSink()
	s.SetUsageSink(sink)
	s.SampleOnce(context.Background(), 100)
	if len(sink.bytes) != 0 {
		t.Errorf("a semeadura foi para a cota: %v", sink.bytes)
	}
}

func TestSinkRecebeAntesDoCorteDeMaxHosts(t *testing.T) {
	// O TESTE QUE AMARRA O CONSUMIDOR AO PRODUTOR.
	//
	// maxHosts corta o RANKING da amostra: quem fica de fora vira o rótulo
	// "outros" na série. Se a cota lesse depois desse corte, o aparelho de menor
	// tráfego numa rede movimentada ficaria mudo — e ficaria mudo exatamente na
	// hora em que outros cinquenta estão consumindo, que é a hora em que alguém
	// declarou cota para ele.
	dados := map[string]nftables.HostCounter{}
	macs := map[string]string{}
	const n = maxHosts + 10
	for i := 0; i < n; i++ {
		ip := "10.0.0." + strconv.Itoa(i)
		dados[ip] = nftables.HostCounter{}
		macs[ip] = "aa:bb:cc:00:00:" + strconv.FormatInt(int64(i), 16)
	}
	c := &contadoresFalso{dados: dados}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{mapa: macs}, g)
	sink := novoSink()
	s.SetUsageSink(sink)
	s.SampleOnce(context.Background(), 100) // semeadura

	// Segunda leitura: cada host consome (i+1) KB, então o host 0 é o MENOR de
	// todos e cai fora do corte com folga.
	novos := map[string]nftables.HostCounter{}
	for i := 0; i < n; i++ {
		novos["10.0.0."+strconv.Itoa(i)] = nftables.HostCounter{RxBytes: uint64(i+1) * 1000}
	}
	c.dados = novos
	s.SampleOnce(context.Background(), 110)

	menor := macs["10.0.0.0"]
	if got := sink.bytes[menor]; got[0] != 1000 {
		t.Errorf("o aparelho fora do top-%d não chegou à cota: %v", maxHosts, got)
	}
	if len(sink.bytes) != n {
		t.Errorf("a cota recebeu %d aparelhos, queria %d", len(sink.bytes), n)
	}
	// E a série continua cortando, como sempre cortou: o corte é do histórico,
	// não da medição.
	if _, ok := g.valor("host.rx_bps", menor); ok {
		t.Errorf("o corte de maxHosts deixou de valer para a série")
	}
}

func TestSinkNaoRecebeQuemNaoTemMAC(t *testing.T) {
	// Sem MAC o consumo vai para o rótulo "outros" da série. Mandá-lo à cota
	// criaria uma linha de consumo que nenhum aparelho pode reivindicar — e que
	// apareceria na tela como uma cota que ninguém consegue remover.
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{"192.168.3.99": {}}}
	g := &gravadorFalso{}
	s := NewSampler(c, &macsFalso{mapa: map[string]string{}}, g)
	sink := novoSink()
	s.SetUsageSink(sink)
	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"192.168.3.99": {RxBytes: 5000}}
	s.SampleOnce(context.Background(), 110)

	if len(sink.bytes) != 0 {
		t.Errorf("a cota recebeu tráfego sem dono: %v", sink.bytes)
	}
	if v, ok := g.valor("host.rx_bps", OtherLabel); !ok || v != 500 {
		t.Errorf("o tráfego sem dono sumiu da série: %v %v", v, ok)
	}
}
