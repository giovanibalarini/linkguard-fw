package hosttraffic

import (
	"context"
	"errors"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// macsQuebrado devolve erro na segunda chamada em diante: é o "ip neigh" que
// estourou o timeout, ou a entrada que caiu para FAILED sem lladdr.
type macsQuebrado struct {
	mapa    map[string]string
	chamada int
	falhaEm int
}

func (m *macsQuebrado) MACByIP(context.Context) (map[string]string, error) {
	m.chamada++
	if m.chamada >= m.falhaEm {
		return nil, errors.New("tabela de vizinhança indisponível")
	}
	return m.mapa, nil
}

// Sem memória do último dono, uma falha da tabela de vizinhança apaga dez
// segundos de cota de TODA a rede — num slog.Debug que ninguém lê, e sem
// recuperação: o contador anterior já foi avançado.
func TestFalhaDaTabelaDeVizinhancaNaoApagaACotaDeTodaARede(t *testing.T) {
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000},
	}}
	macs := &macsQuebrado{mapa: map[string]string{"192.168.3.50": macTeste}, falhaEm: 2}
	s := NewSampler(c, macs, &gravadorFalso{})
	sink := novoSink()
	s.SetUsageSink(sink)

	s.SampleOnce(context.Background(), 100) // semeia, com MAC conhecido
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 11000}}
	s.SampleOnce(context.Background(), 110) // ip neigh falhou

	if got := sink.bytes[macTeste]; got[0] != 10000 {
		t.Errorf("a cota recebeu %d bytes, queria 10000: a falha do ip neigh comeu a medição", got[0])
	}
}

const macTeste = "aa:bb:cc:dd:ee:ff"

// O elemento do set acct vive um dia inteiro e a entrada de vizinhança pode
// levar dezenas de segundos para trocar depois de um lease novo. Nessa janela o
// delta é do aparelho NOVO e o MAC lido ainda é o do antigo: a cota de quem
// saiu da rede subiria sozinha. Perder uma amostra é aceitável; inventar
// consumo não é.
func TestHandoverDeEnderecoNaoCobraDoDonoAnterior(t *testing.T) {
	const antigo = "aa:bb:cc:dd:ee:ff"
	const novo = "11:22:33:44:55:66"
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000},
	}}
	macs := &macsFalso{mapa: map[string]string{"192.168.3.50": antigo}}
	s := NewSampler(c, macs, &gravadorFalso{})
	sink := novoSink()
	s.SetUsageSink(sink)
	s.SampleOnce(context.Background(), 100)

	// O DHCP entregou o endereço para outro aparelho.
	macs.mapa = map[string]string{"192.168.3.50": novo}
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 9_000_000}}
	s.SampleOnce(context.Background(), 110)

	if got := sink.bytes[antigo]; got[0] != 0 {
		t.Errorf("o dono anterior foi cobrado por %d bytes que não gastou", got[0])
	}
	if got := sink.bytes[novo]; got[0] != 0 {
		t.Errorf("o dono novo recebeu %d bytes de um intervalo que não é dele", got[0])
	}

	// E a amostra seguinte, já com o dono estável, volta a contar normalmente.
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 9_005_000}}
	s.SampleOnce(context.Background(), 120)
	if got := sink.bytes[novo]; got[0] != 5000 {
		t.Errorf("depois do handover a contagem não voltou: %d", got[0])
	}
}

// dt<=0 é preocupação de TAXA — dividir por zero, ou por um número negativo
// depois de um passo de NTP para trás, corriqueiro numa caixa sem RTC logo
// depois do boot. A contabilidade de BYTES não precisa de dt para nada, e a
// guarda vazava para ela: um passo de relógio descartava o intervalo inteiro de
// cota de todos os endereços de uma vez.
func TestPassoDeRelogioParaTrasNaoApagaOsBytesDaCota(t *testing.T) {
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000},
	}}
	s := NewSampler(c, &macsFalso{mapa: map[string]string{"192.168.3.50": macTeste}}, &gravadorFalso{})
	sink := novoSink()
	s.SetUsageSink(sink)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 51000}}
	s.SampleOnce(context.Background(), 95) // o NTP puxou o relógio para trás

	if got := sink.bytes[macTeste]; got[0] != 50000 {
		t.Errorf("a cota recebeu %d bytes, queria 50000: um passo de relógio apagou a medição", got[0])
	}
}

// O ciclo a que um byte pertence é função do momento em que ele foi MEDIDO. O
// sink recebe o instante junto para o acumulador da cota poder decidir isso —
// ver internal/hostquota, seção O TEMPO.
func TestOSinkRecebeOInstanteDaMedicao(t *testing.T) {
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000},
	}}
	s := NewSampler(c, &macsFalso{mapa: map[string]string{"192.168.3.50": macTeste}}, &gravadorFalso{})
	sink := novoSink()
	s.SetUsageSink(sink)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 2000}}
	s.SampleOnce(context.Background(), 110)

	ts := sink.instantes[macTeste]
	if len(ts) != 1 || ts[0] != 110 {
		t.Errorf("o sink recebeu os instantes %v, queria [110]", ts)
	}
}
