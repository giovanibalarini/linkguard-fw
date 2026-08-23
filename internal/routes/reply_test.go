package routes

import (
	"context"
	"os"
	"strings"
	"testing"
)

type execEspiao struct {
	rodou  []string
	saidas map[string]string
	dryRun bool
}

func (e *execEspiao) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.rodou = append(e.rodou, cmd+" "+strings.Join(args, " "))
	return "", nil
}

func (e *execEspiao) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	full := cmd + " " + strings.Join(args, " ")
	e.rodou = append(e.rodou, full)
	for k, v := range e.saidas {
		if strings.Contains(full, k) {
			return v, nil
		}
	}
	return "", nil
}

func (e *execEspiao) IsDryRun() bool                              { return e.dryRun }
func (e *execEspiao) WriteFile(string, []byte, os.FileMode) error { return nil }

func (e *execEspiao) rodouAlgoCom(trechos ...string) bool {
	for _, c := range e.rodou {
		todos := true
		for _, t := range trechos {
			if !strings.Contains(c, t) {
				todos = false
				break
			}
		}
		if todos {
			return true
		}
	}
	return false
}

const regrasDoKernel = `0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default`

func TestEnsureReplyRoutingPopulaTabelaEAdicionaRegra(t *testing.T) {
	ex := &execEspiao{saidas: map[string]string{"rule show": regrasDoKernel}}
	s := NewService(ex)

	err := s.EnsureReplyRouting(context.Background(), []ReplyRoute{
		{Interface: "wan1", Gateway: "192.168.18.1", Table: "100", Mark: "0x64"},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if !ex.rodouAlgoCom("route replace default", "via 192.168.18.1", "dev wan1", "table 100") {
		t.Errorf("a tabela do link não foi populada; rodou: %v", ex.rodou)
	}
	if !ex.rodouAlgoCom("rule add", "fwmark 0x64", "lookup 100") {
		t.Errorf("a regra de marca não foi criada; rodou: %v", ex.rodou)
	}
}

func TestRegraJaExistenteNaoEhDuplicada(t *testing.T) {
	// `ip rule add` é aditivo: repetir a cada boot empilharia cópias da mesma
	// regra, do jeito que o append-only do iptables empilhava regra antes da
	// Fase 0.
	ex := &execEspiao{saidas: map[string]string{
		"rule show": regrasDoKernel + "\n32700:\tfrom all fwmark 0x64 lookup 100",
	}}
	s := NewService(ex)
	if err := s.EnsureReplyRouting(context.Background(), []ReplyRoute{
		{Interface: "wan1", Gateway: "192.168.18.1", Table: "100", Mark: "0x64"},
	}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if ex.rodouAlgoCom("rule add") {
		t.Errorf("duplicou uma regra que já existia; rodou: %v", ex.rodou)
	}
}

func TestMarcaEmDecimalCasaComRegraEmHexa(t *testing.T) {
	// O kernel imprime a marca em hexadecimal mesmo quando ela foi adicionada
	// em decimal. Sem normalizar, a busca falharia e a regra seria adicionada
	// de novo a cada boot — uma cópia por reinício.
	ex := &execEspiao{saidas: map[string]string{
		"rule show": regrasDoKernel + "\n32700:\tfrom all fwmark 0x64 lookup 100",
	}}
	s := NewService(ex)
	if err := s.EnsureReplyRouting(context.Background(), []ReplyRoute{
		{Interface: "wan1", Gateway: "192.168.18.1", Table: "100", Mark: "100"},
	}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if ex.rodouAlgoCom("rule add") {
		t.Errorf("marca decimal não casou com a regra em hexa; rodou: %v", ex.rodou)
	}
}

func TestPrioridadeFicaAntesDaMain(t *testing.T) {
	// Depois da main (32766), a main resolveria primeiro pelo default e a
	// marca não mudaria rota nenhuma.
	if replyRulePriorityBase >= 32766 {
		t.Fatalf("prioridade base %d não vem antes da main (32766)", replyRulePriorityBase)
	}
	if replyRulePriorityBase <= 0 {
		t.Fatalf("prioridade base %d atropelaria a tabela local", replyRulePriorityBase)
	}
}

func TestUmaWANQuebradaNaoImpedeAsOutras(t *testing.T) {
	ex := &execEspiao{saidas: map[string]string{"rule show": regrasDoKernel}}
	s := NewService(ex)
	err := s.EnsureReplyRouting(context.Background(), []ReplyRoute{
		{Interface: "wan-invalida-com-nome-enorme", Gateway: "10.0.0.1", Table: "100", Mark: "0x64"},
		{Interface: "wan2", Gateway: "192.168.15.1", Table: "101", Mark: "0x65"},
	})
	if err == nil {
		t.Error("a falha da primeira WAN foi engolida em silêncio")
	}
	if !ex.rodouAlgoCom("rule add", "fwmark 0x65", "lookup 101") {
		t.Errorf("a segunda WAN não foi configurada; rodou: %v", ex.rodou)
	}
}

func TestDryRunNaoTocaNoRoteamento(t *testing.T) {
	ex := &execEspiao{dryRun: true}
	s := NewService(ex)
	if err := s.EnsureReplyRouting(context.Background(), []ReplyRoute{
		{Interface: "wan1", Gateway: "10.0.0.1", Table: "100", Mark: "0x64"},
	}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.rodou) != 0 {
		t.Errorf("dry-run executou: %v", ex.rodou)
	}
}

func TestReplaceRouteUsaOnlink(t *testing.T) {
	// Gateway de provedor frequentemente não está na mesma sub-rede da
	// interface (PPPoE, /32). Sem onlink o `ip route` recusa com "Nexthop has
	// invalid gateway", e a tabela do link fica vazia.
	ex := &execEspiao{}
	s := NewService(ex)
	if _, err := s.ReplaceRoute(context.Background(), "default", "10.0.0.1", "wan1", "100"); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if !ex.rodouAlgoCom("route replace default", "onlink") {
		t.Errorf("faltou onlink; rodou: %v", ex.rodou)
	}
}

// execComGateway responde ao `ip -4 route show default dev X` com o gateway vivo
// daquela interface.
type execComGateway struct {
	execEspiao
	porIface map[string]string
	escritos []string
}

func (e *execComGateway) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "ip" && len(args) >= 5 && args[1] == "route" && args[2] == "show" && args[3] == "default" {
		return e.porIface[args[len(args)-1]], nil
	}
	if cmd == "ip" && len(args) >= 2 && args[0] == "rule" {
		return "", nil
	}
	return "", nil
}

func (e *execComGateway) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.escritos = append(e.escritos, cmd+" "+strings.Join(args, " "))
	return "", nil
}

// TestOGatewayVemDoKernelENaoDoBanco é a regressão da issue #154.
//
// storage.Link.Gateway só é reescrito quando o admin clica em "detectar links"
// ou edita o link à mão — nenhum timer, boot ou monitor o refresca. Troque-se o
// modem do provedor e o dhclient conserta a tabela `main`, enquanto esta função
// continuava gravando o gateway ANTIGO na tabela do link. Com `onlink`, o kernel
// aceita sem reclamar.
//
// O efeito é seletivo e por isso enganoso: a navegação da LAN continua indo pela
// `main`, mas tudo que CHEGA por aquela WAN deixa de ser respondido — SSH e
// painel acessados de fora, e os encaminhamentos de porta.
func TestOGatewayVemDoKernelENaoDoBanco(t *testing.T) {
	e := &execComGateway{porIface: map[string]string{
		"wan1": "default via 10.0.0.254 dev wan1 proto dhcp metric 100",
	}}
	s := &Service{exec: e}

	err := s.EnsureReplyRouting(context.Background(), []ReplyRoute{
		{Interface: "wan1", Gateway: "10.0.0.1", Table: "100", Mark: "0x64"}, // gravado: velho
	})
	if err != nil {
		t.Fatalf("EnsureReplyRouting: %v", err)
	}

	var achou bool
	for _, c := range e.escritos {
		if strings.Contains(c, "route replace") {
			achou = true
			if !strings.Contains(c, "10.0.0.254") {
				t.Errorf("gravou o gateway do banco em vez do vivo: %q", c)
			}
			if strings.Contains(c, "10.0.0.1 ") {
				t.Errorf("o gateway antigo foi para a tabela do link: %q", c)
			}
		}
	}
	if !achou {
		t.Fatalf("nenhuma rota foi escrita: %v", e.escritos)
	}
}

func TestSemGatewayVivoUsaOGravado(t *testing.T) {
	// Link caído ou endereçamento estático sem default: trocar um gateway
	// possivelmente velho por NENHUM deixaria a tabela do link sem rota de
	// volta, que é pior do que uma rota velha.
	e := &execComGateway{porIface: map[string]string{}}
	s := &Service{exec: e}

	if err := s.EnsureReplyRouting(context.Background(), []ReplyRoute{
		{Interface: "wan1", Gateway: "10.0.0.1", Table: "100", Mark: "0x64"},
	}); err != nil {
		t.Fatalf("EnsureReplyRouting: %v", err)
	}
	for _, c := range e.escritos {
		if strings.Contains(c, "route replace") && !strings.Contains(c, "10.0.0.1") {
			t.Errorf("sem gateway vivo, não caiu no gravado: %q", c)
		}
	}
}

// TestGatewayDeMultipathNaoPegaOPrimeiro é a regressão do gateway trocado que
// se viu na máquina de produção: a tabela de retorno da WAN VIVO estava com o
// gateway da WAN GIGA.
//
// A saída abaixo é a de verdade, copiada da caixa. O filtro `dev` casa a rota
// multipath INTEIRA quando qualquer nexthop usa aquela interface, e a leitura
// antiga devolvia o `via` do primeiro nexthop para qualquer interface pedida.
func TestGatewayDeMultipathNaoPegaOPrimeiro(t *testing.T) {
	const multipath = `default 
	nexthop via 192.168.18.1 dev lg-wan-giga weight 256 onlink 
	nexthop via 192.168.15.1 dev lg-wan-vivo weight 110 onlink `

	for _, c := range []struct {
		iface, quer string
	}{
		{"lg-wan-giga", "192.168.18.1"},
		{"lg-wan-vivo", "192.168.15.1"},
		{"lg-wan-fantasma", ""},
	} {
		if got := viaDaInterface(multipath, c.iface); got != c.quer {
			t.Errorf("multipath, %s: veio %q, esperado %q", c.iface, got, c.quer)
		}
	}
}

// TestGatewayDeRotaSimplesContinuaFuncionando: o caminho comum, uma WAN só, não
// pode ter sido quebrado pela correção do multipath.
func TestGatewayDeRotaSimplesContinuaFuncionando(t *testing.T) {
	const simples = "default via 192.168.15.1 dev lg-wan-vivo proto dhcp src 192.168.15.2 metric 100 "
	if got := viaDaInterface(simples, "lg-wan-vivo"); got != "192.168.15.1" {
		t.Errorf("rota simples: veio %q", got)
	}
	if got := viaDaInterface(simples, "outra"); got != "" {
		t.Errorf("interface que não está na saída devia dar vazio, veio %q", got)
	}
}
