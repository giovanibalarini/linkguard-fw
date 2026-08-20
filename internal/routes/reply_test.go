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
