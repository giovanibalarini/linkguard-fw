package nftables

import (
	"context"
	"strings"
	"testing"
)

func TestMSSClampRules(t *testing.T) {
	got := mssClampRules([]string{"wan1", "wan2"})
	if len(got) != 2 {
		t.Fatalf("queria uma regra por WAN, veio %d", len(got))
	}
	want := `oifname "wan1" tcp flags syn / syn,rst counter tcp option maxseg size set rt mtu`
	if s := strings.Join(got[0], " "); s != want {
		t.Errorf("regra:\n  %q\nqueria:\n  %q", s, want)
	}
}

func TestOAjusteNaoCarregaNumeroFixo(t *testing.T) {
	// `rt mtu` é o que torna a regra correta em qualquer link sem perguntar a
	// MTU ao admin — e no-op por construção onde a MTU é 1500. Um número
	// cravado quebraria os dois casos.
	regra := strings.Join(mssClampRules([]string{"wan1"})[0], " ")
	if !strings.Contains(regra, "size set rt mtu") {
		t.Errorf("o ajuste não usa a MTU da rota: %q", regra)
	}
	for _, numero := range []string{"1460", "1452", "1440"} {
		if strings.Contains(regra, numero) {
			t.Errorf("a regra cravou um MSS fixo (%s): %q", numero, regra)
		}
	}
}

func TestOAjusteSoValeNoApertoDeMao(t *testing.T) {
	// O MSS só é negociado no SYN. Casar outro pacote seria mexer numa conexão
	// já estabelecida.
	regra := strings.Join(mssClampRules([]string{"wan1"})[0], " ")
	if !strings.Contains(regra, "tcp flags syn / syn,rst") {
		t.Errorf("o casamento de flags não está restrito ao SYN: %q", regra)
	}
}

func TestMSSClampSemWANNaoFazNada(t *testing.T) {
	ex := &execFalso{}
	s := &Service{exec: ex}
	if err := s.EnsureMSSClamp(context.Background(), nil); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.comandos) != 0 {
		t.Errorf("executou sem WAN: %v", ex.comandos)
	}
}

func TestMSSClampDryRunNaoExecuta(t *testing.T) {
	ex := &execFalso{dryRun: true}
	s := &Service{exec: ex}
	if err := s.EnsureMSSClamp(context.Background(), []string{"wan1"}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.comandos) != 0 {
		t.Errorf("dry-run executou: %v", ex.comandos)
	}
}
