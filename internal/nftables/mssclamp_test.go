package nftables

import (
	"context"
	"strings"
	"testing"
)

func TestMSSClampRules(t *testing.T) {
	got := mssClampRules(zonaOnPrem("wan1", "wan2"))
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
	regra := strings.Join(mssClampRules(zonaOnPrem("wan1"))[0], " ")
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
	regra := strings.Join(mssClampRules(zonaOnPrem("wan1"))[0], " ")
	if !strings.Contains(regra, "tcp flags syn / syn,rst") {
		t.Errorf("o casamento de flags não está restrito ao SYN: %q", regra)
	}
}

// TestMSSClampSemWANCriaAChainVaziaEmVezDeNaoCriarNada é a virada deliberada de
// um teste que afirmava o contrário.
//
// O QUE ELE AFIRMAVA: sem WAN cadastrada, EnsureMSSClamp não executava NADA —
// o early-return vinha antes do `add chain`. O efeito colateral era a chain
// mss_clamp simplesmente não existir na caixa, nem vazia, e ninguém conseguir
// distinguir "não há link cadastrado" de "a reconciliação quebrou".
//
// O QUE ELE AFIRMA AGORA: a chain é criada e fica VAZIA. Estrutura montada,
// zero regra. É seguro porque a chain é `policy accept` e não decide nada
// sozinha, e é honesto porque o estado passa a ser inspecionável.
//
// O QUE CONTINUA VALENDO, e é a metade que não pode ser perdida: nenhuma REGRA
// é emitida. Uma regra de clamp sem saber por onde se sai é pior do que
// nenhuma.
func TestMSSClampSemWANCriaAChainVaziaEmVezDeNaoCriarNada(t *testing.T) {
	ex := &execFalso{}
	s := &Service{exec: ex}
	if err := s.EnsureMSSClamp(context.Background(), nil); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	var criouChain bool
	for _, c := range ex.comandos {
		if strings.Contains(c, "add chain inet linkguard mss_clamp") {
			criouChain = true
		}
		if strings.Contains(c, "add rule") {
			t.Errorf("emitiu regra sem WAN cadastrada: %q", c)
		}
	}
	if !criouChain {
		t.Errorf("a chain mss_clamp tinha de nascer, mesmo vazia: %v", ex.comandos)
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
