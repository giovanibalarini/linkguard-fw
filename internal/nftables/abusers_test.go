package nftables

import (
	"strings"
	"testing"
)

// A contenção de tentativa repetida (issue #127).
//
// A PROPRIEDADE QUE TORNA ISTO SEGURO, e ela é estrutural: só origem que chega
// pelas WANs pode ENTRAR no set. Contenção por taxa que pega o próprio admin é
// tranca com outro nome, e este projeto já pagou por uma hoje.

func TestSoQuemVemDaWANPodeSerContido(t *testing.T) {
	regras := linhas(abuseRules([]string{"wan0"}, "{ 22, 9997 }"))
	var add string
	for _, r := range regras {
		if strings.Contains(r, "add @"+AbusersSet) {
			add = r
		}
	}
	if add == "" {
		t.Fatal("nenhuma regra alimenta a contenção")
	}
	if !strings.HasPrefix(add, `iifname { "wan0" }`) {
		t.Errorf("a regra que contém não é escopada por WAN: %q", add)
	}
}

func TestOLimiteCasaOEXCEDENTE(t *testing.T) {
	// `limit rate over` casa o que EXCEDE; `limit rate` (sem `over`) casa o que
	// CABE na taxa. Trocar um pelo outro conteria exatamente quem se comporta —
	// e é o mesmo tipo de inversão que a #122 documentou do outro lado.
	regras := strings.Join(linhas(abuseRules([]string{"wan0"}, "{ 22 }")), "\n")
	if !strings.Contains(regras, "limit rate over "+abusersRate) {
		t.Errorf("o limite não casa o excedente:\n%s", regras)
	}
}

func TestSemWANOuSemPortaNadaEhEmitido(t *testing.T) {
	// Um set que nada alimenta é enfeite com cara de proteção.
	if r := abuseRules(nil, "{ 22 }"); r != nil {
		t.Errorf("sem WAN emitiu regra: %v", linhas(r))
	}
	if r := abuseRules([]string{"wan0"}, ""); r != nil {
		t.Errorf("sem porta de gerência emitiu regra: %v", linhas(r))
	}
}

func TestPrazoRestanteEhLidoDoNft(t *testing.T) {
	// "ms" é milissegundo, e não minuto: somá-lo como minuto daria um prazo
	// absurdo na tela — 512 minutos onde há meio segundo.
	saida := `table inet linkguard {
	set abusers {
		type ipv4_addr
		flags dynamic,timeout
		timeout 1h
		elements = { 203.0.113.7 expires 59m30s512ms, 198.51.100.4 expires 1h }
	}
}`
	got := parseContidos(saida)
	if len(got) != 2 {
		t.Fatalf("queria 2 contidos, veio %d: %+v", len(got), got)
	}
	if got[0].IP != "203.0.113.7" || got[0].ExpiraEmSeg != 59*60+30 {
		t.Errorf("primeiro contido errado: %+v", got[0])
	}
	if got[1].ExpiraEmSeg != 3600 {
		t.Errorf("segundo contido errado: %+v", got[1])
	}
}

func TestSetVaziaNaoEhErro(t *testing.T) {
	if got := parseContidos("table inet linkguard {\n\tset abusers {\n\t\ttype ipv4_addr\n\t}\n}"); len(got) != 0 {
		t.Errorf("set sem elementos virou %v", got)
	}
}
