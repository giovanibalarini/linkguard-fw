package nftables

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A proteção de entrada das WANs (#119, fase 1).
//
// O primeiro teste é o que mais importa, e ele afirma uma NÃO-MUDANÇA: sem WAN
// conhecida, a chain é byte a byte a de antes. Toda instalação nova nasce assim.

func TestSemWANConhecidaNadaEhEmitido(t *testing.T) {
	if r := WANInputRules(nil); r != nil {
		t.Errorf("lista vazia gerou regras: %v", linhas(r))
	}
	if r := WANInputRules([]string{"", ""}); r != nil {
		t.Errorf("só nomes vazios geraram regras: %v", linhas(r))
	}

	// E a chain inteira continua a de sempre.
	got := linhas(inputChainRules(nil, nil, false, PolicyAccept, AdminAccess{}, nil))
	querida := []string{"ct state related counter accept"}
	if len(got) != 1 || got[0] != querida[0] {
		t.Errorf("a chain input mudou para quem não tem WAN cadastrada:\n  veio     %v\n  esperada %v", got, querida)
	}
}

func TestODescarteCasaSomenteConexaoNova(t *testing.T) {
	// A REGRESSÃO QUE ESTE TESTE PRENDE. Se o descarte deixar de casar
	// `ct state new`, ele passa a pegar o RETORNO das conexões que a própria
	// caixa abriu — e o apt, o atualizador, a recursão do unbound e o chrony
	// morrem todos de uma vez, sem nada no ruleset dizendo por quê. É
	// exatamente o problema que trava a issue #78, e a razão de esta entrega
	// não precisar resolvê-lo.
	regras := linhas(WANInputRules([]string{"wan0"}))
	drop := regras[len(regras)-1]
	if !strings.Contains(drop, "ct state new") {
		t.Fatalf("o descarte não está limitado a conexão nova: %q", drop)
	}
	if strings.Contains(drop, "established") {
		t.Errorf("o descarte encosta em conexão estabelecida: %q", drop)
	}
	if !strings.HasPrefix(drop, `iifname { "wan0" }`) {
		t.Errorf("o descarte não está escopado pela WAN: %q", drop)
	}
}

func TestOAdminNaoPodeSerTrancadoForaPelaLAN(t *testing.T) {
	// Nenhuma regra desta lista pode casar tráfego que não venha de uma WAN.
	// É esta propriedade — e não um teste de 90 segundos — que torna seguro
	// ligar a proteção sem o admin pedir.
	for _, r := range linhas(WANInputRules([]string{"wan0", "wan1"})) {
		if !strings.HasPrefix(r, "iifname {") {
			t.Errorf("regra sem escopo de interface, alcança a LAN: %q", r)
		}
	}
}

func TestLiberacoesQueEvitamQuebraDiasDepois(t *testing.T) {
	regras := strings.Join(linhas(WANInputRules([]string{"wan0"})), "\n")
	obrigatorias := map[string]string{
		"nd-router-advert":   "sem RA a rota padrão IPv6 expira e o IPv6 morre ~30min depois do deploy",
		"nd-neighbor-advert": "sem vizinhança IPv6 nada de IPv6 funciona",
		"udp dport 68":       "sem isto a WAN por DHCP não renova depois de um flap",
		"udp dport 546":      "sem isto o dia de ligar delegação de prefixo vira o dia de descobrir que o firewall bloqueia",
		"packet-too-big":     "sem isto o PMTUD do IPv6 trava páginas grandes no meio",
		"ct status dnat":     "sem isto encaminhamento de porta para a própria máquina morre",
	}
	for token, porque := range obrigatorias {
		if !strings.Contains(regras, token) {
			t.Errorf("falta a liberação %q: %s", token, porque)
		}
	}
}

func TestODescarteVemDepoisDeTudo(t *testing.T) {
	// A ORDEM É A DECISÃO. O descarte tem de ser a ÚLTIMA linha da chain:
	// depois dos jumps dos grupos, para que um grupo de escopo input que libere
	// algo vindo da WAN seja avaliado antes. Emiti-lo acima anularia em
	// silêncio uma decisão explícita do admin.
	g := StoredGroup{ID: "g1", Name: "libera", ChainName: "grp_libera", Enabled: true, Position: 1, Scope: ScopeInput}
	regras := linhas(inputChainRules([]StoredGroup{g}, nil, false, PolicyAccept, AdminAccess{}, []string{"wan0"}))

	ultima := regras[len(regras)-1]
	if !strings.Contains(ultima, "ct state new counter drop") {
		t.Fatalf("a última linha não é o descarte: %q\ntodas:\n%s", ultima, strings.Join(regras, "\n"))
	}
	iJump, iDrop := -1, len(regras)-1
	for i, r := range regras {
		if strings.Contains(r, "grp_libera") {
			iJump = i
		}
	}
	if iJump < 0 {
		t.Fatalf("o jump do grupo sumiu da chain:\n%s", strings.Join(regras, "\n"))
	}
	if iJump > iDrop {
		t.Errorf("o jump do grupo (%d) ficou DEPOIS do descarte (%d): o admin perdeu a decisão dele", iJump, iDrop)
	}
}

func TestNomeDeInterfaceInseguroEhIgnorado(t *testing.T) {
	// O nome sai do banco e é interpolado no argv do nft.
	regras := linhas(WANInputRules([]string{"wan0; drop", "wan1"}))
	junto := strings.Join(regras, "\n")
	if strings.Contains(junto, "drop; ") || strings.Contains(junto, "wan0") {
		t.Errorf("nome inseguro chegou ao ruleset:\n%s", junto)
	}
	if !strings.Contains(junto, `"wan1"`) {
		t.Errorf("a interface boa foi perdida junto com a ruim:\n%s", junto)
	}
	// Só nomes ruins não pode virar uma chain sem proteção NEM uma regra torta:
	// vira lista vazia, e o log já registrou o motivo.
	if r := WANInputRules([]string{"wan0; drop"}); r != nil {
		t.Errorf("nome inseguro sozinho gerou regra: %v", linhas(r))
	}
}

func TestInterfaceRepetidaNaoViraRegraRepetida(t *testing.T) {
	regras := linhas(WANInputRules([]string{"wan0", "wan0"}))
	if n := strings.Count(regras[0], `"wan0"`); n != 1 {
		t.Errorf("a interface aparece %d vezes no set: %q", n, regras[0])
	}
}

func TestErroAoLerAsWANsAbortaSemTocarNaChain(t *testing.T) {
	// UM SELECT QUE FALHOU NÃO É "esta máquina não tem WAN". Obedecer a essa
	// lista vazia apagaria a proteção de uma caixa que a tem, e o painel
	// continuaria dizendo que ela está protegida. Mesmo contrato dos grupos.
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetWANInterfacesSource(func() ([]string, error) { return nil, errors.New("banco fora") })

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err == nil {
		t.Fatal("a reconciliação seguiu adiante com a leitura das WANs falhando")
	}
	for _, c := range e.comandos {
		if linha := strings.Join(c, " "); strings.Contains(linha, InputChain) {
			t.Errorf("a chain foi tocada mesmo com a leitura falhando: %q", linha)
		}
	}
}

func TestFonteLigadaEmiteAProtecao(t *testing.T) {
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetWANInterfacesSource(func() ([]string, error) { return []string{"wan0"}, nil })

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err != nil {
		t.Fatalf("reconcileInputChain: %v", err)
	}
	var achou bool
	for _, c := range e.comandos {
		if strings.Contains(strings.Join(c, " "), "ct state new counter drop") {
			achou = true
		}
	}
	if !achou {
		t.Errorf("a proteção não chegou ao nft; comandos: %v", e.comandos)
	}
}
