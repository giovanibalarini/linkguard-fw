package nftables

import "testing"

// O descritor estruturado (issue #109).
//
// A propriedade que mais importa: para TODA linha que o produto sabe descrever
// em português, o descritor também tem chave. Se um dos dois souber e o outro
// não, a Visão geral fica meio traduzida — e só em inglês, que é onde menos
// gente olha.

func TestDescritorCobreOMesmoQueAFrase(t *testing.T) {
	casos := []struct{ chain, expr string }{
		{masqueradeChain, `oifname { "enp2s0", "enp5s0" } masquerade`},
		{InputChain, "ct state related counter accept"},
		{InputChain, "udp dport 123 ip saddr { 192.168.3.0/24 } counter accept"},
		{InputChain, "udp dport 123 counter drop"},
		{ForwardChain, "jump user_rules"},
		{ForwardChain, "ip saddr @blocked_hosts counter drop"},
		{ForwardChain, "ip daddr @blocked_hosts counter drop"},
		{ForwardChain, "ip saddr @blocklist counter drop"},
		{ForwardChain, "ip daddr @blocklist counter drop"},
		{MarkHostsChain, "meta mark set ip saddr map @host_wan"},
		{DNATChain, "iifname enp3s0 tcp dport 8080 dnat ip to 192.168.1.5:80"},
	}
	for _, c := range casos {
		frase := describeRule(c.chain, c.expr)
		d := descStructured(c.chain, c.expr, true)
		// "sabe descrever" = a frase não é a expressão crua devolvida no fallback.
		sabe := frase != c.expr
		if sabe && d.Key == "" {
			t.Errorf("chain %s, %q: a frase descreve (%q) mas o descritor não tem chave.\n"+
				"A Visão geral ficaria em português nesta linha mesmo com o painel em inglês.",
				c.chain, c.expr, frase)
		}
		if !sabe && d.Key != "" {
			t.Errorf("chain %s, %q: o descritor promete %q mas a frase caiu no fallback",
				c.chain, c.expr, d.Key)
		}
	}
}

// TestDescritorDNATCarregaOsValores: os valores não se traduzem, mas precisam
// chegar — uma frase "Encaminha {proto}/{porta}" sem as variáveis viraria
// literalmente isso na tela.
func TestDescritorDNATCarregaOsValores(t *testing.T) {
	d := descStructured(DNATChain, "iifname enp3s0 tcp dport 8080 dnat ip to 192.168.1.5:80", true)
	if d.Key != "desc.dnat" {
		t.Fatalf("chave = %q", d.Key)
	}
	for k, want := range map[string]string{"proto": "TCP", "porta": "8080", "destino": "192.168.1.5:80"} {
		if d.Vars[k] != want {
			t.Errorf("var %s = %q, queria %q", k, d.Vars[k], want)
		}
	}
}

// TestDescritorDeRegraDoAdminNaoColaPedacos: a condição vai inteira numa
// variável, e a frase mora no dicionário. Colar "origem X" + "destino Y"
// traduzidos produziria inglês de robô, porque a ordem das palavras muda.
func TestDescritorDeRegraDoAdminNaoColaPedacos(t *testing.T) {
	d := userRuleDesc("ip saddr 10.0.0.0/8 tcp dport 22 drop")
	if d.Key != "desc.user.drop" {
		t.Errorf("chave = %q, queria desc.user.drop", d.Key)
	}
	if d.Vars["cond"] == "" {
		t.Fatal("a condição não chegou ao descritor")
	}
	// Regra sem condição nenhuma tem chave própria: "Bloqueia qualquer tráfego"
	// não é "Bloqueia " + vazio.
	if k := userRuleDesc("drop").Key; k != "desc.user.drop.any" {
		t.Errorf("regra sem condição = %q, queria desc.user.drop.any", k)
	}
}

// TestDescritorNaoInventa: expressão desconhecida devolve chave vazia, e a tela
// cai na expressão crua — honesto em vez de um palpite errado, que é a mesma
// disciplina que describeRule já segue.
func TestDescritorNaoInventa(t *testing.T) {
	if d := descStructured(ForwardChain, "meta l4proto 132 counter accept", true); d.Key != "" {
		t.Errorf("inventou %q para uma expressão que não conhece", d.Key)
	}
}
