package nftables

import "testing"

// ─── ExpressionMatches (shared building block behind C-2's round-trip check
// and I-4's live-rule identity check) ───────────────────────────────────────
//
// Both ask the same question: "does this structured RuleFields really mean
// what this raw nft text says?" buildRuleTokens always appends the literal
// "counter" keyword, which ListUserRules/ListRuleset strip out entirely
// (along with the runtime packet/byte counts) when producing the live text
// this is compared against — so the comparison must normalize the same way
// or every real rule would spuriously "mismatch".

func TestExpressionMatchesIgnoresTheCounterKeyword(t *testing.T) {
	f := RuleFields{Action: "accept", Saddr: "10.0.0.1"}
	live := "ip saddr 10.0.0.1 accept" // what ListUserRules/ListRuleset produce: no "counter" at all
	if !ExpressionMatches(f, live) {
		t.Errorf("expected a faithful round-trip to match despite the counter keyword, fields=%+v live=%q", f, live)
	}
}

func TestExpressionMatchesDetectsADivergentRule(t *testing.T) {
	// The C-2 production example: `ct state established,related counter
	// accept` best-effort-parses into just {Action: accept} — which then
	// renders as "accept everything", not what the live rule actually says.
	f := RuleFields{Action: "accept"}
	live := "ct state established,related accept"
	if ExpressionMatches(f, live) {
		t.Errorf("expected a mismatch: fields=%+v cannot faithfully reproduce live=%q", f, live)
	}
}

func TestExpressionMatchesFullFieldsRoundTrip(t *testing.T) {
	f := RuleFields{Action: "drop", Iif: "eth0", Proto: "tcp", Dport: "22"}
	live := "iifname eth0 tcp dport 22 drop"
	if !ExpressionMatches(f, live) {
		t.Errorf("expected a full field set to round-trip, fields=%+v live=%q", f, live)
	}
}

func TestExpressionMatchesInvalidFieldsNeverMatch(t *testing.T) {
	f := RuleFields{Action: "bogus"}
	if ExpressionMatches(f, "accept") {
		t.Error("expected invalid fields (which don't even build) to never match")
	}
}

// ─── Normalização da forma de saída real do nft ─────────────────────────────
//
// Os fixtures acima são sintéticos: foram escritos a partir do que
// buildRuleTokens emite, e por isso nunca exercitaram a diferença entre o
// que se manda para o nft e o que o nft devolve. Os testes abaixo usam a
// saída **real** do nft (Debian 13), colhida num table inerte de sondagem:
//
//	# comando dado:
//	nft add rule inet lgprobe c iifname enp5s0 ip saddr 10.0.0.1/32 tcp dport 22 counter accept
//	# `nft list table inet lgprobe` devolveu:
//	iifname "enp5s0" ip saddr 10.0.0.1 tcp dport 22 counter packets 0 bytes 0 accept
//
// Duas divergências reais: o nft aspeia o operando de iifname/oifname, e
// remove a máscara cheia de um CIDR de host (/32), canonicalizando os
// demais para o endereço de rede.

func TestExpressionMatchesRealNftOutput(t *testing.T) {
	// Exatamente a linha devolvida pelo nft, com a cláusula de counter
	// runtime já removida por ListUserRules/ListRuleset.
	f := RuleFields{Action: "accept", Iif: "enp5s0", Saddr: "10.0.0.1/32", Proto: "tcp", Dport: "22"}
	live := `iifname "enp5s0" ip saddr 10.0.0.1 tcp dport 22 accept`
	if !ExpressionMatches(f, live) {
		t.Errorf("a saída real do nft tem que casar com os campos que a geraram, fields=%+v live=%q", f, live)
	}
}

func TestExpressionMatchesQuotedInterfaceOperand(t *testing.T) {
	f := RuleFields{Action: "drop", Iif: "eth0", Oif: "eth1"}
	live := `iifname "eth0" oifname "eth1" drop`
	if !ExpressionMatches(f, live) {
		t.Errorf("aspas do nft em iifname/oifname não podem causar mismatch, fields=%+v live=%q", f, live)
	}
}

func TestExpressionMatchesHostMaskDropped(t *testing.T) {
	// /32 na origem e no destino: o nft imprime o IP puro nos dois casos.
	f := RuleFields{Action: "accept", Saddr: "10.0.0.1/32", Daddr: "192.168.1.10/32"}
	live := "ip saddr 10.0.0.1 ip daddr 192.168.1.10 accept"
	if !ExpressionMatches(f, live) {
		t.Errorf("máscara cheia (/32) omitida pelo nft não pode causar mismatch, fields=%+v live=%q", f, live)
	}
}

func TestExpressionMatchesCIDRCanonicalizedToNetworkAddress(t *testing.T) {
	// O admin digita um host dentro da rede; o nft guarda (e imprime) o
	// endereço de rede.
	f := RuleFields{Action: "drop", Saddr: "10.0.0.5/24"}
	live := "ip saddr 10.0.0.0/24 drop"
	if !ExpressionMatches(f, live) {
		t.Errorf("CIDR canonicalizado pelo nft não pode causar mismatch, fields=%+v live=%q", f, live)
	}
}

func TestExpressionMatchesStillDetectsADifferentAddress(t *testing.T) {
	// A normalização não pode virar uma peneira: endereços de fato
	// diferentes continuam sendo mismatch.
	f := RuleFields{Action: "accept", Saddr: "10.0.0.1"}
	if ExpressionMatches(f, "ip saddr 10.0.0.2 accept") {
		t.Error("endereços diferentes têm que continuar dando mismatch")
	}
	if ExpressionMatches(RuleFields{Action: "accept", Saddr: "10.0.0.0/24"}, "ip saddr 10.0.0.0/25 accept") {
		t.Error("prefixos diferentes têm que continuar dando mismatch")
	}
	if ExpressionMatches(RuleFields{Action: "drop", Iif: "eth0"}, `iifname "eth1" drop`) {
		t.Error("interfaces diferentes têm que continuar dando mismatch")
	}
}

// ─── normalizeExpression e o `ct state new` ──────────────────────────────

// normalizeExpression é o único lugar do pacote onde duas formas da mesma
// linha viram comparáveis, e ela é estreita de propósito: só toca nos
// operandos cuja impressão o nft muda. `ct state new` não é um deles — o nft
// o reimprime literal, no mesmo lugar (medido contra o nft v1.1.3) —, então
// os três tokens têm que atravessar intactos, ou o classificador do painel
// deixaria de reconhecer a linha e o grupo restrito apareceria eternamente
// como "configurada, não aplicada".
func TestNormalizeExpressionKeepsCtStateNewIntact(t *testing.T) {
	live := "ip saddr 192.168.50.0/24 ct state new jump grp_aaa"
	if got := normalizeExpression(live); got != live {
		t.Errorf("\n  obtive %q\n  queria %q", got, live)
	}
}

// E o contrapeso, que é o que realmente importa: normalizar NUNCA pode
// apagar o `ct state new` para "fazer casar". Se alguém o tirasse aqui para
// resolver algum desencontro, a linha restrita passaria a comparar igual à
// irrestrita — e o painel diria "aplicada" para um grupo cuja linha viva faz
// outra coisa, que é pior do que dizer "não aplicada".
func TestNormalizeExpressionDoesNotMakeARestrictedLineEqualAnUnrestrictedOne(t *testing.T) {
	restricted := normalizeExpression("ip saddr 192.168.50.0/24 ct state new jump grp_aaa")
	plain := normalizeExpression("ip saddr 192.168.50.0/24 jump grp_aaa")
	if restricted == plain {
		t.Errorf("a linha restrita a conexões novas não pode normalizar igual à irrestrita: %q", restricted)
	}
}
