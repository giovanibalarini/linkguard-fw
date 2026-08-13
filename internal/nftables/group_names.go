package nftables

import (
	"fmt"
	"strings"
)

// ApplyGroupNames rewrites, in place, the Description of every rule that jumps
// into a rule-group chain (GroupChainPrefix, "grp_") so it names the group and
// states when it is evaluated, instead of the generic text describeRule falls
// back to for a chain it doesn't specifically recognise.
//
// As duas chains que hospedam esses jumps são varridas — a forward e, desde a
// Fase C2, a input (ver GroupHostChain). São a mesma linha, renderizada pelo
// mesmo código a partir da condição de entrada do grupo, e o admin não tem por
// que ler uma delas em português e a outra em sintaxe nft crua.
//
// This is deliberately a separate post-processing pass over already-parsed
// chains, not a parameter threaded through describeRule (and, from there,
// parseChainRuleLine → parseTableRuleset → ListRuleset up to the handler).
// describeRule is a pure function of (chain, expression) with exactly one
// production caller, parseChainRuleLine — but that caller is also
// parseTableRuleset's, which reconciliation's orphan-chain cleanup uses too,
// and cleanup has no group name to give it. Growing three signatures for a
// need only one of their callers has would be worse than this: one small,
// independently testable function the Overview handler applies to its own
// result, right before responding.
//
// groupNames maps a group's chain name (StoredGroup.ChainName /
// storage.FirewallGroup.ChainName, e.g. "grp_a3f21c08") to the admin-given
// name — built by the caller from db.ListFirewallGroups(). A target chain
// with no entry in groupNames means the group was deleted between the DB
// read and the nft read that produced chains: ApplyGroupNames falls back to
// the raw chain name rather than inventing one or leaving the description
// blank (the project's no-fake-data rule applies to this panel above all).
func ApplyGroupNames(chains []ChainInfo, groupNames map[string]string) {
	for i := range chains {
		if chains[i].Name != ForwardChain && chains[i].Name != InputChain {
			continue
		}
		for j := range chains[i].Rules {
			rewriteGroupJumpDescription(&chains[i].Rules[j], groupNames)
		}
	}
}

// newOnlySuffix é como a Visão geral diz, em português, o que `ct state new`
// faz com a linha. O parêntese não é enfeite: sem ele "só para conexões
// novas" ainda deixa em aberto o que acontece com o que já está de pé, que é
// exatamente a dúvida que trouxe esta feature.
const newOnlySuffix = "só para conexões novas (o que já está estabelecido segue sem passar por ele)"

func rewriteGroupJumpDescription(rule *ChainRule, groupNames map[string]string) {
	// Same convention MergeGroups already uses to find a jump's target in a
	// parsed expression (merge_groups.go): the last "jump " in the line,
	// whatever comes after it. Matching it here — rather than reinventing a
	// similar-but-different lookup — is deliberate: the two must never
	// disagree about which chain a forward-chain jump line targets.
	idx := strings.LastIndex(rule.Expression, "jump ")
	if idx < 0 {
		return
	}
	target := strings.TrimSpace(rule.Expression[idx+len("jump "):])
	if !strings.HasPrefix(target, GroupChainPrefix) {
		return // some other jump (e.g. "jump user_rules") — not ours to rename
	}

	name, ok := groupNames[target]
	if !ok {
		// Grupo apagado entre a leitura do banco e a do nft: a chain crua é a
		// única coisa honesta a mostrar — nunca um nome inventado, nunca vazio.
		name = target
	}

	// Everything before "jump ..." is the entry condition. In production this
	// expression already had its counter clause stripped whole by
	// parseChainRuleLine (reCounterCapture matches "counter packets N bytes
	// M"), so the bare word "counter" should never actually reach here — but
	// TrimSuffix defensively drops it if it does, rather than let it leak
	// into the condition text shown to the admin.
	cond := strings.TrimSpace(rule.Expression[:idx])
	cond = strings.TrimSpace(strings.TrimSuffix(cond, "counter"))

	// E, logo antes do counter, o `ct state new` de um grupo restrito a
	// conexões novas (groupJumpTokens, ctStateNewExpr). Ele sai da condição e
	// vira PROSA: a descrição desta tela é o texto que explica a linha a quem
	// não lê nftables, e a sintaxe crua já está ali do lado, na coluna da
	// expressão. Deixá-lo dentro do "quando ..." produzia
	// `quando ip saddr 192.168.50.0/24 ct state new` — meia frase em
	// português, meia em nft — e, no grupo sem condição nenhuma, o pior dos
	// dois: `quando ct state new`.
	var newOnly bool
	if trimmed, ok := strings.CutSuffix(cond, ctStateNewExpr); ok {
		newOnly = true
		cond = strings.TrimSpace(trimmed)
	}

	switch {
	case cond == "" && newOnly:
		// Sem condição de entrada, mas NÃO "vale para todo o tráfego que
		// chegar ali": o que já está estabelecido passa reto sem ser
		// avaliado. Dizer o texto do caso irrestrito aqui seria afirmar uma
		// proteção mais larga do que a linha faz.
		//
		// O travessão é o conector que faltava: sem ele a frase saía emendada
		// (`Avalia o grupo "Acesso ao firewall" só para conexões novas`), lida
		// como se algo tivesse sido cortado no meio — e é texto que o operador
		// lê na Visão geral.
		rule.Description = fmt.Sprintf("Avalia o grupo %q — %s", name, newOnlySuffix)
	case cond == "":
		rule.Description = fmt.Sprintf("Avalia o grupo %q (sem condição: vale para todo o tráfego que chegar ali)", name)
	case newOnly:
		rule.Description = fmt.Sprintf("Avalia o grupo %q quando %s, e %s", name, cond, newOnlySuffix)
	default:
		rule.Description = fmt.Sprintf("Avalia o grupo %q quando %s", name, cond)
	}
}
