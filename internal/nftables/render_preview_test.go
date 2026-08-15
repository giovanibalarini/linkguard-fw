package nftables

import (
	"strings"
	"testing"
)

// A garantia que esta função existe para dar: o que a tela mostra é, palavra
// por palavra, o que a chain recebe. Enquanto o preview era remontado em
// TypeScript, nada verificava isso — e a divergência seria assintomática.
func TestRenderRuleIsExactlyWhatGoesToTheChain(t *testing.T) {
	casos := []RuleFields{
		{Action: "accept", Iif: "enp0s3", Proto: "tcp", Dport: "22"},
		{Action: "drop", Saddr: "10.0.0.0/8", Daddr: "192.168.1.10"},
		{Action: "reject", Oif: "enp0s4", Proto: "udp", Dport: "53"},
		{Action: "accept", Proto: "icmp"},
		{Action: "accept", Iif: "enp0s3", Oif: "enp0s4", Saddr: "10.0.0.0/8",
			Daddr: "192.168.1.0/24", Proto: "tcp", Dport: "443"},
	}
	for _, f := range casos {
		tokens, err := buildRuleTokens(f)
		if err != nil {
			t.Fatalf("buildRuleTokens(%+v): %v", f, err)
		}
		rendered, err := RenderRule(f)
		if err != nil {
			t.Fatalf("RenderRule(%+v): %v", f, err)
		}
		if want := strings.Join(tokens, " "); rendered != want {
			t.Errorf("preview divergiu da linha real:\n  preview: %q\n  real:    %q", rendered, want)
		}
	}
}

// O `counter` precisa estar no preview. expressionTokens o remove de propósito
// — ela existe para COMPARAR com a saída viva do nft, que traz "counter packets
// N bytes M". Usar aquela função no preview mostraria ao operador uma linha
// diferente da que o kernel recebe.
func TestRenderRuleKeepsTheCounterThatExpressionTokensStrips(t *testing.T) {
	f := RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}

	rendered, err := RenderRule(f)
	if err != nil {
		t.Fatalf("RenderRule: %v", err)
	}
	if !strings.Contains(rendered, "counter") {
		t.Errorf("o preview perdeu o counter: %q", rendered)
	}

	expr, err := expressionTokens(f)
	if err != nil {
		t.Fatalf("expressionTokens: %v", err)
	}
	if strings.Contains(expr, "counter") {
		t.Error("expressionTokens deixou de remover o counter; RenderRule e ela não são mais distinguíveis, e o preview pode acabar usando a errada")
	}
}

func TestRenderGroupJumpIsExactlyTheJumpLine(t *testing.T) {
	casos := []StoredGroup{
		{ChainName: "grp_abc", CondIif: "enp0s3"},
		{ChainName: "grp_def", CondSaddr: "10.0.0.0/8", ConnState: ConnStateNew},
		{ChainName: "grp_ghi", CondDaddr: "192.168.1.10", Scope: ScopeInput},
		{ChainName: "grp_jkl"},
	}
	for _, g := range casos {
		tokens, err := groupJumpTokens(g)
		if err != nil {
			t.Fatalf("groupJumpTokens(%+v): %v", g, err)
		}
		rendered, err := RenderGroupJump(g)
		if err != nil {
			t.Fatalf("RenderGroupJump(%+v): %v", g, err)
		}
		if want := strings.Join(tokens, " "); rendered != want {
			t.Errorf("preview do jump divergiu:\n  preview: %q\n  real:    %q", rendered, want)
		}
	}
}
