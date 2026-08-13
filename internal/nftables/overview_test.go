package nftables

import (
	"context"
	"strings"
	"testing"
)

// prodTableFixture is the actual production `table inet linkguard` dump
// (captured verbatim, see the spec for the firewall-page redesign, Phase A
// Part 1) — used as-is here (without `-a`, i.e. no `# handle N` comments) so
// the parser is proven against real data, not a synthetic sample. It
// exercises: an empty chain (user_rules), a mangle/prerouting chain
// (mark_hosts), a forward chain whose rules all carry counters — some zero,
// some not — a nat/postrouting chain and a filter/input chain whose rules
// carry NO counters at all. That is deliberate: only the forward chain was
// hand-created with `counter` in June 2026, so this fixture is exactly what
// proves "counter present" and "counter absent" must be told apart.
const prodTableFixture = `table inet linkguard {
	map host_wan {
		type ipv4_addr : mark
	}

	set blocklist {
		type ipv4_addr
		flags interval
	}

	set blocked_hosts {
		type ipv4_addr
	}

	chain user_rules {
	}

	chain mark_hosts {
		type filter hook prerouting priority mangle; policy accept;
		meta mark set ip saddr map @host_wan
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		jump user_rules
		ip saddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocklist counter packets 11628 bytes 764849 drop
		ip saddr @blocklist counter packets 33 bytes 1980 drop
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname { "enp2s0", "enp5s0" } masquerade
	}

	chain input {
		type filter hook input priority filter; policy accept;
		udp dport 123 ip saddr 192.168.3.0/24 accept
		udp dport 123 drop
	}
}
`

func chainByName(chains []ChainInfo, name string) *ChainInfo {
	for i := range chains {
		if chains[i].Name == name {
			return &chains[i]
		}
	}
	return nil
}

func TestParseTableRulesetFindsAllFiveChainsInOrder(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)
	want := []string{"user_rules", "mark_hosts", "forward", "postrouting", "input"}
	if len(chains) != len(want) {
		t.Fatalf("got %d chains, want %d: %+v", len(chains), len(want), chains)
	}
	for i, name := range want {
		if chains[i].Name != name {
			t.Errorf("chain %d = %q, want %q", i, chains[i].Name, name)
		}
	}
}

func TestParseTableRulesetSkipsMapsAndSets(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)
	for _, c := range chains {
		if c.Name == "host_wan" || c.Name == "blocklist" || c.Name == "blocked_hosts" {
			t.Errorf("map/set %q must not be reported as a chain", c.Name)
		}
	}
}

func TestParseTableRulesetEmptyChainHasNoRulesAndNonNilSlice(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)
	ur := chainByName(chains, "user_rules")
	if ur == nil {
		t.Fatal("user_rules chain not found")
	}
	if ur.Rules == nil {
		t.Error("Rules must be a non-nil empty slice, not nil (breaks JSON .map() on the frontend)")
	}
	if len(ur.Rules) != 0 {
		t.Errorf("expected 0 rules in user_rules, got %d", len(ur.Rules))
	}
}

func TestParseTableRulesetChainProperties(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)

	cases := []struct {
		name, typ, hook, priority, policy string
	}{
		{"mark_hosts", "filter", "prerouting", "mangle", "accept"},
		{"forward", "filter", "forward", "filter", "accept"},
		{"postrouting", "nat", "postrouting", "srcnat", "accept"},
		{"input", "filter", "input", "filter", "accept"},
	}
	for _, c := range cases {
		ci := chainByName(chains, c.name)
		if ci == nil {
			t.Fatalf("chain %q not found", c.name)
		}
		if ci.Type != c.typ || ci.Hook != c.hook || ci.Priority != c.priority || ci.Policy != c.policy {
			t.Errorf("chain %q = %+v, want type=%s hook=%s priority=%s policy=%s", c.name, ci, c.typ, c.hook, c.priority, c.policy)
		}
	}

	// user_rules has no `type ... hook ...` line at all (it's not a base
	// chain, only jumped into) — those fields must stay empty, not garbage.
	ur := chainByName(chains, "user_rules")
	if ur.Type != "" || ur.Hook != "" || ur.Priority != "" || ur.Policy != "" {
		t.Errorf("user_rules must have empty hook properties, got %+v", ur)
	}
}

func TestParseTableRulesetCountersPresentOnForwardChain(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)
	fwd := chainByName(chains, "forward")
	if fwd == nil {
		t.Fatal("forward chain not found")
	}
	// jump user_rules has no counter; the four drop rules that follow do.
	if len(fwd.Rules) != 5 {
		t.Fatalf("expected 5 rules in forward, got %d: %+v", len(fwd.Rules), fwd.Rules)
	}
	if fwd.Rules[0].HasCounter {
		t.Errorf("jump user_rules must not report a counter: %+v", fwd.Rules[0])
	}
	want := []struct {
		packets, bytes uint64
	}{
		{0, 0},
		{0, 0},
		{11628, 764849},
		{33, 1980},
	}
	for i, w := range want {
		r := fwd.Rules[i+1]
		if !r.HasCounter {
			t.Errorf("rule %d must report HasCounter=true, got false: %+v", i+1, r)
		}
		if r.Packets != w.packets || r.Bytes != w.bytes {
			t.Errorf("rule %d counters = %d/%d, want %d/%d", i+1, r.Packets, r.Bytes, w.packets, w.bytes)
		}
	}
}

// TestParseTableRulesetCountersAbsentAreNotZero is the central regression
// test for the "not measured != measured zero" rule: mark_hosts, postrouting
// and input rules were never created with `counter` in production, and must
// report HasCounter=false — not HasCounter=true with Packets=0.
func TestParseTableRulesetCountersAbsentAreNotZero(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)
	for _, name := range []string{"mark_hosts", "postrouting", "input"} {
		c := chainByName(chains, name)
		if c == nil {
			t.Fatalf("chain %q not found", name)
		}
		for _, r := range c.Rules {
			if r.HasCounter {
				t.Errorf("chain %q rule %q must report HasCounter=false (no counter in source), got true with %d/%d", name, r.Expression, r.Packets, r.Bytes)
			}
			if r.Packets != 0 || r.Bytes != 0 {
				t.Errorf("chain %q rule %q: Packets/Bytes must stay zero-valued when absent, got %d/%d", name, r.Expression, r.Packets, r.Bytes)
			}
		}
	}
}

func TestParseTableRulesetExpressionsAreCleanedOfCounterAndHandle(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)
	fwd := chainByName(chains, "forward")
	for _, r := range fwd.Rules {
		if strings.Contains(r.Expression, "counter") {
			t.Errorf("expression must not contain the counter clause: %q", r.Expression)
		}
		if strings.Contains(r.Expression, "handle") {
			t.Errorf("expression must not contain a handle comment: %q", r.Expression)
		}
	}
	want := "ip daddr @blocklist drop"
	found := false
	for _, r := range fwd.Rules {
		if r.Expression == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a cleaned expression %q among forward rules: %+v", want, fwd.Rules)
	}
}

func TestParseTableRulesetEveryRuleCarriesItsChainName(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)
	for _, c := range chains {
		for _, r := range c.Rules {
			if r.Chain != c.Name {
				t.Errorf("rule %+v has Chain=%q, want %q", r, r.Chain, c.Name)
			}
		}
	}
}

// TestParseTableRulesetHandlesFromDashA proves the parser accounts for the
// `-a` flag's trailing `# handle N` on each rule line (the fixture above,
// like the spec's captured sample, is from a plain `nft list ruleset`
// without -a — production callers always use `-a`, see ListRuleset).
func TestParseTableRulesetHandlesFromDashA(t *testing.T) {
	fixture := `table inet linkguard {
	chain input {
		type filter hook input priority filter; policy accept;
		udp dport 123 ip saddr 192.168.3.0/24 accept # handle 14
		udp dport 123 drop # handle 15
	}
}
`
	chains := parseTableRuleset(fixture)
	in := chainByName(chains, "input")
	if in == nil {
		t.Fatal("input chain not found")
	}
	if len(in.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(in.Rules))
	}
	if in.Rules[0].Handle != 14 {
		t.Errorf("rule 0 handle = %d, want 14", in.Rules[0].Handle)
	}
	if in.Rules[1].Handle != 15 {
		t.Errorf("rule 1 handle = %d, want 15", in.Rules[1].Handle)
	}
	if strings.Contains(in.Rules[0].Expression, "handle") {
		t.Errorf("handle comment leaked into expression: %q", in.Rules[0].Expression)
	}
	wantExpr := "udp dport 123 ip saddr 192.168.3.0/24 accept"
	if in.Rules[0].Expression != wantExpr {
		t.Errorf("expression = %q, want %q", in.Rules[0].Expression, wantExpr)
	}
}

func TestParseTableRulesetHandlesWithCountersTogether(t *testing.T) {
	fixture := `table inet linkguard {
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip daddr @blocklist counter packets 11628 bytes 764849 drop # handle 9
	}
}
`
	chains := parseTableRuleset(fixture)
	fwd := chainByName(chains, "forward")
	if len(fwd.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(fwd.Rules))
	}
	r := fwd.Rules[0]
	if r.Handle != 9 {
		t.Errorf("handle = %d, want 9", r.Handle)
	}
	if !r.HasCounter || r.Packets != 11628 || r.Bytes != 764849 {
		t.Errorf("counters not parsed correctly: %+v", r)
	}
	if r.Expression != "ip daddr @blocklist drop" {
		t.Errorf("expression = %q, want %q", r.Expression, "ip daddr @blocklist drop")
	}
}

// TestListRulesetUsesDashAAndTheOwnedTable is a thin integration check that
// ListRuleset invokes exactly the read-only command this whole feature is
// specified against, and returns what the fake gives it back, parsed.
func TestListRulesetUsesDashAAndTheOwnedTable(t *testing.T) {
	exec := &fakeReadExec{out: prodTableFixture}
	s := &Service{exec: exec}

	chains, err := s.ListRuleset(context.Background())
	if err != nil {
		t.Fatalf("ListRuleset: %v", err)
	}
	if len(chains) != 5 {
		t.Fatalf("expected 5 chains, got %d", len(chains))
	}
	wantCmd := "nft -a list table inet linkguard"
	if exec.gotCmd != wantCmd {
		t.Errorf("ListRuleset ran %q, want %q", exec.gotCmd, wantCmd)
	}
}

// fakeReadExec is a minimal firewall.Executor whose ExecuteRead returns a
// fixed string and records the exact command line issued — enough to prove
// ListRuleset never mutates state (Execute must never be called) and uses
// the right nft invocation.
type fakeReadExec struct {
	out    string
	gotCmd string
}

func (e *fakeReadExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	panic("ListRuleset must be read-only: Execute must never be called, got " + cmd)
}
func (e *fakeReadExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	e.gotCmd = strings.Join(append([]string{cmd}, args...), " ")
	return e.out, nil
}
func (e *fakeReadExec) IsDryRun() bool { return false }

// ─── Correções da revisão da Fase C2 ─────────────────────────────────────

// M-2. prodTableFixture acima é uma captura REAL de produção, e por isso
// continua como está: é o que uma máquina que ainda não reconciliou com esta
// versão tem vivo na chain input. Mas deixou de ser o que este código EMITE —
// as duas linhas de NTP passaram a carregar `counter`, que o nft imprime de
// volta como `counter packets N bytes M` antes do verbo, e com o `-a` da
// produção ainda vem o `# handle N` no fim. Fixture que não é mais a saída do
// que geramos não prova nada sobre a próxima linha que vamos gerar.
func TestParseTableRulesetReadsTheNTPLinesInTheCounterFormWeNowEmit(t *testing.T) {
	fixture := `table inet linkguard {
	chain input {
		type filter hook input priority filter; policy accept;
		udp dport 123 ip saddr { 10.20.0.0/24, 192.168.3.0/24 } counter packets 5 bytes 380 accept # handle 14
		udp dport 123 counter packets 2 bytes 152 drop # handle 15
		ip saddr 192.168.50.0/24 counter packets 0 bytes 0 jump grp_a3f21c08 # handle 16
	}
}
`
	in := chainByName(parseTableRuleset(fixture), "input")
	if in == nil {
		t.Fatal("input chain not found")
	}
	if len(in.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d: %+v", len(in.Rules), in.Rules)
	}

	accept := in.Rules[0]
	if accept.Handle != 14 || !accept.HasCounter || accept.Packets != 5 || accept.Bytes != 380 {
		t.Errorf("handle/contador da linha de accept não foram lidos: %+v", accept)
	}
	if accept.Expression != "udp dport 123 ip saddr { 10.20.0.0/24, 192.168.3.0/24 } accept" {
		t.Errorf("a cláusula counter vazou para a expressão: %q", accept.Expression)
	}
	if accept.Owner.Key != "ntp" || accept.Description != "Aceita NTP vindo de 10.20.0.0/24, 192.168.3.0/24" {
		t.Errorf("linha de accept do NTP mal classificada/descrita: %+v", accept)
	}

	drop := in.Rules[1]
	if drop.Handle != 15 || !drop.HasCounter || drop.Packets != 2 || drop.Bytes != 152 {
		t.Errorf("handle/contador da linha de drop não foram lidos: %+v", drop)
	}
	if drop.Owner.Key != "ntp" || drop.Description != "Bloqueia NTP de qualquer outra origem" {
		t.Errorf("linha de drop do NTP mal classificada/descrita: %+v", drop)
	}

	// E o jump de um grupo de escopo input, que a Fase C2 pôs nesta mesma
	// chain, tem o dono dele — não o rótulo genérico.
	jump := in.Rules[2]
	if jump.Owner.Key != "rule_groups" {
		t.Errorf("o jump do grupo na input não tem dono: %+v", jump)
	}
}
