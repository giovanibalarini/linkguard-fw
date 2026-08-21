package nftables

import (
	"context"
	"strings"
	"testing"
)

// ─── ReconcileStructuralChains (forward, mark_hosts) ─────────────────────
//
// Regression coverage for §1/§6 of the design spec: forward and mark_hosts
// were, until now, only ever created once at EnsureTable/bootstrap and
// never reconciled — the exact gap that let a double-load of the ruleset
// (2026-08-10 incident) leave every rule in both chains permanently
// duplicated, because nothing ever flushed and rewrote them again. These
// tests mirror TestReconcileMasquerade*'s safety properties exactly.

// Era TestReconcileStructuralChainsFlushesForwardBeforeAdding. Mudança
// INTENCIONAL de comportamento (grupos de regras, Fase C1): a forward saiu
// desta função e passou a ser reconstruída por ReconcileGroups, a única que
// conhece os grupos do admin. Se as duas continuassem reconciliando a mesma
// chain, a última a rodar apagaria os jumps escritos pela outra — e é por
// isso que a expectativa aqui virou o oposto: esta função não pode mais
// encostar na forward.
func TestReconcileStructuralChainsLeavesTheForwardToReconcileGroups(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, ForwardChain) {
			t.Errorf("esta função não pode mais mexer na forward (quem reconstrói é ReconcileGroups): %q", c)
		}
	}
}

func TestReconcileStructuralChainsFlushesMarkHostsBeforeAdding(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}

	wantFlush := "nft flush chain inet linkguard mark_hosts"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("missing %q; ran: %v", wantFlush, exec.executed)
	}
	flushIdx, addIdx := -1, -1
	for i, c := range exec.executed {
		if c == wantFlush {
			flushIdx = i
		}
		if strings.HasPrefix(c, "nft add rule inet linkguard mark_hosts") {
			addIdx = i
		}
	}
	if flushIdx == -1 || addIdx == -1 || flushIdx > addIdx {
		t.Errorf("mark_hosts chain must be flushed before its rule is added; ran: %v", exec.executed)
	}
}

// TestReconcileStructuralChainsNeverFlushesTheWholeTable guards every other
// piece of live state in the table: host_wan, blocklist, blocked_hosts,
// user_rules, postrouting, input, prerouting_dnat.
func TestReconcileStructuralChainsNeverFlushesTheWholeTable(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush table") || strings.Contains(c, "flush ruleset") {
			t.Errorf("must never flush the table/ruleset, ran: %q", c)
		}
		if strings.Contains(c, "flush chain") && !strings.Contains(c, "mark_hosts") {
			t.Errorf("must only ever flush mark_hosts, ran: %q", c)
		}
	}
}

func TestReconcileStructuralChainsIsIdempotent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	exec.executed = nil
	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first) != len(exec.executed) {
		t.Errorf("second run issued a different command set:\nfirst=%v\nsecond=%v", first, exec.executed)
	}
	for i := range first {
		if first[i] != exec.executed[i] {
			t.Errorf("command %d differs between runs:\nfirst=%q\nsecond=%q", i, first[i], exec.executed[i])
		}
	}
}

func TestReconcileStructuralChainsNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains in dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands in dry-run, ran: %v", exec.executed)
	}
}

// TestReconcileStructuralChainsEveryRuleCarriesCounter is the regression
// test for the spec's explicit caution (§6): production's forward-chain
// drop rules were hand-created in June 2026 WITH `counter`, and reconciling
// to a counter-less definition would silently reset that data to zero on
// every boot. Every `add rule` this reconcile issues must include `counter`.
// Desde a Fase C1 sobrou só a regra do mark_hosts aqui — a cobertura das
// linhas da forward mudou de casa junto com a chain, para
// TestForwardChainEveryRuleCarriesCounter.
func TestReconcileStructuralChainsEveryRuleCarriesCounter(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}
	found := 0
	for _, c := range exec.executed {
		if !strings.HasPrefix(c, "nft add rule") {
			continue
		}
		found++
		if !strings.Contains(c, "counter") {
			t.Errorf("rule was added without a counter: %q", c)
		}
	}
	if found != 1 {
		t.Errorf("expected 1 add-rule command (mark_hosts; a forward é do ReconcileGroups), got %d: %v", found, exec.executed)
	}
}

// Era TestReconcileStructuralChainsForwardRuleOrder, que assertava a ordem
// ANTIGA: `jump user_rules` primeiro e os bloqueios depois. A intenção
// continua a mesma — o nft avalia de cima para baixo, então a ordem desta
// chain é comportamento observável e precisa de teste —, mas a expectativa
// está invertida de propósito (design spec §3): bloqueio administrativo é
// avaliado antes dos grupos e sempre vence, porque "bloquear host em 1
// clique" que perde para uma regra criada meses antes é um bloqueio que
// mente. E a forward deixou de alcançar user_rules: as regras do admin
// passaram a morar dentro de grupos.
//
// ATUALIZADO (a forward virou uma lista ordenada só): os quatro bloqueios
// deixaram de ser literais em código e passaram a ser dois itens da lista,
// então a lista deste teste é a que a produção tem depois da migração — os
// dois grupos do sistema nas posições 0 e 1, o grupo do admin depois. A
// asserção não mudou: bloqueio antes do jump.
func TestForwardChainNoLongerLetsUserRulesShadowTheBlocks(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	wireNoInputExtras(s)
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Position: 0, Fallthrough: FallthroughContinue},
		{ID: "l", Name: "Destinos bloqueados", ChainName: SystemChainBlocklist,
			Kind: GroupKindBlocklist, Enabled: true, Position: 1, Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Minhas regras", ChainName: "grp_aaa", Kind: GroupKindAdmin,
			Enabled: true, Position: 2, Fallthrough: FallthroughContinue}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}
	var adds []string
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard forward") {
			adds = append(adds, c)
		}
	}
	if len(adds) != 6 {
		t.Fatalf("expected 6 rules added to forward (5 blocks + 1 group jump), got %d: %v", len(adds), adds)
	}
	for i, want := range []string{"@blocked_hosts", "@blocked_hosts", "@blocked_macs", "@blocklist", "@blocklist"} {
		if !strings.Contains(adds[i], want) {
			t.Errorf("forward rule %d = %q, want it to contain %q", i, adds[i], want)
		}
	}
	if !strings.Contains(adds[5], "jump grp_aaa") {
		t.Errorf("last forward rule must be the group jump, got %q", adds[5])
	}
	for _, c := range adds {
		if strings.Contains(c, "jump "+UserChain) {
			t.Errorf("a forward não pode mais pular para %s: %q", UserChain, c)
		}
	}
}

func TestReconcileStructuralChainsMarkHostsRule(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}
	wantSubstr := "meta mark set ip saddr map @" + HostWanMap
	found := false
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard mark_hosts") && strings.Contains(c, wantSubstr) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a mark_hosts rule containing %q; ran: %v", wantSubstr, exec.executed)
	}
}

// TestReconcileStructuralChainsResultParsesBackCleanly proves the canonical
// definition, once round-tripped through the same parser used for the
// panel (parseTableRuleset/classifyRule/describeRule), still classifies
// exactly as expected — i.e. the reconcile and the overview agree on what
// these chains contain.
//
// The forward fixture is the post-Phase-C1 chain — blocks first, then one
// jump per enabled group, and no `jump user_rules` at all. Feeding it the
// OLD forward (which is what this did until now) meant it proved that
// agreement about a chain the reconcile no longer produces.
func TestReconcileStructuralChainsResultParsesBackCleanly(t *testing.T) {
	rendered := `table inet linkguard {
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocklist counter packets 0 bytes 0 drop
		ip saddr @blocklist counter packets 0 bytes 0 drop
		ip saddr 192.168.50.0/24 counter packets 4 bytes 240 jump grp_aaa
	}
	chain mark_hosts {
		type filter hook prerouting priority mangle; policy accept;
		counter packets 3 bytes 4 meta mark set ip saddr map @host_wan
	}
}
`
	chains := parseTableRuleset(rendered)
	fwd := chainByName(chains, "forward")
	if fwd == nil || len(fwd.Rules) != 5 {
		t.Fatalf("expected 5 rules in forward, got %+v", fwd)
	}
	for _, r := range fwd.Rules {
		if !r.HasCounter {
			t.Errorf("forward rule must report HasCounter=true after the fix, got false: %+v", r)
		}
		if !r.Managed {
			t.Errorf("forward rule must be managed: %+v", r)
		}
	}
	// The group jump is the last line — the blocks win, and a group the
	// panel shows is one the kernel evaluates after them (design spec §3).
	if !strings.Contains(fwd.Rules[4].Expression, "jump grp_aaa") {
		t.Errorf("last forward rule should be the group jump, got %+v", fwd.Rules[4])
	}
	mh := chainByName(chains, "mark_hosts")
	if mh == nil || len(mh.Rules) != 1 || !mh.Rules[0].HasCounter {
		t.Fatalf("mark_hosts rule must have a counter after the fix: %+v", mh)
	}
	if mh.Rules[0].Owner.Key != "wan_steering" {
		t.Errorf("mark_hosts rule owner = %+v, want wan_steering", mh.Rules[0].Owner)
	}
}
