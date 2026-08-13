package handlers

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Every storage.FirewallGroup -> nftables.StoredGroup conversion must carry
// Kind, and there are two of them: this one and firewallrules.StoredGroups.
// Dropping it here compiles, passes every other test in the repository, and
// only bites later — the delete/rename protections for system groups land on
// top of this exact conversion, so a silently empty Kind would make a system
// group look like the admin's and hand it protections it must not have (or
// withhold the ones it must). An independent review proved by mutation that
// both conversions were unprotected.
//
// This lives in an internal test file on purpose: groups_test.go is
// package handlers_test and cannot reach an unexported function.
func TestToStoredGroupCarriesEveryFieldThatDecidesBehaviour(t *testing.T) {
	row := storage.FirewallGroup{
		ID: "g1", Name: "Hosts bloqueados", ChainName: "sys_blocked_hosts",
		Position: 3, Enabled: true, Kind: "blocked_hosts",
		CondSaddr: "10.0.0.0/8", CondDaddr: "192.168.1.0/24", CondIif: "enp0s3",
		Fallthrough: "drop", Scope: "input",
	}
	got := toStoredGroup(row)

	if got.Kind != row.Kind {
		t.Errorf("Kind não foi propagado: %q", got.Kind)
	}
	if !nftables.IsSystemGroup(got.Kind) {
		t.Error("um grupo do sistema tem que continuar sendo do sistema depois da conversão")
	}
	for _, c := range []struct{ name, got, want string }{
		{"ID", got.ID, row.ID}, {"Name", got.Name, row.Name},
		{"ChainName", got.ChainName, row.ChainName},
		{"CondSaddr", got.CondSaddr, row.CondSaddr},
		{"CondDaddr", got.CondDaddr, row.CondDaddr},
		{"CondIif", got.CondIif, row.CondIif},
		{"Fallthrough", got.Fallthrough, row.Fallthrough},
		// Scope decide em QUAL chain o grupo é alcançado (Fase C2): perdê-lo
		// aqui faria o pré-voo validar um grupo de escopo input como se ele
		// fosse da forward — validar uma coisa e aplicar outra.
		{"Scope", got.Scope, row.Scope},
	} {
		if c.got != c.want {
			t.Errorf("%s: obtive %q, queria %q", c.name, c.got, c.want)
		}
	}
	if got.Position != row.Position || got.Enabled != row.Enabled {
		t.Errorf("Position/Enabled não propagados: %+v", got)
	}
}
