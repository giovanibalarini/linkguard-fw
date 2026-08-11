package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── firewall_rules (Phase B: the admin's rules live in the DB) ────────────

func TestCreateFirewallRuleAppendsAtTheEndAndStartsEnabled(t *testing.T) {
	db := newTestDB(t)

	r1 := &storage.FirewallRule{Action: "drop", Daddr: "203.0.113.0/24"}
	if err := db.CreateFirewallRule(r1); err != nil {
		t.Fatalf("CreateFirewallRule r1: %v", err)
	}
	if r1.ID == "" {
		t.Error("expected ID to be set after create")
	}
	if !r1.Enabled {
		t.Error("expected a newly created rule to start enabled")
	}
	if r1.Position != 0 {
		t.Errorf("expected first rule at position 0, got %d", r1.Position)
	}

	r2 := &storage.FirewallRule{Action: "accept", Saddr: "192.168.3.0/24"}
	if err := db.CreateFirewallRule(r2); err != nil {
		t.Fatalf("CreateFirewallRule r2: %v", err)
	}
	if r2.Position != 1 {
		t.Errorf("expected second rule appended at position 1, got %d", r2.Position)
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(all))
	}
	if all[0].ID != r1.ID || all[1].ID != r2.ID {
		t.Errorf("expected rules ordered by position (r1, r2), got %+v", all)
	}
}

func TestListFirewallRulesEmptyIsNotNil(t *testing.T) {
	db := newTestDB(t)

	got, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if got == nil {
		t.Error("expected an empty slice, got nil")
	}
}

func TestUpdateFirewallRuleChangesContentNotPositionOrEnabled(t *testing.T) {
	db := newTestDB(t)

	r := &storage.FirewallRule{Action: "drop", Daddr: "203.0.113.0/24", Description: "bloqueio inicial"}
	if err := db.CreateFirewallRule(r); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := db.SetFirewallRuleEnabled(r.ID, false); err != nil {
		t.Fatalf("SetFirewallRuleEnabled: %v", err)
	}

	edit := &storage.FirewallRule{
		ID: r.ID, Action: "reject", Saddr: "10.0.0.0/8", Proto: "tcp", Dport: "22",
		Description: "regra editada",
	}
	if err := db.UpdateFirewallRule(edit); err != nil {
		t.Fatalf("UpdateFirewallRule: %v", err)
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(all))
	}
	got := all[0]
	if got.Action != "reject" || got.Saddr != "10.0.0.0/8" || got.Proto != "tcp" || got.Dport != "22" {
		t.Errorf("expected edited content, got %+v", got)
	}
	if got.Description != "regra editada" {
		t.Errorf("expected updated description, got %q", got.Description)
	}
	if got.Position != 0 {
		t.Errorf("expected position untouched by content edit, got %d", got.Position)
	}
	if got.Enabled {
		t.Error("expected enabled flag untouched by content edit (still disabled)")
	}
}

func TestDeleteFirewallRule(t *testing.T) {
	db := newTestDB(t)

	r := &storage.FirewallRule{Action: "accept"}
	if err := db.CreateFirewallRule(r); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := db.DeleteFirewallRule(r.ID); err != nil {
		t.Fatalf("DeleteFirewallRule: %v", err)
	}
	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(all))
	}
}

func TestSetFirewallRuleEnabledTogglesWithoutDeleting(t *testing.T) {
	db := newTestDB(t)

	r := &storage.FirewallRule{Action: "drop"}
	if err := db.CreateFirewallRule(r); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	if err := db.SetFirewallRuleEnabled(r.ID, false); err != nil {
		t.Fatalf("SetFirewallRuleEnabled(false): %v", err)
	}
	all, _ := db.ListFirewallRules()
	if len(all) != 1 {
		t.Fatalf("expected the rule to still exist after disabling, got %d rules", len(all))
	}
	if all[0].Enabled {
		t.Error("expected rule to be disabled")
	}

	if err := db.SetFirewallRuleEnabled(r.ID, true); err != nil {
		t.Fatalf("SetFirewallRuleEnabled(true): %v", err)
	}
	all, _ = db.ListFirewallRules()
	if !all[0].Enabled {
		t.Error("expected rule to be re-enabled")
	}
}

func TestSetFirewallRuleEnabledUnknownIDErrors(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetFirewallRuleEnabled("does-not-exist", true); err == nil {
		t.Error("expected an error for an unknown rule id")
	}
}

func TestReorderFirewallRulesSetsExplicitPositions(t *testing.T) {
	db := newTestDB(t)

	r1 := &storage.FirewallRule{Action: "accept", Description: "first"}
	r2 := &storage.FirewallRule{Action: "drop", Description: "second"}
	r3 := &storage.FirewallRule{Action: "reject", Description: "third"}
	for _, r := range []*storage.FirewallRule{r1, r2, r3} {
		if err := db.CreateFirewallRule(r); err != nil {
			t.Fatalf("CreateFirewallRule: %v", err)
		}
	}

	// New order: r3, r1, r2
	if err := db.ReorderFirewallRules([]string{r3.ID, r1.ID, r2.ID}); err != nil {
		t.Fatalf("ReorderFirewallRules: %v", err)
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(all))
	}
	if all[0].ID != r3.ID || all[1].ID != r1.ID || all[2].ID != r2.ID {
		t.Fatalf("expected order r3,r1,r2 after reorder, got %s,%s,%s", all[0].ID, all[1].ID, all[2].ID)
	}
}

func TestReorderFirewallRulesUnknownIDErrorsAndChangesNothing(t *testing.T) {
	db := newTestDB(t)

	r1 := &storage.FirewallRule{Action: "accept"}
	r2 := &storage.FirewallRule{Action: "drop"}
	for _, r := range []*storage.FirewallRule{r1, r2} {
		if err := db.CreateFirewallRule(r); err != nil {
			t.Fatalf("CreateFirewallRule: %v", err)
		}
	}

	err := db.ReorderFirewallRules([]string{r2.ID, "does-not-exist"})
	if err == nil {
		t.Fatal("expected an error for an unknown id in the reorder list")
	}

	// Nothing should have changed (the whole reorder is one transaction).
	all, lerr := db.ListFirewallRules()
	if lerr != nil {
		t.Fatalf("ListFirewallRules: %v", lerr)
	}
	if all[0].ID != r1.ID || all[1].ID != r2.ID {
		t.Fatalf("expected original order preserved after a failed reorder, got %s,%s", all[0].ID, all[1].ID)
	}
}

func TestFirewallRulesImportedSettingRoundTrips(t *testing.T) {
	db := newTestDB(t)

	val, err := db.GetSetting("firewall_rules_imported")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if val != "" {
		t.Fatalf("expected the import guard unset on a fresh DB, got %q", val)
	}

	if err := db.SetSetting("firewall_rules_imported", "true"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	val, err = db.GetSetting("firewall_rules_imported")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if val != "true" {
		t.Fatalf("expected the import guard to stick, got %q", val)
	}
}
