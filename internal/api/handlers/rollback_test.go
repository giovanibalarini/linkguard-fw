package handlers_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── Rollback (I-1) ─────────────────────────────────────────────────────────
//
// Restore writes a stored ruleset snapshot straight into nft via `nft -f`,
// bypassing the DB-authoritative model entirely (design spec §4.1): right
// after a rollback, the live user_rules chain would hold whatever the
// snapshot happened to contain, disagreeing with the DB's own rule rows
// until the next unrelated mutation silently re-renders over it. Rollback
// must reconcile user_rules from the DB immediately afterwards, the same as
// every other mutation, so the panel and the firewall never disagree.

func TestRollbackReconcilesUserRulesFromDBAfterRestoring(t *testing.T) {
	h, db, exec := newFirewallRulesTestHandler(t)

	row := &storage.FirewallRule{Action: "accept", Saddr: "10.0.0.55"}
	if err := db.CreateFirewallRule(row); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	backup := &storage.IptablesBackup{Label: "antes-do-incidente", Rules: "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n"}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	exec.executed = nil

	req := httptest.NewRequest("POST", "/api/nftables/rollback", strings.NewReader(mustJSON(t, map[string]any{"backup_id": backup.ID})))
	w := httptest.NewRecorder()
	h.Rollback(w, req)
	if w.Code != 200 {
		t.Fatalf("Rollback: status %d, body %s", w.Code, w.Body.String())
	}

	found := false
	for _, c := range exec.executed {
		if strings.Contains(c, "10.0.0.55") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the rollback to reconcile user_rules from the DB afterwards (the DB rule's content must be re-rendered), ran: %v", exec.executed)
	}
}

func mustJSON(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
