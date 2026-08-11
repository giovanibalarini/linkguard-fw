package nftables

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPersistWritesOnlyTheLinkguardTable is the regression guard for the
// production incident: an operator's manually-added `table ip nat { ...
// masquerade }` rule got captured by a full `nft list ruleset` dump into
// ConfPath and resurrected on every boot, masquerading loopback traffic and
// breaking the box's own DNS. Persist must serialize only `table inet
// linkguard`, never a foreign table, however the fake executor answers.
func TestPersistWritesOnlyTheLinkguardTable(t *testing.T) {
	dir := t.TempDir()
	old := ConfPath
	ConfPath = filepath.Join(dir, "nftables.conf")
	defer func() { ConfPath = old }()

	exec := &recordExec{
		tableOut: "table inet linkguard {\n\tchain forward {\n\t}\n}\n",
		// If Persist ever regresses to dumping the whole ruleset, this is
		// what a real `nft list ruleset` would return on the incident box —
		// it must never end up in the written file.
		rulesetOut: "table inet linkguard {\n\tchain forward {\n\t}\n}\n" +
			"table ip nat {\n\tchain POSTROUTING {\n\t\tmasquerade\n\t}\n}\n",
	}
	s := NewService(exec)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	body, err := os.ReadFile(ConfPath)
	if err != nil {
		t.Fatalf("read ConfPath: %v", err)
	}
	content := string(body)

	if !strings.Contains(content, "table inet linkguard") {
		t.Errorf("expected persisted file to contain the linkguard table, got:\n%s", content)
	}
	if strings.Contains(content, "table ip nat") {
		t.Errorf("persisted file must never contain a foreign table (table ip nat), got:\n%s", content)
	}

	// The command issued must ask for the specific table, not the whole
	// ruleset — guards against a future refactor silently going back to
	// `nft list ruleset`.
	askedForTable := false
	askedForRuleset := false
	for _, c := range exec.calls {
		if strings.Contains(c, "list table "+Family+" "+Table) {
			askedForTable = true
		}
		if strings.Contains(c, "list ruleset") {
			askedForRuleset = true
		}
	}
	if !askedForTable {
		t.Errorf("expected Persist to issue `nft list table %s %s`; calls: %v", Family, Table, exec.calls)
	}
	if askedForRuleset {
		t.Errorf("Persist must not issue `nft list ruleset`; calls: %v", exec.calls)
	}
}

// TestPersistedFileIsIdempotentOnReload guards against the second defect from
// the same incident: a bare `table inet linkguard { ... }` block with no
// reset makes `nft -f` APPEND to an already-existing table at boot instead of
// replacing it, which is how the box ended up with two masquerade rules (one
// referencing a since-removed interface). The file must lead with the
// standard create-then-delete preamble so the load always starts clean.
func TestPersistedFileIsIdempotentOnReload(t *testing.T) {
	dir := t.TempDir()
	old := ConfPath
	ConfPath = filepath.Join(dir, "nftables.conf")
	defer func() { ConfPath = old }()

	exec := &recordExec{
		tableOut: "table inet linkguard {\n\tchain forward {\n\t}\n}\n",
	}
	s := NewService(exec)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	body, err := os.ReadFile(ConfPath)
	if err != nil {
		t.Fatalf("read ConfPath: %v", err)
	}
	content := string(body)

	if strings.Contains(content, "flush ruleset") {
		t.Errorf("persisted file must not flush ruleset (would destroy foreign tables at boot), got:\n%s", content)
	}

	createIdx := strings.Index(content, "table "+Family+" "+Table+"\n")
	deleteIdx := strings.Index(content, "delete table "+Family+" "+Table+"\n")
	defIdx := strings.Index(content, "table "+Family+" "+Table+" {")

	if createIdx < 0 {
		t.Fatalf("expected a bare `table %s %s` preamble line, got:\n%s", Family, Table, content)
	}
	if deleteIdx < 0 {
		t.Fatalf("expected a `delete table %s %s` preamble line, got:\n%s", Family, Table, content)
	}
	if defIdx < 0 {
		t.Fatalf("expected the full table definition to follow, got:\n%s", content)
	}
	if !(createIdx < deleteIdx && deleteIdx < defIdx) {
		t.Errorf("expected order: bare `table` create, then `delete table`, then full definition; got:\n%s", content)
	}
}

// TestPersistIsNoopInDryRun ensures Persist never touches ConfPath (or asks
// the executor for anything) when running in dry-run mode.
func TestPersistIsNoopInDryRun(t *testing.T) {
	dir := t.TempDir()
	old := ConfPath
	ConfPath = filepath.Join(dir, "nftables.conf")
	defer func() { ConfPath = old }()

	exec := &recordExec{dryRun: true}
	s := NewService(exec)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	if _, err := os.Stat(ConfPath); !os.IsNotExist(err) {
		t.Errorf("expected ConfPath to not be written in dry-run, stat err: %v", err)
	}
	if len(exec.calls) != 0 {
		t.Errorf("expected no executor calls in dry-run, got: %v", exec.calls)
	}
}
