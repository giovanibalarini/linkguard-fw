package ai_test

import (
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLoadConfigDefaults(t *testing.T) {
	db := newTestDB(t)
	c := ai.LoadConfig(db)

	if c.Enabled {
		t.Error("expected disabled by default (opt-in feature)")
	}
	if c.Model != "claude-opus-4-8" {
		t.Errorf("expected default model claude-opus-4-8, got %q", c.Model)
	}
	if c.MonthlyBudgetUSD != 5.0 {
		t.Errorf("expected default budget $5, got %v", c.MonthlyBudgetUSD)
	}
}

func TestSaveThenLoadConfigRoundTrips(t *testing.T) {
	db := newTestDB(t)
	want := ai.Config{
		Enabled: true, Model: "claude-haiku-4-5", Effort: "medium",
		MonthlyBudgetUSD: 10.0, DigestHour: 6,
		TelemetryConsent: map[string]bool{"hostname": false, "mac": false},
	}
	if err := ai.SaveConfig(db, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got := ai.LoadConfig(db)
	if got.Enabled != want.Enabled || got.Model != want.Model || got.MonthlyBudgetUSD != want.MonthlyBudgetUSD {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}
