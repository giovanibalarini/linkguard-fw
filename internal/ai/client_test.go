package ai_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TestReportRecommendationIsPlainStringField is a structural guardrail, not a
// behavioral test: it fails to compile (and this comment fails to be true) if
// Recommendation is ever changed from a plain string to something a caller
// could dispatch as an action (e.g. a struct with a Command field). This is
// the invariant "the AI is never in the control loop" made mechanically
// checkable rather than a comment someone can miss in review.
func TestReportRecommendationIsPlainStringField(t *testing.T) {
	f, ok := reflect.TypeOf(ai.Report{}).FieldByName("Recommendation")
	if !ok {
		t.Fatal("Report has no Recommendation field")
	}
	if f.Type.Kind() != reflect.String {
		t.Fatalf("Report.Recommendation must be a plain string (human-readable text only), got %s — "+
			"a structured type here risks a future caller treating it as an executable action", f.Type.Kind())
	}
}

func TestAnalyzeRefusesWhenOverBudget(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	_ = sec.Set("ai_api_token", "sk-ant-test-key-not-real")

	cfg := ai.LoadConfig(db)
	cfg.MonthlyBudgetUSD = 1.0
	_ = ai.SaveConfig(db, cfg)

	budget := ai.NewBudgetGuard(db)
	_ = budget.RecordSpend(2.0) // already over the $1 cap

	client := ai.NewClient(sec, budget, func() ai.Config { return ai.LoadConfig(db) })

	_, err = client.Analyze(context.Background(), ai.Evidence{Period: "test"})
	if err == nil {
		t.Fatal("expected Analyze to refuse when over budget, without making any network call")
	}
	if !errors.Is(err, ai.ErrBudgetExceeded) {
		t.Fatalf("expected ErrBudgetExceeded, got %v", err)
	}
}

func TestAnalyzeRefusesWhenTokenNotConfigured(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	// token deliberately never set

	budget := ai.NewBudgetGuard(db)
	client := ai.NewClient(sec, budget, func() ai.Config { return ai.LoadConfig(db) })

	_, err = client.Analyze(context.Background(), ai.Evidence{Period: "test"})
	if err == nil {
		t.Fatal("expected Analyze to refuse when no token is configured")
	}
	if !errors.Is(err, ai.ErrTokenNotConfigured) {
		t.Fatalf("expected ErrTokenNotConfigured, got %v", err)
	}
}
