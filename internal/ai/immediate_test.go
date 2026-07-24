package ai_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestTriggerImmediateNeverBlocksOnMissingToken(t *testing.T) {
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
	budget := ai.NewBudgetGuard(db)
	client := ai.NewClient(sec, budget, func() ai.Config { return ai.LoadConfig(db) })
	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)

	link := &storage.Link{ID: "a", Name: "WAN SUMICITY"}

	done := make(chan struct{})
	go func() {
		ai.TriggerImmediate(context.Background(), client, tsdbSvc, alertSvc, db, link)
		close(done)
	}()

	select {
	case <-done:
		// good: returned promptly even with no token configured
	case <-time.After(2 * time.Second):
		t.Fatal("TriggerImmediate did not return promptly with a missing token — it must fail fast, not hang")
	}

	reports, err := db.ListAIReports(10)
	if err != nil {
		t.Fatalf("ListAIReports: %v", err)
	}
	if len(reports) != 0 {
		t.Fatalf("expected no report to be created when the token is missing, got %d", len(reports))
	}
}
