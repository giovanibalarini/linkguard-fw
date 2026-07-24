package ai_test

import (
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
)

func TestBudgetGuardAllowsUnderBudget(t *testing.T) {
	db := newTestDB(t)
	g := ai.NewBudgetGuard(db)

	if err := g.Check(); err != nil {
		t.Fatalf("expected no error with zero spend, got %v", err)
	}
}

func TestBudgetGuardRefusesOverBudget(t *testing.T) {
	db := newTestDB(t)
	cfg := ai.LoadConfig(db)
	cfg.MonthlyBudgetUSD = 1.0
	_ = ai.SaveConfig(db, cfg)

	g := ai.NewBudgetGuard(db)
	if err := g.RecordSpend(1.5); err != nil {
		t.Fatalf("RecordSpend: %v", err)
	}

	if err := g.Check(); err == nil {
		t.Fatal("expected Check to refuse once spend exceeds the monthly budget")
	}
}

func TestBudgetResetsOnNewMonth(t *testing.T) {
	db := newTestDB(t)
	cfg := ai.LoadConfig(db)
	cfg.MonthlyBudgetUSD = 1.0
	cfg.SpentThisMonthUSD = 5.0                         // already over budget
	cfg.BudgetResetAt = time.Now().Add(-24 * time.Hour) // reset date already passed
	_ = ai.SaveConfig(db, cfg)

	g := ai.NewBudgetGuard(db)
	if err := g.Check(); err != nil {
		t.Fatalf("expected Check to pass after the reset date, got %v", err)
	}
}

// TestBudgetGuardRecordSpendConcurrent proves RecordSpend serializes its
// load-mutate-save cycle: N goroutines each adding the same amount to a
// SHARED BudgetGuard instance (mirroring two links degrading close together,
// both calling TriggerImmediate -> RecordSpend on the one BudgetGuard main.go
// constructs) must never lose an increment to a concurrent overwrite. Run
// with -race; this also catches the underlying data race directly.
func TestBudgetGuardRecordSpendConcurrent(t *testing.T) {
	db := newTestDB(t)
	g := ai.NewBudgetGuard(db)

	const n = 20
	const perCall = 0.01

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if err := g.RecordSpend(perCall); err != nil {
				t.Errorf("RecordSpend: %v", err)
			}
		}()
	}
	wg.Wait()

	cfg := ai.LoadConfig(db)
	want := n * perCall
	if diff := cfg.SpentThisMonthUSD - want; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("lost update: SpentThisMonthUSD = %v, want %v (n=%d concurrent RecordSpend calls)",
			cfg.SpentThisMonthUSD, want, n)
	}
}
