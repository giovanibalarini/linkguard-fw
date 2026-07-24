package ai_test

import (
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
