package ai

import (
	"fmt"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// BudgetGuard is checked before every outbound call. Once the monthly cap is
// hit, it refuses further calls until the reset date — automatically and
// without exception, the same philosophy as the balancer never leaving the
// default route empty: a hard limit that protects the product from itself.
type BudgetGuard struct {
	db *storage.DB
}

// NewBudgetGuard creates a BudgetGuard.
func NewBudgetGuard(db *storage.DB) *BudgetGuard {
	return &BudgetGuard{db: db}
}

// Check returns an error if the monthly spend cap has been reached. Call this
// BEFORE making a request — it never touches the network itself.
func (g *BudgetGuard) Check() error {
	cfg := g.resetIfDue()
	if cfg.SpentThisMonthUSD >= cfg.MonthlyBudgetUSD {
		return fmt.Errorf("monthly AI budget of $%.2f reached (spent $%.2f) — resets %s",
			cfg.MonthlyBudgetUSD, cfg.SpentThisMonthUSD, cfg.BudgetResetAt.Format("2006-01-02"))
	}
	return nil
}

// RecordSpend adds usd to this month's running total.
func (g *BudgetGuard) RecordSpend(usd float64) error {
	cfg := g.resetIfDue()
	cfg.SpentThisMonthUSD += usd
	return SaveConfig(g.db, cfg)
}

// resetIfDue zeroes the spend counter and advances BudgetResetAt if the reset
// date has passed, persisting the reset before returning the fresh config.
//
// Two edge cases were traced deliberately here (see task-2-report.md):
//   - BudgetResetAt == time.Now() exactly: time.Time.After is a strict
//     inequality, so an exact tie does not reset on this call. The window is
//     sub-nanosecond and self-heals on the very next Check/RecordSpend, so
//     this is intentional, not a bug — it only ever delays a reset by one
//     call, never skips it.
//   - BudgetResetAt is the zero value (very first call ever, config never
//     saved with a reset date before): this is treated as "no reset date set
//     yet", not as "reset is overdue". SpentThisMonthUSD is left untouched
//     (it is 0 on a fresh config anyway) and BudgetResetAt is initialized to
//     the start of next month. If this branch instead fell through to the
//     "already passed" branch, IsZero()'s year-1 timestamp is trivially
//     before time.Now(), so every fresh install would immediately zero a
//     spend total that was already zero — harmless in isolation, but it
//     would also silently discard any SpentThisMonthUSD a caller had set
//     directly via SaveConfig before ever constructing a BudgetGuard (as
//     TestBudgetGuardRefusesOverBudget's sibling scenarios do). Keeping the
//     zero-value case distinct avoids that surprise.
func (g *BudgetGuard) resetIfDue() Config {
	cfg := LoadConfig(g.db)
	if cfg.BudgetResetAt.IsZero() {
		cfg.BudgetResetAt = nextMonthStart(time.Now())
		_ = SaveConfig(g.db, cfg)
		return cfg
	}
	if time.Now().After(cfg.BudgetResetAt) {
		cfg.SpentThisMonthUSD = 0
		cfg.BudgetResetAt = nextMonthStart(time.Now())
		_ = SaveConfig(g.db, cfg)
	}
	return cfg
}

func nextMonthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m+1, 1, 0, 0, 0, 0, t.Location())
}
