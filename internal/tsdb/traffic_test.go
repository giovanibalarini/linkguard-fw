package tsdb_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestGetHistoryUnknownRangeDefaultsTo12h(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	res, err := svc.GetHistory("eth0", "not-a-real-range")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if res.Step != 60 {
		t.Fatalf("expected default range to use step=60 (12h/60s), got %d", res.Step)
	}
}

func TestGetHistoryRequiresInterface(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	if _, err := svc.GetHistory("", "12h"); err == nil {
		t.Fatal("expected error for empty interface")
	}
}
