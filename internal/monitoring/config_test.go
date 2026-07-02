package monitoring

import (
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLoadConfigDefaultsWhenAbsent(t *testing.T) {
	db := openTestDB(t) // shared helper defined in Global Constraints
	c := LoadConfig(db)
	if !c.Enabled {
		t.Error("expected Enabled=true by default (zero-config)")
	}
	if c.DiskThresholdPct != 90 {
		t.Errorf("disk threshold default = %d, want 90", c.DiskThresholdPct)
	}
	want := []string{"kea-dhcp4-server", "unbound", "nftables"}
	if len(c.Services) != len(want) {
		t.Fatalf("services = %v, want %v", c.Services, want)
	}
	for i := range want {
		if c.Services[i] != want[i] {
			t.Errorf("service[%d] = %q, want %q", i, c.Services[i], want[i])
		}
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	db := openTestDB(t)
	in := Config{Enabled: false, Services: []string{"unbound"}, DiskThresholdPct: 80}
	if err := SaveConfig(db, in); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db)
	if got.Enabled != false || got.DiskThresholdPct != 80 || len(got.Services) != 1 || got.Services[0] != "unbound" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}
