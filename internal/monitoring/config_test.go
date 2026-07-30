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

func TestLoadConfigNewFieldDefaults(t *testing.T) {
	db := openTestDB(t)
	c := LoadConfig(db)
	if c.SMARTReallocatedThreshold != 0 {
		t.Errorf("SMARTReallocatedThreshold default = %d, want 0", c.SMARTReallocatedThreshold)
	}
	if c.SMARTTempThresholdC != 55 {
		t.Errorf("SMARTTempThresholdC default = %d, want 55", c.SMARTTempThresholdC)
	}
	if c.BootTimeThresholdSec != 180 {
		t.Errorf("BootTimeThresholdSec default = %d, want 180", c.BootTimeThresholdSec)
	}
	if c.JournalVerifyIntervalDays != 7 {
		t.Errorf("JournalVerifyIntervalDays default = %d, want 7", c.JournalVerifyIntervalDays)
	}
}

func TestLoadConfigClampsInvalidNewThresholds(t *testing.T) {
	db := openTestDB(t)
	bad := Config{Enabled: true, DiskThresholdPct: 90, SMARTTempThresholdC: -5, BootTimeThresholdSec: 0, JournalVerifyIntervalDays: -1}
	if err := SaveConfig(db, bad); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db)
	if got.SMARTTempThresholdC != 55 {
		t.Errorf("SMARTTempThresholdC should clamp to default 55, got %d", got.SMARTTempThresholdC)
	}
	if got.BootTimeThresholdSec != 180 {
		t.Errorf("BootTimeThresholdSec should clamp to default 180, got %d", got.BootTimeThresholdSec)
	}
	if got.JournalVerifyIntervalDays != 7 {
		t.Errorf("JournalVerifyIntervalDays should clamp to default 7, got %d", got.JournalVerifyIntervalDays)
	}
}

func TestLoadConfigPreservesZeroReallocatedThreshold(t *testing.T) {
	db := openTestDB(t)
	// 0 is a legitimate, meaningful value here ("alert on any reallocated
	// sector") — must NOT be clamped away like the other thresholds.
	in := Config{Enabled: true, DiskThresholdPct: 90, SMARTReallocatedThreshold: 0, SMARTTempThresholdC: 55, BootTimeThresholdSec: 180, JournalVerifyIntervalDays: 7}
	if err := SaveConfig(db, in); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db)
	if got.SMARTReallocatedThreshold != 0 {
		t.Errorf("SMARTReallocatedThreshold should stay 0, got %d", got.SMARTReallocatedThreshold)
	}
}
