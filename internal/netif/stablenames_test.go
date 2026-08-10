package netif

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TestStableNamesOnlyCoversPhysicalWANWithKnownMAC is the regression test
// for the 2026-08-10 incident: enp5s0 (WAN1) silently became enp4s0 after a
// hardware change, and the whole LAN/WAN topology had to be rebuilt by hand.
// wlp2s0 (sampleLinkJSON, MAC f4:8c:50:1b:c3:b2) is configured as a WAN
// Link named "WAN" — must get a stable "lg-wan" name. enp0s31f6 has no
// configured Link — must be skipped entirely (not WAN).
func TestStableNamesOnlyCoversPhysicalWANWithKnownMAC(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	if err := linkSvc.Create(&storage.Link{ID: "wan1", Name: "WAN", Interface: "wlp2s0", Weight: 1}); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	svc := NewService(exec, db, linkSvc)

	entries, err := svc.StableNames(context.Background())
	if err != nil {
		t.Fatalf("StableNames: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 entry (only wlp2s0 is WAN), got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Interface != "wlp2s0" {
		t.Errorf("Interface = %q, want %q", e.Interface, "wlp2s0")
	}
	if e.MAC != "f4:8c:50:1b:c3:b2" {
		t.Errorf("MAC = %q, want %q", e.MAC, "f4:8c:50:1b:c3:b2")
	}
	if e.LinkName != "WAN" {
		t.Errorf("LinkName = %q, want %q", e.LinkName, "WAN")
	}
	if e.StableName != "lg-wan" {
		t.Errorf("StableName = %q, want %q", e.StableName, "lg-wan")
	}
}

// TestStableIfaceNameTruncatesToKernelLimit is the regression test for a
// real correctness gap: Linux interface names are capped at IFNAMSIZ-1 (15
// chars). A long, perfectly reasonable admin-chosen Link name like "WAN
// Fibra Principal Sede" must never produce a name the kernel would reject —
// it has to be truncated deterministically instead.
func TestStableIfaceNameTruncatesToKernelLimit(t *testing.T) {
	got := stableIfaceName("WAN Fibra Principal Sede", "aa:bb:cc:dd:ee:ff", map[string]bool{})
	if len(got) > maxIfaceName {
		t.Errorf("stableIfaceName produced %q (%d chars), exceeds kernel limit of %d", got, len(got), maxIfaceName)
	}
	if got[:3] != "lg-" {
		t.Errorf("stableIfaceName = %q, expected lg- prefix", got)
	}
}

// TestStableIfaceNameDisambiguatesCollisions is the regression test for two
// Links whose names slugify to the same value (e.g. "WAN Vivo" and
// "wan-vivo" both -> "wan-vivo") — the second one must not silently
// overwrite the first's .link file with a colliding MACAddress= match.
func TestStableIfaceNameDisambiguatesCollisions(t *testing.T) {
	seen := map[string]bool{}
	first := stableIfaceName("WAN Vivo", "b8:ca:3a:fc:d6:03", seen)
	seen[first] = true
	second := stableIfaceName("wan-vivo", "f4:f2:6d:05:e2:f0", seen)

	if first == second {
		t.Fatalf("expected distinct names for colliding slugs, both got %q", first)
	}
	if len(second) > maxIfaceName {
		t.Errorf("disambiguated name %q (%d chars) exceeds kernel limit of %d", second, len(second), maxIfaceName)
	}
}

func TestApplyStableNamesWritesLinkFiles(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	if err := linkSvc.Create(&storage.Link{ID: "wan1", Name: "WAN", Interface: "wlp2s0", Weight: 1}); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	svc := NewService(exec, db, linkSvc)
	svc.networkDir = dir

	entries, err := svc.ApplyStableNames(context.Background())
	if err != nil {
		t.Fatalf("ApplyStableNames: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	wantPath := dir + "/10-lg-wan.link"
	content, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("expected .link file at %s: %v", wantPath, err)
	}
	if !strings.Contains(string(content), "MACAddress=f4:8c:50:1b:c3:b2") {
		t.Errorf(".link file missing expected MACAddress line:\n%s", content)
	}
}
