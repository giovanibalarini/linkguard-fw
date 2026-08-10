package networkd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reuses fakeApplyExec, already defined in networkd_test.go (same package,
// same test binary) for Render/Apply's own tests — no new fake executor
// type needed. fakeApplyExec.Execute only special-cases "networkctl"
// (recording to reloadCalls) and errors on anything else, which is exactly
// right here: WriteLinkFile must never call Execute at all (it only checks
// IsDryRun before doing its own os.* calls directly), so reusing it doubles
// as proof that no unexpected command gets shelled out.

func TestRenderLinkMatchesByMACAndPinsName(t *testing.T) {
	f := RenderLink("b8:ca:3a:fc:d6:03", "lg-wan-vivo", "/etc/systemd/network")

	if want := "/etc/systemd/network/10-lg-wan-vivo.link"; f.Path != want {
		t.Errorf("Path = %q, want %q", f.Path, want)
	}
	for _, want := range []string{
		"# managed by linkguard",
		"[Match]",
		"MACAddress=b8:ca:3a:fc:d6:03",
		"[Link]",
		"Name=lg-wan-vivo",
	} {
		if !strings.Contains(f.Content, want) {
			t.Errorf("content missing %q:\n%s", want, f.Content)
		}
	}
}

func TestRenderLinkDefaultsDir(t *testing.T) {
	f := RenderLink("aa:bb:cc:dd:ee:ff", "lg-test", "")
	if !strings.HasPrefix(f.Path, defaultNetworkDir+"/") {
		t.Errorf("Path = %q, want prefix %q", f.Path, defaultNetworkDir+"/")
	}
}

func TestWriteLinkFileWritesContentAtomically(t *testing.T) {
	dir := t.TempDir()
	f := RenderLink("b8:ca:3a:fc:d6:03", "lg-wan-vivo", dir)
	exec := &fakeApplyExec{}

	if err := WriteLinkFile(exec, f); err != nil {
		t.Fatalf("WriteLinkFile: %v", err)
	}

	got, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != f.Content {
		t.Errorf("file content = %q, want %q", got, f.Content)
	}
	// No stray temp file left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected exactly 1 file in %s, got %d: %v", dir, len(entries), entries)
	}
	if len(exec.reloadCalls) != 0 {
		t.Error("WriteLinkFile must never call `networkctl reload` — .link only takes effect on reboot (spec §3)")
	}
}

func TestWriteLinkFileNoopInDryRun(t *testing.T) {
	dir := t.TempDir()
	f := RenderLink("b8:ca:3a:fc:d6:03", "lg-wan-vivo", filepath.Join(dir, "sub"))

	if err := WriteLinkFile(&fakeApplyExec{dryRun: true}, f); err != nil {
		t.Fatalf("WriteLinkFile in dry-run: %v", err)
	}
	if _, err := os.Stat(f.Path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected no file written in dry-run, got err=%v", err)
	}
}
