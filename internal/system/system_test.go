package system

import (
	"os"
	"strings"
	"testing"
)

// TestReadBootID exercises the real /proc/sys/kernel/random/boot_id on this
// host — that path is fixed by the kernel and isn't practical to mock, so
// this test runs against the live file. It is skipped only if the file is
// genuinely absent (e.g. a non-Linux CI runner or a heavily sandboxed
// container without /proc/sys); on any normal modern Linux box it exists.
func TestReadBootID(t *testing.T) {
	if _, err := os.Stat("/proc/sys/kernel/random/boot_id"); err != nil {
		t.Skip("/proc/sys/kernel/random/boot_id not present on this system (expected on any modern Linux host); skipping")
	}

	id, err := ReadBootID()
	if err != nil {
		t.Fatalf("ReadBootID() error = %v", err)
	}
	if id == "" {
		t.Fatal("ReadBootID() returned an empty string")
	}
	if strings.ContainsAny(id, "\n\r") {
		t.Errorf("ReadBootID() = %q, should be trimmed of trailing newline", id)
	}
	// Loose UUID shape check: 36 chars, hyphens in the canonical positions.
	if len(id) == 36 {
		if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Errorf("ReadBootID() = %q, does not look like a UUID", id)
		}
	}
}
