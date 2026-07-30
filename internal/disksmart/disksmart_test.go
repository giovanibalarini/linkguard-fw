package disksmart

import (
	"context"
	"strings"
	"testing"
)

type fakeExec struct {
	findmntOut  string
	lsblkOut    string
	smartctlOut string
	smartctlErr error
}

func (f *fakeExec) Execute(_ context.Context, _ string, _ ...string) (string, error) { return "", nil }
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	switch cmd {
	case "findmnt":
		return f.findmntOut, nil
	case "lsblk":
		return f.lsblkOut, nil
	case "smartctl":
		return f.smartctlOut, f.smartctlErr
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool { return false }

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

func TestDetectRootDiskStripsPartition(t *testing.T) {
	fe := &fakeExec{findmntOut: "/dev/sda2\n", lsblkOut: "sda\n"}
	dev, err := DetectRootDisk(context.Background(), fe)
	if err != nil {
		t.Fatal(err)
	}
	if dev != "/dev/sda" {
		t.Fatalf("got %q, want /dev/sda", dev)
	}
}

func TestDetectRootDiskWholeDiskNoParent(t *testing.T) {
	fe := &fakeExec{findmntOut: "/dev/sda\n", lsblkOut: ""}
	dev, err := DetectRootDisk(context.Background(), fe)
	if err != nil {
		t.Fatal(err)
	}
	if dev != "/dev/sda" {
		t.Fatalf("got %q, want /dev/sda", dev)
	}
}

const sampleSmartctlJSON = `{
  "smart_status": {"passed": true},
  "ata_smart_attributes": {
    "table": [
      {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 0, "string": "0"}},
      {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 35, "string": "35"}}
    ]
  }
}`

func TestReadParsesHealthAndAttributes(t *testing.T) {
	fe := &fakeExec{smartctlOut: sampleSmartctlJSON}
	r, err := Read(context.Background(), fe, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Passed {
		t.Error("expected Passed=true")
	}
	if r.ReallocatedSectors != 0 {
		t.Errorf("ReallocatedSectors = %d, want 0", r.ReallocatedSectors)
	}
	if r.TemperatureC != 35 {
		t.Errorf("TemperatureC = %d, want 35", r.TemperatureC)
	}
}

const failingSmartctlJSON = `{
  "smart_status": {"passed": false},
  "ata_smart_attributes": {
    "table": [
      {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 12, "string": "12"}},
      {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 58, "string": "58"}}
    ]
  }
}`

func TestReadDetectsFailureAndDegradedAttributes(t *testing.T) {
	fe := &fakeExec{smartctlOut: failingSmartctlJSON}
	r, err := Read(context.Background(), fe, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if r.Passed {
		t.Error("expected Passed=false")
	}
	if r.ReallocatedSectors != 12 {
		t.Errorf("ReallocatedSectors = %d, want 12", r.ReallocatedSectors)
	}
	if r.TemperatureC != 58 {
		t.Errorf("TemperatureC = %d, want 58", r.TemperatureC)
	}
}

func TestReadErrorPropagates(t *testing.T) {
	fe := &fakeExec{smartctlErr: errBoom{}}
	_, err := Read(context.Background(), fe, "/dev/sda")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "/dev/sda") {
		t.Errorf("error should mention device: %v", err)
	}
}

// TestReadParsesJSONEvenWhenExecReturnsError guards against the real
// smartctl behavior: it uses its exit code as a bitmask where bits 3-7 mean
// "ran fine, and the disk (or its history) is unhealthy" — not "execution
// failed" — while still writing a complete, valid JSON report to stdout.
// This is exactly the scenario Vigia SMART exists to detect, so Read must
// not discard it just because the underlying exec call also returned an
// error.
func TestReadParsesJSONEvenWhenExecReturnsError(t *testing.T) {
	fe := &fakeExec{smartctlOut: failingSmartctlJSON, smartctlErr: errBoom{}}
	r, err := Read(context.Background(), fe, "/dev/sda")
	if err != nil {
		t.Fatalf("expected no error when a valid JSON report is present despite exec error, got: %v", err)
	}
	if r.Passed {
		t.Error("expected Passed=false")
	}
	if r.ReallocatedSectors != 12 {
		t.Errorf("ReallocatedSectors = %d, want 12", r.ReallocatedSectors)
	}
	if r.TemperatureC != 58 {
		t.Errorf("TemperatureC = %d, want 58", r.TemperatureC)
	}
}

// productionPackedTempJSON reproduces a real `smartctl -x -j /dev/sda`
// reading seen in production: attribute 194's raw.value is a 48-bit field
// that packs extra bytes (historical min/max, over-limit counter) alongside
// the actual temperature, so raw.value itself (64424509477) is garbage — the
// real temperature (37) only appears as the first token of raw.string.
const productionPackedTempJSON = `{
  "smart_status": {"passed": true},
  "ata_smart_attributes": {
    "table": [
      {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 0, "string": "0"}},
      {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 64424509477, "string": "37 (0 15 0 0 0)"}}
    ]
  }
}`

// TestReadParsesTemperatureFromRawStringNotPackedValue guards against the
// production bug where raw.value for attribute 194 is a vendor-packed 48-bit
// field, not a plain temperature — Read must parse the leading integer out
// of raw.string instead.
func TestReadParsesTemperatureFromRawStringNotPackedValue(t *testing.T) {
	fe := &fakeExec{smartctlOut: productionPackedTempJSON}
	r, err := Read(context.Background(), fe, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if r.TemperatureC != 37 {
		t.Errorf("TemperatureC = %d, want 37 (parsed from raw.string, not the packed raw.value)", r.TemperatureC)
	}
}

// malformedTempStringJSON has an empty raw.string for the temperature
// attribute, simulating an unexpected/malformed smartctl output.
const malformedTempStringJSON = `{
  "smart_status": {"passed": true},
  "ata_smart_attributes": {
    "table": [
      {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 3, "string": "3"}},
      {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 12345, "string": ""}}
    ]
  }
}`

// TestReadToleratesMalformedTemperatureString confirms a malformed/empty
// raw.string for the temperature attribute doesn't fail the whole Read (the
// other two signals, Passed and ReallocatedSectors, remain valid) — it just
// leaves TemperatureC at 0.
func TestReadToleratesMalformedTemperatureString(t *testing.T) {
	fe := &fakeExec{smartctlOut: malformedTempStringJSON}
	r, err := Read(context.Background(), fe, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Passed {
		t.Error("expected Passed=true")
	}
	if r.ReallocatedSectors != 3 {
		t.Errorf("ReallocatedSectors = %d, want 3", r.ReallocatedSectors)
	}
	if r.TemperatureC != 0 {
		t.Errorf("TemperatureC = %d, want 0 (malformed raw.string must not crash Read)", r.TemperatureC)
	}
}

// TestReadErrorPropagatesWhenNoJSONEvenWithError confirms Read still
// propagates the original exec error when there is genuinely no usable JSON
// on stdout alongside it (e.g. smartctl missing, device not found) — the
// fallback parse must not swallow real failures.
func TestReadErrorPropagatesWhenNoJSONEvenWithError(t *testing.T) {
	fe := &fakeExec{smartctlOut: "", smartctlErr: errBoom{}}
	_, err := Read(context.Background(), fe, "/dev/sda")
	if err == nil {
		t.Fatal("expected error when neither valid JSON nor a clean run is available")
	}
	if !strings.Contains(err.Error(), "/dev/sda") {
		t.Errorf("error should mention device: %v", err)
	}
}
