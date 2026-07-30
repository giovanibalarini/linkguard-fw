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
      {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 0}},
      {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 35}}
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
      {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 12}},
      {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 58}}
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
