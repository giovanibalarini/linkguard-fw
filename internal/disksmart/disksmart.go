// Package disksmart reads S.M.A.R.T. health data for the disk backing the
// root filesystem.
package disksmart

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Report is the subset of `smartctl -x -j <device>` the Vigia SMART checks
// need: the overall self-assessed health verdict, reallocated sector count,
// and current temperature.
type Report struct {
	Passed             bool
	ReallocatedSectors int
	TemperatureC       int
}

type smartctlOutput struct {
	SmartStatus struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	AtaSmartAttributes struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value int `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
}

const (
	attrReallocatedSectorCt = 5
	attrTemperatureCelsius  = 194
)

// DetectRootDisk finds the whole-disk block device backing the root
// filesystem (e.g. "/dev/sda2" -> "/dev/sda"), via findmnt + lsblk's own
// parent-device lookup — never hardcoded or string-guessed, same philosophy
// as the project's interface/route parsers. A root that is already a
// whole-disk device (no parent) is returned as-is.
func DetectRootDisk(ctx context.Context, exec firewall.Executor) (string, error) {
	part, err := exec.ExecuteRead(ctx, "findmnt", "-no", "SOURCE", "/")
	if err != nil {
		return "", fmt.Errorf("findmnt root device: %w", err)
	}
	part = strings.TrimSpace(part)
	if part == "" {
		return "", fmt.Errorf("findmnt returned empty root device")
	}
	parent, err := exec.ExecuteRead(ctx, "lsblk", "-ndo", "pkname", part)
	if err != nil {
		return "", fmt.Errorf("lsblk parent of %s: %w", part, err)
	}
	name := strings.TrimSpace(parent)
	if name == "" {
		return part, nil
	}
	return "/dev/" + name, nil
}

// Read runs `smartctl -x -j <device>` and parses its JSON output. JSON
// (not the text table) so parsing never depends on smartctl's
// column-alignment/wording across versions.
//
// smartctl encodes its findings in its exit code as a bitmask: bits 0-2
// mean the command itself failed to run, but bits 3-7 (e.g. "disk failing
// now", a pre-fail attribute, or a non-empty error log) make it exit
// non-zero even though it wrote a perfectly valid, informative JSON report
// to stdout — exactly the case Vigia SMART exists to catch. So on error we
// still try to parse whatever stdout we got; only if that also fails do we
// propagate the original exec error.
func Read(ctx context.Context, exec firewall.Executor, device string) (Report, error) {
	out, execErr := exec.ExecuteRead(ctx, "smartctl", "-x", "-j", device)
	var parsed smartctlOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		if execErr != nil {
			return Report{}, fmt.Errorf("smartctl %s: %w", device, execErr)
		}
		return Report{}, fmt.Errorf("parse smartctl JSON for %s: %w", device, err)
	}
	r := Report{Passed: parsed.SmartStatus.Passed}
	for _, attr := range parsed.AtaSmartAttributes.Table {
		switch attr.ID {
		case attrReallocatedSectorCt:
			r.ReallocatedSectors = attr.Raw.Value
		case attrTemperatureCelsius:
			r.TemperatureC = attr.Raw.Value
		}
	}
	return r, nil
}
