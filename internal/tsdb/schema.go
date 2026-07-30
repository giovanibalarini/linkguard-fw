package tsdb

import (
	"strings"
	"time"
)

// nativeSteps maps a series name prefix to the cadence (in seconds) its
// producer measures at. Gauge() looks this up so callers never have to know
// or pass a step — the tsdb package is the single owner of bucketing.
var nativeSteps = map[string]int{
	"link.":  10,
	"sys.":   30,
	"if.":    1,
	"smart.": 30,
	"boot.":  3600,
}

// derivedSteps are the rollup degrees every series gets in addition to its
// native step, in seconds: 1 minute, 15 minutes, 1 hour.
var derivedSteps = []int{60, 900, 3600}

func nativeStep(series string) int {
	for prefix, step := range nativeSteps {
		if strings.HasPrefix(series, prefix) {
			return step
		}
	}
	// Unknown series: treat as 10s native (safe default; producers are
	// expected to use a registered prefix).
	return 10
}

// nativeStepValues returns the distinct step values used across nativeSteps,
// deduplicated. Service.NewService uses this (instead of a separately
// maintained literal) to pre-create a pending-bucket map for every native
// step, so nativeSteps and the pre-created maps can never drift out of sync
// — adding a new prefix/step pair to nativeSteps is automatically picked up
// here, rather than risking a nil-map panic on the first Gauge() call for it.
func nativeStepValues() []int {
	seen := make(map[int]bool, len(nativeSteps))
	out := make([]int, 0, len(nativeSteps))
	for _, step := range nativeSteps {
		if !seen[step] {
			seen[step] = true
			out = append(out, step)
		}
	}
	return out
}

// Supported profile IDs — unchanged from the old trafficrrd, same meaning.
const (
	Profile30d = "30d"
	Profile1y  = "1y"
	Profile5y  = "5y"
)

type stepRetention struct {
	StepSeconds int
	KeepFor     time.Duration
}

func profileRetention(profile string) []stepRetention {
	switch profile {
	case Profile1y:
		return []stepRetention{
			{1, 30 * time.Minute}, {10, 48 * time.Hour}, {30, 48 * time.Hour},
			{60, 14 * 24 * time.Hour}, {900, 180 * 24 * time.Hour}, {3600, 365 * 24 * time.Hour},
		}
	case Profile5y:
		return []stepRetention{
			{1, 15 * time.Minute}, {10, 48 * time.Hour}, {30, 48 * time.Hour},
			{60, 7 * 24 * time.Hour}, {900, 365 * 24 * time.Hour}, {3600, 5 * 365 * 24 * time.Hour},
		}
	default:
		return []stepRetention{
			{1, 2 * time.Hour}, {10, 48 * time.Hour}, {30, 48 * time.Hour},
			{60, 7 * 24 * time.Hour}, {900, 30 * 24 * time.Hour}, {3600, 90 * 24 * time.Hour},
		}
	}
}
