// Package tsdb is the generic time-series substrate for LinkGuard: gauges with
// min/avg/max per bucket, and states as intervals. It absorbs what used to be
// internal/trafficrrd (traffic-only, average-only) — traffic is now just one
// more series.
package tsdb

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Recorder is the write surface producers use. Gauge accumulates a reading
// into the current bucket in memory; it must never block on disk — the
// service's own goroutine does all writes, on its own ticker. State opens a
// new interval only when the state actually changes.
type Recorder interface {
	Gauge(series, label string, v float64)
	State(kind, label, state string)
}

type bucket struct {
	start    int64
	min, max float64
	sum      float64
	count    int
}

type openState struct {
	state     string
	startedAt int64
}

// Service is the tsdb writer/reader. One instance per process, shared by every
// producer via the Recorder interface.
type Service struct {
	db *storage.DB

	mu      sync.Mutex
	pending map[int]map[seriesLabel]*bucket // step -> (series,label) -> current bucket

	stateMu sync.Mutex
	states  map[stateKey]*openState

	lastPrune time.Time

	profileMu    sync.RWMutex
	profileCache string
}

type seriesLabel struct{ series, label string }
type stateKey struct{ kind, label string }

// NewService creates a tsdb Service.
func NewService(db *storage.DB) *Service {
	s := &Service{
		db:      db,
		pending: make(map[int]map[seriesLabel]*bucket),
		states:  make(map[stateKey]*openState),
	}
	for _, step := range append([]int{1, 10, 30}, derivedSteps...) {
		s.pending[step] = make(map[seriesLabel]*bucket)
	}
	if p, _ := db.GetSetting(retentionProfileSettingKey); p != "" {
		s.profileCache = p
	}
	return s
}

// Gauge accumulates one reading into the in-memory bucket for series+label at
// its native step. Memory-only — see the package doc.
func (s *Service) Gauge(series, label string, v float64) {
	step := nativeStep(series)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accumulate(step, series, label, v, time.Now().Unix())
}

// accumulate must be called with s.mu held.
func (s *Service) accumulate(step int, series, label string, v float64, now int64) {
	key := seriesLabel{series, label}
	bucketStart := now - (now % int64(step))
	b := s.pending[step][key]
	if b == nil || b.start != bucketStart {
		if b != nil {
			s.flushBucket(step, series, label, b)
		}
		b = &bucket{start: bucketStart, min: v, max: v, sum: v, count: 1}
		s.pending[step][key] = b
		return
	}
	if v < b.min {
		b.min = v
	}
	if v > b.max {
		b.max = v
	}
	b.sum += v
	b.count++
}

// flushBucket writes a closed bucket to disk and, for the native steps (not
// the derived ones), feeds its average into every derived-step bucket so the
// rollup chain builds up incrementally rather than re-scanning raw data.
func (s *Service) flushBucket(step int, series, label string, b *bucket) {
	avg := b.sum / float64(b.count)
	_ = s.db.UpsertMetricSample(storage.MetricSample{
		Series: series, Label: label, StepSeconds: step,
		TsUnix: b.start, VMin: b.min, VAvg: avg, VMax: b.max,
	})
	if isDerivedStep(step) {
		return
	}
	for _, derived := range derivedSteps {
		s.rollInto(derived, series, label, b.min, avg, b.max, b.start)
	}
}

// rollInto merges one native bucket's min/avg/max into the current bucket of
// a longer (derived) step. min/max propagate directly; avg is folded as a new
// sample into a running mean — see mergeAvg.
func (s *Service) rollInto(step int, series, label string, min, avg, max float64, now int64) {
	key := seriesLabel{series, label}
	bucketStart := now - (now % int64(step))
	b := s.pending[step][key]
	if b == nil || b.start != bucketStart {
		if b != nil {
			s.flushBucket(step, series, label, b)
		}
		b = &bucket{start: bucketStart, min: min, max: max, sum: avg, count: 1}
		s.pending[step][key] = b
		return
	}
	if min < b.min {
		b.min = min
	}
	if max > b.max {
		b.max = max
	}
	b.sum += avg
	b.count++
}

func isDerivedStep(step int) bool {
	for _, d := range derivedSteps {
		if d == step {
			return true
		}
	}
	return false
}

// State opens a new interval for (kind, label) only if the state actually
// changed — repeating the same state is a no-op, matching the "state is a
// level, not an event" model.
func (s *Service) State(kind, label, state string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.transitionState(kind, label, state, time.Now().Unix())
}

// transitionState must be called with s.stateMu held.
func (s *Service) transitionState(kind, label, state string, now int64) {
	key := stateKey{kind, label}
	cur := s.states[key]
	if cur != nil && cur.state == state {
		return
	}
	if cur != nil {
		_ = s.db.CloseOpenStateInterval(kind, label, now)
	}
	_ = s.db.OpenStateInterval(kind, label, state, now)
	s.states[key] = &openState{state: state, startedAt: now}
}

// Run starts the 1s writer tick. It flushes any bucket whose window has
// closed and prunes old data periodically. Blocks until ctx is done.
func (s *Service) Run(ctx context.Context) {
	slog.Info("tsdb service started")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(time.Now().Unix())
		}
	}
}

func (s *Service) tick(now int64) {
	s.mu.Lock()
	// Process steps smallest-first. A native bucket closing (e.g. step 10)
	// can roll a fresh sample into a derived bucket (step 60) via rollInto;
	// visiting derived steps after native ones in the same tick ensures that
	// roll-in is merged before the derived bucket's own window-close check
	// runs, instead of landing in a bucket already skipped this tick (Go map
	// iteration order is randomized, so this must not rely on range order).
	steps := make([]int, 0, len(s.pending))
	for step := range s.pending {
		steps = append(steps, step)
	}
	sort.Ints(steps)
	for _, step := range steps {
		m := s.pending[step]
		for key, b := range m {
			if now-(now%int64(step)) != b.start {
				s.flushBucket(step, key.series, key.label, b)
				delete(m, key)
			}
		}
	}
	s.mu.Unlock()

	if time.Since(s.lastPrune) > 2*time.Minute {
		s.prune(now)
		s.lastPrune = time.Now()
	}
}

func (s *Service) prune(now int64) {
	for _, keep := range profileRetention(s.profile()) {
		_ = s.db.PruneMetricSamples(keep.StepSeconds, now-int64(keep.KeepFor.Seconds()))
	}
}

// FlushForTest forces every pending bucket whose window would have closed by
// "now" to flush, without waiting for the real ticker. Test-only.
func (s *Service) FlushForTest(now int64) {
	s.tick(now)
}

// StateForTest calls transitionState with an explicit timestamp instead of
// time.Now(), so interval tests are deterministic. Test-only.
func (s *Service) StateForTest(kind, label, state string, at int64) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.transitionState(kind, label, state, at)
}

const retentionProfileSettingKey = "traffic_retention_profile"

func (s *Service) profile() string {
	s.profileMu.RLock()
	defer s.profileMu.RUnlock()
	if s.profileCache == "" {
		return Profile30d
	}
	return s.profileCache
}

// GetProfile returns the active retention profile.
func (s *Service) GetProfile() string {
	return s.profile()
}

// SetProfile persists the retention profile and prunes immediately so a
// shorter profile takes effect right away instead of waiting for the next tick.
func (s *Service) SetProfile(profile string) error {
	if profile != Profile30d && profile != Profile1y && profile != Profile5y {
		return fmt.Errorf("invalid profile")
	}
	if err := s.db.SetSetting(retentionProfileSettingKey, profile); err != nil {
		return err
	}
	s.profileMu.Lock()
	s.profileCache = profile
	s.profileMu.Unlock()
	s.prune(time.Now().Unix())
	return nil
}
