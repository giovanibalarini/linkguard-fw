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

// bucket accumulates one time window's worth of readings.
//
// sum/count double as the weight for a count-weighted average:
//   - For a native-step bucket (built by accumulate), each raw Gauge() call
//     adds its value to sum and increments count by 1, so count is the raw
//     sample count and avg = sum/count is a plain average of raw samples.
//   - For a derived-step bucket (built by rollInto, merging native buckets
//     into a longer window), sum accumulates avg*count from each
//     contributing native bucket and count accumulates that native bucket's
//     raw sample count — so count is still the total raw sample count the
//     derived bucket represents, and avg = sum/count is a true count-weighted
//     average rather than an average-of-averages.
type bucket struct {
	start    int64
	min, max float64
	sum      float64
	count    int
}

// closedBucket is a bucket that accumulate() closed on a rollover, queued for
// closeBucket/flush on the next tick(). Appending to this queue is the only
// thing accumulate() does on rollover — no disk I/O — so Gauge() (which calls
// accumulate synchronously) never blocks on s.db, even when a sample crosses
// a bucket boundary. tick(), running on its own ticker goroutine, drains the
// queue and is the sole writer to s.db.
type closedBucket struct {
	step   int
	series string
	label  string
	b      *bucket
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
	closed  []closedBucket                  // buckets closed by a rollover, awaiting flush by tick()

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
	// Pre-create a pending map for every native step plus every derived
	// step. The native list is derived from nativeSteps itself (not a
	// separate hardcoded literal) so a future series added to nativeSteps
	// with a new step value can never hit a nil map entry in accumulate().
	for _, step := range append(nativeStepValues(), derivedSteps...) {
		s.pending[step] = make(map[seriesLabel]*bucket)
	}
	if p, err := db.GetSetting(retentionProfileSettingKey); err != nil {
		slog.Warn("tsdb: load retention profile failed, using default", "err", err)
	} else if p != "" {
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

// accumulate must be called with s.mu held. It only ever touches in-memory
// state (s.pending, s.closed) — never s.db — so it's safe to call
// synchronously from Gauge() no matter whether the sample lands in the
// current bucket or closes it on a rollover.
func (s *Service) accumulate(step int, series, label string, v float64, now int64) {
	key := seriesLabel{series, label}
	bucketStart := now - (now % int64(step))
	b := s.pending[step][key]
	if b == nil || b.start != bucketStart {
		if b != nil {
			// Rollover: the just-closed bucket must not be lost, but it also
			// must not be flushed here — queue it for tick() to write.
			s.closed = append(s.closed, closedBucket{step: step, series: series, label: label, b: b})
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

// closeBucket must be called with s.mu held. It computes the final
// min/avg/max for a closed bucket and appends it to out — it does not touch
// s.db itself, so building the write list stays lock-scoped and I/O-free;
// the caller (tick) performs the actual writes after releasing s.mu. For
// native steps it also rolls the bucket's min/avg/max into every derived
// step's pending bucket, which may itself close a derived bucket and append
// that too (recursively, via rollInto).
func (s *Service) closeBucket(out *[]storage.MetricSample, step int, series, label string, b *bucket) {
	avg := b.sum / float64(b.count)
	*out = append(*out, storage.MetricSample{
		Series: series, Label: label, StepSeconds: step,
		TsUnix: b.start, VMin: b.min, VAvg: avg, VMax: b.max,
	})
	if isDerivedStep(step) {
		return
	}
	for _, derived := range derivedSteps {
		s.rollInto(out, derived, series, label, b.min, avg, b.max, b.count, b.start)
	}
}

// rollInto must be called with s.mu held. It merges one native bucket's
// min/avg/max (and the raw sample count it represents) into the current
// bucket of a longer (derived) step. min/max propagate directly; avg is
// folded in count-weighted — see the bucket doc comment.
func (s *Service) rollInto(out *[]storage.MetricSample, step int, series, label string, min, avg, max float64, count int, now int64) {
	key := seriesLabel{series, label}
	bucketStart := now - (now % int64(step))
	b := s.pending[step][key]
	if b == nil || b.start != bucketStart {
		if b != nil {
			s.closeBucket(out, step, series, label, b)
		}
		b = &bucket{start: bucketStart, min: min, max: max, sum: avg * float64(count), count: count}
		s.pending[step][key] = b
		return
	}
	if min < b.min {
		b.min = min
	}
	if max > b.max {
		b.max = max
	}
	b.sum += avg * float64(count)
	b.count += count
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
		if err := s.db.CloseOpenStateInterval(kind, label, now); err != nil {
			slog.Warn("tsdb: close state interval failed", "kind", kind, "label", label, "err", err)
		}
	}
	if err := s.db.OpenStateInterval(kind, label, state, now); err != nil {
		slog.Warn("tsdb: open state interval failed", "kind", kind, "label", label, "state", state, "err", err)
	}
	// The in-memory model still advances even if the write above failed —
	// State() has no error return and this stays best-effort — but the
	// warning above ensures a persistence gap is at least visible in logs
	// instead of silently desyncing memory from disk.
	s.states[key] = &openState{state: state, startedAt: now}
}

// Run starts the 1s writer tick. It samples interface traffic and flushes
// any bucket whose window has closed and prunes old data periodically.
// Blocks until ctx is done.
func (s *Service) Run(ctx context.Context) {
	slog.Info("tsdb service started")
	sampler := NewTrafficSampler(s)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			sampler.SampleOnce(now)
			s.tick(now)
		}
	}
}

// tick is the tsdb package's single writer path: it is only ever called from
// Run's ticker goroutine (or, in tests, FlushForTest). It has two jobs:
//  1. Drain s.closed — buckets that accumulate() already closed on a
//     rollover but, per the no-disk-I/O-in-Gauge() constraint, could not
//     flush itself.
//  2. Boundary-check every still-open pending bucket, so a series that stops
//     receiving samples still has its last bucket closed on schedule instead
//     of waiting forever for a sample that never comes.
//
// All s.pending/s.closed bookkeeping happens under s.mu, but that work is
// pure in-memory arithmetic — the actual s.db writes happen in a second pass
// after s.mu is released, so a slow disk write never makes a concurrent
// Gauge()/State() call block on the mutex for I/O-scale time.
func (s *Service) tick(now int64) {
	var toWrite []storage.MetricSample

	s.mu.Lock()
	for _, cb := range s.closed {
		s.closeBucket(&toWrite, cb.step, cb.series, cb.label, cb.b)
	}
	s.closed = s.closed[:0]

	// Steps are visited smallest-first: a native bucket closing here can
	// roll a fresh sample into a derived bucket via rollInto, and visiting
	// derived steps after native ones in the same pass ensures that roll-in
	// is merged before the derived bucket's own boundary check runs, instead
	// of landing in a bucket already skipped this tick (Go map iteration
	// order is randomized, so this must not rely on range order).
	steps := make([]int, 0, len(s.pending))
	for step := range s.pending {
		steps = append(steps, step)
	}
	sort.Ints(steps)
	for _, step := range steps {
		m := s.pending[step]
		for key, b := range m {
			if now-(now%int64(step)) != b.start {
				s.closeBucket(&toWrite, step, key.series, key.label, b)
				delete(m, key)
			}
		}
	}
	s.mu.Unlock()

	for _, rec := range toWrite {
		if err := s.db.UpsertMetricSample(rec); err != nil {
			slog.Warn("tsdb: upsert metric sample failed", "series", rec.Series, "label", rec.Label, "step", rec.StepSeconds, "err", err)
		}
	}

	if time.Since(s.lastPrune) > 2*time.Minute {
		s.prune(now)
		s.lastPrune = time.Now()
	}
}

func (s *Service) prune(now int64) {
	for _, keep := range profileRetention(s.profile()) {
		if err := s.db.PruneMetricSamples(keep.StepSeconds, now-int64(keep.KeepFor.Seconds())); err != nil {
			slog.Warn("tsdb: prune metric samples failed", "step", keep.StepSeconds, "err", err)
		}
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

// GaugeForTest calls accumulate with an explicit timestamp instead of
// time.Now(), so tests can deterministically force a sample to land in a
// specific bucket or cross a bucket boundary (a rollover) without racing the
// wall clock. Test-only.
func (s *Service) GaugeForTest(series, label string, v float64, at int64) {
	step := nativeStep(series)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accumulate(step, series, label, v, at)
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
