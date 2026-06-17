package trafficrrd

import (
  "context"
  "encoding/json"
  "fmt"
  "log/slog"
  "strings"
  "sync"
  "time"

  "github.com/giovanibalarini/linkguard-fw/internal/storage"
  "github.com/giovanibalarini/linkguard-fw/internal/system"
)

const retentionProfileSettingKey = "traffic_retention_profile"

// Supported profile IDs.
const (
  Profile30d = "30d"
  Profile1y  = "1y"
  Profile5y  = "5y"
)

type aggregateBucket struct {
  bucketStart int64
  sumRx       float64
  sumTx       float64
  count       int
}

type stepRetention struct {
  StepSeconds int
  KeepFor     time.Duration
}

// HistoryResponse is returned by API handlers for chart rendering.
type HistoryResponse struct {
  Interface string                `json:"interface"`
  Range     string                `json:"range"`
  Step      int                   `json:"step_seconds"`
  Points    []storage.TrafficSample `json:"points"`
}

// Service collects, stores and queries traffic samples in RRD-like fixed archives.
type Service struct {
  db      *storage.DB
  sysCol  *system.Collector

  mu      sync.RWMutex
  profile string

  prevCounters map[string]struct {
    ts int64
    rx uint64
    tx uint64
  }
  pending map[int]map[string]*aggregateBucket
  lastPrune time.Time
}

func NewService(db *storage.DB) *Service {
  s := &Service{
    db:          db,
    sysCol:      system.NewCollector(),
    profile:     Profile30d,
    prevCounters: make(map[string]struct {
      ts int64
      rx uint64
      tx uint64
    }),
    pending: make(map[int]map[string]*aggregateBucket),
  }
  for _, step := range []int{60, 900, 3600} {
    s.pending[step] = make(map[string]*aggregateBucket)
  }
  if p, err := s.getProfile(); err == nil && p != "" {
    s.profile = p
  }
  return s
}

func (s *Service) Run(ctx context.Context) {
  ticker := time.NewTicker(1 * time.Second)
  defer ticker.Stop()

  s.collectOnce()

  for {
    select {
    case <-ctx.Done():
      return
    case <-ticker.C:
      s.collectOnce()
    }
  }
}

func (s *Service) collectOnce() {
  snap, err := s.sysCol.Collect()
  if err != nil {
    slog.Warn("traffic rrd collect failed", "err", err)
    return
  }

  now := time.Now().Unix()
  s.mu.RLock()
  activeProfile := s.profile
  s.mu.RUnlock()
  retention := profileRetention(activeProfile)

  for _, iface := range snap.Interfaces {
    if iface.Name == "lo" {
      continue
    }

    prev, ok := s.prevCounters[iface.Name]
    s.prevCounters[iface.Name] = struct {
      ts int64
      rx uint64
      tx uint64
    }{ts: now, rx: iface.RxBytes, tx: iface.TxBytes}

    if !ok {
      continue
    }

    dt := float64(now - prev.ts)
    if dt <= 0 {
      continue
    }

    rxDelta := float64(iface.RxBytes - prev.rx)
    txDelta := float64(iface.TxBytes - prev.tx)
    if rxDelta < 0 {
      rxDelta = 0
    }
    if txDelta < 0 {
      txDelta = 0
    }

    rxRate := rxDelta / dt
    txRate := txDelta / dt

    _ = s.db.UpsertTrafficSample(storage.TrafficSample{
      Interface: iface.Name,
      StepSeconds: 1,
      Timestamp: now,
      RxBps: rxRate,
      TxBps: txRate,
    })

    for _, step := range []int{60, 900, 3600} {
      s.rollup(step, iface.Name, now, rxRate, txRate)
    }
  }

  if time.Since(s.lastPrune) > 2*time.Minute {
    s.prune(retention)
    s.lastPrune = time.Now()
  }
}

func (s *Service) rollup(step int, iface string, ts int64, rxRate, txRate float64) {
  bucketStart := ts - (ts % int64(step))
  b := s.pending[step][iface]
  if b == nil {
    s.pending[step][iface] = &aggregateBucket{
      bucketStart: bucketStart,
      sumRx: rxRate,
      sumTx: txRate,
      count: 1,
    }
    return
  }

  if b.bucketStart == bucketStart {
    b.sumRx += rxRate
    b.sumTx += txRate
    b.count++
    return
  }

  _ = s.db.UpsertTrafficSample(storage.TrafficSample{
    Interface: iface,
    StepSeconds: step,
    Timestamp: b.bucketStart,
    RxBps: b.sumRx / float64(max(1, b.count)),
    TxBps: b.sumTx / float64(max(1, b.count)),
  })

  s.pending[step][iface] = &aggregateBucket{
    bucketStart: bucketStart,
    sumRx: rxRate,
    sumTx: txRate,
    count: 1,
  }
}

func (s *Service) prune(retention []stepRetention) {
  now := time.Now().Unix()
  for _, r := range retention {
    cutoff := now - int64(r.KeepFor.Seconds())
    _ = s.db.PruneTrafficSamples(r.StepSeconds, cutoff)
  }
}

func (s *Service) GetHistory(iface, rangeID string) (*HistoryResponse, error) {
  iface = strings.TrimSpace(iface)
  if iface == "" {
    return nil, fmt.Errorf("interface is required")
  }

  step, dur := rangeToStepDuration(rangeID)
  toUnix := time.Now().Unix()
  fromUnix := toUnix - int64(dur.Seconds())

  points, err := s.db.GetTrafficSamples(iface, step, fromUnix, toUnix)
  if err != nil {
    return nil, err
  }

  return &HistoryResponse{
    Interface: iface,
    Range: rangeID,
    Step: step,
    Points: points,
  }, nil
}

func (s *Service) GetProfile() string {
  s.mu.RLock()
  defer s.mu.RUnlock()
  return s.profile
}

func (s *Service) SetProfile(profile string) error {
  profile = strings.TrimSpace(strings.ToLower(profile))
  if profile != Profile30d && profile != Profile1y && profile != Profile5y {
    return fmt.Errorf("invalid profile")
  }
  payload, _ := json.Marshal(map[string]string{"profile": profile})
  if err := s.db.SetSetting(retentionProfileSettingKey, string(payload)); err != nil {
    return err
  }
  s.mu.Lock()
  s.profile = profile
  s.mu.Unlock()
  s.prune(profileRetention(profile))
  return nil
}

func (s *Service) getProfile() (string, error) {
  raw, err := s.db.GetSetting(retentionProfileSettingKey)
  if err != nil || strings.TrimSpace(raw) == "" {
    return "", err
  }
  var v map[string]string
  if err := json.Unmarshal([]byte(raw), &v); err != nil {
    return "", err
  }
  return strings.TrimSpace(strings.ToLower(v["profile"])), nil
}

func profileRetention(profile string) []stepRetention {
  switch profile {
  case Profile1y:
    return []stepRetention{
      {StepSeconds: 1, KeepFor: 30 * time.Minute},
      {StepSeconds: 60, KeepFor: 14 * 24 * time.Hour},
      {StepSeconds: 900, KeepFor: 180 * 24 * time.Hour},
      {StepSeconds: 3600, KeepFor: 365 * 24 * time.Hour},
    }
  case Profile5y:
    return []stepRetention{
      {StepSeconds: 1, KeepFor: 15 * time.Minute},
      {StepSeconds: 60, KeepFor: 7 * 24 * time.Hour},
      {StepSeconds: 900, KeepFor: 365 * 24 * time.Hour},
      {StepSeconds: 3600, KeepFor: 5 * 365 * 24 * time.Hour},
    }
  default:
    return []stepRetention{
      {StepSeconds: 1, KeepFor: 2 * time.Hour},
      {StepSeconds: 60, KeepFor: 7 * 24 * time.Hour},
      {StepSeconds: 900, KeepFor: 30 * 24 * time.Hour},
      {StepSeconds: 3600, KeepFor: 90 * 24 * time.Hour},
    }
  }
}

func rangeToStepDuration(rangeID string) (int, time.Duration) {
  switch strings.ToLower(strings.TrimSpace(rangeID)) {
  case "5m":
    return 1, 5 * time.Minute
  case "30m":
    return 1, 30 * time.Minute
  case "12h":
    return 60, 12 * time.Hour
  case "30d":
    return 900, 30 * 24 * time.Hour
  case "1y":
    return 3600, 365 * 24 * time.Hour
  case "5y":
    return 3600, 5 * 365 * 24 * time.Hour
  default:
    return 60, 12 * time.Hour
  }
}

func max(a, b int) int {
  if a > b {
    return a
  }
  return b
}
