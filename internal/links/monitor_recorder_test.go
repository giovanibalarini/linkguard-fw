package links_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

type recorderSpy struct {
	gauges []struct {
		series, label string
		v             float64
	}
	states []struct{ kind, label, state string }
}

func (r *recorderSpy) Gauge(series, label string, v float64) {
	r.gauges = append(r.gauges, struct {
		series, label string
		v             float64
	}{series, label, v})
}
func (r *recorderSpy) State(kind, label, state string) {
	r.states = append(r.states, struct{ kind, label, state string }{kind, label, state})
}

func TestMonitorRecordsGaugesAndState(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	linkSvc := links.NewService(db)
	l := &storage.Link{
		Name: "WAN1", Interface: "lo", Gateway: "127.0.0.1",
		DNSTest: "127.0.0.1", MonitorHosts: "127.0.0.1", Enabled: true,
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	rec := &recorderSpy{}
	mon := links.NewMonitor(db, linkSvc, time.Second, 1, rec, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	mon.RunOnceForTest(ctx)

	foundLatency, foundLoss, foundState := false, false, false
	for _, g := range rec.gauges {
		if g.series == "link.latency_ms" && g.label == "WAN1" {
			foundLatency = true
		}
		if g.series == "link.loss_pct" && g.label == "WAN1" {
			foundLoss = true
		}
	}
	for _, s := range rec.states {
		if s.kind == "link" && s.label == "WAN1" {
			foundState = true
		}
	}
	if !foundLatency || !foundLoss || !foundState {
		t.Fatalf("expected latency, loss and state to be recorded; got gauges=%v states=%v", rec.gauges, rec.states)
	}
}

// compile-time check that tsdb.Recorder is satisfiable by recorderSpy
var _ tsdb.Recorder = (*recorderSpy)(nil)
