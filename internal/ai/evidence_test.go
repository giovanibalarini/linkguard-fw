package ai_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestBuildEvidenceSummarizesEpisodesNotRawPoints(t *testing.T) {
	db := newTestDB(t)
	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)

	now := int64(100000)
	// Two degraded episodes for one link.
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-3600)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "degraded", now-1800)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-1790)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "degraded", now-900)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-885)

	ev, err := ai.BuildEvidence(tsdbSvc, alertSvc, []string{"WAN SUMICITY"}, now-7200, now)
	if err != nil {
		t.Fatalf("BuildEvidence: %v", err)
	}
	if len(ev.Links) != 1 {
		t.Fatalf("expected 1 link summary, got %d", len(ev.Links))
	}
	if ev.Links[0].EpisodeCount != 2 {
		t.Fatalf("expected 2 episodes counted, got %d", ev.Links[0].EpisodeCount)
	}
	if ev.Links[0].Name != "WAN SUMICITY" {
		t.Fatalf("expected link name WAN SUMICITY, got %q", ev.Links[0].Name)
	}
}

// TestBuildEvidenceMinEpisodeSecKeepsLegitimateZero guards against using
// MinEpisodeSec == 0 as a "not yet set" sentinel: an episode that starts and
// ends within the same second is a real, legitimate 0-second duration (an
// instantaneous flap), not an absence of data. If a later, longer episode
// were allowed to overwrite that 0 just because the field still reads 0, the
// reported minimum would silently jump upward and understate how briefly the
// link can flap.
//
// NOTE: this deliberately produces a same-second close+reopen (StartedAt ==
// EndedAt for the first "degraded" interval), which logs one benign
// "tsdb: open state interval failed ... UNIQUE constraint" WARN — the
// immediately-following interval's started_at collides with the just-closed
// row's started_at, a pre-existing internal/tsdb characteristic (any
// 0-duration interval's boundary timestamp is shared with the interval that
// closes it) unrelated to internal/ai and out of this task's scope. The
// warning is swallowed (best-effort write, see tsdb.transitionState) and the
// in-memory state still advances correctly, so the assertions below still
// exercise real, DB-persisted data — see task-2-report.md.
func TestBuildEvidenceMinEpisodeSecKeepsLegitimateZero(t *testing.T) {
	db := newTestDB(t)
	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)

	now := int64(100000)
	// First episode: degraded and back to online within the same second (0s).
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-3600)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "degraded", now-3000)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-3000)
	// Second episode: a real, much longer 100s outage.
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "degraded", now-900)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-800)

	ev, err := ai.BuildEvidence(tsdbSvc, alertSvc, []string{"WAN SUMICITY"}, now-7200, now)
	if err != nil {
		t.Fatalf("BuildEvidence: %v", err)
	}
	if len(ev.Links) != 1 {
		t.Fatalf("expected 1 link summary, got %d", len(ev.Links))
	}
	got := ev.Links[0]
	if got.EpisodeCount != 2 {
		t.Fatalf("expected 2 episodes, got %d", got.EpisodeCount)
	}
	if got.MinEpisodeSec != 0 {
		t.Errorf("expected MinEpisodeSec to stay 0 (the real first episode's duration), got %d", got.MinEpisodeSec)
	}
	if got.MaxEpisodeSec != 100 {
		t.Errorf("expected MaxEpisodeSec 100, got %d", got.MaxEpisodeSec)
	}
}
