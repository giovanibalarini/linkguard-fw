package ai

import (
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// LinkSummary is the pre-computed, per-link shape of an evidence window — the
// facts the model reasons over, never raw timeline points. ~800 tokens of
// facts is roughly 9x cheaper than a few thousand raw samples, and the model
// reasons better over facts than it does parsing a CSV of numbers.
type LinkSummary struct {
	Name          string  `json:"name"`
	EpisodeCount  int     `json:"episode_count"`
	MinEpisodeSec int     `json:"min_episode_sec"`
	MaxEpisodeSec int     `json:"max_episode_sec"`
	PeakLatencyMs float64 `json:"peak_latency_ms"`
	PeakLossPct   float64 `json:"peak_loss_pct"`
}

// AlertRef is a minimal alert reference — type/severity/time only, not the
// full message (the message is already summarized elsewhere in Evidence).
type AlertRef struct {
	Ts       int64  `json:"ts"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
}

// Evidence is what gets sent to the model — pre-computed facts about a
// window, never a raw series dump.
type Evidence struct {
	Period        string        `json:"period"`
	Links         []LinkSummary `json:"links"`
	CarrierEvents int           `json:"carrier_events"`
	TrafficLevel  string        `json:"traffic_level"`
	RecentAlerts  []AlertRef    `json:"recent_alerts"`
}

// BuildEvidence queries tsdb for the state intervals and gauge extremes of
// each named link in [fromUnix, toUnix] and reduces them to LinkSummary
// facts. This is the same underlying data the diagnostic timeline (Project 1)
// renders — reused here, not re-derived.
func BuildEvidence(tsdbSvc *tsdb.Service, alertSvc *alerts.Service, linkNames []string, fromUnix, toUnix int64) (Evidence, error) {
	ev := Evidence{
		Period: formatPeriod(fromUnix, toUnix),
		Links:  []LinkSummary{},
	}

	for _, name := range linkNames {
		_, series, states, err := tsdbSvc.Timeline(tsdb.TimelineRequest{
			FromUnix: fromUnix, ToUnix: toUnix,
			Series: []tsdb.SeriesLabel{
				{Series: "link.latency_ms", Label: name},
				{Series: "link.loss_pct", Label: name},
			},
			States: []tsdb.StateKindLabel{{Kind: "link", Label: name}},
		})
		if err != nil {
			return Evidence{}, err
		}
		ev.Links = append(ev.Links, summarizeLink(name, series, states))
	}

	all, err := alertSvc.List(false, 200)
	if err != nil {
		return Evidence{}, err
	}
	for _, a := range all {
		ts := a.CreatedAt.Unix()
		if ts < fromUnix || ts > toUnix {
			continue
		}
		ev.RecentAlerts = append(ev.RecentAlerts, AlertRef{Ts: ts, Type: a.Type, Severity: a.Severity})
	}
	ev.TrafficLevel = "ocioso" // conservative placeholder — refined by a follow-up
	// task once Project 1's if.rx_bps/if.tx_bps thresholds for "moderado"/
	// "saturado" are calibrated against real production traffic levels; do not
	// invent threshold numbers here without that data.

	return ev, nil
}

func summarizeLink(name string, series []tsdb.TimelineSeries, states []tsdb.TimelineState) LinkSummary {
	s := LinkSummary{Name: name}

	for _, st := range states {
		if st.State == "online" || st.State == "up" {
			continue
		}
		s.EpisodeCount++
		dur := 0
		if st.EndedAt != nil {
			dur = int(*st.EndedAt - st.StartedAt)
		}
		// NOTE: deliberately NOT "s.MinEpisodeSec == 0" here — see
		// task-2-report.md. A state interval that opens and closes within
		// the same second is a legitimate 0-second episode (an
		// instantaneous flap), not "no episode recorded yet". Using the
		// field's zero value as a sentinel would let any later, longer
		// episode overwrite that real 0 the moment it's processed, since
		// the field would still read 0. EpisodeCount == 1 marks "this is
		// the first episode we've seen" unambiguously, independent of
		// what duration that first episode happens to have.
		if s.EpisodeCount == 1 || dur < s.MinEpisodeSec {
			s.MinEpisodeSec = dur
		}
		if dur > s.MaxEpisodeSec {
			s.MaxEpisodeSec = dur
		}
	}

	for _, sr := range series {
		for _, p := range sr.Points {
			if sr.Name == "link.latency_ms" && p.Max > s.PeakLatencyMs {
				s.PeakLatencyMs = p.Max
			}
			if sr.Name == "link.loss_pct" && p.Max > s.PeakLossPct {
				s.PeakLossPct = p.Max
			}
		}
	}
	return s
}

func formatPeriod(fromUnix, toUnix int64) string {
	return fmtUnix(fromUnix) + "/" + fmtUnix(toUnix)
}

func fmtUnix(u int64) string {
	return time.Unix(u, 0).UTC().Format(time.RFC3339)
}
