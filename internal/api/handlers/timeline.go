package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// TimelineHandler serves the correlated diagnostic timeline: gauges (with
// min/avg/max), state intervals, and the alerts raised in the window — all
// against one shared time axis so the frontend can render them stacked.
type TimelineHandler struct {
	tsdbSvc  *tsdb.Service
	alertSvc *alerts.Service
}

func NewTimelineHandler(tsdbSvc *tsdb.Service, alertSvc *alerts.Service) *TimelineHandler {
	return &TimelineHandler{tsdbSvc: tsdbSvc, alertSvc: alertSvc}
}

type timelineResponse struct {
	StepSeconds int                   `json:"step_seconds"`
	Series      []tsdb.TimelineSeries `json:"series"`
	States      []tsdb.TimelineState  `json:"states"`
	Alerts      []timelineAlert       `json:"alerts"`
}

type timelineAlert struct {
	Ts       int64  `json:"ts"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// Timeline handles GET /api/monitoring/timeline?from=<unix>&to=<unix>&series=<csv of series:label>&states=<csv of kind:label>
func (h *TimelineHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		writeError(w, http.StatusBadRequest, "from and to are required (unix seconds)")
		return
	}
	from, err := strconv.ParseInt(fromStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid from")
		return
	}
	to, err := strconv.ParseInt(toStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid to")
		return
	}
	if to <= from {
		writeError(w, http.StatusBadRequest, "to must be after from")
		return
	}

	req := tsdb.TimelineRequest{FromUnix: from, ToUnix: to}
	for _, sl := range parsePairs(r.URL.Query().Get("series")) {
		req.Series = append(req.Series, tsdb.SeriesLabel{Series: sl[0], Label: sl[1]})
	}
	for _, kl := range parsePairs(r.URL.Query().Get("states")) {
		req.States = append(req.States, tsdb.StateKindLabel{Kind: kl[0], Label: kl[1]})
	}

	step, series, states, err := h.tsdbSvc.Timeline(req)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if series == nil {
		series = []tsdb.TimelineSeries{}
	}
	if states == nil {
		states = []tsdb.TimelineState{}
	}

	all, err := h.alertSvc.List(false, 500)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	alertsOut := []timelineAlert{}
	for _, a := range all {
		ts := a.CreatedAt.Unix()
		if ts < from || ts > to {
			continue
		}
		alertsOut = append(alertsOut, timelineAlert{Ts: ts, Type: a.Type, Severity: a.Severity, Title: a.Title})
	}

	writeJSON(w, http.StatusOK, timelineResponse{
		StepSeconds: step, Series: series, States: states, Alerts: alertsOut,
	})
}

// parsePairs splits a CSV of "key:value" entries (label values may contain
// spaces, encoded as "+" by the query string — net/url already decodes that).
func parsePairs(csv string) [][2]string {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil
	}
	var out [][2]string
	for _, part := range strings.Split(csv, ",") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out = append(out, [2]string{kv[0], kv[1]})
	}
	return out
}
