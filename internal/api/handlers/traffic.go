package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/hosttraffic"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TrafficHandler exposes per-host bandwidth (top talkers) from conntrack.
type TrafficHandler struct {
	svc *hosttraffic.Service
	db  *storage.DB
}

// NewTrafficHandler creates a TrafficHandler.
func NewTrafficHandler(svc *hosttraffic.Service, db *storage.DB) *TrafficHandler {
	return &TrafficHandler{svc: svc, db: db}
}

// TopTalkers returns the LAN hosts consuming the most bandwidth right now.
func (h *TrafficHandler) TopTalkers(w http.ResponseWriter, r *http.Request) {
	subnet := "192.168.3.0/24"
	if raw, _ := h.db.GetSetting("netsvc_config"); raw != "" {
		var c struct {
			SubnetCIDR string `json:"subnet_cidr"`
		}
		if json.Unmarshal([]byte(raw), &c) == nil && c.SubnetCIDR != "" {
			subnet = c.SubnetCIDR
		}
	}
	talkers, err := h.svc.TopTalkers(r.Context(), subnet)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(talkers) > 20 {
		talkers = talkers[:20]
	}
	writeJSON(w, http.StatusOK, talkers)
}
