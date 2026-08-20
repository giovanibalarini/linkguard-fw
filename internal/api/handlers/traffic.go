package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/hosttraffic"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// TrafficHandler exposes per-host bandwidth (top talkers) from conntrack.
type TrafficHandler struct {
	svc *hosttraffic.Service
	db  *storage.DB
	rrd *tsdb.Service
}

// NewTrafficHandler creates a TrafficHandler.
func NewTrafficHandler(svc *hosttraffic.Service, db *storage.DB, rrd *tsdb.Service) *TrafficHandler {
	return &TrafficHandler{svc: svc, db: db, rrd: rrd}
}

// HostHistory devolve o histórico de consumo de um host (issue #113).
//
// O host é identificado pelo MAC, que é a identidade do inventário — a mesma
// que bloqueio e alias usam. O IP não serve: ele muda com o lease e partiria o
// histórico do aparelho em dois.
func (h *TrafficHandler) HostHistory(w http.ResponseWriter, r *http.Request) {
	mac := validate.NormalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		writeError(w, http.StatusBadRequest, "mac inválido")
		return
	}
	resp, err := h.rrd.GetHostHistory(mac, r.URL.Query().Get("range"))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
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
		writeInternalError(w, err)
		return
	}
	if len(talkers) > 20 {
		talkers = talkers[:20]
	}
	writeJSON(w, http.StatusOK, talkers)
}
