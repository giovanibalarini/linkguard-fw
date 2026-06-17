package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
	"github.com/giovanibalarini/linkguard-fw/internal/trafficrrd"
)

const interfaceAliasSettingKey = "interface_aliases"

// SystemHandler handles system status requests.
type SystemHandler struct {
	sysCol *system.Collector
	db     *storage.DB
	rrdSvc *trafficrrd.Service
}

// NewSystemHandler creates a SystemHandler.
func NewSystemHandler(sysCol *system.Collector, db *storage.DB, rrdSvc *trafficrrd.Service) *SystemHandler {
	return &SystemHandler{sysCol: sysCol, db: db, rrdSvc: rrdSvc}
}

// Status returns current system resource metrics.
func (h *SystemHandler) Status(w http.ResponseWriter, r *http.Request) {
	m, err := h.sysCol.Collect()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to collect system metrics")
		return
	}
	aliases, err := h.getInterfaceAliases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load interface aliases")
		return
	}
	for i := range m.Interfaces {
		if alias := strings.TrimSpace(aliases[m.Interfaces[i].Name]); alias != "" {
			m.Interfaces[i].Alias = alias
		}
	}

	type response struct {
		*system.Metrics
		UptimeStr string `json:"uptime_str"`
	}

	writeJSON(w, http.StatusOK, response{
		Metrics:   m,
		UptimeStr: system.UptimeString(m.UptimeSeconds),
	})
}

// ListInterfaceAliases returns persisted interface aliases.
func (h *SystemHandler) ListInterfaceAliases(w http.ResponseWriter, r *http.Request) {
	aliases, err := h.getInterfaceAliases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, aliases)
}

// UpsertInterfaceAlias creates, updates, or removes an interface alias.
func (h *SystemHandler) UpsertInterfaceAlias(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Interface string `json:"interface"`
		Alias     string `json:"alias"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	iface := strings.TrimSpace(body.Interface)
	if iface == "" {
		writeError(w, http.StatusBadRequest, "interface is required")
		return
	}
	if len(iface) > 64 {
		writeError(w, http.StatusBadRequest, "interface name too long")
		return
	}
	alias := strings.TrimSpace(body.Alias)
	if len(alias) > 64 {
		writeError(w, http.StatusBadRequest, "alias too long")
		return
	}

	aliases, err := h.getInterfaceAliases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if alias == "" {
		delete(aliases, iface)
	} else {
		aliases[iface] = alias
	}
	if err := h.saveInterfaceAliases(aliases); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"interface": iface,
		"alias":     alias,
	})
}

func (h *SystemHandler) getInterfaceAliases() (map[string]string, error) {
	raw, err := h.db.GetSetting(interfaceAliasSettingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read interface aliases: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}

	var aliases map[string]string
	if err := json.Unmarshal([]byte(raw), &aliases); err != nil {
		return nil, fmt.Errorf("invalid interface aliases payload")
	}

	clean := make(map[string]string, len(aliases))
	for iface, alias := range aliases {
		iface = strings.TrimSpace(iface)
		alias = strings.TrimSpace(alias)
		if iface == "" || alias == "" {
			continue
		}
		clean[iface] = alias
	}
	return clean, nil
}

func (h *SystemHandler) saveInterfaceAliases(aliases map[string]string) error {
	payload, err := json.Marshal(aliases)
	if err != nil {
		return fmt.Errorf("failed to encode interface aliases: %w", err)
	}
	if err := h.db.SetSetting(interfaceAliasSettingKey, string(payload)); err != nil {
		return fmt.Errorf("failed to persist interface aliases: %w", err)
	}
	return nil
}

// TrafficHistory returns RRD-like traffic history for an interface and range.
func (h *SystemHandler) TrafficHistory(w http.ResponseWriter, r *http.Request) {
	iface := strings.TrimSpace(r.URL.Query().Get("iface"))
	rangeID := strings.TrimSpace(r.URL.Query().Get("range"))
	if rangeID == "" {
		rangeID = "12h"
	}
	res, err := h.rrdSvc.GetHistory(iface, rangeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// GetTrafficRetention returns the active retention profile.
func (h *SystemHandler) GetTrafficRetention(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"profile": h.rrdSvc.GetProfile()})
}

// SetTrafficRetention updates the active retention profile.
func (h *SystemHandler) SetTrafficRetention(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Profile string `json:"profile"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.rrdSvc.SetProfile(body.Profile); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"profile": h.rrdSvc.GetProfile()})
}
