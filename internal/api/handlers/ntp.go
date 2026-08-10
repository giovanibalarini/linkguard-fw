package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
)

const ntpCfgKey = "ntp_config"
const ntpApplyStatusKey = "ntp_last_apply"

// reNTPServer guards values rendered into the chrony drop-in via string
// formatting — hostname or IP, no spaces/quotes/control characters.
var reNTPServer = regexp.MustCompile(`^[a-zA-Z0-9.:-]{1,253}$`)

func validNTPServer(s string) bool { return reNTPServer.MatchString(s) }

// NTPHandler manages NTP server/timezone config through internal/timesync.
// Same auto-apply-on-save pattern as NetsvcHandler (DHCP/DNS,
// internal/api/handlers/netsvc.go) — reuses its applyStatus type and
// autoApplier/autoApplyDelay rather than duplicating them.
type NTPHandler struct {
	db       *storage.DB
	svc      *timesync.Service
	alertSvc *alerts.Service
	applier  *autoApplier
}

// NewNTPHandler creates an NTPHandler. Saving config auto-applies
// (debounced), matching NetsvcHandler's convention.
func NewNTPHandler(db *storage.DB, svc *timesync.Service, alertSvc *alerts.Service) *NTPHandler {
	h := &NTPHandler{db: db, svc: svc, alertSvc: alertSvc}
	h.applier = newAutoApplier(autoApplyDelay, func() { _ = h.doReload(context.Background()) })
	return h
}

func (h *NTPHandler) getConfig() timesync.Config {
	cfg := timesync.DefaultConfig()
	if raw, _ := h.db.GetSetting(ntpCfgKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

func (h *NTPHandler) saveConfig(c timesync.Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return h.db.SetSetting(ntpCfgKey, string(b))
}

// lastApplyStatus returns the persisted result of the most recent apply, or
// nil if nothing has been applied yet — same "never attempted" vs "attempted
// and failed" distinction as NetsvcHandler.lastApplyStatus.
func (h *NTPHandler) lastApplyStatus() *applyStatus {
	raw, _ := h.db.GetSetting(ntpApplyStatusKey)
	if raw == "" {
		return nil
	}
	var st applyStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil
	}
	return &st
}

// doReload applies the current config and records the result, shared by
// the debounced auto-apply and the manual "Aplicar agora" button.
func (h *NTPHandler) doReload(ctx context.Context) error {
	err := h.svc.ReloadConfig(ctx, h.getConfig())
	st := applyStatus{OK: err == nil, At: time.Now().Unix()}
	if err != nil {
		st.Error = err.Error()
		if h.alertSvc != nil {
			_ = h.alertSvc.RuleError("Falha ao aplicar configuração de NTP: " + err.Error())
		}
	}
	if b, mErr := json.Marshal(st); mErr == nil {
		_ = h.db.SetSetting(ntpApplyStatusKey, string(b))
	}
	return err
}

func (h *NTPHandler) scheduleApply() {
	if h.applier != nil {
		h.applier.schedule()
	}
}

// GetNTP returns the current config, live status, available timezones, and
// last-apply result in one payload.
func (h *NTPHandler) GetNTP(w http.ResponseWriter, r *http.Request) {
	zones, err := h.svc.ListTimezones(r.Context())
	if err != nil {
		zones = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":     h.getConfig(),
		"status":     h.svc.Status(r.Context()),
		"timezones":  zones,
		"last_apply": h.lastApplyStatus(),
	})
}

// UpdateNTPConfig updates servers/timezone and schedules the debounced
// auto-apply.
func (h *NTPHandler) UpdateNTPConfig(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Servers  []string `json:"servers"`
		Timezone string   `json:"timezone"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	servers := []string{}
	for _, srv := range b.Servers {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if !validNTPServer(srv) {
			writeError(w, http.StatusBadRequest, "servidor NTP inválido: "+srv)
			return
		}
		servers = append(servers, srv)
	}
	cfg := timesync.Config{Servers: servers, Timezone: strings.TrimSpace(b.Timezone)}
	if err := h.saveConfig(cfg); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "ntp.config", "ntp", "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, cfg)
}

// Apply is the "Aplicar agora" button: reloads immediately, bypassing the
// debounce.
func (h *NTPHandler) Apply(w http.ResponseWriter, r *http.Request) {
	if err := h.doReload(r.Context()); err != nil {
		writeInternalError(w, fmt.Errorf("falha ao aplicar: %w", err))
		return
	}
	auditAction(h.db, r, "ntp.apply", "ntp", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "aplicado"})
}

// InstallChrony is the explicit "Instalar chrony" button — never automatic,
// see timesync.Service.InstallChrony's doc comment.
func (h *NTPHandler) InstallChrony(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.InstallChrony(r.Context()); err != nil {
		writeInternalError(w, fmt.Errorf("falha ao instalar chrony: %w", err))
		return
	}
	auditAction(h.db, r, "ntp.install_chrony", "ntp", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "instalado"})
}
