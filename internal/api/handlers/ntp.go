package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
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
//
// nftSvc and triggerDHCPReload exist only for the "serve NTP to the LAN"
// toggle (2026-08-11): applying the config now also reconciles the
// nftables input-chain protection and, when wired via SetDHCPReload, asks
// the DHCP/DNS handler to reapply so clients pick up the ntp-servers
// option. Both are nil-safe — a handler built without them (older tests,
// or a future caller that doesn't need the toggle) still works exactly as
// before.
type NTPHandler struct {
	db                *storage.DB
	svc               *timesync.Service
	alertSvc          *alerts.Service
	applier           *autoApplier
	nftSvc            *nftables.Service
	triggerDHCPReload func(ctx context.Context) error
}

// NewNTPHandler creates an NTPHandler. Saving config auto-applies
// (debounced), matching NetsvcHandler's convention. nftSvc is needed to
// reconcile the NTP-protection input chain (nil-safe: pass nil where the
// toggle's firewall effect isn't needed, e.g. in tests unrelated to it) —
// same precedent as LinksHandler gaining nftSvc for the NAT rule.
func NewNTPHandler(db *storage.DB, svc *timesync.Service, alertSvc *alerts.Service, nftSvc *nftables.Service) *NTPHandler {
	h := &NTPHandler{db: db, svc: svc, alertSvc: alertSvc, nftSvc: nftSvc}
	h.applier = newAutoApplier(autoApplyDelay, func() { _ = h.doReload(context.Background()) })
	return h
}

// SetDHCPReload wires this handler to trigger a DHCP/DNS reload after
// applying — toggling ServeLAN changes the DHCP config's ntp-servers
// option (internal/keaunbound.GenerateKeaConfig), so clients only receive
// it once that config is regenerated and reloaded. A plain func value
// (rather than a hard *NetsvcHandler dependency) keeps the coupling
// between the two handlers to exactly this one call — see
// WireNTPDHCPReload, which supplies it from server.go using
// NetsvcHandler's existing unexported doReload (both handlers live in this
// same package, so no export is needed just for this wiring).
func (h *NTPHandler) SetDHCPReload(fn func(ctx context.Context) error) {
	h.triggerDHCPReload = fn
}

// WireNTPDHCPReload connects an already-constructed NTPHandler to an
// already-constructed NetsvcHandler's reload path, for server.go to call
// once both exist. It exists so server.go (package api) never needs
// NetsvcHandler.doReload exported just for this one wiring — the two
// handlers are already in the same package, so a package-level helper here
// can reach the unexported method directly, keeping doReload's visibility
// unchanged and the coupling between the handlers limited to exactly this
// call.
func WireNTPDHCPReload(ntpH *NTPHandler, netH *NetsvcHandler) {
	ntpH.SetDHCPReload(netH.doReload)
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

// doReload applies the current config (chrony + the LAN allow directive)
// and records the result, shared by the debounced auto-apply and the
// manual "Aplicar agora" button. It also drives the toggle's other two
// effects (spec §3): reconciling the nftables input-chain protection, and
// — when wired via SetDHCPReload — asking DHCP/DNS to reapply so the
// ntp-servers option reaches clients. Both are best-effort: a failure there
// is logged but never turns an otherwise-successful chrony apply into a
// reported failure, matching LinksHandler.reconcileNAT's precedent for
// this kind of secondary, self-healing reconciliation.
func (h *NTPHandler) doReload(ctx context.Context) error {
	cfg := h.getConfig()
	err := h.svc.ReloadConfig(ctx, cfg)

	h.reconcileFirewall(ctx, cfg.AllowedNetworks, cfg.ServeLAN)

	if h.triggerDHCPReload != nil {
		if dErr := h.triggerDHCPReload(ctx); dErr != nil {
			slog.Warn("não foi possível reaplicar DHCP/DNS após mudança de NTP", "err", dErr)
		}
	}

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

// reconcileFirewall rebuilds the NTP-protection input chain from the
// admin's chosen allowed networks (spec §3.1/§4). Best-effort and nil-safe,
// same convention as LinksHandler.reconcileNAT: a failure here is logged
// but never fails the NTP apply that triggered it.
func (h *NTPHandler) reconcileFirewall(ctx context.Context, allowedNetworks []string, serving bool) {
	if h.nftSvc == nil {
		return
	}
	if err := h.nftSvc.ReconcileNTPInput(ctx, allowedNetworks, serving); err != nil {
		slog.Warn("não foi possível reconciliar a chain de proteção do NTP", "err", err)
	}
}

func (h *NTPHandler) scheduleApply() {
	if h.applier != nil {
		h.applier.schedule()
	}
}

// suggestedNetwork returns the DHCP LAN subnet as the suggested default for
// AllowedNetworks — the same value UpdateNTPConfig pre-fills with on first
// enable (spec §3.1/§6). Exposed separately in GetNTP's response
// (suggested_network) so the UI can pre-fill the "Redes autorizadas" input
// on first render, before any save has happened. Empty when the DHCP
// subnet itself is unconfigured — never inventing a range.
func (h *NTPHandler) suggestedNetwork() string {
	return netsvcConfigFromDB(h.db).SubnetCIDR
}

// GetNTP returns the current config, live status, available timezones,
// last-apply result, and the suggested default network in one payload.
func (h *NTPHandler) GetNTP(w http.ResponseWriter, r *http.Request) {
	zones, err := h.svc.ListTimezones(r.Context())
	if err != nil {
		zones = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":            h.getConfig(),
		"status":            h.svc.Status(r.Context()),
		"timezones":         zones,
		"last_apply":        h.lastApplyStatus(),
		"suggested_network": h.suggestedNetwork(),
	})
}

// UpdateNTPConfig updates servers/timezone/serve_lan/allowed_networks and
// schedules the debounced auto-apply.
//
// AllowedNetworks (spec §3.1) is validated server-side via
// timesync.ValidateAllowedNetworks — an invalid CIDR or the open wildcard
// (0.0.0.0/0, ::/0) is a 400 with a message the UI can show, never silently
// dropped.
//
// Default pre-fill: turning serve_lan on for the first time (the previously
// saved config had it off) with an empty AllowedNetworks list seeds it from
// the DHCP LAN subnet, so the common case needs zero typing. This only
// fires on the off->on transition — once serving is already on, an admin
// who explicitly empties the list gets exactly that ("nothing allowed" is a
// deliberate, explicit state per spec §3.1), not a silent re-fill on every
// save.
func (h *NTPHandler) UpdateNTPConfig(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Servers         []string `json:"servers"`
		Timezone        string   `json:"timezone"`
		ServeLAN        bool     `json:"serve_lan"`
		AllowedNetworks []string `json:"allowed_networks"`
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

	networks := []string{}
	for _, n := range b.AllowedNetworks {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		networks = append(networks, n)
	}

	firstEnable := b.ServeLAN && !h.getConfig().ServeLAN
	if firstEnable && len(networks) == 0 {
		if subnet := h.suggestedNetwork(); subnet != "" {
			networks = []string{subnet}
		}
	}

	if err := timesync.ValidateAllowedNetworks(networks); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	cfg := timesync.Config{Servers: servers, Timezone: strings.TrimSpace(b.Timezone), ServeLAN: b.ServeLAN, AllowedNetworks: networks}
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
