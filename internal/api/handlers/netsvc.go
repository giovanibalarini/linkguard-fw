package handlers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Strict validators for values rendered into unbound/Kea configs.
var (
	// reDNSDomain is intentionally lenient about structure — single-label names
	// ("lan", "localhost") and underscore labels ("_dmarc.example.com") are all
	// legitimate for a DNS blocklist or a DHCP domain suffix — but strict about
	// charset. The value is written into unbound.conf, so anything outside
	// [a-z0-9._-] (quotes, spaces, ';', newlines) must be rejected.
	reDNSDomain = regexp.MustCompile(`^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$`)
	reNetIface  = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)
)

func validDomain(d string) bool {
	return d != "" && len(d) <= 253 && reDNSDomain.MatchString(d)
}

func validIface(s string) bool { return reNetIface.MatchString(s) }

// NetsvcHandler manages DHCP + DNS through the configured backend provider
// (Kea + unbound). Config and lists live in the DB; the provider renders the
// engine configs and applies them.
type NetsvcHandler struct {
	db       *storage.DB
	provider netsvc.Provider
	alertSvc *alerts.Service
	applier  *autoApplier
}

// autoApplyDelay is how long the handler waits for edits to settle before
// applying — long enough to coalesce a burst of saves, short enough to feel
// instant.
const autoApplyDelay = 1500 * time.Millisecond

// NewNetsvcHandler creates a NetsvcHandler. Saving any DHCP/DNS change now
// auto-applies (debounced), so the admin no longer needs a separate "Aplicar".
func NewNetsvcHandler(db *storage.DB, provider netsvc.Provider, alertSvc *alerts.Service) *NetsvcHandler {
	h := &NetsvcHandler{db: db, provider: provider, alertSvc: alertSvc}
	h.applier = newAutoApplier(autoApplyDelay, func() { _ = h.doReload(context.Background()) })
	return h
}

const netsvcCfgKey = "netsvc_config"
const netsvcApplyStatusKey = "netsvc_last_apply"

// applyStatus is the persisted result of the most recent (auto or manual) apply,
// surfaced in the UI so an async failure isn't silent.
type applyStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	At    int64  `json:"at"` // unix seconds
}

// doReload regenerates and gracefully reloads the backend, records the result,
// and alerts on failure. Shared by the debounced auto-apply and the manual
// "Aplicar agora" button.
func (h *NetsvcHandler) doReload(ctx context.Context) error {
	bl, _ := h.db.ListDNSBlocklist()
	out, err := h.provider.ReloadConfigs(ctx, h.getConfig(), h.reservationsForProvider(), bl)
	st := applyStatus{OK: err == nil, At: time.Now().Unix()}
	if err != nil {
		st.Error = err.Error()
		if h.alertSvc != nil {
			_ = h.alertSvc.RuleError("Falha ao aplicar DHCP/DNS: " + err.Error())
		}
	}
	if b, mErr := json.Marshal(st); mErr == nil {
		_ = h.db.SetSetting(netsvcApplyStatusKey, string(b))
	}
	_ = out
	return err
}

// scheduleApply arms the debounced auto-apply after a mutation.
func (h *NetsvcHandler) scheduleApply() {
	if h.applier != nil {
		h.applier.schedule()
	}
}

// lastApplyStatus returns the persisted result of the most recent apply.
func (h *NetsvcHandler) lastApplyStatus() applyStatus {
	var st applyStatus
	if raw, _ := h.db.GetSetting(netsvcApplyStatusKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	return st
}

func (h *NetsvcHandler) getConfig() netsvc.Config {
	cfg := netsvc.DefaultConfig()
	if raw, _ := h.db.GetSetting(netsvcCfgKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

func (h *NetsvcHandler) saveConfig(c netsvc.Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return h.db.SetSetting(netsvcCfgKey, string(b))
}

func (h *NetsvcHandler) reservationsForProvider() []netsvc.Reservation {
	rs, _ := h.db.ListDHCPReservations()
	out := make([]netsvc.Reservation, 0, len(rs))
	for _, r := range rs {
		out = append(out, netsvc.Reservation{MAC: r.MAC, IP: r.IP, Hostname: r.Hostname})
	}
	return out
}

// ─── DHCP ────────────────────────────────────────────────────────────────────

// GetDHCP returns the DHCP config, reservations and live leases.
func (h *NetsvcHandler) GetDHCP(w http.ResponseWriter, r *http.Request) {
	rs, _ := h.db.ListDHCPReservations()
	if rs == nil {
		rs = []storage.DHCPReservation{}
	}
	leases, err := h.provider.Leases(r.Context())
	if err != nil {
		leases = []netsvc.Lease{} // backend not active yet (pre-cutover)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":       h.getConfig(),
		"reservations": rs,
		"leases":       leases,
		"backend":      h.provider.Backend(),
		"last_apply":   h.lastApplyStatus(),
	})
}

// UpdateDHCPConfig updates the DHCP-related settings.
func (h *NetsvcHandler) UpdateDHCPConfig(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Interface    string   `json:"interface"`
		SubnetCIDR   string   `json:"subnet_cidr"`
		RangeStart   string   `json:"range_start"`
		RangeEnd     string   `json:"range_end"`
		Gateway      string   `json:"gateway"`
		LeaseHours   int      `json:"lease_hours"`
		DNSToClients []string `json:"dns_to_clients"`
		DomainSuffix string   `json:"domain_suffix"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Validate every field: some (gateway, subnet, domain suffix) are rendered
	// into unbound.conf by string concatenation, so an unvalidated value could
	// inject config directives.
	iface := strings.TrimSpace(b.Interface)
	subnet := strings.TrimSpace(b.SubnetCIDR)
	rStart := strings.TrimSpace(b.RangeStart)
	rEnd := strings.TrimSpace(b.RangeEnd)
	gw := strings.TrimSpace(b.Gateway)
	suffix := strings.TrimSpace(b.DomainSuffix)
	if iface != "" && !validIface(iface) {
		writeError(w, http.StatusBadRequest, "interface inválida")
		return
	}
	if subnet != "" {
		if _, _, err := net.ParseCIDR(subnet); err != nil {
			writeError(w, http.StatusBadRequest, "sub-rede inválida")
			return
		}
	}
	for _, v := range []string{rStart, rEnd, gw} {
		if v != "" && net.ParseIP(v) == nil {
			writeError(w, http.StatusBadRequest, "endereço IP inválido: "+v)
			return
		}
	}
	if suffix != "" && !validDomain(suffix) {
		writeError(w, http.StatusBadRequest, "domínio (domain_suffix) inválido")
		return
	}
	dns := []string{}
	for _, d := range b.DNSToClients {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if net.ParseIP(d) == nil {
			writeError(w, http.StatusBadRequest, "DNS inválido: "+d)
			return
		}
		dns = append(dns, d)
	}
	cfg := h.getConfig()
	cfg.Interface, cfg.SubnetCIDR = iface, subnet
	cfg.RangeStart, cfg.RangeEnd = rStart, rEnd
	cfg.Gateway, cfg.LeaseHours = gw, b.LeaseHours
	cfg.DNSToClients, cfg.DomainSuffix = dns, suffix
	if err := h.saveConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "dhcp.config", "netsvc", "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, cfg)
}

// UpsertReservation creates/updates a DHCP reservation (by MAC).
func (h *NetsvcHandler) UpsertReservation(w http.ResponseWriter, r *http.Request) {
	var b struct{ MAC, IP, Hostname string }
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mac := normalizeMAC(b.MAC)
	if mac == "" {
		writeError(w, http.StatusBadRequest, "MAC inválido")
		return
	}
	if net.ParseIP(strings.TrimSpace(b.IP)) == nil {
		writeError(w, http.StatusBadRequest, "IP inválido")
		return
	}
	if err := h.db.UpsertDHCPReservation(mac, strings.TrimSpace(b.IP), strings.TrimSpace(b.Hostname)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "dhcp.reservation.set", "mac:"+mac, b.IP)
	h.scheduleApply()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DeleteReservation removes a reservation by MAC.
func (h *NetsvcHandler) DeleteReservation(w http.ResponseWriter, r *http.Request) {
	var b struct{ MAC string }
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mac := normalizeMAC(b.MAC)
	if mac == "" {
		writeError(w, http.StatusBadRequest, "MAC inválido")
		return
	}
	if err := h.db.DeleteDHCPReservation(mac); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "dhcp.reservation.del", "mac:"+mac, "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── DNS ─────────────────────────────────────────────────────────────────────

// GetDNS returns the DNS config and blocklist.
func (h *NetsvcHandler) GetDNS(w http.ResponseWriter, r *http.Request) {
	bl, _ := h.db.ListDNSBlocklist()
	if bl == nil {
		bl = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":     h.getConfig(),
		"blocklist":  bl,
		"backend":    h.provider.Backend(),
		"last_apply": h.lastApplyStatus(),
	})
}

// UpdateDNSConfig updates the DNS-related settings.
func (h *NetsvcHandler) UpdateDNSConfig(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Upstreams  []string `json:"upstreams"`
		LogQueries bool     `json:"log_queries"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ups := []string{}
	for _, u := range b.Upstreams {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if net.ParseIP(u) == nil {
			writeError(w, http.StatusBadRequest, "upstream inválido: "+u)
			return
		}
		ups = append(ups, u)
	}
	cfg := h.getConfig()
	cfg.Upstreams = ups
	cfg.LogQueries = b.LogQueries
	if err := h.saveConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "dns.config", "netsvc", "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, cfg)
}

// AddBlocklist / DeleteBlocklist manage blocked DNS domains.
func (h *NetsvcHandler) AddBlocklist(w http.ResponseWriter, r *http.Request) {
	h.blocklist(w, r, true)
}
func (h *NetsvcHandler) DeleteBlocklist(w http.ResponseWriter, r *http.Request) {
	h.blocklist(w, r, false)
}
func (h *NetsvcHandler) blocklist(w http.ResponseWriter, r *http.Request, add bool) {
	var b struct{ Domain string }
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	d := strings.ToLower(strings.TrimSpace(b.Domain))
	if d == "" {
		writeError(w, http.StatusBadRequest, "domínio vazio")
		return
	}
	// Validate charset only when adding; a delete must always be able to remove
	// an already-stored entry, including ones saved under an older, laxer rule.
	if add && !validDomain(d) {
		writeError(w, http.StatusBadRequest, "domínio inválido")
		return
	}
	var err error
	if add {
		err = h.db.AddDNSBlocklist(d)
		auditAction(h.db, r, "dns.blocklist.add", d, "")
	} else {
		err = h.db.DeleteDNSBlocklist(d)
		auditAction(h.db, r, "dns.blocklist.del", d, "")
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.scheduleApply()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Preview / Apply ─────────────────────────────────────────────────────────

// Preview returns the rendered backend config files (without applying).
func (h *NetsvcHandler) Preview(w http.ResponseWriter, r *http.Request) {
	bl, _ := h.db.ListDNSBlocklist()
	files := h.provider.GenerateConfigs(h.getConfig(), h.reservationsForProvider(), bl)
	writeJSON(w, http.StatusOK, files)
}

// Apply is the "Aplicar agora" button: it gracefully reloads the backend
// immediately (bypassing the debounce), validating the config first.
func (h *NetsvcHandler) Apply(w http.ResponseWriter, r *http.Request) {
	if err := h.doReload(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "falha ao aplicar: "+err.Error())
		return
	}
	auditAction(h.db, r, "netsvc.apply", string(h.provider.Backend()), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "aplicado"})
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, err := net.ParseMAC(s); err != nil {
		return ""
	}
	return s
}
