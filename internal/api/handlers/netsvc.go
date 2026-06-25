package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// NetsvcHandler manages DHCP + DNS through the configured backend provider
// (Kea + unbound). Config and lists live in the DB; the provider renders the
// engine configs and applies them.
type NetsvcHandler struct {
	db       *storage.DB
	provider netsvc.Provider
}

// NewNetsvcHandler creates a NetsvcHandler.
func NewNetsvcHandler(db *storage.DB, provider netsvc.Provider) *NetsvcHandler {
	return &NetsvcHandler{db: db, provider: provider}
}

const netsvcCfgKey = "netsvc_config"

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
	cfg := h.getConfig()
	cfg.Interface, cfg.SubnetCIDR = strings.TrimSpace(b.Interface), strings.TrimSpace(b.SubnetCIDR)
	cfg.RangeStart, cfg.RangeEnd = strings.TrimSpace(b.RangeStart), strings.TrimSpace(b.RangeEnd)
	cfg.Gateway, cfg.LeaseHours = strings.TrimSpace(b.Gateway), b.LeaseHours
	cfg.DNSToClients, cfg.DomainSuffix = b.DNSToClients, strings.TrimSpace(b.DomainSuffix)
	if err := h.saveConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "dhcp.config", "netsvc", "")
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
		"config":    h.getConfig(),
		"blocklist": bl,
		"backend":   h.provider.Backend(),
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
	if d == "" || strings.ContainsAny(d, " /") {
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Preview / Apply ─────────────────────────────────────────────────────────

// Preview returns the rendered backend config files (without applying).
func (h *NetsvcHandler) Preview(w http.ResponseWriter, r *http.Request) {
	bl, _ := h.db.ListDNSBlocklist()
	files := h.provider.GenerateConfigs(h.getConfig(), h.reservationsForProvider(), bl)
	writeJSON(w, http.StatusOK, files)
}

// Apply writes the configs and restarts the backend services.
func (h *NetsvcHandler) Apply(w http.ResponseWriter, r *http.Request) {
	bl, _ := h.db.ListDNSBlocklist()
	out, err := h.provider.Apply(r.Context(), h.getConfig(), h.reservationsForProvider(), bl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "falha ao aplicar: "+err.Error())
		return
	}
	auditAction(h.db, r, "netsvc.apply", string(h.provider.Backend()), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "aplicado", "output": out})
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, err := net.ParseMAC(s); err != nil {
		return ""
	}
	return s
}
