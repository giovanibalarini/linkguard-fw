// Package keaunbound is the high-performance DHCP/DNS Provider: Kea (DHCP) +
// unbound (DNS). It follows the "generate config + reload service" model used
// for nftables — the panel owns /etc/kea/kea-dhcp4.conf and the unbound config,
// and restarts the daemons. It implements netsvc.Provider.
package keaunbound

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
)

const (
	KeaConfPath     = "/etc/kea/kea-dhcp4.conf"
	UnboundConfPath = "/etc/unbound/unbound.conf.d/linkguard.conf"
	KeaLeasesPath   = "/var/lib/kea/kea-leases4.csv"

	keaService     = "kea-dhcp4-server"
	unboundService = "unbound"
	keaBinDefault  = "/usr/sbin/kea-dhcp4"
)

// Service is the Kea+unbound Provider. Config paths and the Kea binary are
// fields (defaulted to the system paths) so tests can point them at a temp dir.
type Service struct {
	exec        firewall.Executor
	keaConf     string
	unboundConf string
	keaBin      string
}

// NewService creates the provider.
func NewService(exec firewall.Executor) *Service {
	return &Service{
		exec:        exec,
		keaConf:     KeaConfPath,
		unboundConf: UnboundConfPath,
		keaBin:      keaBinDefault,
	}
}

// Backend implements netsvc.Provider.
func (s *Service) Backend() netsvc.Backend { return netsvc.BackendKeaUnbound }

// GenerateConfigs renders the Kea (DHCP) and unbound (DNS) config files.
func (s *Service) GenerateConfigs(c netsvc.Config, res []netsvc.Reservation, blocked []string) []netsvc.ConfigFile {
	return []netsvc.ConfigFile{
		{Path: s.keaConf, Content: GenerateKeaConfig(c, res)},
		{Path: s.unboundConf, Content: GenerateUnboundConfig(c, blocked)},
	}
}

// ReloadConfigs writes the configs and reloads the services via systemd's
// canonical reload-or-restart, which keeps them systemd-tracked: unbound (which
// ships an ExecReload) reloads in place with no downtime; Kea (no ExecReload) is
// cleanly restarted, its memfile leases surviving. The Kea config is validated
// first (kea-dhcp4 -t) — critical, since a restart with a broken config would
// take DHCP down. If validation fails, nothing is written or reloaded and the
// running config is left intact.
func (s *Service) ReloadConfigs(ctx context.Context, c netsvc.Config, res []netsvc.Reservation, blocked []string) (string, error) {
	files := s.GenerateConfigs(c, res, blocked)

	// Validate the Kea config before touching anything in production.
	var keaContent string
	for _, f := range files {
		if f.Path == s.keaConf {
			keaContent = f.Content
		}
	}
	if err := s.validateKea(ctx, keaContent); err != nil {
		return "", fmt.Errorf("config do Kea inválida (nada aplicado): %w", err)
	}

	if !s.exec.IsDryRun() {
		for _, f := range files {
			if err := os.WriteFile(f.Path, []byte(f.Content), 0o644); err != nil {
				return "", fmt.Errorf("write %s: %w", f.Path, err)
			}
		}
	}

	var out []string
	for _, svc := range []string{keaService, unboundService} {
		o, err := s.exec.Execute(ctx, "systemctl", "reload-or-restart", svc)
		out = append(out, svc+": "+o)
		if err != nil {
			return strings.Join(out, "; "), fmt.Errorf("reload %s: %w", svc, err)
		}
	}
	return strings.Join(out, "; "), nil
}

// validateKea writes the candidate config to a temp file and runs the Kea
// config-test mode against it. Read-only, so it runs even in dry-run.
func (s *Service) validateKea(ctx context.Context, content string) error {
	f, err := os.CreateTemp("", "kea-validate-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	f.Close()
	_, err = s.exec.ExecuteRead(ctx, s.keaBin, "-t", f.Name())
	return err
}

// ─── Kea (DHCP) ──────────────────────────────────────────────────────────────

type keaConfig struct {
	Dhcp4 keaDhcp4 `json:"Dhcp4"`
}
type keaDhcp4 struct {
	InterfacesConfig keaIfaces   `json:"interfaces-config"`
	LeaseDatabase    keaLeaseDB  `json:"lease-database"`
	ValidLifetime    int         `json:"valid-lifetime"`
	Subnet4          []keaSubnet `json:"subnet4"`
}
type keaIfaces struct {
	Interfaces []string `json:"interfaces"`
}
type keaLeaseDB struct {
	Type    string `json:"type"`
	Persist bool   `json:"persist"`
	Name    string `json:"name"`
}
type keaSubnet struct {
	ID           int              `json:"id"`
	Subnet       string           `json:"subnet"`
	Pools        []keaPool        `json:"pools"`
	OptionData   []keaOption      `json:"option-data"`
	Reservations []keaReservation `json:"reservations,omitempty"`
}
type keaPool struct {
	Pool string `json:"pool"`
}
type keaOption struct {
	Name string `json:"name"`
	Data string `json:"data"`
}
type keaReservation struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
	Hostname  string `json:"hostname,omitempty"`
}

// GenerateKeaConfig renders kea-dhcp4.conf (pure function, JSON).
func GenerateKeaConfig(c netsvc.Config, reservations []netsvc.Reservation) string {
	lease := c.LeaseHours
	if lease <= 0 {
		lease = 12
	}
	opts := []keaOption{}
	if c.Gateway != "" {
		opts = append(opts, keaOption{Name: "routers", Data: c.Gateway})
	}
	if len(c.DNSToClients) > 0 {
		opts = append(opts, keaOption{Name: "domain-name-servers", Data: strings.Join(c.DNSToClients, ", ")})
	}
	if c.DomainSuffix != "" {
		opts = append(opts, keaOption{Name: "domain-name", Data: c.DomainSuffix})
	}

	rs := append([]netsvc.Reservation(nil), reservations...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].IP < rs[j].IP })
	kres := make([]keaReservation, 0, len(rs))
	for _, r := range rs {
		kres = append(kres, keaReservation{
			HWAddress: strings.ToLower(r.MAC),
			IPAddress: r.IP,
			Hostname:  r.Hostname,
		})
	}

	cfg := keaConfig{Dhcp4: keaDhcp4{
		InterfacesConfig: keaIfaces{Interfaces: []string{c.Interface}},
		LeaseDatabase:    keaLeaseDB{Type: "memfile", Persist: true, Name: KeaLeasesPath},
		ValidLifetime:    lease * 3600,
		Subnet4: []keaSubnet{{
			ID:           1,
			Subnet:       c.SubnetCIDR,
			Pools:        []keaPool{{Pool: c.RangeStart + " - " + c.RangeEnd}},
			OptionData:   opts,
			Reservations: kres,
		}},
	}}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return "// Managed by LinkGuard FW — do not edit by hand.\n" + string(out) + "\n"
}

// ParseKeaLeases parses Kea's memfile CSV. Columns:
//
//	address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,...
//
// Kea appends rows; the last row per address is authoritative. Only state 0
// (assigned) leases are returned.
func ParseKeaLeases(content string) []netsvc.Lease {
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return []netsvc.Lease{}
	}
	type rec struct {
		l     netsvc.Lease
		state string
	}
	latest := map[string]rec{} // address -> last row
	order := []string{}
	for i, row := range rows {
		if i == 0 || len(row) < 10 {
			continue // header or malformed
		}
		addr := row[0]
		exp, _ := strconv.ParseInt(row[4], 10, 64)
		if _, seen := latest[addr]; !seen {
			order = append(order, addr)
		}
		latest[addr] = rec{
			l:     netsvc.Lease{IP: addr, MAC: strings.ToLower(row[1]), Expiry: exp, Hostname: row[8]},
			state: row[9],
		}
	}
	out := []netsvc.Lease{}
	for _, addr := range order {
		if latest[addr].state == "0" { // 0 = assigned/active
			out = append(out, latest[addr].l)
		}
	}
	return out
}

// ─── unbound (DNS) ───────────────────────────────────────────────────────────

// GenerateUnboundConfig renders the unbound config fragment (pure function).
func GenerateUnboundConfig(c netsvc.Config, blocked []string) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteString("\n") }

	w("# Managed by LinkGuard FW — do not edit by hand.")
	w("server:")
	if c.Gateway != "" {
		w("  interface: " + c.Gateway) // bind on the firewall LAN IP
	}
	w("  interface: 127.0.0.1")
	w("  access-control: 127.0.0.0/8 allow")
	if c.SubnetCIDR != "" {
		w("  access-control: " + c.SubnetCIDR + " allow")
	}
	w("  hide-identity: yes")
	w("  hide-version: yes")
	w("  prefetch: yes")
	w("  num-threads: 2")
	w("  msg-cache-size: 64m")
	w("  rrset-cache-size: 128m")
	if c.LogQueries {
		w("  log-queries: yes")
	}
	if c.DomainSuffix != "" {
		w("  local-zone: \"" + c.DomainSuffix + ".\" transparent")
	}

	if len(blocked) > 0 {
		w("  # DNS filtering (blocklist) — NXDOMAIN")
		bd := append([]string(nil), blocked...)
		sort.Strings(bd)
		for _, d := range bd {
			w("  local-zone: \"" + d + ".\" always_nxdomain")
		}
	}

	if len(c.Upstreams) > 0 {
		w("forward-zone:")
		w("  name: \".\"")
		for _, up := range c.Upstreams {
			w("  forward-addr: " + up)
		}
	}
	return b.String()
}

// ─── Provider apply / leases ─────────────────────────────────────────────────

// Apply writes both config files and restarts kea-dhcp4 + unbound.
func (s *Service) Apply(ctx context.Context, c netsvc.Config, res []netsvc.Reservation, blocked []string) (string, error) {
	if !s.exec.IsDryRun() {
		for _, f := range s.GenerateConfigs(c, res, blocked) {
			if err := os.WriteFile(f.Path, []byte(f.Content), 0o644); err != nil {
				return "", fmt.Errorf("write %s: %w", f.Path, err)
			}
		}
	}
	return s.exec.Execute(ctx, "systemctl", "restart", "kea-dhcp4-server", "unbound")
}

// Leases reads and parses the active Kea leases.
func (s *Service) Leases(ctx context.Context) ([]netsvc.Lease, error) {
	out, err := s.exec.ExecuteRead(ctx, "cat", KeaLeasesPath)
	if err != nil {
		return nil, err
	}
	return ParseKeaLeases(out), nil
}

// compile-time check that Service satisfies the Provider interface.
var _ netsvc.Provider = (*Service)(nil)
