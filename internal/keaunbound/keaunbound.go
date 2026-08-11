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
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
)

const (
	KeaConfPath      = "/etc/kea/kea-dhcp4.conf"
	UnboundConfPath  = "/etc/unbound/unbound.conf.d/linkguard.conf"
	KeaLeasesPath    = "/var/lib/kea/kea-leases4.csv"
	ResolvConfPath   = "/etc/resolv.conf"
	DhclientConfPath = "/etc/dhcp/dhclient.conf"

	keaService             = "kea-dhcp4-server"
	unboundService         = "unbound"
	keaBinDefault          = "/usr/sbin/kea-dhcp4"
	unboundCheckBinDefault = "/usr/sbin/unbound-checkconf"
)

// Service is the Kea+unbound Provider. Config paths and the Kea binary are
// fields (defaulted to the system paths) so tests can point them at a temp dir.
type Service struct {
	exec            firewall.Executor
	keaConf         string
	unboundConf     string
	keaBin          string
	unboundCheckBin string
	resolvConf      string
	dhclientConf    string
}

// NewService creates the provider.
func NewService(exec firewall.Executor) *Service {
	return &Service{
		exec:            exec,
		keaConf:         KeaConfPath,
		unboundConf:     UnboundConfPath,
		keaBin:          keaBinDefault,
		unboundCheckBin: unboundCheckBinDefault,
		resolvConf:      ResolvConfPath,
		dhclientConf:    DhclientConfPath,
	}
}

// Backend implements netsvc.Provider.
func (s *Service) Backend() netsvc.Backend { return netsvc.BackendKeaUnbound }

// EnsureKeaDirReadable relaxes /etc/kea's directory permissions so both
// LinkGuard's own config validation and kea-dhcp4-server's own startup can
// actually read the config that lives there. Debian's kea-dhcp-server
// package ships the directory owned _kea:_kea mode 0750; kea-dhcp4's
// AppArmor profile grants path-based read access under /etc/kea/** but not
// the dac_override/dac_read_search capabilities needed to bypass that Unix
// DAC restriction, so even root gets "Unable to open file" despite the file
// itself being 0644 and the AppArmor path rule allowing it — the directory
// blocks traversal before either of those checks matter. LinkGuard owns this
// the same way it owns nftables bootstrap/ip_forward/conntrack accounting:
// called at every startup so it self-heals regardless of what a package
// reinstall resets it to. Best-effort — a failure here surfaces later as a
// real validate/reload error instead of blocking startup.
func (s *Service) EnsureKeaDirReadable() {
	dir := filepath.Dir(s.keaConf)
	if err := os.Chmod(dir, 0o755); err != nil {
		slog.Warn("could not relax kea config directory permissions; DHCP apply may fail under AppArmor", "path", dir, "err", err)
	}
}

// EnsureResolvConf makes the box actually use its own resolver (unbound on
// 127.0.0.1) instead of whatever nameservers the WAN's DHCP lease proposes.
//
// Found in production on 2026-08-10: /etc/resolv.conf pointed at the ISP,
// and nothing in this codebase managed that file — so the appliance was
// silently bypassing its own DNS, losing the blocklist and the query
// visibility unbound provides. Rewriting resolv.conf alone would not hold:
// dhclient rewrites it on every lease renewal, which is why this also adds
// a `supersede domain-name-servers` directive so dhclient stops proposing
// the ISP's servers in the first place (working with dhclient rather than
// fighting it).
//
// Self-heals on every start, like the other Ensure* calls. Best-effort: a
// failure is logged as a warning rather than blocking startup. A dedicated
// dns-resolver health check to surface this failure in the UI is planned
// but not implemented yet.
//
// Gated on unbound actually being enabled: the Debian package lists unbound
// as `Recommends:`, never `Depends:`, so it can legitimately be absent (or
// present but failed to start). Unconditionally pointing resolv.conf at
// 127.0.0.1 on such a box, and stripping the ISP's servers from dhclient's
// config, would leave nothing answering DNS at all — silently breaking the
// updater's fetch from GitHub releases, Telegram/webhook notifications, the
// AI digest, and chrony's pool hostnames. Do NOT remove this guard "to
// simplify" without re-reading this comment: it is the difference between
// gaining a resolver and losing name resolution entirely.
//
// `systemctl is-enabled` (not `is-active`) is used deliberately: it answers
// from unit configuration rather than current process state, so it gives
// the same answer regardless of where in the boot sequence this runs,
// instead of racing unbound's own startup.
func (s *Service) EnsureResolvConf(ctx context.Context) {
	out, err := s.exec.ExecuteRead(ctx, "systemctl", "is-enabled", "unbound")
	if err != nil || strings.TrimSpace(out) != "enabled" {
		slog.Info("resolver local (unbound) não está instalado/habilitado; resolv.conf foi deixado como está", "path", s.resolvConf, "systemctl_output", strings.TrimSpace(out), "err", err)
		return
	}

	const body = "# managed by linkguard\nnameserver 127.0.0.1\n"
	if err := os.WriteFile(s.resolvConf, []byte(body), 0o644); err != nil {
		slog.Warn("não foi possível apontar o resolv.conf para o resolver local", "path", s.resolvConf, "err", err)
	} else {
		slog.Info("resolv.conf apontando para o resolver local (unbound)", "path", s.resolvConf)
	}

	const directive = "supersede domain-name-servers 127.0.0.1;"
	current, err := os.ReadFile(s.dhclientConf)
	if err != nil && !os.IsNotExist(err) {
		slog.Warn("não foi possível ler a config do dhclient; o DNS do provedor pode voltar na renovação do lease", "path", s.dhclientConf, "err", err)
		return
	}
	updated := ensureSupersedeDirective(string(current), directive)
	if updated == string(current) {
		return // already in place, exactly as we want it — this runs on every boot
	}
	if err := os.WriteFile(s.dhclientConf, []byte(updated), 0o644); err != nil {
		slog.Warn("não foi possível fixar o DNS local na config do dhclient", "path", s.dhclientConf, "err", err)
	}
}

// ensureSupersedeDirective returns dhclient.conf content updated so exactly
// one *active* `supersede domain-name-servers` statement is present, with
// the given directive's value. LinkGuard owns this option outright — the
// whole point of the feature is that the box always resolves through its
// own unbound — so any other active statement for it is wrong and gets
// replaced in place, not left alongside a second, conflicting one (dhclient
// treats two modifier statements for one option as at best last-wins, at
// worst a parse failure that breaks DHCP on that WAN at lease renewal).
//
// Matching is line-based, not a full dhclient.conf grammar parse: a line is
// "active" if, after stripping leading whitespace, it does not start with
// `#` and its whitespace-separated fields start with "supersede",
// "domain-name-servers". This is deliberately field-based rather than a
// literal substring match, so it isn't fooled by a commented-out leftover
// (which must never count as "already in place") and isn't blind to a
// pre-existing directive that merely differs in spacing or value (which
// must be replaced, not duplicated). Everything else in the file is left
// untouched, in order.
func ensureSupersedeDirective(content, directive string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)+1)
	found := false
	for _, line := range lines {
		if isActiveSupersedeDomainNameServers(line) {
			if found {
				continue // drop a redundant duplicate active statement
			}
			found = true
			if strings.TrimSpace(line) == directive {
				out = append(out, line) // already exactly right, leave untouched
			} else {
				out = append(out, directive) // wrong value/spacing: replace in place
			}
			continue
		}
		out = append(out, line)
	}
	if found {
		return strings.Join(out, "\n")
	}

	// No active directive found (file absent, or only commented-out
	// occurrences) — append ours.
	updated := strings.Join(out, "\n")
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += "\n# managed by linkguard — mantém o resolver local mesmo após renovação de lease\n" + directive + "\n"
	return updated
}

// isActiveSupersedeDomainNameServers reports whether line is a live (not
// commented-out) dhclient.conf `supersede domain-name-servers ...`
// statement, regardless of its value or exact spacing.
func isActiveSupersedeDomainNameServers(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") {
		return false
	}
	fields := strings.Fields(trimmed)
	return len(fields) >= 2 && fields[0] == "supersede" && fields[1] == "domain-name-servers"
}

// GenerateConfigs renders the Kea (DHCP) and unbound (DNS) config files.
// ntpServer is threaded straight through to GenerateKeaConfig — see its doc
// comment and netsvc.Provider.GenerateConfigs.
func (s *Service) GenerateConfigs(c netsvc.Config, res []netsvc.Reservation, blocked []string, ntpServer string) []netsvc.ConfigFile {
	return []netsvc.ConfigFile{
		{Path: s.keaConf, Content: GenerateKeaConfig(c, res, ntpServer)},
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
func (s *Service) ReloadConfigs(ctx context.Context, c netsvc.Config, res []netsvc.Reservation, blocked []string, ntpServer string) (string, error) {
	files := s.GenerateConfigs(c, res, blocked, ntpServer)

	// Validate both candidates before touching anything in production —
	// neither is written, nor is anything reloaded, unless both pass. This
	// used to only validate Kea; the unbound side landed on disk with no
	// pre-apply check at all (finding #3 in the input-validation audit), so
	// a broken unbound.conf could sit there and survive a reboot, taking DNS
	// down at the next boot with no admin action in between.
	var keaContent, unboundContent string
	for _, f := range files {
		switch f.Path {
		case s.keaConf:
			keaContent = f.Content
		case s.unboundConf:
			unboundContent = f.Content
		}
	}
	if err := s.validateKea(ctx, keaContent); err != nil {
		return "", fmt.Errorf("config do Kea inválida (nada aplicado): %w", err)
	}
	if err := s.validateUnbound(ctx, unboundContent); err != nil {
		return "", fmt.Errorf("config do unbound inválida (nada aplicado): %w", err)
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
//
// The temp file is created next to the real Kea config (in the same
// directory as s.keaConf, normally /etc/kea) instead of the system /tmp:
// Debian's kea-dhcp4 package ships an AppArmor profile
// (/etc/apparmor.d/usr.sbin.kea-dhcp4) that only grants kea-dhcp4 read
// access under /etc/kea/ — a file in /tmp is invisible to it regardless of
// Unix permissions, and `kea-dhcp4 -t` fails with "Unable to open file".
// /etc/kea is already writable by this process (see ReadWritePaths in
// deploy/linkguard-fw.service), so no new capability is needed.
func (s *Service) validateKea(ctx context.Context, content string) error {
	f, err := os.CreateTemp(filepath.Dir(s.keaConf), "kea-validate-*.conf")
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

// validateUnbound writes the candidate unbound config to a temp file and
// runs unbound-checkconf against it — the unbound-side sibling of
// validateKea, added because ReloadConfigs used to write unbound.conf with
// no pre-apply check at all (finding #3, input-validation-audit.md): a
// broken config landed on disk and survived a reboot, taking DNS down at
// the next boot with no admin action in between (confirmed as a real
// production incident, not a hypothetical, in the session that produced the
// audit).
//
// The temp file is created next to the real unbound config for the same
// reason validateKea's is created next to the real Kea config — see that
// function's doc comment. unbound-checkconf has no AppArmor profile
// confining it on Debian the way kea-dhcp4 does, so this placement isn't
// strictly required for unbound-checkconf itself, but keeping both
// validators structurally identical is worth more than the marginal
// freedom to use the system temp dir here, and it costs nothing.
//
// unbound-checkconf is optional at runtime: Debian's unbound package is a
// Recommends:, not a Depends:, of this project (see EnsureResolvConf's doc
// comment for why that guard exists elsewhere too) — a box can legitimately
// run without unbound installed, or with unbound installed but its checker
// missing (a minimal/manually-trimmed install). Treating a missing checker
// as a hard failure would block every DHCP/DNS apply on such a box, which
// is strictly worse than the gap this validation closes — so a missing
// binary is logged and treated as "validation not possible here, proceed",
// never as a validation failure.
func (s *Service) validateUnbound(ctx context.Context, content string) error {
	f, err := os.CreateTemp(filepath.Dir(s.unboundConf), "unbound-validate-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	f.Close()

	_, err = s.exec.ExecuteRead(ctx, s.unboundCheckBin, f.Name())
	if err != nil && isMissingBinary(err) {
		slog.Warn("unbound-checkconf não encontrado; pulando validação pré-apply do unbound.conf (o pacote unbound é Recommends:, não Depends:, deste projeto)", "bin", s.unboundCheckBin, "err", err)
		return nil
	}
	return err
}

// isMissingBinary reports whether err looks like the executor failed to
// even start the target binary (not found), as opposed to the binary
// running and reporting a real validation failure. Go's os/exec surfaces a
// missing binary as a fixed, English, locale-independent message —
// "executable file not found in $PATH" via LookPath for a bare command
// name, or "no such file or directory" via fork/exec for an absolute path
// like unboundCheckBinDefault — so matching on those substrings reliably
// distinguishes "the tool isn't installed" from "the tool ran and rejected
// the config", without needing firewall.Executor to grow a dedicated
// not-found signal just for this one caller.
func isMissingBinary(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "executable file not found") || strings.Contains(msg, "no such file or directory")
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

// GenerateKeaConfig renders kea-dhcp4.conf (pure function, JSON). ntpServer,
// when non-empty, adds a DHCP option 42 (ntp-servers) pointing clients at
// it — normally the firewall's own LAN IP (netsvc.Config.Gateway), the same
// address already used for the routers option, passed in by the caller
// rather than read from the DB here (see docs/superpowers/specs/
// 2026-08-11-ntp-server-for-lan-design.md §5: the NTP toggle lives in
// internal/timesync, a package this one must not import, to avoid either
// package reaching into the other's config). An empty string omits the
// option entirely, matching today's behaviour exactly.
func GenerateKeaConfig(c netsvc.Config, reservations []netsvc.Reservation, ntpServer string) string {
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
	if ntpServer != "" {
		opts = append(opts, keaOption{Name: "ntp-servers", Data: ntpServer})
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

// Apply writes both config files and restarts kea-dhcp4 + unbound. Part of
// netsvc.Provider's original, pre-NTP surface — not on the auto-apply path
// (ReloadConfigs is), so it has no NTP-toggle context of its own; it always
// renders without the ntp-servers option.
//
// Verified 2026-08-11 (NTP review Fix, "Minor" list): as of this writing
// nothing in the codebase actually calls this method — NetsvcHandler.Apply
// (the "Aplicar agora" button) goes through doReload -> ReloadConfigs,
// which does thread ntpServerOption() through. Left inert rather than
// wired up: doing so would mean either duplicating ntpServerOption's
// db-read-and-decide logic into this package (which owns neither ntpCfgKey
// nor internal/timesync.Config) or growing this method's signature to take
// an ntpServer string that its one remaining purpose — satisfying the
// netsvc.Provider interface — has no caller to supply. If a future caller
// does appear, that caller (like NetsvcHandler already does for
// ReloadConfigs) is the right place to decide the ntpServer value and pass
// it through the existing GenerateConfigs(..., ntpServer) parameter, not
// this method inventing its own.
func (s *Service) Apply(ctx context.Context, c netsvc.Config, res []netsvc.Reservation, blocked []string) (string, error) {
	if !s.exec.IsDryRun() {
		for _, f := range s.GenerateConfigs(c, res, blocked, "") {
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
