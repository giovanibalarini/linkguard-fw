// Package timesync makes LinkGuard the owner of the box's NTP time
// synchronization — the same "own this runtime prerequisite" pattern already
// used for IPv4 forwarding (routes.EnsureForwarding) and conntrack
// accounting (hosttraffic.EnsureAccounting).
//
// EnsureEnabled/IsSynced below are unchanged since this package's original
// version and remain the ONLY thing the Vigia alert/health-check
// (internal/monitoring/healthchecks.go, checkNTP) calls — Service (added
// 2026-08-10) is a separate, additive admin-control surface: it reuses
// IsSynced for display but never duplicates sync detection. See
// docs/superpowers/specs/2026-08-10-ntp-control-design.md.
package timesync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/sysprep"
)

// reChronyServer guards values rendered into the chrony drop-in via string
// formatting — hostname or IP, no spaces/quotes/control characters.
// Mirrors internal/api/handlers's own reNTPServer/validNTPServer (identical
// charset), duplicated here rather than imported: internal/api/handlers
// already imports this package (to call ReloadConfig/GenerateChronyConf),
// so the reverse import would be a cycle. See GenerateChronyConf's doc
// comment for why the render boundary must re-validate independently of
// whatever the handler already did.
var reChronyServer = regexp.MustCompile(`^[a-zA-Z0-9.:-]{1,253}$`)

func validChronyServer(s string) bool { return s != "" && reChronyServer.MatchString(s) }

// EnsureEnabled turns on chrony (NTP time sync) if the systemd unit is
// installed, so the clock stays correct without any manual step. It never
// installs the chrony package itself — only enables it if already present —
// because running a package manager from inside a long-running service is a
// different, riskier category of action than flipping a switch on software
// that's already there (apt lock contention, unattended-upgrades). It's a
// no-op in dry-run mode via Execute's own dry-run handling — no separate
// check needed here.
func EnsureEnabled(ctx context.Context, exec firewall.Executor) {
	out, err := exec.ExecuteRead(ctx, "systemctl", "list-unit-files", "--no-legend", "chrony.service")
	if err != nil || !strings.Contains(out, "chrony.service") {
		slog.Info("chrony not installed; skipping NTP auto-enable (install chrony to enable time sync)")
		return
	}
	if _, err := exec.Execute(ctx, "systemctl", "enable", "--now", "chrony"); err != nil {
		slog.Warn("could not enable chrony; NTP time sync will not be configured", "err", err)
	}
}

// IsSynced reports whether the system clock is currently NTP-synchronized,
// via systemd-timedated's own view of clock state — this works regardless of
// which NTP client owns the sync (chrony or systemd-timesyncd), so the
// caller never needs to know which one is installed.
func IsSynced(ctx context.Context, exec firewall.Executor) bool {
	out, err := exec.ExecuteRead(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "yes"
}

// chronyDropinPath is the LinkGuard-managed chrony drop-in. Debian's
// packaged /etc/chrony/chrony.conf already contains `confdir
// /etc/chrony/conf.d` — LinkGuard never touches chrony.conf itself, only
// this file, so the vendor's own defaults (driftfile, rtcsync, makestep,
// etc.) are never at risk of being dropped by a LinkGuard-generated file.
const chronyDropinPath = "/etc/chrony/conf.d/linkguard.conf"

// Config holds the admin-editable NTP settings. Empty fields mean
// "unmanaged" — Servers empty falls back to the Debian package's own pool
// default; Timezone empty leaves the OS's already-configured zone alone.
// ServeLAN defaults to false (off) — purely additive, existing installs keep
// today's client-only behaviour until an admin opts in. See
// docs/superpowers/specs/2026-08-11-ntp-server-for-lan-design.md.
//
// AllowedNetworks is the admin's own choice of which networks may use the
// time service (§3.1 of the revised spec) — a list of CIDRs, not derived
// from any single implicit subnet. It replaced an earlier, narrower design
// where the allowed network was implicitly netsvc.Config.SubnetCIDR (the
// single DHCP LAN subnet); an operator correctly pointed out that VLANs, a
// separate Wi-Fi network or a guest network may also need access, and only
// the admin — not the software — should decide which. An empty list with
// ServeLAN on is an explicit "nothing allowed" state, never an implicit
// allow-all. See GenerateChronyConf and ValidateAllowedNetworks.
type Config struct {
	Servers         []string `json:"servers"`
	Timezone        string   `json:"timezone"`
	ServeLAN        bool     `json:"serve_lan"`
	AllowedNetworks []string `json:"allowed_networks"`
}

// DefaultConfig is the "unmanaged" starting state — identical to today's
// behaviour before this feature existed (EnsureEnabled already turns on
// chrony with the Debian default pool). Servers is an empty slice, not nil,
// so it marshals to JSON `[]` rather than `null`.
func DefaultConfig() Config {
	return Config{Servers: []string{}, AllowedNetworks: []string{}}
}

// StatusInfo is the read-only NTP status shown in the panel.
type StatusInfo struct {
	Installed  bool    `json:"installed"`
	Synced     bool    `json:"synced"`
	Stratum    int     `json:"stratum,omitempty"`
	OffsetSecs float64 `json:"offset_secs,omitempty"`
	Source     string  `json:"source,omitempty"`
}

// Service owns the NTP admin-control surface: applying Config, reporting
// detailed status, listing timezones, and installing chrony on demand.
type Service struct {
	exec     firewall.Executor
	confPath string // overridden in tests; production uses chronyDropinPath
}

// NewService creates the NTP control service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec, confPath: chronyDropinPath}
}

// isOpenCIDR reports whether a CIDR is the "allow everyone" wildcard —
// 0.0.0.0/0 or ::/0 — checked by mask size (/0) after parsing rather than
// string comparison, so any equivalent spelling is caught the same way
// ValidateAllowedNetworks rejects it up front. Used here as defense in
// depth: this function must never render an open `allow` line into the
// chrony drop-in even if an invalid value somehow reached it without going
// through validation first (an old DB row from before this guard existed,
// for instance).
func isOpenCIDR(cidr string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, _ := ipnet.Mask.Size()
	return ones == 0
}

// GenerateChronyConf renders the LinkGuard-managed chrony drop-in from the
// configured NTP servers and, when serving the LAN, one `allow <cidr>` line
// per network in c.AllowedNetworks — the admin's own choice of which
// networks may use the time service (spec §3.1), not an implicit single LAN
// subnet. Pure — no I/O. Called even when both Servers and AllowedNetworks/
// ServeLAN are "empty" (ReloadConfig now only removes the drop-in when
// *neither* a custom server list nor ServeLAN is configured — see its own
// doc comment).
//
// Each entry — both Servers and AllowedNetworks — is re-validated here (not
// just by the caller, e.g. ValidateAllowedNetworks at the API boundary)
// because this is the function that interpolates admin-supplied strings
// into a config file a privileged daemon (chronyd) reads: an invalid,
// malicious, or open-wildcard value must never reach a rendered `server`/
// `allow` line, regardless of what upstream validation exists. A bad entry
// is skipped (with a warning), not fatal — the other, valid entries in the
// list must still be served. Servers used to be the one exception to this
// (input-validation-audit.md finding, "the same GenerateChronyConf" note):
// AllowedNetworks was already re-validated at render time and Servers was
// not, even though both are interpolated the same way into the same file.
//
// The second return carries those skipped entries as plain-Portuguese
// sentences (I-7). "Skip and log" is the right policy for a list, but a
// journal line is not a report: without this, the drop-in silently lost a
// server the panel kept showing as configured, under a green "aplicado".
func GenerateChronyConf(c Config) (string, []string) {
	var warnings []string
	var b strings.Builder
	b.WriteString("# managed by linkguard\n\n")
	skippedServers := 0
	for _, srv := range c.Servers {
		if !validChronyServer(srv) {
			slog.Warn("servidor NTP inválido; linha 'server' omitida do drop-in do chrony", "server", srv)
			skippedServers++
			continue
		}
		fmt.Fprintf(&b, "server %s iburst\n", srv)
	}
	if skippedServers > 0 {
		warnings = append(warnings, fmt.Sprintf("%d servidor(es) NTP são inválidos e não foram aplicados ao chrony", skippedServers))
	}
	if c.ServeLAN && len(c.AllowedNetworks) > 0 {
		var allowLines strings.Builder
		skippedNetworks := 0
		for _, network := range c.AllowedNetworks {
			if _, _, err := net.ParseCIDR(network); err != nil {
				slog.Warn("rede inválida; diretiva allow do chrony omitida para esta entrada", "network", network, "err", err)
				skippedNetworks++
				continue
			}
			if isOpenCIDR(network) {
				slog.Warn("rede aberta (0.0.0.0/0 ou ::/0) rejeitada; diretiva allow do chrony omitida", "network", network)
				skippedNetworks++
				continue
			}
			fmt.Fprintf(&allowLines, "allow %s\n", network)
		}
		if skippedNetworks > 0 {
			warnings = append(warnings, fmt.Sprintf("%d rede(s) autorizada(s) a usar o NTP são inválidas e não foram aplicadas", skippedNetworks))
		}
		if allowLines.Len() > 0 {
			b.WriteString("\n")
			b.WriteString(allowLines.String())
		}
	}
	return b.String(), warnings
}

// ValidateAllowedNetworks checks that every entry in an admin-supplied
// AllowedNetworks list is a valid IPv4 CIDR, and rejects the open wildcard
// (0.0.0.0/0 or ::/0) with a clear error — spec §3.1's "guarda-corpo": an
// open NTP server is a known amplification-attack vector, and offering it
// is almost certainly a mistake rather than an informed choice. Any other
// IPv4 range is accepted without further judgment — the admin knows their
// own network. Meant to be called at the point a value is about to be
// persisted (the API handler), so a rejected value is a 400 the UI can
// show, not a silently-skipped line discovered later in the rendered
// config.
//
// IPv6 is rejected explicitly (spec §8 puts it out of scope), not just
// implicitly unsupported: the rule builder
// (internal/nftables.ReconcileNTPInput) emits `ip saddr { … }`, which in
// the `inet` family only ever matches IPv4 — nft errors out on an IPv6
// prefix there. Left unchecked, that nft error surfaced *after* the chain
// had already been flushed and *before* the drop rule was added, leaving
// the input chain empty (no protection at all) while chrony's own `allow`
// line and the panel both kept claiming the network was served. Rejecting
// here, atomically for the whole list (one bad entry fails the entire
// save, never a silent partial apply), makes that failure mode
// unreachable rather than merely unlikely.
func ValidateAllowedNetworks(networks []string) error {
	for _, network := range networks {
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			return fmt.Errorf("rede inválida %q: precisa ser um CIDR (ex: 192.168.3.0/24)", network)
		}
		if isOpenCIDR(network) {
			return fmt.Errorf("rede %q libera todo o tráfego (0.0.0.0/0 ou ::/0) — um servidor NTP aberto para a internet é um vetor de ataque conhecido; escolha uma faixa específica", network)
		}
		if ipnet.IP.To4() == nil {
			return fmt.Errorf("rede %q: IPv6 ainda não é suportado nesta lista (apenas IPv4 por enquanto) — ver spec §8", network)
		}
	}
	return nil
}

// NormalizeAllowedNetworks rewrites each entry to its canonical network
// form via net.ParseCIDR + IPNet.String() — e.g. "192.168.3.5/24" (host
// bits set, which net.ParseCIDR happily accepts) becomes "192.168.3.0/24".
// Without this, what an admin typed, what gets persisted, what chrony's
// `allow` line says, and what nft actually stores in its saddr set could
// all be different (but equivalent) spellings of the same network — this
// makes them the same bytes everywhere, so "what's applied" and "what's
// shown" never diverge over a cosmetic difference. Call only on a list that
// has already passed ValidateAllowedNetworks; an entry that still somehow
// fails to parse is left unchanged rather than dropped, since this
// function's job is normalization, not validation.
func NormalizeAllowedNetworks(networks []string) []string {
	out := make([]string, len(networks))
	for i, n := range networks {
		if _, ipnet, err := net.ParseCIDR(n); err == nil {
			out[i] = ipnet.String()
		} else {
			out[i] = n
		}
	}
	return out
}

// ReloadConfig applies Servers (drop-in write/remove), AllowedNetworks and
// Timezone, then reloads chrony gracefully via systemd's reload-or-restart
// — same convention as keaunbound.Service.ReloadConfigs
// (internal/keaunbound), not a raw SIGHUP or an unconditional restart. File
// writes are skipped in dry-run mode; Execute calls always go through
// (RealExecutor itself handles dry-run by logging instead of running).
//
// AllowedNetworks now lives directly on c (spec §3.1) — the admin's own
// choice, no longer threaded in from netsvc.Config.SubnetCIDR the way the
// single implicit LAN subnet used to be. The DHCP subnet is still used, but
// only by the API handler as a one-time default pre-fill when the admin
// first enables the toggle (see internal/api/handlers.NTPHandler), never as
// the enforced value here.
//
// The drop-in is written whenever there is something to manage — a custom
// server list, OR serving the LAN (which needs the drop-in even with zero
// custom servers and/or an empty AllowedNetworks list — the latter is a
// deliberate, explicit "nothing allowed" state, not "nothing configured").
// It is removed only when both are off, restoring today's fully-unmanaged
// behaviour exactly.
//
// The returned warnings are the entries GenerateChronyConf had to drop (an
// invalid server, an invalid or wide-open allowed network) — the apply
// worked, but not with everything the admin configured, and the caller is
// expected to record that alongside the apply status rather than let the
// panel show those values as if they were in effect (I-7).
func (s *Service) ReloadConfig(ctx context.Context, c Config) ([]string, error) {
	var warnings []string
	if !s.exec.IsDryRun() {
		if len(c.Servers) == 0 && !c.ServeLAN {
			if err := os.Remove(s.confPath); err != nil && !os.IsNotExist(err) {
				return warnings, fmt.Errorf("remover %s: %w", s.confPath, err)
			}
		} else {
			content, w := GenerateChronyConf(c)
			warnings = w
			if err := os.WriteFile(s.confPath, []byte(content), 0o644); err != nil {
				// A falha provável aqui é a armadilha do namespace, não uma
				// falha de escrita comum: o chrony é instalado sob demanda,
				// e até esta correção o /etc/chrony/conf.d não era criado
				// por nenhum instalador. Reproduzido na VM com o serviço no
				// ar desde antes: "Read-only file system". O erro chegava ao
				// last_apply da tela de NTP sem dizer o que fazer.
				// SandboxHint devolve a explicação e o comando; para erros
				// que não são a armadilha, devolve só o motivo cru.
				return warnings, errors.New(sysprep.SandboxHint(s.confPath, err))
			}
		}
	}
	if c.Timezone != "" {
		if _, err := s.exec.Execute(ctx, "timedatectl", "set-timezone", c.Timezone); err != nil {
			return warnings, fmt.Errorf("definir fuso horário: %w", err)
		}
	}
	if _, err := s.exec.Execute(ctx, "systemctl", "reload-or-restart", "chrony"); err != nil {
		return warnings, fmt.Errorf("recarregar chrony: %w", err)
	}
	return warnings, nil
}

// ParseChronycTracking parses `chronyc tracking` output into its most
// useful display fields. Best-effort: a field chronyc omits is left at its
// zero value.
func ParseChronycTracking(out string) (stratum int, offsetSecs float64, source string) {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "Reference ID":
			source = val
		case "Stratum":
			stratum, _ = strconv.Atoi(val)
		case "System time":
			fields := strings.Fields(val)
			if len(fields) > 0 {
				f, _ := strconv.ParseFloat(fields[0], 64)
				if strings.Contains(val, "slow") {
					f = -f
				}
				offsetSecs = f
			}
		}
	}
	return stratum, offsetSecs, source
}

// Status reports the current chrony install/sync/detail state for display.
// Reuses IsSynced (unchanged, see package doc) for the `synced` field —
// never re-implements sync detection; Vigia's checkNTP remains the single
// source of truth for alerting.
func (s *Service) Status(ctx context.Context) StatusInfo {
	installed, _ := s.exec.ExecuteRead(ctx, "systemctl", "list-unit-files", "--no-legend", "chrony.service")
	st := StatusInfo{Installed: strings.Contains(installed, "chrony.service")}
	if !st.Installed {
		return st
	}
	st.Synced = IsSynced(ctx, s.exec)
	out, err := s.exec.ExecuteRead(ctx, "chronyc", "tracking")
	if err == nil {
		st.Stratum, st.OffsetSecs, st.Source = ParseChronycTracking(out)
	}
	return st
}

// ListTimezones returns every IANA timezone name systemd knows about, for
// populating a <select> in the UI — never a free-text field, to avoid a
// typo silently producing an invalid `timedatectl set-timezone` call.
// Always returns a non-nil slice on success (even zero matches), so a
// caller marshaling it to JSON never emits `null` for a field the frontend
// expects to `.map()` over.
func (s *Service) ListTimezones(ctx context.Context) ([]string, error) {
	out, err := s.exec.ExecuteRead(ctx, "timedatectl", "list-timezones")
	if err != nil {
		return nil, err
	}
	zones := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			zones = append(zones, line)
		}
	}
	return zones, nil
}

// InstallChrony installs the chrony package on demand. Only ever triggered
// by an explicit admin action (never automatic/on startup), same safety
// property EnsureEnabled already relies on for "no silent apt": chrony is an
// optional package, not part of the base that bootstrapdeps.Ensure guarantees
// at boot.
//
// The apt mechanics themselves (transient systemd unit, so the package
// manager never runs inside this process's own sandbox) live in
// bootstrapdeps.InstallPackages — a single call site for every apt install in
// the codebase. See its doc comment.
func (s *Service) InstallChrony(ctx context.Context) error {
	return bootstrapdeps.InstallPackages(ctx, s.exec, "chrony")
}
