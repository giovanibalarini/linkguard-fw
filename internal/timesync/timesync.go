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
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

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
type Config struct {
	Servers  []string `json:"servers"`
	Timezone string   `json:"timezone"`
	ServeLAN bool     `json:"serve_lan"`
}

// DefaultConfig is the "unmanaged" starting state — identical to today's
// behaviour before this feature existed (EnsureEnabled already turns on
// chrony with the Debian default pool). Servers is an empty slice, not nil,
// so it marshals to JSON `[]` rather than `null`.
func DefaultConfig() Config {
	return Config{Servers: []string{}}
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

// GenerateChronyConf renders the LinkGuard-managed chrony drop-in from the
// configured NTP servers and, when serving the LAN, an `allow <cidr>`
// directive. Pure — no I/O. Called even when both Servers and lanCIDR/
// ServeLAN are "empty" (ReloadConfig now only removes the drop-in when
// *neither* a custom server list nor ServeLAN is configured — see its own
// doc comment).
//
// lanCIDR comes from netsvc.Config.SubnetCIDR (the DHCP/DNS config) — the
// single source of truth for the LAN subnet, deliberately not duplicated as
// a field on this Config. It is re-validated here (not just by the caller)
// because this is the function that interpolates it into a config file a
// privileged daemon (chronyd) reads: an invalid or malicious value must
// never reach the rendered `allow` line, regardless of what upstream
// validation exists.
func GenerateChronyConf(c Config, lanCIDR string) string {
	var b strings.Builder
	b.WriteString("# managed by linkguard\n\n")
	for _, srv := range c.Servers {
		fmt.Fprintf(&b, "server %s iburst\n", srv)
	}
	if c.ServeLAN && lanCIDR != "" {
		if _, _, err := net.ParseCIDR(lanCIDR); err == nil {
			fmt.Fprintf(&b, "\nallow %s\n", lanCIDR)
		} else {
			slog.Warn("CIDR da LAN inválido; diretiva allow do chrony omitida", "cidr", lanCIDR, "err", err)
		}
	}
	return b.String()
}

// ReloadConfig applies Servers (drop-in write/remove) and Timezone, then
// reloads chrony gracefully via systemd's reload-or-restart — same
// convention as keaunbound.Service.ReloadConfigs (internal/keaunbound), not
// a raw SIGHUP or an unconditional restart. File writes are skipped in
// dry-run mode; Execute calls always go through (RealExecutor itself
// handles dry-run by logging instead of running).
//
// lanCIDR is the LAN subnet (netsvc.Config.SubnetCIDR), needed only when
// c.ServeLAN is true — passed in rather than read by this package, so
// timesync never needs to import internal/netsvc (see GenerateChronyConf's
// doc comment).
//
// The drop-in is written whenever there is something to manage — a custom
// server list, OR serving the LAN (which needs the `allow` line even with
// zero custom servers, a very likely combination: default upstream pool,
// serve the LAN). It is removed only when both are off, restoring today's
// fully-unmanaged behaviour exactly.
func (s *Service) ReloadConfig(ctx context.Context, c Config, lanCIDR string) error {
	if !s.exec.IsDryRun() {
		if len(c.Servers) == 0 && !c.ServeLAN {
			if err := os.Remove(s.confPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remover %s: %w", s.confPath, err)
			}
		} else {
			if err := os.WriteFile(s.confPath, []byte(GenerateChronyConf(c, lanCIDR)), 0o644); err != nil {
				return fmt.Errorf("escrever %s: %w", s.confPath, err)
			}
		}
	}
	if c.Timezone != "" {
		if _, err := s.exec.Execute(ctx, "timedatectl", "set-timezone", c.Timezone); err != nil {
			return fmt.Errorf("definir fuso horário: %w", err)
		}
	}
	if _, err := s.exec.Execute(ctx, "systemctl", "reload-or-restart", "chrony"); err != nil {
		return fmt.Errorf("recarregar chrony: %w", err)
	}
	return nil
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

// InstallChrony asks systemd to run apt-get in its own transient,
// unhardened unit — never inside this process's own sandbox, which would
// need ReadWritePaths widened across most of the package-management
// filesystem (/var/lib/dpkg, /var/cache/apt, /usr, ...) to work. Only ever
// triggered by an explicit admin action (never automatic/on startup), same
// safety property EnsureEnabled already relies on for "no silent apt".
func (s *Service) InstallChrony(ctx context.Context) error {
	_, err := s.exec.Execute(ctx, "systemd-run", "--pipe", "--wait",
		"--", "apt-get", "install", "-y", "--no-install-recommends", "chrony")
	return err
}
