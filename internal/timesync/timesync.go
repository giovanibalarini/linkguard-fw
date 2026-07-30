// Package timesync makes LinkGuard the owner of the box's NTP time
// synchronization — the same "own this runtime prerequisite" pattern already
// used for IPv4 forwarding (routes.EnsureForwarding) and conntrack
// accounting (hosttraffic.EnsureAccounting).
package timesync

import (
	"context"
	"log/slog"
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
