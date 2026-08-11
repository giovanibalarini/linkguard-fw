// Package sysupdates reports which system packages have pending updates,
// highlighting security ones — so an operator sees "this firewall is
// missing a kernel security update" on the panel instead of discovering it
// over SSH.
//
// Read-only by design: it never runs `apt-get update`, `install` or
// `upgrade`. Refreshing the package lists is left to Debian's own
// apt-daily.timer, and applying updates is an operator decision — an
// unattended upgrade on a border firewall can restart networking and drop
// the link. This mirrors the same call made in timesync.EnsureEnabled about
// not driving a package manager from inside a long-running service.
package sysupdates

import (
	"context"
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// securityOrigin is the APT origin marker Debian stamps on security
// updates, e.g. "Debian-Security:13/stable-security".
const securityOrigin = "Debian-Security"

// Package is one pending package update.
type Package struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version"` // empty when the package is newly pulled in
	NewVersion     string `json:"new_version"`
	Origin         string `json:"origin"`
	Security       bool   `json:"security"`
}

// Report summarises the pending updates.
type Report struct {
	Total    int       `json:"total"`
	Security int       `json:"security"`
	Packages []Package `json:"packages"`
}

// Check enumerates pending updates from apt's already-cached package lists.
//
// Two production-verified details are load-bearing here. LC_ALL=C: apt's
// output is localized, and on the real box it came back in Portuguese, which
// silently defeats any English-keyed parsing. dist-upgrade (not upgrade):
// `apt-get --just-print upgrade` reported zero pending changes for a real
// pending kernel security update, because kernel upgrades pull in a new
// package; dist-upgrade reports it. Using `upgrade` would under-report
// precisely the updates that matter most on a firewall.
func Check(ctx context.Context, exec firewall.Executor) (Report, error) {
	out, err := exec.ExecuteRead(ctx, "env", "LC_ALL=C", "apt-get", "--just-print", "dist-upgrade")
	if err != nil {
		return Report{}, fmt.Errorf("consultar atualizações pendentes: %w", err)
	}
	return parseAptOutput(out), nil
}

// parseAptOutput extracts the pending packages from apt's simulation
// output. Only `Inst` lines count — `Conf` lines describe the configuration
// step of the very same packages and would double every count.
//
// Line shapes handled (both real, from the production capture):
//
//	Inst linux-image-amd64 [6.12.94-1] (6.12.101-1 Debian-Security:13/stable-security [amd64])
//	Inst linux-image-6.12.101+deb13-amd64 (6.12.101-1 Debian-Security:13/stable-security [amd64])
//
// The second has no `[current]` bracket because the package is new, not
// upgraded. Anything it cannot parse is skipped rather than guessed at.
func parseAptOutput(out string) Report {
	rep := Report{Packages: []Package{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "Inst "))

		name, rest, ok := strings.Cut(rest, " ")
		if !ok || name == "" {
			continue
		}
		pkg := Package{Name: name}

		// Optional "[current-version]" before the parenthesised part.
		if strings.HasPrefix(rest, "[") {
			if cur, tail, found := strings.Cut(strings.TrimPrefix(rest, "["), "]"); found {
				pkg.CurrentVersion = strings.TrimSpace(cur)
				rest = strings.TrimSpace(tail)
			}
		}

		// "(new-version Origin:suite/pocket [arch])"
		inner, _, found := strings.Cut(strings.TrimPrefix(rest, "("), ")")
		if !found {
			continue
		}
		fields := strings.Fields(inner)
		if len(fields) == 0 {
			continue
		}
		pkg.NewVersion = fields[0]
		if len(fields) > 1 {
			pkg.Origin = fields[1]
		}
		pkg.Security = strings.Contains(pkg.Origin, securityOrigin)

		rep.Packages = append(rep.Packages, pkg)
		rep.Total++
		if pkg.Security {
			rep.Security++
		}
	}
	return rep
}
