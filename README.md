# LinkGuard FW

A Linux firewall management tool for Debian servers with multiple WAN links. Supports load balancing, failover, iptables management, routing, and real-time monitoring — all through a modern web interface.

## ⚠️ Read before installing: LinkGuard takes over the machine

**LinkGuard is an appliance, not a helper tool.** Once installed, it takes
ownership of the host's networking stack — hardware, addressing, firewall and
the network services it manages. It **enforces its own configuration on every
startup**, which means manual edits to the files below are overwritten
without warning. That is the intended behaviour: the whole point is that the
panel is the source of truth, not a pile of hand-edited files.

Do not install it on a machine that is also doing something else you care
about, and do not expect hand-made changes to these to survive:

| What it takes over | Where |
|---|---|
| Firewall ruleset | its own `table inet linkguard` in nftables, persisted to `/etc/nftables.conf` |
| IP forwarding & conntrack accounting | `/proc/sys/net/ipv4/ip_forward`, `/etc/sysctl.d/99-linkguard-*.conf` |
| Routing between WANs | the default route (multipath/failover), `ip rule` policy routing |
| DNS resolver (unbound) | `/etc/unbound/unbound.conf.d/linkguard.conf` |
| The host's own resolver | `/etc/resolv.conf` → `127.0.0.1`, plus a `supersede` line in `/etc/dhcp/dhclient.conf` so DHCP renewals stop reverting it |
| DHCP server (Kea) | `/etc/kea/kea-dhcp4.conf` (owned entirely), and `/etc/kea` permissions |
| Time sync (chrony) | `/etc/chrony/conf.d/linkguard.conf`; enables the service, and can install it on request |
| Network interface naming | `.link` files under `/etc/systemd/network` (pins names to MAC addresses) |
| Its own config & secrets | `/etc/linkguard-fw/` |
| Its own base packages | installs `nftables`, `iproute2`, `iptables` and `iputils-ping` itself on the first boot if they are missing (see "Installing on a bare machine") |

It never edits the packages' own primary config files (`chrony.conf`,
`unbound.conf`): it writes drop-ins alongside them, so a package upgrade
never fights LinkGuard. `/etc/nftables.conf` is the exception — LinkGuard
owns that file, and as of v1.0.94 writes only its own table into it.

What it deliberately does **not** touch: `/etc/network/interfaces` (ifupdown
is still hand-managed on current installs) and anything unrelated to
networking.

## Delivery rule (non-negotiable)

> **Nothing here is a mock-up. Everything implemented must actually work on
> the system, and must be manageable from the web panel — enable, disable,
> edit and verify — without SSH.**

A feature counts as delivered only when all three hold: it applies real
system state (config files, nftables rules, service reloads) rather than just
persisting to the database; it is fully controllable from the panel under the
matching RBAC permission; and the panel lets the admin verify it is genuinely
in effect (configured is not the same as working — a watcher that only reads
a config file proves nothing).

Backend without a screen is not a delivery. A screen without real effect is
worse than nothing: it creates false confidence, which is precisely what this
tool exists to eliminate. See `FEATURES.md` for the full statement.

## Features

- **Dashboard** — Live view of system health, WAN status, latency, packet loss and bandwidth
- **WAN Link Management** — Register and monitor multiple internet links (eth0, eth1, ppp0, etc.)
- **Automatic Failover** — Detects link failures and restores routing automatically; configurable thresholds and cooldown
- **Route Management** — View and manage routing tables, `ip rule` entries, and gateway configuration
- **Firewall Rules** — List and inspect iptables rules across filter, NAT, mangle tables
- **NAT / Mangle** — View PREROUTING, POSTROUTING, FORWARD, MARK and related rules
- **Prometheus Metrics** — Exposes `/metrics` for integration with Prometheus and Grafana
- **Alerts** — Visual alerts in the web UI and log file for link events, high resource usage, and errors
- **Audit Logging** — Full audit trail of configuration changes
- **Dry-run Mode** — Preview all commands before applying to the live system
- **Backup & Rollback** — Automatic iptables backup before any change; one-click rollback
- **JWT Authentication** — Secure web UI with session tokens; change default password on first login

## Architecture

```
linkguard-fw/
├── cmd/linkguard-fw/        # Main entry point
├── internal/
│   ├── api/                 # HTTP server & REST handlers
│   │   └── handlers/        # Per-resource handlers
│   ├── auth/                # JWT authentication & middleware
│   ├── alerts/              # Alert generation and retrieval
│   ├── config/              # Configuration loading and defaults
│   ├── failover/            # Failover state machine
│   ├── firewall/            # Executor interface (real + dry-run)
│   ├── iptables/            # iptables-L parser and service
│   ├── links/               # WAN link CRUD and validation
│   ├── metrics/             # Prometheus metrics registry
│   ├── monitoring/          # Background metrics collector
│   ├── routes/              # ip route / ip rule service
│   ├── storage/             # SQLite persistence (models + repository)
│   └── system/              # CPU, memory, disk, network metrics
├── web/                     # React + Vite frontend
│   └── src/
│       ├── api/             # Axios client
│       ├── components/      # Shared UI components
│       ├── context/         # Auth context
│       └── pages/           # Dashboard, Links, Routes, Firewall, etc.
├── deploy/                  # Deployment files
│   ├── linkguard-fw.service # systemd unit file
│   └── install.sh           # Installation script
├── embed.go                 # Go embed directive for web/dist
└── Makefile                 # Build, test and install targets
```

## Requirements

- **OS**: Debian 13 (Trixie) or compatible — a bare install is enough, see below
- **Go**: 1.21+ (to build from source)
- **Node.js**: 18+ (for frontend build)
- **Permissions**: Root (it manages nftables, routing and system services)

## Installing on a bare machine

**You do not install the dependencies and then LinkGuard. You install
LinkGuard, and it brings what it needs.** That is the same premise as
"LinkGuard takes over the machine" above, applied to the install itself: it
goes in first, on a machine with nothing on it, and coordinates the rest.

```bash
# Either of these works on a machine with nothing installed on it:
sudo apt install ./linkguard-fw_<version>_amd64.deb   # apt resolves everything up front
sudo dpkg -i ./linkguard-fw_<version>_amd64.deb       # no apt needed; LinkGuard finishes the job
```

The package declares its base (`nftables`, `iproute2`, `iptables`,
`iputils-ping`) as `Recommends:`, not `Depends:`, on purpose: with `Depends:`,
a plain `dpkg -i` on a bare box stops half-way (`iU`, "dependency problems
prevent configuration"), the service never starts, and there is no panel left
to explain what went wrong. As `Recommends:` the package always installs *and*
configures, the service starts, and on its first boot it installs whatever
base package is missing itself (`internal/bootstrapdeps`) — a running service
can call apt, a package's own maintainer scripts cannot (dpkg holds its lock
for the whole run).

The optional packages (`kea-dhcp4-server`, `unbound`, `chrony`,
`smartmontools`) are **not** installed at boot. They are installed on demand,
when an admin turns the corresponding feature on in the panel.

**If it cannot install them** (no network, unreachable mirror, broken
repository), it does not pretend: it retries once after refreshing the apt
index, then raises a **critical alert on the Alerts screen** naming each
missing package and what stops working because of it ("without nftables there
is no packet filter at all: nothing is blocked, NAT is not applied and no rule
from the panel has any effect"), together with the command to install it by
hand. The same goes to the journal, and the service keeps running — so there
is a panel to read the alert on. Fix the repository and restart the service
(`systemctl restart linkguard-fw`): it tries again and clears the alert by
itself once it succeeds.

## Quick Start

### Build from source

```bash
# 1. Build frontend and backend
make build

# 2. Run in dry-run mode (safe, no system changes)
./dist/linkguard-fw --dry-run --debug --addr 127.0.0.1 --port 9997

# 3. Open the web UI
# http://127.0.0.1:9997
# Login: admin / admin   <-- change immediately!
```

### Install as systemd service

```bash
# 1. Build the binary
make build

# 2. Run the install script as root
sudo bash deploy/install.sh

# 3. (optional) Adjust the config — jwt_secret is already a strong random
#    value generated by install.sh; only edit it if you specifically need to
#    replace it. Other settings (listen_addr, etc.) are safe to change.
sudo nano /etc/linkguard-fw/config.json

# 4. Enable and start the service
sudo systemctl enable --now linkguard-fw

# 5. Check status
sudo systemctl status linkguard-fw
sudo journalctl -u linkguard-fw -f
```

### Using Make

```
make build          - Build frontend + backend
make build-frontend - Build only the React frontend
make build-backend  - Build only the Go binary
make test           - Run all Go tests
make test-coverage  - Run tests with HTML coverage report
make run            - Build and run in dry-run mode
make install        - Install binary and service (requires root)
make uninstall      - Remove binary and service
make clean          - Remove build artifacts
make clean-all      - Remove build artifacts and node_modules
make help           - Show all available targets
```

## Configuration

Default config file: `/etc/linkguard-fw/config.json`

```json
{
  "listen_addr": "127.0.0.1",
  "port": 9997,
  "db_path": "/var/lib/linkguard-fw/linkguard.db",
  "jwt_secret": "<64-char random value, auto-generated by install.sh — must be at least 32 chars or the service refuses to start>",
  "dry_run": false,
  "debug": false,
  "monitor_interval_seconds": 30,
  "failover_enabled": true,
  "failover_threshold": 3,
  "recovery_threshold": 2,
  "failover_cooldown_seconds": 60,
  "metrics_enabled": true
}
```

CLI flags override config file values:

```
--config   path to config file
--dry-run  enable dry-run mode (no system changes)
--debug    enable debug logging
--addr     listen address (default: 127.0.0.1)
--port     listen port (default: 9997)
```

## API Endpoints

```
GET  /api/health                  - Health check (no auth)
GET  /api/system/status           - System metrics
POST /api/auth/login              - Login, returns JWT token
POST /api/auth/change-password    - Change password

GET  /api/links                   - List WAN links
POST /api/links                   - Create WAN link
GET  /api/links/{id}              - Get WAN link
PUT  /api/links/{id}              - Update WAN link
DELETE /api/links/{id}            - Delete WAN link

GET  /api/routes                  - List routing table
GET  /api/routes/rules            - List ip rules
GET  /api/routes/all              - List all routing tables

GET  /api/iptables/rules          - List all iptables tables
GET  /api/iptables/{table}        - List specific table (filter, nat, mangle)
GET  /api/iptables/backups        - List iptables backups
POST /api/firewall/preview        - Preview command
POST /api/firewall/apply          - Apply firewall changes (with auto-backup)
POST /api/firewall/rollback       - Rollback to previous backup

GET  /api/alerts                  - List alerts
PUT  /api/alerts/{id}/resolve     - Resolve an alert

GET  /api/failover/events         - List failover events

GET  /api/logs                    - List audit logs

GET  /metrics                     - Prometheus metrics (no auth)
```

## Prometheus Metrics

Exposed at `/metrics`:

| Metric | Description |
|--------|-------------|
| `linkguard_link_status` | WAN link status (1=online, 0=offline) |
| `linkguard_link_latency_ms` | Average latency per link |
| `linkguard_link_packet_loss_percent` | Packet loss per link |
| `linkguard_interface_rx_bytes_total` | Bytes received per interface |
| `linkguard_interface_tx_bytes_total` | Bytes transmitted per interface |
| `linkguard_failover_events_total` | Total failover events |
| `linkguard_alerts_unresolved_total` | Current unresolved alerts |
| `linkguard_cpu_usage_percent` | System CPU usage |
| `linkguard_memory_usage_percent` | System memory usage |
| `linkguard_disk_usage_percent` | System disk usage |

### Grafana / external Prometheus

If you already run Prometheus on the box (or reachable from it), point it at
LinkGuard with the job in `deploy/prometheus/linkguard.yml` — copy its
contents into your `scrape_configs`. A starter Grafana dashboard is at
`deploy/grafana/linkguard-dashboard.json` (Dashboards → Import → paste the
file contents).

This is entirely optional — LinkGuard keeps its own history (see the
Monitoring page's timeline) and does not require Prometheus to function.

**Known pitfall:** if you migrated from bind9 to unbound (see the DHCP/DNS
docs), remove any leftover `job_name: bind` entry in your `prometheus.yml` —
it will show as a permanently-down target for a service that no longer runs.

## Security

- The web UI is bound to `127.0.0.1` by default — not exposed to the internet
- All API endpoints (except `/api/health` and `/api/auth/login`) require a valid JWT token
- Default admin password is `admin` — **change it immediately after first login**
- All firewall commands are validated before execution; inputs are never concatenated into shell strings
- Every configuration change is logged in the audit log
- Dry-run mode previews commands without applying them
- Automatic iptables backup before any `apply` operation with one-click rollback

### Firewall evaluation order changed: blocks now win

**As of this release, blocked hosts and blocked destinations ("Bloqueios e
direcionamento" tab) are evaluated BEFORE the admin's own rule groups, and
always win.** Before, it was the other way around — an `accept` in a rule
group could override a block. If you are updating an existing production
install: anything you had relying on a rule group letting through a host or
destination that is also on a blocklist will now be blocked instead. Review
your blocklists and rule groups after updating.

## Development

```bash
# Backend (hot-recompile with go run)
go run ./cmd/linkguard-fw/ --dry-run --debug

# Frontend (Vite dev server with HMR)
cd web && npm run dev

# Run tests
make test

# Run tests with race detector
go test -race ./...
```

## License

MIT
