// Package netsvc defines the backend-agnostic model for the LAN network
// services (DHCP + DNS) and the Provider interface each backend implements.
// The product ships the high-performance stack — Kea (DHCP) + unbound (DNS) —
// for real/large networks; the Provider abstraction keeps the management layer
// (reservations, ranges, DNS settings, blocklist) independent of the engine so
// another backend could be added without reworking the app.
package netsvc

import "context"

// Backend identifies which DHCP/DNS engine the admin selected.
type Backend string

const (
	// BackendKeaUnbound: Kea (DHCP — multi-subnet, HA-capable) + unbound (DNS —
	// multi-threaded recursive resolver, high QPS). The product default.
	BackendKeaUnbound Backend = "kea-unbound"
)

// Config holds the backend-agnostic DHCP/DNS settings the admin edits.
type Config struct {
	Backend      Backend  `json:"backend"`
	Interface    string   `json:"interface"`      // LAN interface to serve (e.g. br10)
	SubnetCIDR   string   `json:"subnet_cidr"`    // e.g. 192.168.3.0/24
	RangeStart   string   `json:"range_start"`    // first DHCP address
	RangeEnd     string   `json:"range_end"`      // last DHCP address
	Gateway      string   `json:"gateway"`        // routers option given to clients
	LeaseHours   int      `json:"lease_hours"`    // lease time in hours
	DNSToClients []string `json:"dns_to_clients"` // DNS servers advertised to clients
	Upstreams    []string `json:"upstreams"`      // DNS forwarders ([] = recurse from root)
	LogQueries   bool     `json:"log_queries"`    // log DNS queries (visibility; I/O heavy)
	DomainSuffix string   `json:"domain_suffix"`  // optional local domain (e.g. lan)

	// Controle de fuga de DNS (issue #124). Desligados por padrão: mudar o
	// caminho do DNS da rede sem o admin pedir seria hostil, e é o tipo de
	// mudança cujo sintoma (site que não abre) ninguém liga ao firewall.
	//
	// ForceLocalDNS redireciona a porta 53 da LAN para o resolver local, de
	// modo que quem configurou 8.8.8.8 no aparelho seja atendido pela caixa —
	// sem isso, a blocklist do painel não vale para ele.
	ForceLocalDNS bool `json:"force_local_dns"`
	// BlockDoT recusa DNS sobre TLS (853) com RST. DoH na 443 continua
	// passando: é HTTPS comum e indistinguível do resto.
	BlockDoT bool `json:"block_dot"`
	// DNSExceptIPs são hosts isentos das duas medidas — quem roda resolver
	// próprio na LAN de propósito.
	DNSExceptIPs []string `json:"dns_except_ips"`
}

// DefaultConfig mirrors the previous isc-dhcp/bind9 behaviour for the strong stack.
func DefaultConfig() Config {
	return Config{
		Backend:      BackendKeaUnbound,
		Interface:    "br10",
		SubnetCIDR:   "192.168.3.0/24",
		RangeStart:   "192.168.3.10",
		RangeEnd:     "192.168.3.100",
		Gateway:      "192.168.3.3",
		LeaseHours:   12,
		DNSToClients: []string{"192.168.3.3"}, // clients use unbound (so filtering/logging work)
		// Empty = unbound resolves recursively from the root (more private and
		// independent; matches the previous bind9 behaviour). Set upstreams to
		// forward instead.
		Upstreams:  []string{},
		LogQueries: false,
	}
}

// Reservation is a static DHCP lease (stable IP for a MAC).
type Reservation struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// Lease is one active DHCP lease.
type Lease struct {
	Expiry   int64  `json:"expiry"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// ConfigFile is one rendered config file (a backend may produce several — e.g.
// Kea's JSON plus unbound's config).
type ConfigFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ApplyResult is what an apply/reload reports back beyond "did it fail".
//
// Warnings exists because "the apply succeeded" and "everything you
// configured is in effect" are different statements, and a backend that
// drops a bad list entry (one invalid blocklist domain, one malformed
// upstream) makes them diverge. Skipping such an entry is the right
// behaviour — one bad entry must not sink the good ones — but doing it
// with nothing but a journal line means the panel keeps showing a value
// the daemon never received. Each warning is a plain-Portuguese sentence,
// ready to be shown to the admin as-is.
// Installed names the packages the provider had to install to make this
// apply possible (kea-dhcp4-server, unbound), empty on every apply after
// the first. The admin turned a feature on and LinkGuard brought in what it
// needed — the caller uses this to record/clear the corresponding alert only
// on the transition, never on every save.
type ApplyResult struct {
	Output    string   `json:"output,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Installed []string `json:"installed,omitempty"`
}

// PrereqError is an apply that did not happen because a prerequisite of the
// machine is missing — the package is not installed and could not be
// installed, or the directory its config lives in is not writable by this
// process. Its message is written for the admin, in Portuguese, and says
// what is missing, why, what stops working and how to fix it by hand.
//
// It exists so the API layer can tell this apart from an internal failure:
// "erro interno do servidor" is the correct answer to a bug, and the wrong
// answer to "o pacote kea-dhcp4-server não está instalado" — the second is
// something the admin can act on, and hiding it is the "mentir por omissão"
// FEATURES.md's delivery rule forbids. Nothing is written and nothing is
// reloaded when this is returned: the running config is left intact.
type PrereqError struct {
	// Msg is the full, admin-facing sentence. Safe to show as-is.
	Msg string
}

func (e *PrereqError) Error() string { return e.Msg }

// Provider is implemented by each DHCP/DNS backend.
type Provider interface {
	// Backend reports which engine this provider drives.
	Backend() Backend
	// GenerateConfigs renders the backend config files (pure, for UI preview
	// before applying). ntpServer is the firewall's LAN IP to advertise as
	// DHCP option 42 (ntp-servers) when NTP-serve-the-LAN is enabled, or ""
	// when it is not — passed in by the caller (internal/timesync's config
	// lives in a different package) rather than read from the DB here, so
	// this stays a pure function of its inputs.
	//
	// The error is for a config that cannot be rendered at all — a
	// singular, non-optional value the backend would otherwise have to drop
	// silently (see keaunbound.GenerateUnboundConfig). A preview must show
	// that failure rather than a config the apply would refuse.
	GenerateConfigs(c Config, reservations []Reservation, blockedDomains []string, ntpServer string) ([]ConfigFile, error)
	// Apply writes the configs and restarts the services.
	Apply(ctx context.Context, c Config, reservations []Reservation, blockedDomains []string) (string, error)
	// ReloadConfigs writes the configs and reloads the services gracefully
	// (validate + SIGHUP, no restart), used by the auto-apply flow. ntpServer
	// is the same DHCP option 42 input as GenerateConfigs.
	ReloadConfigs(ctx context.Context, c Config, reservations []Reservation, blockedDomains []string, ntpServer string) (ApplyResult, error)
	// Leases returns the active DHCP leases.
	Leases(ctx context.Context) ([]Lease, error)
}
