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
	SubnetCIDR   string   `json:"subnet_cidr"`     // e.g. 192.168.3.0/24
	RangeStart   string   `json:"range_start"`     // first DHCP address
	RangeEnd     string   `json:"range_end"`       // last DHCP address
	Gateway      string   `json:"gateway"`         // routers option given to clients
	LeaseHours   int      `json:"lease_hours"`     // lease time in hours
	DNSToClients []string `json:"dns_to_clients"`  // DNS servers advertised to clients
	Upstreams    []string `json:"upstreams"`       // DNS forwarders ([] = recurse from root)
	LogQueries   bool     `json:"log_queries"`     // log DNS queries (visibility; I/O heavy)
	DomainSuffix string   `json:"domain_suffix"`   // optional local domain (e.g. lan)
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
		Upstreams:    []string{"1.1.1.1", "8.8.8.8"},
		LogQueries:   false,
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

// Provider is implemented by each DHCP/DNS backend.
type Provider interface {
	// Backend reports which engine this provider drives.
	Backend() Backend
	// GenerateConfigs renders the backend config files (pure, for UI preview
	// before applying).
	GenerateConfigs(c Config, reservations []Reservation, blockedDomains []string) []ConfigFile
	// Apply writes the configs and reloads the services.
	Apply(ctx context.Context, c Config, reservations []Reservation, blockedDomains []string) (string, error)
	// Leases returns the active DHCP leases.
	Leases(ctx context.Context) ([]Lease, error)
}
