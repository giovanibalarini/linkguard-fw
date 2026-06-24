package storage

import (
	"database/sql"
	"time"
)

// ─── Link ────────────────────────────────────────────────────────────────────

// Link represents a WAN link configuration.
type Link struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Interface    string    `json:"interface"`
	IPAddress    string    `json:"ip_address"`
	Gateway      string    `json:"gateway"`
	Weight       int       `json:"weight"`
	DNSTest      string    `json:"dns_test"`
	MonitorHosts string    `json:"monitor_hosts"`
	Status       string    `json:"status"` // online, offline, degraded, unknown
	LatencyMs    float64   `json:"latency_ms"`
	PacketLoss   float64   `json:"packet_loss"`
	LastCheck    *time.Time `json:"last_check"`
	Enabled      bool      `json:"enabled"`
	TableID      int       `json:"table_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ─── Alert ───────────────────────────────────────────────────────────────────

// Alert represents a system alert.
type Alert struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Severity   string     `json:"severity"` // info, warning, critical
	Title      string     `json:"title"`
	Message    string     `json:"message"`
	LinkID     string     `json:"link_id,omitempty"`
	Resolved   bool       `json:"resolved"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// ─── AuditLog ────────────────────────────────────────────────────────────────

// AuditLog records an auditable action.
type AuditLog struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Details   string    `json:"details"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

// ─── FailoverEvent ───────────────────────────────────────────────────────────

// FailoverEvent records a state change on a link.
type FailoverEvent struct {
	ID         string    `json:"id"`
	LinkID     string    `json:"link_id"`
	LinkName   string    `json:"link_name"`
	FromStatus string    `json:"from_status"`
	ToStatus   string    `json:"to_status"`
	Reason     string    `json:"reason"`
	Commands   string    `json:"commands"`
	DryRun     bool      `json:"dry_run"`
	CreatedAt  time.Time `json:"created_at"`
}

// ─── RoutingPolicy ───────────────────────────────────────────────────────────

// RoutingPolicy defines how traffic from/to a CIDR is routed.
type RoutingPolicy struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	SourceCIDR string    `json:"source_cidr"`
	DestCIDR   string    `json:"dest_cidr"`
	LinkID     string    `json:"link_id"`
	Priority   int       `json:"priority"`
	Enabled    bool      `json:"enabled"`
	Failover   bool      `json:"failover"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ─── IptablesBackup ──────────────────────────────────────────────────────────

// IptablesBackup stores a snapshot of iptables rules.
type IptablesBackup struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Rules     string    `json:"rules"`
	CreatedAt time.Time `json:"created_at"`
}

// ─── User ────────────────────────────────────────────────────────────────────

// User represents an application user.
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"` // bcrypt hash, never serialised
	Role      string    `json:"role"` // legacy single-role column (kept for compat)
	RoleIDs   []string  `json:"role_ids"` // assigned roles (RBAC); populated on demand
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ─── Role (RBAC) ─────────────────────────────────────────────────────────────

// Role is a named, user-defined set of permissions.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Builtin     bool      `json:"builtin"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleSeed describes a built-in role to seed on first run. It mirrors the
// in-code permission catalog (internal/auth) without creating an import cycle.
type RoleSeed struct {
	ID          string
	Name        string
	Description string
	Permissions []string
}

// ─── HostMetadata ────────────────────────────────────────────────────────────

// HostMetadata stores admin-set and observed data about a LAN host, keyed by
// MAC (more stable than IP under DHCP). The live state (interface, NUD state)
// comes from the neighbour table at list time and is not persisted here.
type HostMetadata struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	Alias     string    `json:"alias"`
	Blocked   bool      `json:"blocked"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ─── TrafficSample ──────────────────────────────────────────────────────────

// TrafficSample stores per-interface traffic rates for a specific archive step.
type TrafficSample struct {
	Interface   string  `json:"interface"`
	StepSeconds int     `json:"step_seconds"`
	Timestamp   int64   `json:"timestamp"`
	RxBps       float64 `json:"rx_bps"`
	TxBps       float64 `json:"tx_bps"`
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func nullableTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func fromNullTime(n sql.NullTime) *time.Time {
	if !n.Valid {
		return nil
	}
	return &n.Time
}
