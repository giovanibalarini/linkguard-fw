package storage

import (
	"database/sql"
	"time"
)

// ─── Link ────────────────────────────────────────────────────────────────────

// Link represents a WAN link configuration.
type Link struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Interface       string     `json:"interface"`
	IPAddress       string     `json:"ip_address"`
	Gateway         string     `json:"gateway"`
	Weight          int        `json:"weight"`
	DNSTest         string     `json:"dns_test"`
	MonitorHosts    string     `json:"monitor_hosts"`
	Status          string     `json:"status"` // online, offline, degraded, unknown
	LatencyMs       float64    `json:"latency_ms"`
	PacketLoss      float64    `json:"packet_loss"`
	LastCheck       *time.Time `json:"last_check"`
	Enabled         bool       `json:"enabled"`
	TableID         int        `json:"table_id"`
	QoSEnabled      bool       `json:"qos_enabled"`
	QoSUploadMbps   int        `json:"qos_upload_mbps"`
	QoSDownloadMbps int        `json:"qos_download_mbps"`
	QoSInteractive  bool       `json:"qos_interactive"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ─── Alert ───────────────────────────────────────────────────────────────────

// Alert represents a system alert.
//
// LinkID é o identificador do QUE o alerta é sobre — junto com Type ele forma
// a identidade de "um problema em curso" que internal/alerts usa para
// deduplicar e para resolver. Guarda o id do link nos alertas de WAN, o nome
// da unidade systemd nos de serviço e "" nas condições que só existem uma vez
// por máquina (disco, CPU, relógio). O nome é herança da época em que só os
// alertas de link o usavam; não há FK nem JOIN com links(id).
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
//
// NÃO É UM RECURSO DO PRODUTO. Nada fora de internal/storage constrói ou lê
// este tipo: sem handler, sem service, sem tela (issue #62). A forma dos campos
// sugere um desenho que nunca foi implementado do outro lado — ver o comentário
// do bloco "Routing Policies" em repo_netsvc.go antes de assumir que basta
// ligá-lo na interface.
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
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	Password        string    `json:"-"`        // bcrypt hash, never serialised
	Role            string    `json:"role"`     // legacy single-role column (kept for compat)
	RoleIDs         []string  `json:"role_ids"` // assigned roles (RBAC); populated on demand
	PasswordVersion int       `json:"-"`        // bumped on every password change; embedded in JWT to revoke old tokens
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
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
	// AlwaysSync re-applies the permission set on every startup (used for the
	// admin role so new catalog permissions reach it after an upgrade).
	AlwaysSync bool
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

// ─── DHCPReservation ─────────────────────────────────────────────────────────

// DHCPReservation is a static DHCP lease (stable IP for a MAC).
type DHCPReservation struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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

// ─── MetricSample ────────────────────────────────────────────────────────────

// MetricSample stores min/avg/max for a named series+label at one bucket. The
// min/max are what let a rollup survive a short spike — averaging alone would
// dilute an 8-second degradation into invisibility inside a 60s bucket.
type MetricSample struct {
	Series      string  `json:"series"`
	Label       string  `json:"label"`
	StepSeconds int     `json:"step_seconds"`
	TsUnix      int64   `json:"ts_unix"`
	VMin        float64 `json:"v_min"`
	VAvg        float64 `json:"v_avg"`
	VMax        float64 `json:"v_max"`
}

// ─── StateInterval ───────────────────────────────────────────────────────────

// StateInterval is a span of time a (kind, label) spent in one state — a link
// being "degraded", a service being "down". EndedAt is nil while the interval
// is still open (the current state).
type StateInterval struct {
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	State     string `json:"state"`
	StartedAt int64  `json:"started_at"`
	EndedAt   *int64 `json:"ended_at,omitempty"`
}

// ─── AIReport ────────────────────────────────────────────────────────────────

// AIReport is one AI-generated analysis — either a scheduled digest or an
// immediate analysis of a severe event.
type AIReport struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"` // "digest" | "immediate"
	Summary        string    `json:"summary"`
	Findings       string    `json:"findings"`       // JSON-encoded []string
	Recommendation string    `json:"recommendation"` // always human-readable text, never a command
	Confidence     string    `json:"confidence"`     // "alta" | "média" | "baixa"
	CreatedAt      time.Time `json:"created_at"`
}

// ─── Managed interface (netif Fase 2) ────────────────────────────────────────

// ManagedInterface is the desired addressing config for one interface the
// admin has explicitly edited and confirmed. Only interfaces present here are
// "Managed" — see internal/netif's Iface.Managed field, which this table backs.
type ManagedInterface struct {
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	AddrMode    string    `json:"addr_mode"`
	CIDR        string    `json:"cidr"`
	Gateway     string    `json:"gateway"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PendingInterfaceChange is an applied-but-not-yet-confirmed interface edit.
// Persisted (not just in memory) so a LinkGuard restart mid-window doesn't
// silently turn an unconfirmed change permanent — see spec 19/07 §6.
type PendingInterfaceChange struct {
	ID           string    `json:"id"`
	Interface    string    `json:"interface"`
	OldConfig    string    `json:"old_config"` // JSON: ManagedInterface before this change (or "" if newly adopted)
	OldFiles     string    `json:"old_files"`  // JSON: []ConfigFileSnapshot to restore on rollback
	NewConfig    string    `json:"new_config"` // JSON: ManagedInterface being applied
	DeadlineUnix int64     `json:"deadline_unix"`
	CreatedAt    time.Time `json:"created_at"`
}

// ─── FirewallRule (Phase B: the admin's rules live in the DB) ───────────────

// FirewallRule is one of the admin's own rules for the `user_rules` chain,
// persisted here instead of existing only inside nft (design spec §4.1).
// nftables has no notion of a disabled rule and identifies rules only by a
// handle that changes every time the chain is rebuilt, so "disable without
// deleting", a stable identity and an explicit order all require the DB to
// be the source of truth and nft to be the rendered result — the same
// reconciliation model already used for NAT, NTP and the structural chains.
//
// Position is an explicit integer, not the row's insertion order: it is what
// ReconcileUserRules sorts by before rendering, and what Reorder sets
// directly from the admin's drag-and-drop (or the up/down fallback).
// Enabled=false means the rule is skipped when rendering into nft — it still
// exists here, fully intact, so re-enabling it needs no reconstruction.
type FirewallRule struct {
	ID          string    `json:"id"`
	Position    int       `json:"position"`
	GroupID     string    `json:"group_id"`
	Enabled     bool      `json:"enabled"`
	Action      string    `json:"action"` // accept | drop | reject
	Iif         string    `json:"iif"`
	Oif         string    `json:"oif"`
	Saddr       string    `json:"saddr"`
	Daddr       string    `json:"daddr"`
	Proto       string    `json:"proto"`
	Dport       string    `json:"dport"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
