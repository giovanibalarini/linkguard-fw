package storage

import (
	"time"

	"github.com/google/uuid"
)

// ─── DHCP/DNS repository ─────────────────────────────────────────────────────

// ListDHCPReservations returns all static reservations ordered by IP.
func (db *DB) ListDHCPReservations() ([]DHCPReservation, error) {
	rows, err := db.conn.Query(`
		SELECT mac, ip, hostname, created_at, updated_at FROM dhcp_reservations ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DHCPReservation{}
	for rows.Next() {
		var r DHCPReservation
		if err := rows.Scan(&r.MAC, &r.IP, &r.Hostname, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertDHCPReservation creates or updates a reservation (keyed by MAC).
func (db *DB) UpsertDHCPReservation(mac, ip, hostname string) error {
	now := time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO dhcp_reservations (mac, ip, hostname, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, hostname = excluded.hostname, updated_at = excluded.updated_at`,
		mac, ip, hostname, now, now)
	return err
}

// DeleteDHCPReservation removes a reservation by MAC.
func (db *DB) DeleteDHCPReservation(mac string) error {
	_, err := db.conn.Exec(`DELETE FROM dhcp_reservations WHERE mac = ?`, mac)
	return err
}

// ListDNSBlocklist returns all blocked domains ordered alphabetically.
func (db *DB) ListDNSBlocklist() ([]string, error) {
	rows, err := db.conn.Query(`SELECT domain FROM dns_blocklist ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddDNSBlocklist adds a domain to the DNS blocklist.
func (db *DB) AddDNSBlocklist(domain string) error {
	_, err := db.conn.Exec(`INSERT OR IGNORE INTO dns_blocklist (domain) VALUES (?)`, domain)
	return err
}

// DeleteDNSBlocklist removes a domain from the DNS blocklist.
func (db *DB) DeleteDNSBlocklist(domain string) error {
	_, err := db.conn.Exec(`DELETE FROM dns_blocklist WHERE domain = ?`, domain)
	return err
}

// ─── Routing Policies ────────────────────────────────────────────────────────

// GetRoutingPolicies returns all routing policies.
func (db *DB) GetRoutingPolicies() ([]RoutingPolicy, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, source_cidr, dest_cidr, link_id, priority, enabled, failover, created_at, updated_at
		FROM routing_policies ORDER BY priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []RoutingPolicy
	for rows.Next() {
		var p RoutingPolicy
		var enabled, failover int
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceCIDR, &p.DestCIDR, &p.LinkID,
			&p.Priority, &enabled, &failover, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		p.Failover = failover != 0
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// CreateRoutingPolicy inserts a new routing policy.
func (db *DB) CreateRoutingPolicy(p *RoutingPolicy) error {
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	_, err := db.conn.Exec(`
		INSERT INTO routing_policies (id, name, source_cidr, dest_cidr, link_id, priority, enabled, failover, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.SourceCIDR, p.DestCIDR, p.LinkID, p.Priority,
		boolToInt(p.Enabled), boolToInt(p.Failover), p.CreatedAt, p.UpdatedAt)
	return err
}

// DeleteRoutingPolicy removes a routing policy by ID.
func (db *DB) DeleteRoutingPolicy(id string) error {
	_, err := db.conn.Exec(`DELETE FROM routing_policies WHERE id=?`, id)
	return err
}
