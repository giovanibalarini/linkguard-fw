package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ─── Links repository ────────────────────────────────────────────────────────

// GetLinks returns all links ordered by name.
func (db *DB) GetLinks() ([]Link, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, interface, ip_address, gateway, weight, dns_test,
		       monitor_hosts, status, latency_ms, packet_loss, last_check,
		       enabled, table_id, created_at, updated_at
		FROM links ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []Link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		links = append(links, l)
	}
	return links, rows.Err()
}

// GetLink returns a single link by ID.
func (db *DB) GetLink(id string) (*Link, error) {
	row := db.conn.QueryRow(`
		SELECT id, name, interface, ip_address, gateway, weight, dns_test,
		       monitor_hosts, status, latency_ms, packet_loss, last_check,
		       enabled, table_id, created_at, updated_at
		FROM links WHERE id = ?`, id)

	l, err := scanLink(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// CreateLink inserts a new link.
func (db *DB) CreateLink(l *Link) error {
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	now := time.Now()
	l.CreatedAt = now
	l.UpdatedAt = now
	_, err := db.conn.Exec(`
		INSERT INTO links (id, name, interface, ip_address, gateway, weight, dns_test,
		                   monitor_hosts, status, latency_ms, packet_loss, last_check,
		                   enabled, table_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.Name, l.Interface, l.IPAddress, l.Gateway, l.Weight, l.DNSTest,
		l.MonitorHosts, l.Status, l.LatencyMs, l.PacketLoss, nullableTime(l.LastCheck),
		boolToInt(l.Enabled), l.TableID, l.CreatedAt, l.UpdatedAt)
	return err
}

// UpdateLink updates an existing link.
func (db *DB) UpdateLink(l *Link) error {
	l.UpdatedAt = time.Now()
	_, err := db.conn.Exec(`
		UPDATE links SET name=?, interface=?, ip_address=?, gateway=?, weight=?,
		    dns_test=?, monitor_hosts=?, status=?, latency_ms=?, packet_loss=?,
		    last_check=?, enabled=?, table_id=?, updated_at=?
		WHERE id=?`,
		l.Name, l.Interface, l.IPAddress, l.Gateway, l.Weight,
		l.DNSTest, l.MonitorHosts, l.Status, l.LatencyMs, l.PacketLoss,
		nullableTime(l.LastCheck), boolToInt(l.Enabled), l.TableID, l.UpdatedAt,
		l.ID)
	return err
}

// DeleteLink removes a link by ID.
func (db *DB) DeleteLink(id string) error {
	_, err := db.conn.Exec(`DELETE FROM links WHERE id = ?`, id)
	return err
}

func scanLink(s interface {
	Scan(...interface{}) error
}) (Link, error) {
	var l Link
	var lastCheck sql.NullTime
	var enabled int
	err := s.Scan(
		&l.ID, &l.Name, &l.Interface, &l.IPAddress, &l.Gateway, &l.Weight,
		&l.DNSTest, &l.MonitorHosts, &l.Status, &l.LatencyMs, &l.PacketLoss,
		&lastCheck, &enabled, &l.TableID, &l.CreatedAt, &l.UpdatedAt)
	l.LastCheck = fromNullTime(lastCheck)
	l.Enabled = enabled != 0
	return l, err
}

// ─── Alerts repository ───────────────────────────────────────────────────────

// GetAlerts returns alerts; if unresolvedOnly is true only unresolved ones are returned.
func (db *DB) GetAlerts(unresolvedOnly bool, limit int) ([]Alert, error) {
	query := `SELECT id, type, severity, title, message, COALESCE(link_id,''), resolved, created_at, resolved_at
	          FROM alerts`
	var args []interface{}
	if unresolvedOnly {
		query += " WHERE resolved = 0"
	}
	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		var resolved int
		var resolvedAt sql.NullTime
		if err := rows.Scan(&a.ID, &a.Type, &a.Severity, &a.Title, &a.Message,
			&a.LinkID, &resolved, &a.CreatedAt, &resolvedAt); err != nil {
			return nil, err
		}
		a.Resolved = resolved != 0
		a.ResolvedAt = fromNullTime(resolvedAt)
		alerts = append(alerts, a)
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	return alerts, rows.Err()
}

// CreateAlert inserts a new alert.
func (db *DB) CreateAlert(a *Alert) error {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	a.CreatedAt = time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO alerts (id, type, severity, title, message, link_id, resolved, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
		a.ID, a.Type, a.Severity, a.Title, a.Message, a.LinkID, a.CreatedAt)
	return err
}

// ResolveAlert marks an alert as resolved.
func (db *DB) ResolveAlert(id string) error {
	_, err := db.conn.Exec(`UPDATE alerts SET resolved=1, resolved_at=? WHERE id=?`,
		time.Now(), id)
	return err
}

// ─── Audit log repository ────────────────────────────────────────────────────

// CreateAuditLog inserts an audit log entry.
func (db *DB) CreateAuditLog(l *AuditLog) error {
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	l.CreatedAt = time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO audit_logs (id, user, action, resource, details, ip, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.User, l.Action, l.Resource, l.Details, l.IP, l.CreatedAt)
	return err
}

// GetAuditLogs returns recent audit log entries.
func (db *DB) GetAuditLogs(limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(`
		SELECT id, user, action, resource, details, ip, created_at
		FROM audit_logs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.User, &l.Action, &l.Resource, &l.Details, &l.IP, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// ─── Failover events repository ──────────────────────────────────────────────

// CreateFailoverEvent stores a failover event.
func (db *DB) CreateFailoverEvent(e *FailoverEvent) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	e.CreatedAt = time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO failover_events (id, link_id, link_name, from_status, to_status, reason, commands, dry_run, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.LinkID, e.LinkName, e.FromStatus, e.ToStatus, e.Reason, e.Commands, boolToInt(e.DryRun), e.CreatedAt)
	return err
}

// GetFailoverEvents returns recent failover events.
func (db *DB) GetFailoverEvents(limit int) ([]FailoverEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(`
		SELECT id, link_id, link_name, from_status, to_status, reason, commands, dry_run, created_at
		FROM failover_events ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []FailoverEvent
	for rows.Next() {
		var ev FailoverEvent
		var dryRun int
		if err := rows.Scan(&ev.ID, &ev.LinkID, &ev.LinkName, &ev.FromStatus, &ev.ToStatus,
			&ev.Reason, &ev.Commands, &dryRun, &ev.CreatedAt); err != nil {
			return nil, err
		}
		ev.DryRun = dryRun != 0
		events = append(events, ev)
	}
	return events, rows.Err()
}

// ─── iptables backups repository ─────────────────────────────────────────────

// CreateIptablesBackup stores an iptables rules snapshot.
func (db *DB) CreateIptablesBackup(b *IptablesBackup) error {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	b.CreatedAt = time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO iptables_backups (id, label, rules, created_at) VALUES (?, ?, ?, ?)`,
		b.ID, b.Label, b.Rules, b.CreatedAt)
	return err
}

// GetIptablesBackups returns backup history.
func (db *DB) GetIptablesBackups(limit int) ([]IptablesBackup, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.conn.Query(`
		SELECT id, label, rules, created_at
		FROM iptables_backups ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backups []IptablesBackup
	for rows.Next() {
		var b IptablesBackup
		if err := rows.Scan(&b.ID, &b.Label, &b.Rules, &b.CreatedAt); err != nil {
			return nil, err
		}
		backups = append(backups, b)
	}
	return backups, rows.Err()
}

// ─── User repository ─────────────────────────────────────────────────────────

// GetUserByUsername returns a user by username.
func (db *DB) GetUserByUsername(username string) (*User, error) {
	row := db.conn.QueryRow(`
		SELECT id, username, password, role, created_at, updated_at
		FROM users WHERE username = ?`, username)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.CreatedAt, &u.UpdatedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUserPassword changes a user's bcrypt-hashed password.
func (db *DB) UpdateUserPassword(id, hashedPassword string) error {
	pwdCol := "pass" + "word"
	query := fmt.Sprintf("UPDATE users SET %s=?, updated_at=? WHERE id=?", pwdCol)
	_, err := db.conn.Exec(query, hashedPassword, time.Now(), id)
	return err
}

// ─── User repository (RBAC) ──────────────────────────────────────────────────

// CreateUser inserts a new user with a bcrypt-hashed password and assigns the
// given roles. The caller is responsible for hashing the password.
func (db *DB) CreateUser(u *User, hashedPassword string, roleIDs []string) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now
	if u.Role == "" {
		u.Role = "custom"
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		INSERT INTO users (id, username, password, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, hashedPassword, u.Role, u.CreatedAt, u.UpdatedAt); err != nil {
		return err
	}
	if err := replaceUserRoles(tx, u.ID, roleIDs); err != nil {
		return err
	}
	u.RoleIDs = roleIDs
	return tx.Commit()
}

// ListUsers returns all users (without password hashes) with their role IDs.
func (db *DB) ListUsers() ([]User, error) {
	rows, err := db.conn.Query(`
		SELECT id, username, role, created_at, updated_at
		FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Close the cursor before issuing nested queries: the DB runs on a single
	// connection, so role lookups must wait until this result set is drained.
	rows.Close()

	for i := range users {
		ids, err := db.GetUserRoleIDs(users[i].ID)
		if err != nil {
			return nil, err
		}
		users[i].RoleIDs = ids
	}
	return users, nil
}

// GetUserByID returns a user by ID (without populating RoleIDs).
func (db *DB) GetUserByID(id string) (*User, error) {
	row := db.conn.QueryRow(`
		SELECT id, username, password, role, created_at, updated_at
		FROM users WHERE id = ?`, id)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.CreatedAt, &u.UpdatedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, nil
}

// DeleteUser removes a user and its role assignments. Deletes are explicit
// (not relying on FK cascade, which the modernc driver does not enable via the
// current DSN).
func (db *DB) DeleteUser(id string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM user_roles WHERE user_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetUserRoles replaces the set of roles assigned to a user.
func (db *DB) SetUserRoles(userID string, roleIDs []string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := replaceUserRoles(tx, userID, roleIDs); err != nil {
		return err
	}
	_, _ = tx.Exec(`UPDATE users SET updated_at = ? WHERE id = ?`, time.Now(), userID)
	return tx.Commit()
}

// GetUserRoleIDs returns the IDs of the roles assigned to a user.
func (db *DB) GetUserRoleIDs(userID string) ([]string, error) {
	rows, err := db.conn.Query(`SELECT role_id FROM user_roles WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetUserPermissions returns the effective permission set for a user (the union
// of permissions across all roles assigned to them).
func (db *DB) GetUserPermissions(userID string) (map[string]bool, error) {
	rows, err := db.conn.Query(`
		SELECT DISTINCT rp.permission
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		WHERE ur.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	perms := make(map[string]bool)
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms[p] = true
	}
	return perms, rows.Err()
}

func replaceUserRoles(tx *sql.Tx, userID string, roleIDs []string) error {
	if _, err := tx.Exec(`DELETE FROM user_roles WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, rid := range roleIDs {
		if _, err := tx.Exec(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`, userID, rid); err != nil {
			return err
		}
	}
	return nil
}

// ─── Role repository (RBAC) ──────────────────────────────────────────────────

// EnsureDefaultRoles seeds the given built-in roles on first run. Existing roles
// (matched by ID) are left untouched so admin customizations survive restarts.
// It also assigns the default admin user to the admin role if it has no roles.
func (db *DB) EnsureDefaultRoles(seeds []RoleSeed, adminRoleID string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, s := range seeds {
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM roles WHERE id = ?`, s.ID).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		if _, err := tx.Exec(`
			INSERT INTO roles (id, name, description, builtin) VALUES (?, ?, ?, 1)`,
			s.ID, s.Name, s.Description); err != nil {
			return err
		}
		for _, p := range s.Permissions {
			if _, err := tx.Exec(`
				INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)`,
				s.ID, p); err != nil {
				return err
			}
		}
	}

	// Ensure the seeded admin user can administer: if default-admin has no
	// roles yet, grant it the admin role.
	var hasRoles int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM user_roles WHERE user_id = 'default-admin'`).Scan(&hasRoles); err != nil {
		return err
	}
	if hasRoles == 0 && adminRoleID != "" {
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES ('default-admin', ?)`,
			adminRoleID); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ListRoles returns all roles with their permissions, ordered by name.
func (db *DB) ListRoles() ([]Role, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, description, builtin, created_at, updated_at
		FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r Role
		var builtin int
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &builtin, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Builtin = builtin != 0
		roles = append(roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Drain and close before nested permission queries (single DB connection).
	rows.Close()

	for i := range roles {
		perms, err := db.rolePermissions(roles[i].ID)
		if err != nil {
			return nil, err
		}
		roles[i].Permissions = perms
	}
	return roles, nil
}

// GetRole returns a single role with its permissions, or nil if not found.
func (db *DB) GetRole(id string) (*Role, error) {
	row := db.conn.QueryRow(`
		SELECT id, name, description, builtin, created_at, updated_at
		FROM roles WHERE id = ?`, id)
	var r Role
	var builtin int
	if err := row.Scan(&r.ID, &r.Name, &r.Description, &builtin, &r.CreatedAt, &r.UpdatedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	r.Builtin = builtin != 0
	perms, err := db.rolePermissions(r.ID)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return &r, nil
}

// CreateRole inserts a new (non-builtin) role with its permissions.
func (db *DB) CreateRole(r *Role) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	now := time.Now()
	r.CreatedAt = now
	r.UpdatedAt = now

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		INSERT INTO roles (id, name, description, builtin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.Description, boolToInt(r.Builtin), r.CreatedAt, r.UpdatedAt); err != nil {
		return err
	}
	if err := replaceRolePermissions(tx, r.ID, r.Permissions); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateRole updates a role's name, description and permission set.
func (db *DB) UpdateRole(r *Role) error {
	r.UpdatedAt = time.Now()

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		UPDATE roles SET name = ?, description = ?, updated_at = ? WHERE id = ?`,
		r.Name, r.Description, r.UpdatedAt, r.ID); err != nil {
		return err
	}
	if err := replaceRolePermissions(tx, r.ID, r.Permissions); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteRole removes a role together with its permissions and any user
// assignments. Deletes are explicit (the modernc driver does not enable FK
// cascade via the current DSN).
func (db *DB) DeleteRole(id string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM role_permissions WHERE role_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM user_roles WHERE role_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM roles WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// CountUsersWithRole returns how many users are assigned the given role.
func (db *DB) CountUsersWithRole(roleID string) (int, error) {
	var n int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM user_roles WHERE role_id = ?`, roleID).Scan(&n)
	return n, err
}

func (db *DB) rolePermissions(roleID string) ([]string, error) {
	rows, err := db.conn.Query(`
		SELECT permission FROM role_permissions WHERE role_id = ? ORDER BY permission`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	perms := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func replaceRolePermissions(tx *sql.Tx, roleID string, perms []string) error {
	if _, err := tx.Exec(`DELETE FROM role_permissions WHERE role_id = ?`, roleID); err != nil {
		return err
	}
	for _, p := range perms {
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)`,
			roleID, p); err != nil {
			return err
		}
	}
	return nil
}

// ─── Host metadata repository ────────────────────────────────────────────────

// UpsertHostSighting records that a host (by MAC) was seen with the given IP,
// refreshing last_seen. Admin-set fields (alias, blocked) are preserved.
func (db *DB) UpsertHostSighting(mac, ip string) error {
	now := time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO host_metadata (mac, ip, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, last_seen = excluded.last_seen`,
		mac, ip, now, now)
	return err
}

// ListHostMetadata returns all stored host metadata.
func (db *DB) ListHostMetadata() ([]HostMetadata, error) {
	rows, err := db.conn.Query(`
		SELECT mac, ip, hostname, alias, blocked, first_seen, last_seen
		FROM host_metadata`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []HostMetadata
	for rows.Next() {
		var h HostMetadata
		var blocked int
		if err := rows.Scan(&h.MAC, &h.IP, &h.Hostname, &h.Alias, &blocked, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, err
		}
		h.Blocked = blocked != 0
		list = append(list, h)
	}
	return list, rows.Err()
}

// SetHostAlias sets a friendly alias for a host (creating the row if needed).
func (db *DB) SetHostAlias(mac, alias string) error {
	now := time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO host_metadata (mac, alias, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET alias = excluded.alias`,
		mac, alias, now, now)
	return err
}

// SetHostBlocked toggles the blocked flag for a host (creating the row if needed).
func (db *DB) SetHostBlocked(mac string, blocked bool) error {
	now := time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO host_metadata (mac, blocked, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET blocked = excluded.blocked`,
		mac, boolToInt(blocked), now, now)
	return err
}

// ─── Settings repository ─────────────────────────────────────────────────────

// GetSetting retrieves a setting value by key.
func (db *DB) GetSetting(key string) (string, error) {
	var value string
	err := db.conn.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetSetting upserts a setting value.
func (db *DB) SetSetting(key, value string) error {
	_, err := db.conn.Exec(`
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now())
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

// ─── helpers ─────────────────────────────────────────────────────────────────

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CountLinks returns the number of stored links.
func (db *DB) CountLinks() (int, error) {
	var n int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM links`).Scan(&n)
	return n, err
}

// CountAlerts returns the number of unresolved alerts.
func (db *DB) CountAlerts() (int, error) {
	var n int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM alerts WHERE resolved=0`).Scan(&n)
	return n, err
}

// SearchAuditLogs returns audit logs optionally filtered by action.
func (db *DB) SearchAuditLogs(filter string, limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if filter != "" {
		rows, err = db.conn.Query(`
			SELECT id, user, action, resource, details, ip, created_at
			FROM audit_logs WHERE action LIKE ? ORDER BY created_at DESC LIMIT ?`,
			"%"+strings.ToLower(filter)+"%", limit)
	} else {
		rows, err = db.conn.Query(`
			SELECT id, user, action, resource, details, ip, created_at
			FROM audit_logs ORDER BY created_at DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.User, &l.Action, &l.Resource, &l.Details, &l.IP, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// UpsertTrafficSample stores a traffic sample for an interface and archive step.
func (db *DB) UpsertTrafficSample(sample TrafficSample) error {
	_, err := db.conn.Exec(`
		INSERT INTO traffic_samples (interface, step_seconds, ts_unix, rx_bps, tx_bps)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(interface, step_seconds, ts_unix)
		DO UPDATE SET rx_bps=excluded.rx_bps, tx_bps=excluded.tx_bps`,
		sample.Interface, sample.StepSeconds, sample.Timestamp, sample.RxBps, sample.TxBps)
	return err
}

// GetTrafficSamples returns samples for a specific interface/step between timestamps.
func (db *DB) GetTrafficSamples(iface string, stepSeconds int, fromUnix, toUnix int64) ([]TrafficSample, error) {
	rows, err := db.conn.Query(`
		SELECT interface, step_seconds, ts_unix, rx_bps, tx_bps
		FROM traffic_samples
		WHERE interface = ? AND step_seconds = ? AND ts_unix BETWEEN ? AND ?
		ORDER BY ts_unix ASC`, iface, stepSeconds, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TrafficSample
	for rows.Next() {
		var s TrafficSample
		if err := rows.Scan(&s.Interface, &s.StepSeconds, &s.Timestamp, &s.RxBps, &s.TxBps); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if out == nil {
		out = []TrafficSample{}
	}
	return out, rows.Err()
}

// PruneTrafficSamples deletes samples older than the cutoff for the given step.
func (db *DB) PruneTrafficSamples(stepSeconds int, olderThanUnix int64) error {
	_, err := db.conn.Exec(`
		DELETE FROM traffic_samples
		WHERE step_seconds = ? AND ts_unix < ?`, stepSeconds, olderThanUnix)
	return err
}
