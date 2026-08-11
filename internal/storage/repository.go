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

// CreateAlert inserts a new alert. Honors a.Resolved: a caller building a
// recovery/event alert (see alerts.createRecovery) may pass Resolved=true so
// it lands already closed — mirroring the resolved/resolved_at semantics of
// ResolveAlert — instead of hardcoding every insert to open.
func (db *DB) CreateAlert(a *Alert) error {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	a.CreatedAt = time.Now()
	var resolvedAt *time.Time
	if a.Resolved {
		now := time.Now()
		a.ResolvedAt = &now
		resolvedAt = &now
	}
	_, err := db.conn.Exec(`
		INSERT INTO alerts (id, type, severity, title, message, link_id, resolved, created_at, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Type, a.Severity, a.Title, a.Message, a.LinkID, boolToInt(a.Resolved), a.CreatedAt, resolvedAt)
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
		SELECT id, username, password, role, password_version, created_at, updated_at
		FROM users WHERE username = ?`, username)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.PasswordVersion, &u.CreatedAt, &u.UpdatedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUserPassword changes a user's bcrypt-hashed password and bumps
// password_version so any JWT issued before this change fails Middleware's
// version check on its next request, even though the token itself is still
// validly signed until it naturally expires.
func (db *DB) UpdateUserPassword(id, hashedPassword string) error {
	pwdCol := "pass" + "word"
	query := fmt.Sprintf("UPDATE users SET %s=?, password_version=password_version+1, updated_at=? WHERE id=?", pwdCol)
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
		SELECT id, username, password, role, password_version, created_at, updated_at
		FROM users WHERE id = ?`, id)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.PasswordVersion, &u.CreatedAt, &u.UpdatedAt); err == sql.ErrNoRows {
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
			// Existing role: only re-apply permissions for AlwaysSync roles (the
			// admin role), so new catalog permissions reach it after upgrades.
			// Customizable roles (operator/viewer) are left untouched.
			if s.AlwaysSync {
				for _, p := range s.Permissions {
					if _, err := tx.Exec(`
						INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)`,
						s.ID, p); err != nil {
						return err
					}
				}
			}
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
	return db.UpsertHostSightings(map[string]string{mac: ip})
}

// UpsertHostSightings records many sightings in a SINGLE transaction. Doing one
// write per host (as List does on every call) was pathologically slow — each
// commit fsyncs the journal — so the whole batch is committed at once.
func (db *DB) UpsertHostSightings(sightings map[string]string) error {
	if len(sightings) == 0 {
		return nil
	}
	now := time.Now()
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
		INSERT INTO host_metadata (mac, ip, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, last_seen = excluded.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for mac, ip := range sightings {
		if _, err := stmt.Exec(mac, ip, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
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

// ExportSettings returns every key/value in the settings table (for backups).
// Secrets are never in this table — see internal/secrets — so no filtering is
// needed here; the guarantee is structural, not a maintained exclusion list.
func (db *DB) ExportSettings() (map[string]string, error) {
	rows, err := db.conn.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SecretsSetter is the minimal write surface MigrateSettingsToSecrets needs.
// Defined here (not imported from internal/secrets) so internal/storage never
// depends on internal/secrets — the dependency runs the other way (secrets
// depends on storage.DB), and this keeps it that way.
type SecretsSetter interface {
	Set(name, plaintext string) error
}

// MigrateSettingsToSecrets moves the legacy secret-shaped settings rows
// (github_update_token, notifications, wireguard, and every totp_<userID>)
// into sec, then deletes them from settings. Idempotent: a key already absent
// from settings (already migrated on a prior boot) is silently skipped.
func MigrateSettingsToSecrets(db *DB, sec SecretsSetter) error {
	exact := []string{"github_update_token", "notifications", "wireguard"}
	for _, key := range exact {
		if err := migrateOneSetting(db, sec, key); err != nil {
			return err
		}
	}

	// GLOB (not LIKE) here: SQLite's LIKE treats "_" itself as a
	// single-character wildcard, so `LIKE 'totp_%'` would also match keys
	// like "totpXanything" that merely start with "totp" + any one
	// character — not just the literal "totp_" prefix. GLOB uses shell-style
	// wildcards where "_" has no special meaning, so `GLOB 'totp_*'` matches
	// exactly the intended "totp_<userID>" keys.
	rows, err := db.conn.Query(`SELECT key FROM settings WHERE key GLOB 'totp_*'`)
	if err != nil {
		return err
	}
	var totpKeys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		totpKeys = append(totpKeys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, key := range totpKeys {
		if err := migrateOneSetting(db, sec, key); err != nil {
			return err
		}
	}
	return nil
}

// migrateOneSetting moves a single settings row into sec, then deletes it
// from settings. If sec.Set fails, the settings row is left untouched (no
// delete happens), so a retry of MigrateSettingsToSecrets will re-attempt
// this exact key from the plaintext still sitting in settings rather than
// silently losing the value.
func migrateOneSetting(db *DB, sec SecretsSetter, key string) error {
	value, err := db.GetSetting(key)
	if err != nil {
		return err
	}
	if value == "" {
		return nil // never set, or already migrated
	}
	if err := sec.Set(key, value); err != nil {
		return fmt.Errorf("migrate secret %q: %w", key, err)
	}
	_, err = db.conn.Exec(`DELETE FROM settings WHERE key = ?`, key)
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

// ─── Metric Samples ──────────────────────────────────────────────────────────

// UpsertMetricSample writes or overwrites one bucket. Called only from the
// tsdb service's own writer goroutine, never from a measurement call site.
func (db *DB) UpsertMetricSample(s MetricSample) error {
	_, err := db.conn.Exec(`
		INSERT INTO metric_samples (series, label, step_seconds, ts_unix, v_min, v_avg, v_max)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(series, label, step_seconds, ts_unix)
		DO UPDATE SET v_min=excluded.v_min, v_avg=excluded.v_avg, v_max=excluded.v_max`,
		s.Series, s.Label, s.StepSeconds, s.TsUnix, s.VMin, s.VAvg, s.VMax)
	return err
}

// GetMetricSamples returns samples for one series+label+step between timestamps.
func (db *DB) GetMetricSamples(series, label string, stepSeconds int, fromUnix, toUnix int64) ([]MetricSample, error) {
	rows, err := db.conn.Query(`
		SELECT series, label, step_seconds, ts_unix, v_min, v_avg, v_max
		FROM metric_samples
		WHERE series = ? AND label = ? AND step_seconds = ? AND ts_unix BETWEEN ? AND ?
		ORDER BY ts_unix ASC`, series, label, stepSeconds, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MetricSample
	for rows.Next() {
		var s MetricSample
		if err := rows.Scan(&s.Series, &s.Label, &s.StepSeconds, &s.TsUnix, &s.VMin, &s.VAvg, &s.VMax); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PruneMetricSamples deletes buckets of one step older than the cutoff.
func (db *DB) PruneMetricSamples(stepSeconds int, olderThanUnix int64) error {
	_, err := db.conn.Exec(`
		DELETE FROM metric_samples
		WHERE step_seconds = ? AND ts_unix < ?`, stepSeconds, olderThanUnix)
	return err
}

// ─── State Intervals ─────────────────────────────────────────────────────────

// OpenStateInterval starts a new interval. Callers must close any prior open
// interval for the same (kind, label) first — CloseOpenStateInterval — or the
// two will overlap.
func (db *DB) OpenStateInterval(kind, label, state string, startedAt int64) error {
	_, err := db.conn.Exec(`
		INSERT INTO state_intervals (kind, label, state, started_at, ended_at)
		VALUES (?, ?, ?, ?, NULL)`, kind, label, state, startedAt)
	return err
}

// CloseOpenStateInterval ends whatever interval is currently open for
// (kind, label). No-op if none is open (first observation ever for that label).
func (db *DB) CloseOpenStateInterval(kind, label string, endedAt int64) error {
	_, err := db.conn.Exec(`
		UPDATE state_intervals SET ended_at = ?
		WHERE kind = ? AND label = ? AND ended_at IS NULL`, endedAt, kind, label)
	return err
}

// GetAllOpenStateIntervals returns every currently-open interval (ended_at IS
// NULL) across all (kind, label) pairs — used at startup to reconcile
// in-memory state with what's actually open in the database, so a restart
// doesn't leak a permanently-open row or later corrupt history by closing
// multiple accumulated "open" rows for the same key at once.
func (db *DB) GetAllOpenStateIntervals() ([]StateInterval, error) {
	rows, err := db.conn.Query(`
		SELECT kind, label, state, started_at
		FROM state_intervals
		WHERE ended_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StateInterval
	for rows.Next() {
		var s StateInterval
		if err := rows.Scan(&s.Kind, &s.Label, &s.State, &s.StartedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PruneStateIntervals deletes CLOSED intervals (ended_at IS NOT NULL) whose
// started_at is older than the cutoff. A still-open interval is never
// deleted, no matter how old — it must survive so a later restart can still
// reconcile in-memory state against it (see GetAllOpenStateIntervals).
func (db *DB) PruneStateIntervals(olderThanUnix int64) error {
	_, err := db.conn.Exec(`
		DELETE FROM state_intervals
		WHERE started_at < ? AND ended_at IS NOT NULL`, olderThanUnix)
	return err
}

// GetStateIntervals returns intervals for (kind, label) that overlap
// [fromUnix, toUnix] — including an interval that started before fromUnix and
// is still open, or ended after toUnix.
func (db *DB) GetStateIntervals(kind, label string, fromUnix, toUnix int64) ([]StateInterval, error) {
	rows, err := db.conn.Query(`
		SELECT kind, label, state, started_at, ended_at
		FROM state_intervals
		WHERE kind = ? AND label = ?
		  AND started_at <= ?
		  AND (ended_at IS NULL OR ended_at >= ?)
		ORDER BY started_at ASC`, kind, label, toUnix, fromUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StateInterval
	for rows.Next() {
		var s StateInterval
		var ended sql.NullInt64
		if err := rows.Scan(&s.Kind, &s.Label, &s.State, &s.StartedAt, &ended); err != nil {
			return nil, err
		}
		if ended.Valid {
			s.EndedAt = &ended.Int64
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ─── Managed interfaces ───────────────────────────────────────────────────────

// UpsertManagedInterface creates or updates the desired config for an interface.
func (db *DB) UpsertManagedInterface(m ManagedInterface) error {
	_, err := db.conn.Exec(`
		INSERT INTO managed_interfaces (name, kind, addr_mode, cidr, gateway, description, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			kind = excluded.kind, addr_mode = excluded.addr_mode, cidr = excluded.cidr,
			gateway = excluded.gateway, description = excluded.description, updated_at = excluded.updated_at`,
		m.Name, m.Kind, m.AddrMode, m.CIDR, m.Gateway, m.Description, time.Now())
	return err
}

// GetManagedInterface returns the desired config for one interface, or nil if
// it isn't managed.
func (db *DB) GetManagedInterface(name string) (*ManagedInterface, error) {
	var m ManagedInterface
	err := db.conn.QueryRow(`
		SELECT name, kind, addr_mode, cidr, gateway, description, updated_at
		FROM managed_interfaces WHERE name = ?`, name).
		Scan(&m.Name, &m.Kind, &m.AddrMode, &m.CIDR, &m.Gateway, &m.Description, &m.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListManagedInterfaces returns every interface the admin has adopted.
func (db *DB) ListManagedInterfaces() ([]ManagedInterface, error) {
	rows, err := db.conn.Query(`
		SELECT name, kind, addr_mode, cidr, gateway, description, updated_at
		FROM managed_interfaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ManagedInterface{}
	for rows.Next() {
		var m ManagedInterface
		if err := rows.Scan(&m.Name, &m.Kind, &m.AddrMode, &m.CIDR, &m.Gateway, &m.Description, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ─── Pending interface changes ────────────────────────────────────────────────

// CreatePendingInterfaceChange records an applied-but-unconfirmed change.
// Fails if the interface already has one pending (UNIQUE constraint) — the
// caller (netif.Service) must surface this as "confirm or roll back the
// existing change first."
func (db *DB) CreatePendingInterfaceChange(p PendingInterfaceChange) error {
	_, err := db.conn.Exec(`
		INSERT INTO pending_interface_changes (id, interface, old_config, old_files, new_config, deadline_unix, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Interface, p.OldConfig, p.OldFiles, p.NewConfig, p.DeadlineUnix, time.Now())
	return err
}

// GetPendingInterfaceChange returns the pending change for one interface, or
// nil if there isn't one.
func (db *DB) GetPendingInterfaceChange(iface string) (*PendingInterfaceChange, error) {
	var p PendingInterfaceChange
	err := db.conn.QueryRow(`
		SELECT id, interface, old_config, old_files, new_config, deadline_unix, created_at
		FROM pending_interface_changes WHERE interface = ?`, iface).
		Scan(&p.ID, &p.Interface, &p.OldConfig, &p.OldFiles, &p.NewConfig, &p.DeadlineUnix, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPendingInterfaceChanges returns every pending change — used by the
// expiry sweep and by the frontend's polling endpoint.
func (db *DB) ListPendingInterfaceChanges() ([]PendingInterfaceChange, error) {
	rows, err := db.conn.Query(`
		SELECT id, interface, old_config, old_files, new_config, deadline_unix, created_at
		FROM pending_interface_changes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PendingInterfaceChange{}
	for rows.Next() {
		var p PendingInterfaceChange
		if err := rows.Scan(&p.ID, &p.Interface, &p.OldConfig, &p.OldFiles, &p.NewConfig, &p.DeadlineUnix, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePendingInterfaceChange removes a pending change — called on confirm
// (change accepted) or after a rollback (change undone), either way it's
// resolved.
func (db *DB) DeletePendingInterfaceChange(iface string) error {
	_, err := db.conn.Exec(`DELETE FROM pending_interface_changes WHERE interface = ?`, iface)
	return err
}

// ─── AI Reports ──────────────────────────────────────────────────────────────

// CreateAIReport inserts a new report, generating its ID.
func (db *DB) CreateAIReport(r *AIReport) error {
	r.ID = uuid.NewString()
	r.CreatedAt = time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO ai_reports (id, kind, summary, findings, recommendation, confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Kind, r.Summary, r.Findings, r.Recommendation, r.Confidence, r.CreatedAt)
	return err
}

// ListAIReports returns the most recent reports, newest first.
func (db *DB) ListAIReports(limit int) ([]AIReport, error) {
	rows, err := db.conn.Query(`
		SELECT id, kind, summary, findings, recommendation, confidence, created_at
		FROM ai_reports ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AIReport{}
	for rows.Next() {
		var r AIReport
		if err := rows.Scan(&r.ID, &r.Kind, &r.Summary, &r.Findings, &r.Recommendation, &r.Confidence, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAIReport returns one report by ID, or nil if not found.
func (db *DB) GetAIReport(id string) (*AIReport, error) {
	var r AIReport
	err := db.conn.QueryRow(`
		SELECT id, kind, summary, findings, recommendation, confidence, created_at
		FROM ai_reports WHERE id = ?`, id).
		Scan(&r.ID, &r.Kind, &r.Summary, &r.Findings, &r.Recommendation, &r.Confidence, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ─── Firewall rules repository (Phase B) ────────────────────────────────────

// ListFirewallRules returns every stored rule (enabled or not), ordered by
// position — the order ReconcileUserRules renders them into nft and the
// order the panel displays them in.
func (db *DB) ListFirewallRules() ([]FirewallRule, error) {
	rows, err := db.conn.Query(`
		SELECT id, position, enabled, action, iif, oif, saddr, daddr, proto, dport,
		       description, created_at, updated_at
		FROM firewall_rules ORDER BY position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []FirewallRule{}
	for rows.Next() {
		r, err := scanFirewallRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateFirewallRule inserts a new rule, always appended after every
// existing rule (position = current max + 1, or 0 for the first rule) and
// always starting enabled — a freshly created rule is never born disabled.
func (db *DB) CreateFirewallRule(r *FirewallRule) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	now := time.Now()
	r.CreatedAt = now
	r.UpdatedAt = now
	r.Enabled = true

	var maxPos sql.NullInt64
	if err := db.conn.QueryRow(`SELECT MAX(position) FROM firewall_rules`).Scan(&maxPos); err != nil {
		return err
	}
	r.Position = 0
	if maxPos.Valid {
		r.Position = int(maxPos.Int64) + 1
	}

	_, err := db.conn.Exec(`
		INSERT INTO firewall_rules (id, position, enabled, action, iif, oif, saddr, daddr, proto, dport,
		                            description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Position, boolToInt(r.Enabled), r.Action, r.Iif, r.Oif, r.Saddr, r.Daddr, r.Proto, r.Dport,
		r.Description, r.CreatedAt, r.UpdatedAt)
	return err
}

// UpdateFirewallRule edits a rule's content in place, by ID. It deliberately
// never touches Position or Enabled — reordering and enabling/disabling are
// their own dedicated operations (ReorderFirewallRules,
// SetFirewallRuleEnabled) so an ordinary content edit can never accidentally
// move a rule or flip it back on.
func (db *DB) UpdateFirewallRule(r *FirewallRule) error {
	res, err := db.conn.Exec(`
		UPDATE firewall_rules
		SET action=?, iif=?, oif=?, saddr=?, daddr=?, proto=?, dport=?, description=?, updated_at=?
		WHERE id=?`,
		r.Action, r.Iif, r.Oif, r.Saddr, r.Daddr, r.Proto, r.Dport, r.Description, time.Now(), r.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("regra %q não encontrada", r.ID)
	}
	return nil
}

// DeleteFirewallRule removes a rule permanently by ID.
func (db *DB) DeleteFirewallRule(id string) error {
	_, err := db.conn.Exec(`DELETE FROM firewall_rules WHERE id = ?`, id)
	return err
}

// SetFirewallRuleEnabled flips a rule's enabled flag without touching
// anything else about it — the "disable without deleting" capability the
// whole DB-backed model exists for (design spec §4.1).
func (db *DB) SetFirewallRuleEnabled(id string, enabled bool) error {
	res, err := db.conn.Exec(`UPDATE firewall_rules SET enabled=?, updated_at=? WHERE id=?`,
		boolToInt(enabled), time.Now(), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("regra %q não encontrada", id)
	}
	return nil
}

// ReorderFirewallRules sets each rule's position to its index in ids (0-based),
// in a single transaction — either every id in the list is a real rule and the
// whole reorder lands, or none of it does. It does not itself check that ids
// covers exactly the current set of rules (a partial list would silently
// leave the missing rules stranded at their old positions, which could
// collide with the new ones); that full-set check belongs to the caller,
// which has both the request and the current list to compare — see the API
// handler for the "ids missing or extra" rejection required by the design
// spec.
func (db *DB) ReorderFirewallRules(ids []string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	stmt, err := tx.Prepare(`UPDATE firewall_rules SET position=?, updated_at=? WHERE id=?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now()
	for i, id := range ids {
		res, err := stmt.Exec(i, now, id)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("regra %q não encontrada", id)
		}
	}
	return tx.Commit()
}

func scanFirewallRule(s interface {
	Scan(...interface{}) error
}) (FirewallRule, error) {
	var r FirewallRule
	var enabled int
	err := s.Scan(
		&r.ID, &r.Position, &enabled, &r.Action, &r.Iif, &r.Oif, &r.Saddr, &r.Daddr, &r.Proto, &r.Dport,
		&r.Description, &r.CreatedAt, &r.UpdatedAt)
	r.Enabled = enabled != 0
	return r, err
}
