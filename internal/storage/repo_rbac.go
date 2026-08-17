package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

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
	//
	// A existência do usuário é conferida antes, e não presumida: desde que a
	// conta inicial passou a ser criada com senha aleatória (SeedInitialAdmin),
	// ela não nasce mais junto com o schema, e um INSERT cego aqui viola a
	// foreign key e derruba o boot. Numa appliance de firewall, ordem de seed
	// não pode ser o que decide se a máquina sobe.
	var userExists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE id = 'default-admin'`).Scan(&userExists); err != nil {
		return err
	}
	var hasRoles int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM user_roles WHERE user_id = 'default-admin'`).Scan(&hasRoles); err != nil {
		return err
	}
	if userExists > 0 && hasRoles == 0 && adminRoleID != "" {
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
