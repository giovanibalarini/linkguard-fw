package storage

import (
	"database/sql"
	"time"
)

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
