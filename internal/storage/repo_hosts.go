package storage

import "time"

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
