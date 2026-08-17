package storage

import (
	"time"

	"github.com/google/uuid"
)

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
