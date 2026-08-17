package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

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

// CountAlerts returns the number of unresolved alerts.
func (db *DB) CountAlerts() (int, error) {
	var n int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM alerts WHERE resolved=0`).Scan(&n)
	return n, err
}
