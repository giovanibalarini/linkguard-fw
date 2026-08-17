package storage

import (
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"
)

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
