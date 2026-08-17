package storage

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

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
