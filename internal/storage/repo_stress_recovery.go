package storage

import (
	"database/sql"
	"errors"
	"time"
)

// SaveStressRecoveryLease persists recovery intent before fault injection.
// The singleton INSERT fails while an unresolved lease already exists.
func (db *DB) SaveStressRecoveryLease(lease *StressRecoveryLease) error {
	if lease == nil {
		return errors.New("stress recovery lease is nil")
	}
	if lease.TestID == "" || lease.Interface == "" {
		return errors.New("stress recovery lease requires test id and interface")
	}
	if lease.Mode != "outage" && lease.Mode != "degrade" {
		return errors.New("stress recovery lease has invalid mode")
	}
	if lease.Mode == "degrade" && (lease.DelayMs <= 0 || lease.LossPct < 0 || lease.LossPct > 100) {
		return errors.New("stress recovery lease has invalid netem parameters")
	}
	createdAt := lease.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := db.conn.Exec(`
		INSERT INTO stress_recovery_lease
			(singleton, test_id, link_id, interface, mode, delay_ms, loss_pct, created_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
		lease.TestID, lease.LinkID, lease.Interface, lease.Mode, lease.DelayMs, lease.LossPct, createdAt)
	return err
}

// GetStressRecoveryLease returns nil when no interrupted test needs recovery.
func (db *DB) GetStressRecoveryLease() (*StressRecoveryLease, error) {
	lease := &StressRecoveryLease{}
	err := db.conn.QueryRow(`
		SELECT test_id, link_id, interface, mode, delay_ms, loss_pct, created_at
		  FROM stress_recovery_lease
		 WHERE singleton = 1`).Scan(
		&lease.TestID, &lease.LinkID, &lease.Interface, &lease.Mode,
		&lease.DelayMs, &lease.LossPct, &lease.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return lease, nil
}

// ClearStressRecoveryLease clears only the lease recovered by this caller.
func (db *DB) ClearStressRecoveryLease(testID string) error {
	result, err := db.conn.Exec(`DELETE FROM stress_recovery_lease WHERE singleton = 1 AND test_id = ?`, testID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}
