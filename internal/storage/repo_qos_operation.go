package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
)

// SaveQoSOperationLease inserts recovery evidence before the first kernel
// mutation. The unique interface constraint prevents an unresolved operation
// from being overwritten by another process.
func (db *DB) SaveQoSOperationLease(lease *qos.OperationLease) error {
	if lease == nil {
		return errors.New("qos operation lease is nil")
	}
	if err := lease.Validate(); err != nil {
		return err
	}
	createdAt := lease.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		lease.CreatedAt = createdAt
	}
	payload, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`
		INSERT INTO qos_operation_lease
			(operation_id, interface, intent, stage, payload, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		lease.ID, lease.Interface, lease.Intent, lease.Stage, payload, createdAt)
	return err
}

// AdvanceQoSOperationLease records one completed kernel mutation without
// allowing a stale process to skip or rewrite a journal boundary.
func (db *DB) AdvanceQoSOperationLease(operationID string, fromStage, toStage int) error {
	if operationID == "" || toStage != fromStage+1 {
		return errors.New("invalid qos operation stage transition")
	}
	result, err := db.conn.Exec(`
		UPDATE qos_operation_lease SET stage = ?
		WHERE operation_id = ? AND stage = ?`, toStage, operationID, fromStage)
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

// ListQoSOperationLeases returns all operations that a fresh process must
// recover before normal QoS reconciliation starts.
func (db *DB) ListQoSOperationLeases() ([]qos.OperationLease, error) {
	rows, err := db.conn.Query(`
		SELECT stage, payload FROM qos_operation_lease
		ORDER BY created_at, operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var leases []qos.OperationLease
	for rows.Next() {
		var stage int
		var payload []byte
		if err := rows.Scan(&stage, &payload); err != nil {
			return nil, err
		}
		var lease qos.OperationLease
		if err := json.Unmarshal(payload, &lease); err != nil {
			return nil, err
		}
		lease.Stage = stage
		if err := lease.Validate(); err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
	return leases, rows.Err()
}

// ClearQoSOperationLease removes only the operation and interface recovered
// by this caller.
func (db *DB) ClearQoSOperationLease(operationID, iface string) error {
	result, err := db.conn.Exec(`
		DELETE FROM qos_operation_lease
		WHERE operation_id = ? AND interface = ?`, operationID, iface)
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
