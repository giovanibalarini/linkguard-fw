package storage

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrLinkStateChanged marks a failed lifecycle/QoS compare-and-swap without
// requiring HTTP callers to import database/sql. The returned error also wraps
// sql.ErrNoRows for repository callers that historically checked it.
var ErrLinkStateChanged = errors.New("link state changed")

// ─── Links repository ────────────────────────────────────────────────────────

// GetLinks returns all links ordered by name.
func (db *DB) GetLinks() ([]Link, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, interface, ip_address, gateway, weight, dns_test,
		       monitor_hosts, status, latency_ms, packet_loss, last_check,
		       enabled, table_id, qos_enabled, qos_upload_mbps,
		       qos_download_mbps, qos_interactive, created_at, updated_at
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
		       enabled, table_id, qos_enabled, qos_upload_mbps,
		       qos_download_mbps, qos_interactive, created_at, updated_at
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
		                   enabled, table_id, qos_enabled, qos_upload_mbps,
		                   qos_download_mbps, qos_interactive, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.Name, l.Interface, l.IPAddress, l.Gateway, l.Weight, l.DNSTest,
		l.MonitorHosts, l.Status, l.LatencyMs, l.PacketLoss, nullableTime(l.LastCheck),
		boolToInt(l.Enabled), l.TableID, boolToInt(l.QoSEnabled), l.QoSUploadMbps,
		l.QoSDownloadMbps, boolToInt(l.QoSInteractive), l.CreatedAt, l.UpdatedAt)
	return err
}

// UpdateLink updates an existing link.
func (db *DB) UpdateLink(l *Link) error {
	l.UpdatedAt = time.Now()
	_, err := db.conn.Exec(`
		UPDATE links SET name=?, interface=?, ip_address=?, gateway=?, weight=?,
		    dns_test=?, monitor_hosts=?, status=?, latency_ms=?, packet_loss=?,
		    last_check=?, enabled=?, table_id=?, qos_enabled=?, qos_upload_mbps=?,
		    qos_download_mbps=?, qos_interactive=?, updated_at=?
		WHERE id=?`,
		l.Name, l.Interface, l.IPAddress, l.Gateway, l.Weight,
		l.DNSTest, l.MonitorHosts, l.Status, l.LatencyMs, l.PacketLoss,
		nullableTime(l.LastCheck), boolToInt(l.Enabled), l.TableID,
		boolToInt(l.QoSEnabled), l.QoSUploadMbps, l.QoSDownloadMbps,
		boolToInt(l.QoSInteractive), l.UpdatedAt, l.ID)
	return err
}

// UpdateLinkQoS updates only the QoS fields and succeeds only if the link's
// interface is still the one used for the kernel apply. The interface check
// prevents a concurrent link edit from receiving QoS that was applied to a
// stale interface, while the targeted update avoids overwriting unrelated
// link fields loaded before the apply completed.
func (db *DB) UpdateLinkQoS(id, expectedInterface string, enabled bool, uploadMbps, downloadMbps int, interactive bool) error {
	result, err := db.conn.Exec(`
		UPDATE links SET qos_enabled=?, qos_upload_mbps=?, qos_download_mbps=?,
		    qos_interactive=?, updated_at=?
		WHERE id=? AND interface=?`,
		boolToInt(enabled), uploadMbps, downloadMbps, boolToInt(interactive), time.Now(), id, expectedInterface)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.Join(ErrLinkStateChanged, sql.ErrNoRows)
	}
	return nil
}

// UpdateLinkQoSIfCurrent updates QoS only when the lifecycle and QoS values
// observed before the kernel apply are still current. Health-monitor samples
// deliberately do not participate in this compare-and-swap: they advance
// updated_at frequently but cannot invalidate a queue-control decision.
func (db *DB) UpdateLinkQoSIfCurrent(
	id, expectedInterface string,
	expectedEnabled, expectedQoSEnabled bool,
	expectedUploadMbps, expectedDownloadMbps int,
	expectedInteractive bool,
	enabled bool, uploadMbps, downloadMbps int, interactive bool,
) error {
	result, err := db.conn.Exec(`
		UPDATE links SET qos_enabled=?, qos_upload_mbps=?, qos_download_mbps=?,
		    qos_interactive=?, updated_at=?
		WHERE id=? AND interface=? AND enabled=?
		  AND qos_enabled=? AND qos_upload_mbps=? AND qos_download_mbps=?
		  AND qos_interactive=?`,
		boolToInt(enabled), uploadMbps, downloadMbps, boolToInt(interactive), time.Now(),
		id, expectedInterface, boolToInt(expectedEnabled), boolToInt(expectedQoSEnabled),
		expectedUploadMbps, expectedDownloadMbps, boolToInt(expectedInteractive))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.Join(ErrLinkStateChanged, sql.ErrNoRows)
	}
	return nil
}

// UpdateLinkQoSIfCurrentAndClearOperation commits the durable QoS row and
// consumes its kernel-operation lease in one SQLite transaction. Therefore a
// crash can observe either the old row plus recovery evidence or the new row
// with no recovery evidence, never the unsafe middle state.
func (db *DB) UpdateLinkQoSIfCurrentAndClearOperation(
	id, expectedInterface string,
	expectedEnabled, expectedQoSEnabled bool,
	expectedUploadMbps, expectedDownloadMbps int,
	expectedInteractive bool,
	enabled bool, uploadMbps, downloadMbps int, interactive bool,
	operationID string,
) error {
	if operationID == "" {
		return errors.New("qos operation id is required for atomic persistence")
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful commit
	result, err := tx.Exec(`
		UPDATE links SET qos_enabled=?, qos_upload_mbps=?, qos_download_mbps=?,
		    qos_interactive=?, updated_at=?
		WHERE id=? AND interface=? AND enabled=?
		  AND qos_enabled=? AND qos_upload_mbps=? AND qos_download_mbps=?
		  AND qos_interactive=?`,
		boolToInt(enabled), uploadMbps, downloadMbps, boolToInt(interactive), time.Now(),
		id, expectedInterface, boolToInt(expectedEnabled), boolToInt(expectedQoSEnabled),
		expectedUploadMbps, expectedDownloadMbps, boolToInt(expectedInteractive))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errors.Join(ErrLinkStateChanged, sql.ErrNoRows)
	}
	result, err = tx.Exec(`
		DELETE FROM qos_operation_lease
		WHERE operation_id = ? AND interface = ?`, operationID, expectedInterface)
	if err != nil {
		return err
	}
	affected, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// UpdateLinkNonQoS updates link fields owned by the generic link service while
// leaving the QoS columns untouched. This prevents a stale link snapshot from
// overwriting a concurrent QoS mutation.
func (db *DB) UpdateLinkNonQoS(l *Link) error {
	l.UpdatedAt = time.Now()
	_, err := db.conn.Exec(`
		UPDATE links SET name=?, interface=?, ip_address=?, gateway=?, weight=?,
		    dns_test=?, monitor_hosts=?, status=?, latency_ms=?, packet_loss=?,
		    last_check=?, enabled=?, table_id=?, updated_at=?
		WHERE id=?`,
		l.Name, l.Interface, l.IPAddress, l.Gateway, l.Weight,
		l.DNSTest, l.MonitorHosts, l.Status, l.LatencyMs, l.PacketLoss,
		nullableTime(l.LastCheck), boolToInt(l.Enabled), l.TableID, l.UpdatedAt, l.ID)
	return err
}

// UpdateLinkStatus updates only health-monitor fields so a stale monitored
// link cannot overwrite QoS or other configuration fields.
func (db *DB) UpdateLinkStatus(id, status string, latencyMs, packetLoss float64, lastCheck *time.Time) error {
	_, err := db.conn.Exec(`
		UPDATE links SET status=?, latency_ms=?, packet_loss=?, last_check=?, updated_at=?
		WHERE id=?`, status, latencyMs, packetLoss, nullableTime(lastCheck), time.Now(), id)
	return err
}

// UpdateLinkDiscovery updates only fields learned from the system route table
// and succeeds only if the link still belongs to expectedInterface.
func (db *DB) UpdateLinkDiscovery(id, expectedInterface, name, ipAddress, gateway string) error {
	result, err := db.conn.Exec(`
		UPDATE links SET name=?, ip_address=?, gateway=?, updated_at=?
		WHERE id=? AND interface=?`, name, ipAddress, gateway, time.Now(), id, expectedInterface)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
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
	var enabled, qosEnabled, qosInteractive int
	err := s.Scan(
		&l.ID, &l.Name, &l.Interface, &l.IPAddress, &l.Gateway, &l.Weight,
		&l.DNSTest, &l.MonitorHosts, &l.Status, &l.LatencyMs, &l.PacketLoss,
		&lastCheck, &enabled, &l.TableID, &qosEnabled, &l.QoSUploadMbps,
		&l.QoSDownloadMbps, &qosInteractive, &l.CreatedAt, &l.UpdatedAt)
	l.LastCheck = fromNullTime(lastCheck)
	l.Enabled = enabled != 0
	l.QoSEnabled = qosEnabled != 0
	l.QoSInteractive = qosInteractive != 0
	return l, err
}

// CountLinks returns the number of stored links.
func (db *DB) CountLinks() (int, error) {
	var n int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM links`).Scan(&n)
	return n, err
}
