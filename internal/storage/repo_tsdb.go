package storage

import "database/sql"

// ─── Traffic Samples ─────────────────────────────────────────────────────────

// UpsertTrafficSample stores a traffic sample for an interface and archive step.
func (db *DB) UpsertTrafficSample(sample TrafficSample) error {
	_, err := db.conn.Exec(`
		INSERT INTO traffic_samples (interface, step_seconds, ts_unix, rx_bps, tx_bps)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(interface, step_seconds, ts_unix)
		DO UPDATE SET rx_bps=excluded.rx_bps, tx_bps=excluded.tx_bps`,
		sample.Interface, sample.StepSeconds, sample.Timestamp, sample.RxBps, sample.TxBps)
	return err
}

// GetTrafficSamples returns samples for a specific interface/step between timestamps.
func (db *DB) GetTrafficSamples(iface string, stepSeconds int, fromUnix, toUnix int64) ([]TrafficSample, error) {
	rows, err := db.conn.Query(`
		SELECT interface, step_seconds, ts_unix, rx_bps, tx_bps
		FROM traffic_samples
		WHERE interface = ? AND step_seconds = ? AND ts_unix BETWEEN ? AND ?
		ORDER BY ts_unix ASC`, iface, stepSeconds, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TrafficSample
	for rows.Next() {
		var s TrafficSample
		if err := rows.Scan(&s.Interface, &s.StepSeconds, &s.Timestamp, &s.RxBps, &s.TxBps); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if out == nil {
		out = []TrafficSample{}
	}
	return out, rows.Err()
}

// PruneTrafficSamples deletes samples older than the cutoff for the given step.
func (db *DB) PruneTrafficSamples(stepSeconds int, olderThanUnix int64) error {
	_, err := db.conn.Exec(`
		DELETE FROM traffic_samples
		WHERE step_seconds = ? AND ts_unix < ?`, stepSeconds, olderThanUnix)
	return err
}

// ─── Metric Samples ──────────────────────────────────────────────────────────

// UpsertMetricSample writes or overwrites one bucket. Called only from the
// tsdb service's own writer goroutine, never from a measurement call site.
func (db *DB) UpsertMetricSample(s MetricSample) error {
	_, err := db.conn.Exec(`
		INSERT INTO metric_samples (series, label, step_seconds, ts_unix, v_min, v_avg, v_max)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(series, label, step_seconds, ts_unix)
		DO UPDATE SET v_min=excluded.v_min, v_avg=excluded.v_avg, v_max=excluded.v_max`,
		s.Series, s.Label, s.StepSeconds, s.TsUnix, s.VMin, s.VAvg, s.VMax)
	return err
}

// GetMetricSamples returns samples for one series+label+step between timestamps.
func (db *DB) GetMetricSamples(series, label string, stepSeconds int, fromUnix, toUnix int64) ([]MetricSample, error) {
	rows, err := db.conn.Query(`
		SELECT series, label, step_seconds, ts_unix, v_min, v_avg, v_max
		FROM metric_samples
		WHERE series = ? AND label = ? AND step_seconds = ? AND ts_unix BETWEEN ? AND ?
		ORDER BY ts_unix ASC`, series, label, stepSeconds, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MetricSample
	for rows.Next() {
		var s MetricSample
		if err := rows.Scan(&s.Series, &s.Label, &s.StepSeconds, &s.TsUnix, &s.VMin, &s.VAvg, &s.VMax); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PruneMetricSamples deletes buckets of one step older than the cutoff.
func (db *DB) PruneMetricSamples(stepSeconds int, olderThanUnix int64) error {
	_, err := db.conn.Exec(`
		DELETE FROM metric_samples
		WHERE step_seconds = ? AND ts_unix < ?`, stepSeconds, olderThanUnix)
	return err
}

// ─── State Intervals ─────────────────────────────────────────────────────────

// OpenStateInterval starts a new interval. Callers must close any prior open
// interval for the same (kind, label) first — CloseOpenStateInterval — or the
// two will overlap.
func (db *DB) OpenStateInterval(kind, label, state string, startedAt int64) error {
	_, err := db.conn.Exec(`
		INSERT INTO state_intervals (kind, label, state, started_at, ended_at)
		VALUES (?, ?, ?, ?, NULL)`, kind, label, state, startedAt)
	return err
}

// CloseOpenStateInterval ends whatever interval is currently open for
// (kind, label). No-op if none is open (first observation ever for that label).
func (db *DB) CloseOpenStateInterval(kind, label string, endedAt int64) error {
	_, err := db.conn.Exec(`
		UPDATE state_intervals SET ended_at = ?
		WHERE kind = ? AND label = ? AND ended_at IS NULL`, endedAt, kind, label)
	return err
}

// GetAllOpenStateIntervals returns every currently-open interval (ended_at IS
// NULL) across all (kind, label) pairs — used at startup to reconcile
// in-memory state with what's actually open in the database, so a restart
// doesn't leak a permanently-open row or later corrupt history by closing
// multiple accumulated "open" rows for the same key at once.
func (db *DB) GetAllOpenStateIntervals() ([]StateInterval, error) {
	rows, err := db.conn.Query(`
		SELECT kind, label, state, started_at
		FROM state_intervals
		WHERE ended_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StateInterval
	for rows.Next() {
		var s StateInterval
		if err := rows.Scan(&s.Kind, &s.Label, &s.State, &s.StartedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PruneStateIntervals deletes CLOSED intervals (ended_at IS NOT NULL) whose
// started_at is older than the cutoff. A still-open interval is never
// deleted, no matter how old — it must survive so a later restart can still
// reconcile in-memory state against it (see GetAllOpenStateIntervals).
func (db *DB) PruneStateIntervals(olderThanUnix int64) error {
	_, err := db.conn.Exec(`
		DELETE FROM state_intervals
		WHERE started_at < ? AND ended_at IS NOT NULL`, olderThanUnix)
	return err
}

// GetStateIntervals returns intervals for (kind, label) that overlap
// [fromUnix, toUnix] — including an interval that started before fromUnix and
// is still open, or ended after toUnix.
func (db *DB) GetStateIntervals(kind, label string, fromUnix, toUnix int64) ([]StateInterval, error) {
	rows, err := db.conn.Query(`
		SELECT kind, label, state, started_at, ended_at
		FROM state_intervals
		WHERE kind = ? AND label = ?
		  AND started_at <= ?
		  AND (ended_at IS NULL OR ended_at >= ?)
		ORDER BY started_at ASC`, kind, label, toUnix, fromUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StateInterval
	for rows.Next() {
		var s StateInterval
		var ended sql.NullInt64
		if err := rows.Scan(&s.Kind, &s.Label, &s.State, &s.StartedAt, &ended); err != nil {
			return nil, err
		}
		if ended.Valid {
			s.EndedAt = &ended.Int64
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
