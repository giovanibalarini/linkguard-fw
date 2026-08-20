package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// LinkQuota é a franquia declarada de um link WAN.
//
// LimitGB é em gigabytes DECIMAIS (10^9), não gibibytes: é a unidade em que
// operadora vende plano e em que o cliente lê a fatura. Usar 2^30 aqui faria a
// conta do painel discordar da conta da operadora em 7%, e quem estivesse
// perto do teto seria avisado tarde.
type LinkQuota struct {
	LinkID   string  `json:"link_id"`
	LimitGB  float64 `json:"limit_gb"`
	CycleDay int     `json:"cycle_day"`
	AlertPct int     `json:"alert_pct"`
	Enabled  bool    `json:"enabled"`
}

// LinkUsage é o consumo acumulado de um link dentro de um ciclo.
type LinkUsage struct {
	LinkID     string `json:"link_id"`
	CycleStart int64  `json:"cycle_start"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	UpdatedAt  int64  `json:"updated_at"`
}

// GetLinkQuotas devolve todas as franquias configuradas, indexadas por link.
func (db *DB) GetLinkQuotas() (map[string]LinkQuota, error) {
	rows, err := db.conn.Query(`SELECT link_id, limit_gb, cycle_day, alert_pct, enabled FROM link_quota`)
	if err != nil {
		return nil, fmt.Errorf("ler franquias: %w", err)
	}
	defer rows.Close()

	out := map[string]LinkQuota{}
	for rows.Next() {
		var q LinkQuota
		if err := rows.Scan(&q.LinkID, &q.LimitGB, &q.CycleDay, &q.AlertPct, &q.Enabled); err != nil {
			return nil, fmt.Errorf("ler franquia: %w", err)
		}
		out[q.LinkID] = q
	}
	return out, rows.Err()
}

// SaveLinkQuota grava (ou substitui) a franquia de um link.
func (db *DB) SaveLinkQuota(q LinkQuota) error {
	_, err := db.conn.Exec(`
		INSERT INTO link_quota (link_id, limit_gb, cycle_day, alert_pct, enabled)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(link_id) DO UPDATE SET
			limit_gb = excluded.limit_gb,
			cycle_day = excluded.cycle_day,
			alert_pct = excluded.alert_pct,
			enabled = excluded.enabled`,
		q.LinkID, q.LimitGB, q.CycleDay, q.AlertPct, q.Enabled)
	if err != nil {
		return fmt.Errorf("gravar franquia: %w", err)
	}
	return nil
}

// AddLinkUsage soma bytes ao ciclo indicado, criando a linha se for o
// primeiro tráfego do ciclo.
//
// A soma acontece no SQL (rx_bytes + ?) e não em Go de propósito: dois
// processos — ou o mesmo processo em dois flushes concorrentes — somando sobre
// um valor lido antes perderiam uma das somas.
func (db *DB) AddLinkUsage(linkID string, cycleStart int64, rx, tx uint64) error {
	_, err := db.conn.Exec(`
		INSERT INTO link_usage (link_id, cycle_start, rx_bytes, tx_bytes, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(link_id, cycle_start) DO UPDATE SET
			rx_bytes = rx_bytes + excluded.rx_bytes,
			tx_bytes = tx_bytes + excluded.tx_bytes,
			updated_at = excluded.updated_at`,
		linkID, cycleStart, rx, tx, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("acumular consumo do link: %w", err)
	}
	return nil
}

// GetLinkUsage devolve o consumo de um link num ciclo. Ausência não é erro —
// é ciclo sem tráfego medido ainda.
func (db *DB) GetLinkUsage(linkID string, cycleStart int64) (LinkUsage, error) {
	u := LinkUsage{LinkID: linkID, CycleStart: cycleStart}
	err := db.conn.QueryRow(`
		SELECT rx_bytes, tx_bytes, updated_at FROM link_usage
		WHERE link_id = ? AND cycle_start = ?`, linkID, cycleStart).
		Scan(&u.RxBytes, &u.TxBytes, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return u, nil
	}
	if err != nil {
		return u, fmt.Errorf("ler consumo do link: %w", err)
	}
	return u, nil
}

// GetLinkUsageHistory devolve os ciclos de um link, do mais recente para o
// mais antigo, limitado a limit linhas.
func (db *DB) GetLinkUsageHistory(linkID string, limit int) ([]LinkUsage, error) {
	if limit <= 0 || limit > 60 {
		limit = 12
	}
	rows, err := db.conn.Query(`
		SELECT link_id, cycle_start, rx_bytes, tx_bytes, updated_at FROM link_usage
		WHERE link_id = ? ORDER BY cycle_start DESC LIMIT ?`, linkID, limit)
	if err != nil {
		return nil, fmt.Errorf("ler histórico de consumo: %w", err)
	}
	defer rows.Close()

	var out []LinkUsage
	for rows.Next() {
		var u LinkUsage
		if err := rows.Scan(&u.LinkID, &u.CycleStart, &u.RxBytes, &u.TxBytes, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ler histórico de consumo: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
