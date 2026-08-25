package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// ─── Cota por aparelho (issue #126, metade "por host") ───────────────────────

// Períodos aceitos por HostQuota.Period. São gravados no banco como texto, e
// por isso os nomes são estáveis.
const (
	// HostPeriodMonthly fecha no dia declarado, como a fatura da operadora.
	HostPeriodMonthly = "monthly"
	// HostPeriodDaily fecha à meia-noite local. É o período que responde a
	// "quanto este aparelho pode gastar por dia" — a pergunta que um tablet de
	// criança ou uma câmera que subiu de resolução levantam.
	HostPeriodDaily = "daily"
)

// HostQuota é a cota declarada de um aparelho da LAN.
//
// A CHAVE É O MAC, e não o IP, pelo mesmo motivo do resto do inventário
// (host_metadata, bloqueio, direcionamento por host): o IP muda a cada lease do
// DHCP, e uma cota que se perde numa renovação de lease não é uma cota. O
// contador do kernel é por endereço (internal/nftables/accounting.go); quem faz
// a ponte de endereço para MAC é o amostrador — ver internal/hosttraffic.
//
// LimitGB é em gigabytes DECIMAIS (10^9), pela mesma razão de LinkQuota: é a
// unidade em que o admin pensa a franquia que está repartindo.
type HostQuota struct {
	MAC      string  `json:"mac"`
	LimitGB  float64 `json:"limit_gb"`
	Period   string  `json:"period"`
	CycleDay int     `json:"cycle_day"`
	AlertPct int     `json:"alert_pct"`
	Enabled  bool    `json:"enabled"`
}

// HostUsage é o consumo acumulado de um aparelho dentro de um ciclo.
type HostUsage struct {
	MAC        string `json:"mac"`
	CycleStart int64  `json:"cycle_start"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	UpdatedAt  int64  `json:"updated_at"`
}

// GetHostQuotas devolve todas as cotas declaradas, indexadas por MAC.
func (db *DB) GetHostQuotas() (map[string]HostQuota, error) {
	rows, err := db.conn.Query(`SELECT mac, limit_gb, period, cycle_day, alert_pct, enabled FROM host_quota`)
	if err != nil {
		return nil, fmt.Errorf("ler cotas por aparelho: %w", err)
	}
	defer rows.Close()

	out := map[string]HostQuota{}
	for rows.Next() {
		var q HostQuota
		if err := rows.Scan(&q.MAC, &q.LimitGB, &q.Period, &q.CycleDay, &q.AlertPct, &q.Enabled); err != nil {
			return nil, fmt.Errorf("ler cota por aparelho: %w", err)
		}
		out[q.MAC] = q
	}
	return out, rows.Err()
}

// SaveHostQuota grava (ou substitui) a cota de um aparelho.
func (db *DB) SaveHostQuota(q HostQuota) error {
	_, err := db.conn.Exec(`
		INSERT INTO host_quota (mac, limit_gb, period, cycle_day, alert_pct, enabled)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			limit_gb = excluded.limit_gb,
			period = excluded.period,
			cycle_day = excluded.cycle_day,
			alert_pct = excluded.alert_pct,
			enabled = excluded.enabled`,
		q.MAC, q.LimitGB, q.Period, q.CycleDay, q.AlertPct, q.Enabled)
	if err != nil {
		return fmt.Errorf("gravar cota por aparelho: %w", err)
	}
	return nil
}

// AddHostUsage soma bytes ao ciclo indicado, criando a linha no primeiro
// tráfego do ciclo.
//
// A soma acontece no SQL, e não em Go, pela mesma razão de AddLinkUsage: dois
// flushes concorrentes somando sobre um valor lido antes perderiam uma das
// somas. Aqui isso pesa mais, porque são dezenas de aparelhos por flush, e não
// dois ou três links.
func (db *DB) AddHostUsage(mac string, cycleStart int64, rx, tx uint64) error {
	_, err := db.conn.Exec(`
		INSERT INTO host_usage (mac, cycle_start, rx_bytes, tx_bytes, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(mac, cycle_start) DO UPDATE SET
			rx_bytes = rx_bytes + excluded.rx_bytes,
			tx_bytes = tx_bytes + excluded.tx_bytes,
			updated_at = excluded.updated_at`,
		mac, cycleStart, rx, tx, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("acumular consumo do aparelho: %w", err)
	}
	return nil
}

// GetHostUsage devolve o consumo de um aparelho num ciclo. Ausência não é
// erro — é ciclo sem tráfego medido ainda.
func (db *DB) GetHostUsage(mac string, cycleStart int64) (HostUsage, error) {
	u := HostUsage{MAC: mac, CycleStart: cycleStart}
	err := db.conn.QueryRow(`
		SELECT rx_bytes, tx_bytes, updated_at FROM host_usage
		WHERE mac = ? AND cycle_start = ?`, mac, cycleStart).
		Scan(&u.RxBytes, &u.TxBytes, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return u, nil
	}
	if err != nil {
		return u, fmt.Errorf("ler consumo do aparelho: %w", err)
	}
	return u, nil
}

// GetHostUsageAll devolve o consumo de TODOS os aparelhos num dado ciclo, numa
// consulta só.
//
// Existe para a tela e o flush não fazerem uma consulta por aparelho: com
// oitenta aparelhos no inventário isso seriam oitenta idas ao banco por minuto,
// no mesmo SQLite que guarda metric_samples. O mapa é indexado por MAC.
func (db *DB) GetHostUsageAll(cycleStart int64) (map[string]HostUsage, error) {
	rows, err := db.conn.Query(`
		SELECT mac, cycle_start, rx_bytes, tx_bytes, updated_at FROM host_usage
		WHERE cycle_start = ?`, cycleStart)
	if err != nil {
		return nil, fmt.Errorf("ler consumo dos aparelhos: %w", err)
	}
	defer rows.Close()

	out := map[string]HostUsage{}
	for rows.Next() {
		var u HostUsage
		if err := rows.Scan(&u.MAC, &u.CycleStart, &u.RxBytes, &u.TxBytes, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ler consumo dos aparelhos: %w", err)
		}
		out[u.MAC] = u
	}
	return out, rows.Err()
}

// GetHostUsageHistory devolve os ciclos de um aparelho, do mais recente para o
// mais antigo, limitado a limit linhas.
func (db *DB) GetHostUsageHistory(mac string, limit int) ([]HostUsage, error) {
	if limit <= 0 || limit > 60 {
		limit = 12
	}
	rows, err := db.conn.Query(`
		SELECT mac, cycle_start, rx_bytes, tx_bytes, updated_at FROM host_usage
		WHERE mac = ? ORDER BY cycle_start DESC LIMIT ?`, mac, limit)
	if err != nil {
		return nil, fmt.Errorf("ler histórico de consumo do aparelho: %w", err)
	}
	defer rows.Close()

	var out []HostUsage
	for rows.Next() {
		var u HostUsage
		if err := rows.Scan(&u.MAC, &u.CycleStart, &u.RxBytes, &u.TxBytes, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ler histórico de consumo do aparelho: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
