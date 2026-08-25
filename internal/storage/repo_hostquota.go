package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// ─── Cota por aparelho (issue #126, metade "por host") ───────────────────

// Períodos aceitos por HostQuota.Period. São gravados no banco como texto, e
// por isso os nomes são estáveis.
const (
	// HostPeriodMonthly fecha no dia declarado, como a fatura da operadora.
	HostPeriodMonthly = "monthly"
	// HostPeriodDaily fecha à meia-noite local. É o período que responde a
	// "quanto este aparelho pode gastar por dia" — a pergunta que um tablet
	// de criança ou uma câmera que subiu de resolução levantam.
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
	// AlertEnabled liga o AVISO, e nada além dele.
	//
	// O NOME É DELIBERADO. O campo chamava-se "enabled", e "enabled"
	// numa linha de cota POR APARELHO é a palavra que qualquer leitor entende
	// como "aplicar a cota a este aparelho" — o encaixe pronto para alguém
	// pendurar corte de tráfego num campo que já está no schema, já viaja na
	// API e já era aceito sem validação. Esta entrega NÃO corta nada (ver o
	// cabeçalho de internal/hostquota), e o nome do campo tem de dizer isso
	// sozinho.
	//
	// Quem o define é hostquota.Service.Save, a partir do limite — nunca o
	// corpo do PUT. Um JSON sem o campo gravaria false por zero-value e
	// produziria uma cota que a tela desenha, cuja barra enche e cujo alerta
	// nunca nasce: ativa aos olhos, morta na prática.
	AlertEnabled bool `json:"alert_enabled"`
}

// HostUsage é o consumo acumulado de um aparelho dentro de um ciclo.
//
// Period faz parte da IDENTIDADE do ciclo, e não é enfeite: o início de um
// ciclo DIÁRIO no dia 1 e o de um ciclo MENSAL que fecha no dia 1 são o mesmo
// inteiro. Sem esta coluna na chave, trocar o período de um aparelho no dia 1
// somaria o consumo do dia com o do mês na mesma linha, e o histórico listaria
// dias ao lado de meses com o mesmo rótulo.
type HostUsage struct {
	MAC        string `json:"mac"`
	Period     string `json:"period"`
	CycleStart int64  `json:"cycle_start"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	UpdatedAt  int64  `json:"updated_at"`
}

// GetHostQuotas devolve todas as cotas declaradas, indexadas por MAC.
func (db *DB) GetHostQuotas() (map[string]HostQuota, error) {
	rows, err := db.conn.Query(`SELECT mac, limit_gb, period, cycle_day, alert_pct, alert_enabled FROM host_quota`)
	if err != nil {
		return nil, fmt.Errorf("ler cotas por aparelho: %w", err)
	}
	defer rows.Close()

	out := map[string]HostQuota{}
	for rows.Next() {
		var q HostQuota
		if err := rows.Scan(&q.MAC, &q.LimitGB, &q.Period, &q.CycleDay, &q.AlertPct, &q.AlertEnabled); err != nil {
			return nil, fmt.Errorf("ler cota por aparelho: %w", err)
		}
		out[q.MAC] = q
	}
	return out, rows.Err()
}

// SaveHostQuota grava (ou substitui) a cota de um aparelho.
func (db *DB) SaveHostQuota(q HostQuota) error {
	_, err := db.conn.Exec(`
		INSERT INTO host_quota (mac, limit_gb, period, cycle_day, alert_pct, alert_enabled)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			limit_gb = excluded.limit_gb,
			period = excluded.period,
			cycle_day = excluded.cycle_day,
			alert_pct = excluded.alert_pct,
			alert_enabled = excluded.alert_enabled`,
		q.MAC, q.LimitGB, q.Period, q.CycleDay, q.AlertPct, q.AlertEnabled)
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
func (db *DB) AddHostUsage(mac, period string, cycleStart int64, rx, tx uint64) error {
	if period == "" {
		period = HostPeriodMonthly
	}
	_, err := db.conn.Exec(`
		INSERT INTO host_usage (mac, period, cycle_start, rx_bytes, tx_bytes, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac, period, cycle_start) DO UPDATE SET
			rx_bytes = rx_bytes + excluded.rx_bytes,
			tx_bytes = tx_bytes + excluded.tx_bytes,
			updated_at = excluded.updated_at`,
		mac, period, cycleStart, rx, tx, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("acumular consumo do aparelho: %w", err)
	}
	return nil
}

// GetHostUsage devolve o consumo de um aparelho num ciclo. Ausência não é
// erro — é ciclo sem tráfego medido ainda.
func (db *DB) GetHostUsage(mac, period string, cycleStart int64) (HostUsage, error) {
	if period == "" {
		period = HostPeriodMonthly
	}
	u := HostUsage{MAC: mac, Period: period, CycleStart: cycleStart}
	err := db.conn.QueryRow(`
		SELECT rx_bytes, tx_bytes, updated_at FROM host_usage
		WHERE mac = ? AND period = ? AND cycle_start = ?`, mac, period, cycleStart).
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
// Existe para a tela E O FLUSH não fazerem uma consulta por aparelho: com
// oitenta aparelhos no inventário isso seriam oitenta idas ao banco por minuto,
// no mesmo SQLite que guarda metric_samples. O mapa é indexado por MAC.
//
// O índice idx_host_usage_cycle é o que faz esta consulta ser uma BUSCA e não
// uma varredura da tabela inteira: a chave primária começa por mac, então
// filtrar por (period, cycle_start) sem ele lê linha a linha — e com ciclo
// diário a tabela cresce uma linha por aparelho por dia.
func (db *DB) GetHostUsageAll(period string, cycleStart int64) (map[string]HostUsage, error) {
	if period == "" {
		period = HostPeriodMonthly
	}
	rows, err := db.conn.Query(`
		SELECT mac, period, cycle_start, rx_bytes, tx_bytes, updated_at FROM host_usage
		WHERE period = ? AND cycle_start = ?`, period, cycleStart)
	if err != nil {
		return nil, fmt.Errorf("ler consumo dos aparelhos: %w", err)
	}
	defer rows.Close()

	out := map[string]HostUsage{}
	for rows.Next() {
		var u HostUsage
		if err := rows.Scan(&u.MAC, &u.Period, &u.CycleStart, &u.RxBytes, &u.TxBytes, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ler consumo dos aparelhos: %w", err)
		}
		out[u.MAC] = u
	}
	return out, rows.Err()
}

// GetHostUsageHistory devolve os ciclos de um aparelho, do mais recente para o
// mais antigo, limitado a limit linhas. Period vem junto para a tela poder
// rotular: depois de uma troca de período a lista tem linhas de dia e linhas de
// mês, e sem a marca as duas se parecem.
func (db *DB) GetHostUsageHistory(mac string, limit int) ([]HostUsage, error) {
	if limit <= 0 || limit > 60 {
		limit = 12
	}
	rows, err := db.conn.Query(`
		SELECT mac, period, cycle_start, rx_bytes, tx_bytes, updated_at FROM host_usage
		WHERE mac = ? ORDER BY cycle_start DESC LIMIT ?`, mac, limit)
	if err != nil {
		return nil, fmt.Errorf("ler histórico de consumo do aparelho: %w", err)
	}
	defer rows.Close()

	var out []HostUsage
	for rows.Next() {
		var u HostUsage
		if err := rows.Scan(&u.MAC, &u.Period, &u.CycleStart, &u.RxBytes, &u.TxBytes, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ler histórico de consumo do aparelho: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// MoveHostUsage transfere o consumo já medido de uma chave de ciclo para outra,
// numa transação.
//
// POR QUE ISTO EXISTE. Trocar o período ou o dia de fechamento de um aparelho
// MOVE a chave (mac, period, cycle_start) do ciclo vigente. Sem esta função o
// consumo medido continua no banco sob a chave antiga e a tela passa a ler a
// nova: a barra volta para 0% e o admin conclui que o ciclo recomeçou. É o
// mesmo defeito que Delete foi escrito para não cometer (ver o comentário lá),
// entrando pela porta do Save.
//
// A soma acontece no SQL e o DELETE vai na MESMA transação: um crash no meio
// não pode deixar o consumo contado duas vezes nem em lugar nenhum.
func (db *DB) MoveHostUsage(mac, fromPeriod string, fromCycle int64, toPeriod string, toCycle int64) error {
	if fromPeriod == "" {
		fromPeriod = HostPeriodMonthly
	}
	if toPeriod == "" {
		toPeriod = HostPeriodMonthly
	}
	if fromPeriod == toPeriod && fromCycle == toCycle {
		return nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("mover consumo do aparelho: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido

	var rx, txb uint64
	err = tx.QueryRow(`SELECT rx_bytes, tx_bytes FROM host_usage WHERE mac = ? AND period = ? AND cycle_start = ?`,
		mac, fromPeriod, fromCycle).Scan(&rx, &txb)
	if err == sql.ErrNoRows {
		return tx.Commit() // nada medido no ciclo antigo: nada a mover
	}
	if err != nil {
		return fmt.Errorf("mover consumo do aparelho: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO host_usage (mac, period, cycle_start, rx_bytes, tx_bytes, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac, period, cycle_start) DO UPDATE SET
			rx_bytes = rx_bytes + excluded.rx_bytes,
			tx_bytes = tx_bytes + excluded.tx_bytes,
			updated_at = excluded.updated_at`,
		mac, toPeriod, toCycle, rx, txb, time.Now().Unix()); err != nil {
		return fmt.Errorf("mover consumo do aparelho: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM host_usage WHERE mac = ? AND period = ? AND cycle_start = ?`,
		mac, fromPeriod, fromCycle); err != nil {
		return fmt.Errorf("mover consumo do aparelho: %w", err)
	}
	return tx.Commit()
}

// PurgeHostUsage apaga ciclos antigos de aparelhos que NÃO têm cota declarada.
//
// POR QUE ISTO EXISTE. Uma linha de host_usage cujo MAC não está no inventário
// nem em host_quota é invisível na tela e imortal no banco: nada a lê e nada a
// apaga. Com telefone moderno rotacionando MAC a cada associação e ciclo
// diário, cada MAC transitório deixa uma linha por dia, para sempre — o
// denominador aqui é "todo MAC que já passou", e não "quantos links
// existem", que é o que mantinha link_usage inofensivo.
//
// Quem TEM cota declarada fica: aquele histórico é o que o admin abre para
// decidir se o teto está certo.
func (db *DB) PurgeHostUsage(before int64) (int64, error) {
	res, err := db.conn.Exec(`
		DELETE FROM host_usage
		WHERE cycle_start < ?
		  AND mac NOT IN (SELECT mac FROM host_quota WHERE limit_gb > 0)`, before)
	if err != nil {
		return 0, fmt.Errorf("podar consumo antigo de aparelho: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil // o DELETE valeu; não saber quantas linhas não é erro
	}
	return n, nil
}
