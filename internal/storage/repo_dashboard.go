package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/dashboard"
)

// ─── Layout do painel ────────────────────────────────────────────────────────

// GetDashboardLayout devolve o painel do usuário. Quem nunca salvou nada recebe
// o layout de fábrica — nunca uma tela em branco.
//
// O que está gravado passa por SanitizeDashboardLayout: item inválido é
// descartado item a item, e o resto renderiza. Um JSON corrompido na linha (o
// único jeito de chegar aqui é edição manual do banco) também cai no padrão em
// vez de derrubar a tela; o erro fica no log de quem chamou, não na cara do
// operador.
func (db *DB) GetDashboardLayout(userID string) ([]dashboard.LayoutItem, error) {
	var raw string
	err := db.conn.QueryRow(`SELECT items FROM dashboard_layout WHERE user_id = ?`, userID).Scan(&raw)
	if err == sql.ErrNoRows {
		return dashboard.Default(), nil
	}
	if err != nil {
		return nil, err
	}
	var items []dashboard.LayoutItem
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return dashboard.Default(), nil
	}
	return dashboard.Sanitize(items), nil
}

// SaveDashboardLayout grava o painel do usuário, substituindo o anterior.
//
// Grava o que recebe, sem julgar nome de widget: quem descarta é a leitura, e é
// ela que precisa continuar funcionando quando um widget deixa de existir numa
// versão futura. Uma lista vazia é uma escolha legítima — o admin tirou tudo —
// e continua diferente de "nunca salvou nada", que é a ausência da linha.
func (db *DB) SaveDashboardLayout(userID string, items []dashboard.LayoutItem) error {
	if userID == "" {
		return fmt.Errorf("layout do painel sem usuário")
	}
	if items == nil {
		items = []dashboard.LayoutItem{}
	}
	if len(items) > dashboard.MaxItems {
		return fmt.Errorf("layout do painel com %d itens (máximo %d)", len(items), dashboard.MaxItems)
	}
	blob, err := json.Marshal(items)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`
		INSERT INTO dashboard_layout (user_id, items, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET items = excluded.items, updated_at = excluded.updated_at`,
		userID, string(blob), time.Now())
	return err
}

// DeleteDashboardLayout apaga o painel do usuário, que volta ao layout de
// fábrica na próxima leitura. É o "Restaurar padrão" da spec §6.
func (db *DB) DeleteDashboardLayout(userID string) error {
	_, err := db.conn.Exec(`DELETE FROM dashboard_layout WHERE user_id = ?`, userID)
	return err
}
