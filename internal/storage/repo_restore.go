package storage

import (
	"fmt"
	"time"
)

// ─── Restauração de backup ───────────────────────────────────────────────────
//
// ApplyRestore grava settings + reservas DHCP + blocklist DNS na MESMA
// transação, então ele atravessa repo_settings.go e repo_netsvc.go. Ele não foi
// partido em três: a transação única é justamente a garantia do restore ("ou
// vale inteiro, ou o banco fica como estava"), e um restore recortado em três
// arquivos convida o próximo a escrever três transações. A restauração é o
// domínio; os três SQLs são o conteúdo dela.
//
// Só o que roda dentro dessa transação mora aqui. Escrita normal de setting,
// reserva ou domínio bloqueado continua em repo_settings.go / repo_netsvc.go.

// RestorePayload é o que uma restauração grava: as três coleções, já validadas
// e normalizadas por quem chama.
type RestorePayload struct {
	Settings     map[string]string
	Reservations []DHCPReservation
	Blocklist    []string
}

// RestoreCounts é quanto de cada coisa entrou.
type RestoreCounts struct {
	Settings     int
	Reservations int
	Blocklist    int
}

// ApplyRestore grava as três coleções numa transação só: ou a configuração
// restaurada vale inteira, ou o banco fica exatamente como estava.
//
// Antes disto o restore era um laço por coleção com o erro engolido
// (`if err := SetSetting(...); err == nil { conta++ }`) e HTTP 200 no fim. Uma
// falha de banco no meio deixava metade da configuração restaurada, metade não,
// e devolvia sucesso — com um contador menor como única pista. Num projeto cuja
// regra é "toda migração em transação" desde o incidente de 2026-07-24,
// restaurar a configuração inteira sem transação era a inconsistência mais
// visível que restava.
//
// O erro agora sobe. Quem chama traduz em 500, e a promessa de "nada foi
// restaurado" que a validação já fazia passa a valer também para a escrita.
func (db *DB) ApplyRestore(p RestorePayload) (RestoreCounts, error) {
	var c RestoreCounts
	tx, err := db.conn.Begin()
	if err != nil {
		return c, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido

	now := time.Now()
	for k, v := range p.Settings {
		if _, err := tx.Exec(`
			INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
			k, v, now); err != nil {
			return RestoreCounts{}, fmt.Errorf("restaurar a chave %q: %w", k, err)
		}
		c.Settings++
	}
	for _, r := range p.Reservations {
		if _, err := tx.Exec(`
			INSERT INTO dhcp_reservations (mac, ip, hostname, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, hostname = excluded.hostname, updated_at = excluded.updated_at`,
			r.MAC, r.IP, r.Hostname, now, now); err != nil {
			return RestoreCounts{}, fmt.Errorf("restaurar a reserva DHCP %s: %w", r.MAC, err)
		}
		c.Reservations++
	}
	for _, d := range p.Blocklist {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO dns_blocklist (domain) VALUES (?)`, d); err != nil {
			return RestoreCounts{}, fmt.Errorf("restaurar o domínio bloqueado %q: %w", d, err)
		}
		c.Blocklist++
	}

	if err := tx.Commit(); err != nil {
		return RestoreCounts{}, fmt.Errorf("confirmar a restauração: %w", err)
	}
	return c, nil
}
