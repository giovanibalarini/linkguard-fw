package storage

import (
	"time"

	"github.com/google/uuid"
)

// ─── DHCP/DNS repository ─────────────────────────────────────────────────────

// ListDHCPReservations returns all static reservations ordered by IP.
func (db *DB) ListDHCPReservations() ([]DHCPReservation, error) {
	rows, err := db.conn.Query(`
		SELECT mac, ip, hostname, created_at, updated_at FROM dhcp_reservations ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DHCPReservation{}
	for rows.Next() {
		var r DHCPReservation
		if err := rows.Scan(&r.MAC, &r.IP, &r.Hostname, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertDHCPReservation creates or updates a reservation (keyed by MAC).
func (db *DB) UpsertDHCPReservation(mac, ip, hostname string) error {
	now := time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO dhcp_reservations (mac, ip, hostname, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, hostname = excluded.hostname, updated_at = excluded.updated_at`,
		mac, ip, hostname, now, now)
	return err
}

// DeleteDHCPReservation removes a reservation by MAC.
func (db *DB) DeleteDHCPReservation(mac string) error {
	_, err := db.conn.Exec(`DELETE FROM dhcp_reservations WHERE mac = ?`, mac)
	return err
}

// ListDNSBlocklist returns all blocked domains ordered alphabetically.
func (db *DB) ListDNSBlocklist() ([]string, error) {
	rows, err := db.conn.Query(`SELECT domain FROM dns_blocklist ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddDNSBlocklist adds a domain to the DNS blocklist.
func (db *DB) AddDNSBlocklist(domain string) error {
	_, err := db.conn.Exec(`INSERT OR IGNORE INTO dns_blocklist (domain) VALUES (?)`, domain)
	return err
}

// DeleteDNSBlocklist removes a domain from the DNS blocklist.
func (db *DB) DeleteDNSBlocklist(domain string) error {
	_, err := db.conn.Exec(`DELETE FROM dns_blocklist WHERE domain = ?`, domain)
	return err
}

// ─── Routing Policies ────────────────────────────────────────────────────────
//
// NADA NO PRODUTO ALCANÇA ESTE BLOCO. Não existe handler HTTP, não existe
// service, não existe tela. As três funções abaixo, o tipo RoutingPolicy e a
// tabela routing_policies não têm um único chamador fora deste pacote e dos
// testes dele (issue #62, confirmado por grep antes de reportar):
//
//	$ grep -rn "RoutingPolic" --include=*.go . | grep -v internal/storage/
//	(vazio)
//
// Isto está escrito aqui porque código que existe, tem schema e tem cobertura
// de teste PARECE recurso pronto. A #26 encontrou este bloco ao recortar o
// repository.go e a #41 lhe deu testes ao cobrir as funções em 0% — as duas
// coisas certas a fazer, e juntas elas deixaram a armadilha mais convincente:
// quem for mexer em roteamento amanhã acha a tabela, acha os testes verdes, e
// conclui que é só ligar na tela.
//
// Não é. Nunca houve nada do outro lado. Se você precisa de política de
// roteamento por origem/destino, o trabalho é inteiro — decidir a semântica
// contra o balancer e o failover, escrever a aplicação em `ip rule`/`ip route`,
// a camada HTTP e a tela. O que está aqui é persistência sem dono, e é a menor
// parte.
//
// A decisão de manter (em vez de remover com uma migração que dropa a tabela)
// é deliberada e é do dono do produto: dropar é irreversível, e qualquer linha
// que exista em routing_policies num firewall instalado sumiria no boot
// seguinte. Documentar custa um comentário e não fecha porta nenhuma.

// GetRoutingPolicies returns all routing policies.
//
// Sem chamadores. Ver o comentário do bloco acima (issue #62).
func (db *DB) GetRoutingPolicies() ([]RoutingPolicy, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, source_cidr, dest_cidr, link_id, priority, enabled, failover, created_at, updated_at
		FROM routing_policies ORDER BY priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []RoutingPolicy
	for rows.Next() {
		var p RoutingPolicy
		var enabled, failover int
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceCIDR, &p.DestCIDR, &p.LinkID,
			&p.Priority, &enabled, &failover, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		p.Failover = failover != 0
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// CreateRoutingPolicy inserts a new routing policy.
func (db *DB) CreateRoutingPolicy(p *RoutingPolicy) error {
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	_, err := db.conn.Exec(`
		INSERT INTO routing_policies (id, name, source_cidr, dest_cidr, link_id, priority, enabled, failover, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.SourceCIDR, p.DestCIDR, p.LinkID, p.Priority,
		boolToInt(p.Enabled), boolToInt(p.Failover), p.CreatedAt, p.UpdatedAt)
	return err
}

// DeleteRoutingPolicy removes a routing policy by ID.
func (db *DB) DeleteRoutingPolicy(id string) error {
	_, err := db.conn.Exec(`DELETE FROM routing_policies WHERE id=?`, id)
	return err
}
