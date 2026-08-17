package storage

import (
	"database/sql"
	"fmt"
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

// ErrDHCPIPTaken diz que o IP pedido já pertence à reserva de OUTRO MAC.
//
// Carrega o MAC dono porque sem ele o erro é inútil na tela: o admin descobre
// que não pode usar aquele IP e não descobre qual reserva remover para poder.
type ErrDHCPIPTaken struct {
	IP       string
	OwnerMAC string
}

func (e *ErrDHCPIPTaken) Error() string {
	return fmt.Sprintf("o IP %s já está reservado para o MAC %s", e.IP, e.OwnerMAC)
}

// UpsertDHCPReservation creates or updates a reservation (keyed by MAC).
//
// Recusa o IP que já é de outro MAC (issue #59). A tabela só tinha PK em `mac`,
// e o handler só validava que MAC e IP parseavam — dois equipamentos podiam
// reivindicar o mesmo endereço, o kea aceitava a configuração gerada e
// entregava o IP para os dois. O sintoma que chega ao admin não é "reserva
// duplicada": é conflito de endereço intermitente, que só aparece com os dois
// aparelhos ligados ao mesmo tempo, e é dos mais caros de diagnosticar numa
// rede.
//
// A checagem e a escrita vão na MESMA transação, e não em duas chamadas: entre
// um SELECT solto e o INSERT cabe a requisição de outro admin, que é justamente
// a corrida que a duplicata precisa para nascer. O índice único da migração 12
// é a rede de baixo; esta transação é o que dá a mensagem com o MAC dono, que o
// índice não teria como dar.
func (db *DB) UpsertDHCPReservation(mac, ip, hostname string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois do Commit

	// `mac != ?` é o que mantém a troca de IP da PRÓPRIA reserva funcionando:
	// sem isso, reeditar um host para o mesmo IP que ele já tem seria recusado.
	var owner string
	err = tx.QueryRow(
		`SELECT mac FROM dhcp_reservations WHERE ip = ? AND mac != ? LIMIT 1`,
		ip, mac).Scan(&owner)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil {
		return &ErrDHCPIPTaken{IP: ip, OwnerMAC: owner}
	}

	now := time.Now()
	if _, err := tx.Exec(`
		INSERT INTO dhcp_reservations (mac, ip, hostname, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, hostname = excluded.hostname, updated_at = excluded.updated_at`,
		mac, ip, hostname, now, now); err != nil {
		return err
	}
	return tx.Commit()
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
