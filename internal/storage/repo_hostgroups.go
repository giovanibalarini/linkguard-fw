package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// HostGroup is a named collection of IPv4 addresses or prefixes used as reusable
// targets for firewall rules and WireGuard ZTNA access profiles.
type HostGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Hosts       []string  `json:"hosts"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ValidateHostGroup checks that the name and all host entries are valid IPv4 addresses or CIDRs.
func ValidateHostGroup(hg HostGroup) error {
	name := strings.TrimSpace(hg.Name)
	if name == "" {
		return fmt.Errorf("nome do grupo de hosts é obrigatório")
	}
	if len(name) > 64 {
		return fmt.Errorf("nome do grupo de hosts deve ter no máximo 64 caracteres")
	}
	for _, h := range hg.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(h); err == nil {
			if !prefix.Addr().Is4() {
				return fmt.Errorf("apenas endereços IPv4 são suportados: %s", h)
			}
			continue
		}
		if addr, err := netip.ParseAddr(h); err == nil {
			if !addr.Is4() {
				return fmt.Errorf("apenas endereços IPv4 são suportados: %s", h)
			}
			continue
		}
		return fmt.Errorf("endereço ou CIDR IPv4 inválido: %s", h)
	}
	return nil
}

// NormalizeHosts ensures each host is trimmed and normalized.
func NormalizeHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	seen := make(map[string]bool)
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		if addr, err := netip.ParseAddr(h); err == nil && addr.Is4() {
			h = addr.String() + "/32"
		} else if prefix, err := netip.ParsePrefix(h); err == nil && prefix.Addr().Is4() {
			h = prefix.String()
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func (db *DB) ListHostGroups() ([]HostGroup, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, description, hosts, created_at, updated_at
		  FROM host_groups
		 ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HostGroup
	for rows.Next() {
		var hg HostGroup
		var hostsJSON string
		if err := rows.Scan(&hg.ID, &hg.Name, &hg.Description, &hostsJSON, &hg.CreatedAt, &hg.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(hostsJSON), &hg.Hosts)
		if hg.Hosts == nil {
			hg.Hosts = []string{}
		}
		out = append(out, hg)
	}
	return out, rows.Err()
}

func (db *DB) GetHostGroup(id string) (*HostGroup, error) {
	var hg HostGroup
	var hostsJSON string
	err := db.conn.QueryRow(`
		SELECT id, name, description, hosts, created_at, updated_at
		  FROM host_groups
		 WHERE id = ?`, id).
		Scan(&hg.ID, &hg.Name, &hg.Description, &hostsJSON, &hg.CreatedAt, &hg.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(hostsJSON), &hg.Hosts)
	if hg.Hosts == nil {
		hg.Hosts = []string{}
	}
	return &hg, nil
}

func (db *DB) CreateHostGroup(hg *HostGroup) error {
	if err := ValidateHostGroup(*hg); err != nil {
		return err
	}
	if hg.ID == "" {
		hg.ID = uuid.NewString()
	}
	hg.Hosts = NormalizeHosts(hg.Hosts)
	hostsJSON, err := json.Marshal(hg.Hosts)
	if err != nil {
		return err
	}
	now := time.Now()
	hg.CreatedAt = now
	hg.UpdatedAt = now

	_, err = db.conn.Exec(`
		INSERT INTO host_groups (id, name, description, hosts, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		hg.ID, strings.TrimSpace(hg.Name), strings.TrimSpace(hg.Description), string(hostsJSON), now, now)
	return err
}

func (db *DB) UpdateHostGroup(hg *HostGroup) error {
	if err := ValidateHostGroup(*hg); err != nil {
		return err
	}
	hg.Hosts = NormalizeHosts(hg.Hosts)
	hostsJSON, err := json.Marshal(hg.Hosts)
	if err != nil {
		return err
	}
	now := time.Now()
	hg.UpdatedAt = now

	res, err := db.conn.Exec(`
		UPDATE host_groups
		   SET name = ?, description = ?, hosts = ?, updated_at = ?
		 WHERE id = ?`,
		strings.TrimSpace(hg.Name), strings.TrimSpace(hg.Description), string(hostsJSON), now, hg.ID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("grupo de hosts não encontrado")
	}
	return nil
}

func (db *DB) DeleteHostGroup(id string) error {
	res, err := db.conn.Exec(`DELETE FROM host_groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("grupo de hosts não encontrado")
	}
	return nil
}

