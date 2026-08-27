package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// WireGuardConfig is the public desired state. Private keys never enter this
// table; they live exclusively in internal/secrets.
type WireGuardConfig struct {
	Enabled        bool      `json:"enabled"`
	ListenPort     int       `json:"listen_port"`
	Address        string    `json:"address"`
	EndpointHost   string    `json:"endpoint_host"`
	EndpointLinkID string    `json:"endpoint_link_id"`
	LastApplyOK    bool      `json:"last_apply_ok"`
	LastApplyError string    `json:"last_apply_error,omitempty"`
	LastAppliedAt  int64     `json:"last_applied_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// WireGuardPeer ties one local panel user to one tunnel identity and one
// firewall group. SecretName is deliberately excluded from JSON.
type WireGuardPeer struct {
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	PublicKey       string    `json:"public_key"`
	Address         string    `json:"address"`
	SecretName      string    `json:"-"`
	FirewallGroupID string    `json:"firewall_group_id"`
	CreatedAt       time.Time `json:"created_at"`
	RotatedAt       time.Time `json:"rotated_at"`
}

func (db *DB) GetWireGuardConfig() (*WireGuardConfig, error) {
	var c WireGuardConfig
	var enabled, ok int
	err := db.conn.QueryRow(`
		SELECT enabled, listen_port, address, endpoint_host, endpoint_link_id,
		       last_apply_ok, last_apply_error, last_applied_at, updated_at
		  FROM wireguard_config WHERE only_row = 1`).
		Scan(&enabled, &c.ListenPort, &c.Address, &c.EndpointHost, &c.EndpointLinkID,
			&ok, &c.LastApplyError, &c.LastAppliedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Enabled, c.LastApplyOK = enabled != 0, ok != 0
	return &c, nil
}

func (db *DB) SaveWireGuardConfig(c *WireGuardConfig) error {
	c.UpdatedAt = time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO wireguard_config
			(only_row, enabled, listen_port, address, endpoint_host, endpoint_link_id,
			 last_apply_ok, last_apply_error, last_applied_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(only_row) DO UPDATE SET
			enabled=excluded.enabled, listen_port=excluded.listen_port,
			address=excluded.address, endpoint_host=excluded.endpoint_host,
			endpoint_link_id=excluded.endpoint_link_id,
			last_apply_ok=excluded.last_apply_ok,
			last_apply_error=excluded.last_apply_error,
			last_applied_at=excluded.last_applied_at,
			updated_at=excluded.updated_at`,
		boolToInt(c.Enabled), c.ListenPort, c.Address, c.EndpointHost, c.EndpointLinkID,
		boolToInt(c.LastApplyOK), c.LastApplyError, c.LastAppliedAt, c.UpdatedAt)
	return err
}

func scanWireGuardPeer(scanner interface{ Scan(...any) error }) (*WireGuardPeer, error) {
	var p WireGuardPeer
	if err := scanner.Scan(&p.UserID, &p.Username, &p.PublicKey, &p.Address, &p.SecretName,
		&p.FirewallGroupID, &p.CreatedAt, &p.RotatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

func (db *DB) GetWireGuardPeer(userID string) (*WireGuardPeer, error) {
	p, err := scanWireGuardPeer(db.conn.QueryRow(`
		SELECT p.user_id, u.username, p.public_key, p.address, p.secret_name,
		       p.firewall_group_id, p.created_at, p.rotated_at
		  FROM wireguard_peers p JOIN users u ON u.id = p.user_id
		 WHERE p.user_id = ?`, userID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func (db *DB) ListWireGuardPeers() ([]WireGuardPeer, error) {
	rows, err := db.conn.Query(`
		SELECT p.user_id, u.username, p.public_key, p.address, p.secret_name,
		       p.firewall_group_id, p.created_at, p.rotated_at
		  FROM wireguard_peers p JOIN users u ON u.id = p.user_id
		 ORDER BY u.username, p.user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WireGuardPeer{}
	for rows.Next() {
		p, err := scanWireGuardPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UpsertWireGuardPeer creates or rotates a peer and its managed firewall group
// in one transaction. Rotation preserves the address, group and all rules.
func (db *DB) UpsertWireGuardPeer(p *WireGuardPeer, g *FirewallGroup) (*WireGuardPeer, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var username string
	if err := tx.QueryRow(`SELECT username FROM users WHERE id = ?`, p.UserID).Scan(&username); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("usuário local %q não encontrado", p.UserID)
		}
		return nil, err
	}
	p.Username = username

	var old *WireGuardPeer
	row := tx.QueryRow(`
		SELECT p.user_id, u.username, p.public_key, p.address, p.secret_name,
		       p.firewall_group_id, p.created_at, p.rotated_at
		  FROM wireguard_peers p JOIN users u ON u.id = p.user_id
		 WHERE p.user_id = ?`, p.UserID)
	if prior, scanErr := scanWireGuardPeer(row); scanErr == nil {
		old = prior
		p.Address = prior.Address
		p.FirewallGroupID = prior.FirewallGroupID
		g.ID = prior.FirewallGroupID
		if _, err := tx.Exec(`
			UPDATE firewall_groups
			   SET name=?, enabled=1, cond_saddr=?, cond_daddr='', cond_iif='',
			       fallthrough=?, kind=?, scope=?, conn_state=?,
			       sched_days='', sched_start='', sched_end='', updated_at=?
			 WHERE id=?`, g.Name, p.Address, g.Fallthrough, g.Kind, g.Scope,
			g.ConnState, time.Now(), g.ID); err != nil {
			return nil, err
		}
	} else if scanErr != sql.ErrNoRows {
		return nil, scanErr
	} else {
		var maxPos sql.NullInt64
		if err := tx.QueryRow(`SELECT MAX(position) FROM firewall_groups`).Scan(&maxPos); err != nil {
			return nil, err
		}
		g.Position = 0
		if maxPos.Valid {
			g.Position = int(maxPos.Int64) + 1
		}
		now := time.Now()
		g.CreatedAt, g.UpdatedAt = now, now
		if _, err := tx.Exec(`
			INSERT INTO firewall_groups
				(id, name, chain_name, position, enabled, cond_saddr, cond_daddr,
				 cond_iif, fallthrough, kind, scope, conn_state, sched_days,
				 sched_start, sched_end, created_at, updated_at)
			VALUES (?, ?, ?, ?, 1, ?, '', '', ?, ?, ?, ?, '', '', '', ?, ?)`,
			g.ID, g.Name, g.ChainName, g.Position, p.Address, g.Fallthrough,
			g.Kind, g.Scope, g.ConnState, now, now); err != nil {
			return nil, err
		}
	}

	now := time.Now()
	if old == nil {
		p.CreatedAt = now
	} else {
		p.CreatedAt = old.CreatedAt
	}
	p.RotatedAt = now
	if _, err := tx.Exec(`
		INSERT INTO wireguard_peers
			(user_id, public_key, address, secret_name, firewall_group_id, created_at, rotated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			public_key=excluded.public_key, address=excluded.address,
			secret_name=excluded.secret_name,
			firewall_group_id=excluded.firewall_group_id,
			rotated_at=excluded.rotated_at`,
		p.UserID, p.PublicKey, p.Address, p.SecretName, p.FirewallGroupID,
		p.CreatedAt, p.RotatedAt); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return old, nil
}

// DeleteWireGuardPeer removes the peer, its managed group and every rule in
// that group atomically. The caller deletes the returned vault secret after
// commit; a failure there can only leave an unreachable encrypted orphan.
func (db *DB) DeleteWireGuardPeer(userID string) (*WireGuardPeer, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	p, err := scanWireGuardPeer(tx.QueryRow(`
		SELECT p.user_id, u.username, p.public_key, p.address, p.secret_name,
		       p.firewall_group_id, p.created_at, p.rotated_at
		  FROM wireguard_peers p JOIN users u ON u.id = p.user_id
		 WHERE p.user_id = ?`, userID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM wireguard_peers WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM firewall_rules WHERE group_id = ?`, p.FirewallGroupID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM firewall_groups WHERE id = ?`, p.FirewallGroupID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

// EnsureWireGuardPeerGroup repairs the managed projection without touching
// its position or rules. It is safe on every boot and every VPN apply.
func (db *DB) EnsureWireGuardPeerGroup(g *FirewallGroup) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM firewall_groups WHERE id = ?`, g.ID).Scan(&exists); err != nil {
		return err
	}
	now := time.Now()
	if exists == 0 {
		var maxPos sql.NullInt64
		if err := tx.QueryRow(`SELECT MAX(position) FROM firewall_groups`).Scan(&maxPos); err != nil {
			return err
		}
		g.Position = 0
		if maxPos.Valid {
			g.Position = int(maxPos.Int64) + 1
		}
		if _, err := tx.Exec(`
			INSERT INTO firewall_groups
				(id, name, chain_name, position, enabled, cond_saddr, cond_daddr,
				 cond_iif, fallthrough, kind, scope, conn_state, sched_days,
				 sched_start, sched_end, created_at, updated_at)
			VALUES (?, ?, ?, ?, 1, ?, '', '', ?, ?, ?, ?, '', '', '', ?, ?)`,
			g.ID, g.Name, g.ChainName, g.Position, g.CondSaddr, g.Fallthrough,
			g.Kind, g.Scope, g.ConnState, now, now); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`
			UPDATE firewall_groups SET name=?, chain_name=?, enabled=1, cond_saddr=?,
				cond_daddr='', cond_iif='', fallthrough=?, kind=?, scope=?, conn_state=?,
				sched_days='', sched_start='', sched_end='', updated_at=? WHERE id=?`,
			g.Name, g.ChainName, g.CondSaddr, g.Fallthrough, g.Kind, g.Scope,
			g.ConnState, now, g.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
