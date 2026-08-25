package storage

import (
	"fmt"
	"strings"
	"time"
)

// Alvo de regra por domínio (#123): a lista que o admin mantém.
//
// O que este arquivo guarda é INTENÇÃO, e não estado do firewall. Os endereços
// que cada domínio ensinou vivem no índice em memória do alimentador e nas
// estruturas do kernel, e nenhum dos dois é gravado aqui — cache de DNS que
// sobrevive ao reboot afirma sobre endereços o que ninguém mais confirmou, que
// é a mesma razão pela qual o mapa da #116 também não é gravado.

// Estágios de um domínio. Ver a coluna stage em createDomainTargetsTable.
const (
	// DomainStageEnsaio aprende e não escreve no firewall.
	DomainStageEnsaio = "ensaio"
	// DomainStageAtivo escreve. Só por ação explícita.
	DomainStageAtivo = "ativo"
)

// Capacidades de um domínio.
const (
	DomainCapBarrar     = "barrar"
	DomainCapDirecionar = "direcionar"
)

// DomainTarget é um domínio listado.
type DomainTarget struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	// Capability é "barrar" ou "direcionar".
	Capability string `json:"capability"`
	// Stage é "ensaio" ou "ativo".
	Stage string `json:"stage"`
	// LinkName é só para a tela; quem vai para o kernel é Mark.
	LinkName  string    `json:"link_name"`
	Mark      uint32    `json:"mark"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListDomainTargets devolve a lista inteira, em ordem de domínio.
func (db *DB) ListDomainTargets() ([]DomainTarget, error) {
	rows, err := db.conn.Query(`
		SELECT id, domain, capability, stage, link_name, mark, note, created_at, updated_at
		FROM domain_targets ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("listar os alvos por domínio: %w", err)
	}
	defer rows.Close()
	out := []DomainTarget{}
	for rows.Next() {
		var t DomainTarget
		if err := rows.Scan(&t.ID, &t.Domain, &t.Capability, &t.Stage,
			&t.LinkName, &t.Mark, &t.Note, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ler um alvo por domínio: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveDomainTarget grava um domínio, criando ou atualizando pelo NOME.
//
// O conflito é resolvido por domain e não por id de propósito: quem digita o
// mesmo nome duas vezes está corrigindo a mesma entrada, e deixar as duas
// entrarem geraria a ambiguidade que o UNIQUE da coluna existe para impedir.
//
// O ESTÁGIO NÃO É GRAVADO AQUI. Editar a capacidade, o link ou a observação de
// um domínio não pode promovê-lo por tabela — promover é PromoteDomainTarget, e
// a separação é o que impede que uma tela de edição, um import de backup ou um
// campo em branco liguem um bloqueio que ninguém pediu.
func (db *DB) SaveDomainTarget(t DomainTarget) error {
	dom := strings.ToLower(strings.Trim(strings.TrimSpace(t.Domain), "."))
	if dom == "" || !strings.Contains(dom, ".") {
		return fmt.Errorf("domínio inválido: %q", t.Domain)
	}
	if t.Capability != DomainCapDirecionar {
		t.Capability = DomainCapBarrar
	}
	if t.ID == "" {
		t.ID = dom
	}
	_, err := db.conn.Exec(`
		INSERT INTO domain_targets (id, domain, capability, stage, link_name, mark, note, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			capability = excluded.capability,
			link_name  = excluded.link_name,
			mark       = excluded.mark,
			note       = excluded.note,
			updated_at = excluded.updated_at`,
		t.ID, dom, t.Capability, DomainStageEnsaio, t.LinkName, t.Mark, t.Note, time.Now())
	if err != nil {
		return fmt.Errorf("gravar o alvo por domínio %s: %w", dom, err)
	}
	return nil
}

// PromoteDomainTarget move o domínio entre ensaio e ativo.
//
// É a ÚNICA porta de saída do ensaio, e existe separada de SaveDomainTarget
// pela razão dita lá: sair do ensaio é a única coisa nesta capacidade que muda
// o que passa na rede, e uma mudança dessas não pode acontecer de carona numa
// gravação de rotina.
func (db *DB) PromoteDomainTarget(domain, stage string) error {
	if stage != DomainStageAtivo {
		stage = DomainStageEnsaio
	}
	dom := strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	res, err := db.conn.Exec(
		`UPDATE domain_targets SET stage = ?, updated_at = ? WHERE domain = ?`,
		stage, time.Now(), dom)
	if err != nil {
		return fmt.Errorf("mudar o estágio de %s: %w", dom, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("domínio não listado: %s", dom)
	}
	return nil
}

// DeleteDomainTarget tira o domínio da lista.
func (db *DB) DeleteDomainTarget(domain string) error {
	dom := strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	_, err := db.conn.Exec(`DELETE FROM domain_targets WHERE domain = ?`, dom)
	if err != nil {
		return fmt.Errorf("apagar o alvo por domínio %s: %w", dom, err)
	}
	return nil
}
