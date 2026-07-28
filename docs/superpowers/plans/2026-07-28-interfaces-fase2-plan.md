# Interfaces — Fase 2 (edição física + commit/confirm) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deixar o admin editar o endereçamento de uma interface física (estático/DHCP/nenhum) pelo painel, com preview do diff antes de aplicar e uma janela de confirmação que reverte sozinha se ninguém confirmar — a primeira vez que o LinkGuard escreve configuração de rede de verdade.

**Architecture:** Novo pacote `internal/netif/networkd` (Provider systemd-networkd: `Render` puro + `Apply` com escrita atômica). O `netif.Service` (já existente da Fase 1) ganha as operações de preview/apply/confirm/rollback e passa a ter a primeira persistência real do pacote (duas tabelas novas: config gerenciada por interface + mudança pendente de confirmação). Um laço em background varre mudanças pendentes vencidas e reverte sozinho — sobrevive a um restart do LinkGuard porque o estado vive no SQLite, não em memória.

**Tech Stack:** Go 1.25 (`internal/netif/networkd`, SQLite via `internal/storage`), React+TypeScript (reaproveitando o padrão de UI já existente em `WanBalancing.tsx`).

## Global Constraints

- **Escopo é só edição de interface física** (AddrMode, CIDR, Gateway, Description) — spec 19/07 §14 Fase 2. Nada de VLAN/bridge (Fase 3) nem histórico/deriva de verdade (Fase 4).
- **Em produção, isso fica sem efeito real por enquanto.** `systemd-networkd` está `inactive` lá (confirmado ao vivo); os arquivos `.network` são escritos corretamente mas ninguém os lê até a migração `ifupdown`→`systemd-networkd` (sub-projeto futuro) acontecer. Isso é seguro e intencional — ver adendo `docs/superpowers/specs/2026-07-28-interfaces-fase2-design-system.md` §2/§4. A verificação de efeito real (Task 10) precisa de uma máquina com `systemd-networkd` ativo — **não** é feita contra produção.
- **Commit/confirm precisa sobreviver a um restart do LinkGuard** (spec 19/07 §6, explícito) — isso é diferente do mecanismo já existente em `internal/balancer` (que é só em memória, com `time.AfterFunc`, e **não sobrevive restart** — não copiar esse detalhe, só a UX). O estado de "mudança pendente" fica no SQLite; um laço com `time.Ticker` varre periodicamente por mudanças vencidas, em vez de um timer preciso em processo. Perder alguns segundos de precisão no rollback automático é aceitável; perder o rollback inteiro por causa de um restart não é.
- **UX do commit/confirm reaproveita `web/src/components/WanBalancing.tsx`** — banner fixo com contagem regressiva, botões "Confirmar"/"Reverter", mesmo texto de aviso ("verifique se a internet/o acesso continua funcionando antes de confirmar"), só restilizado com `Panel`/`Tag`.
- **Nenhum padrão de escrita atômica existe ainda no projeto** (confirmado — `os.Rename` não é usado em nenhum lugar hoje). `networkd.Apply` introduz esse padrão pela primeira vez: escrever em arquivo temporário no **mesmo diretório** do alvo (`/etc/systemd/network/`) e `os.Rename` por cima — atômico porque é o mesmo filesystem.
- **`networkctl reload` é suficiente para todo caso desta fase** — Fase 2 só edita conteúdo de arquivo `.network` já existente (endereçamento), nunca cria/remove `.netdev` nem muda o tipo de uma interface (isso é Fase 3, quando VLAN/bridge entram em cena e `networkctl reconfigure` passa a ser necessário conforme spec 19/07 §5.3).
- **`Adotar` fica implícito**: em vez de um passo separado "marcar como gerenciada, depois editar", o primeiro apply+confirm bem-sucedido de uma interface já a torna gerenciada (grava em `managed_interfaces`). Decisão tomada ao escrever este plano — reduz uma tela sem perder segurança (nada é escrito até o admin editar e confirmar explicitamente).
- **Sem framework de teste unitário no frontend** (mesmo padrão dos sub-projetos anteriores) — build por tarefa + Playwright no final. Backend usa `go test`, sempre prefixado com `PATH=/home/gov/sdk/go1.25.0/bin:$PATH`.
- **Sem teste em network namespace privilegiado nesta primeira fase** — a spec 19/07 §13 menciona essa camada (`Apply` real dentro de netns descartável, atrás de build tag) como parte do plano de testes completo, mas não existe nenhum precedente desse padrão neste repositório ainda (confirmado — nenhuma build tag de privilégio/netns existe hoje). Introduzir essa infraestrutura do zero é desproporcional para o primeiro corte desta fase. Este plano cobre `Render` com teste de arquivo golden (puro, sem privilégio), `Apply`/commit-confirm com executor falso (sem tocar rede de verdade), e prova o efeito real via verificação ao vivo (Task 10) contra uma máquina de teste com `systemd-networkd` habilitado. A camada de netns fica registrada como débito técnico para quando a Fase 3 (mais mudanças de tipo de interface, mais risco) tornar isso necessário.

---

### Task 1: Modelo — `CIDR`/`Gateway` em `Iface` + regra de integridade

**Files:**
- Modify: `internal/netif/netif.go`
- Create: `internal/netif/rules.go`
- Test: `internal/netif/rules_test.go`

**Interfaces:**
- Consumes: `Iface`, `AddrMode` (já existentes, Fase 1)
- Produces: `Iface.CIDR string`, `Iface.Gateway string` (novos campos); `func ValidateIface(i Iface) error`

- [ ] **Step 1: Write the failing test**

Create `internal/netif/rules_test.go`:

```go
package netif

import "testing"

func TestValidateIfaceStaticRequiresValidCIDR(t *testing.T) {
	cases := []struct {
		name    string
		iface   Iface
		wantErr bool
	}{
		{"static com CIDR válido", Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24"}, false},
		{"static sem CIDR", Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: ""}, true},
		{"static com CIDR malformado", Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "not-a-cidr"}, true},
		{"dhcp não exige CIDR", Iface{Name: "eth0", AddrMode: AddrModeDHCP, CIDR: ""}, false},
		{"none não exige CIDR", Iface{Name: "eth0", AddrMode: AddrModeNone, CIDR: ""}, false},
		{
			"gateway dentro da rede", 
			Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24", Gateway: "192.168.3.1"},
			false,
		},
		{
			"gateway fora da rede",
			Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24", Gateway: "10.0.0.1"},
			true,
		},
		{
			"gateway malformado",
			Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24", Gateway: "not-an-ip"},
			true,
		},
		{
			"sem gateway é válido (rede sem rota padrão por essa interface)",
			Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24", Gateway: ""},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateIface(c.iface)
			if c.wantErr && err == nil {
				t.Errorf("esperava erro, não teve nenhum")
			}
			if !c.wantErr && err != nil {
				t.Errorf("não esperava erro, teve: %v", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -run TestValidateIface -v`
Expected: FAIL — `ValidateIface`, `Iface.CIDR`, `Iface.Gateway` não existem ainda.

- [ ] **Step 3: Add the fields and write the validation rule**

Em `internal/netif/netif.go`, no struct `Iface`, adicione dois campos logo após `AddrMode`:

```go
	AddrMode AddrMode `json:"addr_mode"`
	CIDR     string   `json:"cidr,omitempty"`    // static: ex. "192.168.3.3/24"
	Gateway  string   `json:"gateway,omitempty"` // static: opcional, deve estar dentro da rede de CIDR
	Role     Role     `json:"role"`
```

Create `internal/netif/rules.go`:

```go
// Package netif's integrity rules — pure functions, no I/O. Fase 2 só valida
// o subconjunto relevante a interfaces físicas (spec 19/07 §5.2); as regras
// de VLAN/bridge (ciclos, unicidade de tag, etc.) ficam para a Fase 3.
package netif

import (
	"fmt"
	"net"
)

// ValidateIface checks the addressing fields are internally consistent.
// AddrMode="static" requires a valid CIDR; a present Gateway must parse as an
// IP inside that CIDR's network. AddrMode="dhcp"/"none" ignore CIDR/Gateway
// entirely (they're meaningless in those modes).
func ValidateIface(i Iface) error {
	if i.AddrMode != AddrModeStatic {
		return nil
	}
	ip, ipNet, err := net.ParseCIDR(i.CIDR)
	if err != nil {
		return fmt.Errorf("cidr inválido para %s: %w", i.Name, err)
	}
	if i.Gateway == "" {
		return nil
	}
	gw := net.ParseIP(i.Gateway)
	if gw == nil {
		return fmt.Errorf("gateway inválido para %s: %q não é um IP", i.Name, i.Gateway)
	}
	if !ipNet.Contains(gw) {
		return fmt.Errorf("gateway %s fora da rede %s (interface %s)", i.Gateway, ipNet.String(), i.Name)
	}
	_ = ip // ip é o endereço da própria interface, já validado pelo ParseCIDR acima
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -v`
Expected: PASS (todos os testes do pacote, incluindo os da Fase 1)

- [ ] **Step 5: Commit**

```bash
git add internal/netif/netif.go internal/netif/rules.go internal/netif/rules_test.go
git commit -m "feat(netif): campos CIDR/Gateway em Iface + regra de validação de endereçamento estático"
```

---

### Task 2: Storage — `managed_interfaces` + `pending_interface_changes`

**Files:**
- Modify: `internal/storage/storage.go`
- Modify: `internal/storage/models.go`
- Modify: `internal/storage/repository.go`
- Test: `internal/storage/netif_test.go`

**Interfaces:**
- Produces: `storage.ManagedInterface{Name, Kind, AddrMode, CIDR, Gateway, Description string; UpdatedAt time.Time}`; `storage.PendingInterfaceChange{ID, Interface, OldConfig, OldFiles, NewConfig string; DeadlineUnix int64; CreatedAt time.Time}`; `func (db *DB) UpsertManagedInterface(m ManagedInterface) error`; `func (db *DB) GetManagedInterface(name string) (*ManagedInterface, error)`; `func (db *DB) ListManagedInterfaces() ([]ManagedInterface, error)`; `func (db *DB) CreatePendingInterfaceChange(p PendingInterfaceChange) error`; `func (db *DB) GetPendingInterfaceChange(iface string) (*PendingInterfaceChange, error)`; `func (db *DB) ListPendingInterfaceChanges() ([]PendingInterfaceChange, error)`; `func (db *DB) DeletePendingInterfaceChange(iface string) error`

- [ ] **Step 1: Write the failing test**

Create `internal/storage/netif_test.go`:

```go
package storage_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestManagedInterfaceUpsertAndGet(t *testing.T) {
	db := newTestDB(t)
	m := storage.ManagedInterface{Name: "eth0", Kind: "physical", AddrMode: "static", CIDR: "192.168.3.3/24", Gateway: "192.168.3.1", Description: "WAN principal"}
	if err := db.UpsertManagedInterface(m); err != nil {
		t.Fatalf("UpsertManagedInterface: %v", err)
	}
	got, err := db.GetManagedInterface("eth0")
	if err != nil {
		t.Fatalf("GetManagedInterface: %v", err)
	}
	if got == nil {
		t.Fatal("esperava encontrar eth0, veio nil")
	}
	if got.CIDR != "192.168.3.3/24" || got.Gateway != "192.168.3.1" {
		t.Errorf("dados errados: %+v", got)
	}

	// Upsert de novo com dado diferente deve substituir, não duplicar.
	m.Gateway = "192.168.3.254"
	if err := db.UpsertManagedInterface(m); err != nil {
		t.Fatalf("UpsertManagedInterface (update): %v", err)
	}
	all, err := db.ListManagedInterfaces()
	if err != nil {
		t.Fatalf("ListManagedInterfaces: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("esperava 1 interface gerenciada, veio %d", len(all))
	}
	if all[0].Gateway != "192.168.3.254" {
		t.Errorf("esperava gateway atualizado, veio %q", all[0].Gateway)
	}
}

func TestGetManagedInterfaceNotFound(t *testing.T) {
	db := newTestDB(t)
	got, err := db.GetManagedInterface("nao-existe")
	if err != nil {
		t.Fatalf("esperava nil error, veio: %v", err)
	}
	if got != nil {
		t.Errorf("esperava nil, veio %+v", got)
	}
}

func TestPendingInterfaceChangeLifecycle(t *testing.T) {
	db := newTestDB(t)
	deadline := time.Now().Add(90 * time.Second).Unix()
	p := storage.PendingInterfaceChange{
		ID:           "test-id-1",
		Interface:    "eth0",
		OldConfig:    `{"addr_mode":"dhcp"}`,
		OldFiles:     `[{"path":"/etc/systemd/network/10-eth0.network","content":"old"}]`,
		NewConfig:    `{"addr_mode":"static","cidr":"192.168.3.3/24"}`,
		DeadlineUnix: deadline,
	}
	if err := db.CreatePendingInterfaceChange(p); err != nil {
		t.Fatalf("CreatePendingInterfaceChange: %v", err)
	}

	got, err := db.GetPendingInterfaceChange("eth0")
	if err != nil {
		t.Fatalf("GetPendingInterfaceChange: %v", err)
	}
	if got == nil || got.ID != "test-id-1" {
		t.Fatalf("esperava encontrar a mudança pendente, veio %+v", got)
	}

	all, err := db.ListPendingInterfaceChanges()
	if err != nil {
		t.Fatalf("ListPendingInterfaceChanges: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("esperava 1 mudança pendente, veio %d", len(all))
	}

	if err := db.DeletePendingInterfaceChange("eth0"); err != nil {
		t.Fatalf("DeletePendingInterfaceChange: %v", err)
	}
	got, err = db.GetPendingInterfaceChange("eth0")
	if err != nil {
		t.Fatalf("GetPendingInterfaceChange after delete: %v", err)
	}
	if got != nil {
		t.Errorf("esperava nil depois de deletar, veio %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/storage/... -run 'TestManagedInterface|TestPendingInterfaceChange|TestGetManagedInterface' -v`
Expected: FAIL — os tipos e métodos não existem ainda.

- [ ] **Step 3: Add the tables**

Em `internal/storage/storage.go`, adicione duas novas constantes de migração (mesmo padrão de `createDHCPReservationsTable`/`createAIReportsTable` já existentes):

```go
const createManagedInterfacesTable = `
CREATE TABLE IF NOT EXISTS managed_interfaces (
    name        TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    addr_mode   TEXT NOT NULL,
    cidr        TEXT NOT NULL DEFAULT '',
    gateway     TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createPendingInterfaceChangesTable = `
CREATE TABLE IF NOT EXISTS pending_interface_changes (
    id            TEXT PRIMARY KEY,
    interface     TEXT NOT NULL UNIQUE,
    old_config    TEXT NOT NULL,
    old_files     TEXT NOT NULL,
    new_config    TEXT NOT NULL,
    deadline_unix INTEGER NOT NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`
```

No slice `migrations` dentro de `migrate()`, adicione as duas logo após `createDNSBlocklistTable` (ou qualquer ponto — a ordem entre `CREATE TABLE IF NOT EXISTS` não importa, mas mantenha perto de outras tabelas de features para facilitar leitura):

```go
		createDNSBlocklistTable,
		createManagedInterfacesTable,
		createPendingInterfaceChangesTable,
		createAIReportsTable,
```

- [ ] **Step 4: Add the model structs**

Em `internal/storage/models.go`, adicione:

```go
// ─── Managed interface (netif Fase 2) ────────────────────────────────────────

// ManagedInterface is the desired addressing config for one interface the
// admin has explicitly edited and confirmed. Only interfaces present here are
// "Managed" — see internal/netif's Iface.Managed field, which this table backs.
type ManagedInterface struct {
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	AddrMode    string    `json:"addr_mode"`
	CIDR        string    `json:"cidr"`
	Gateway     string    `json:"gateway"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PendingInterfaceChange is an applied-but-not-yet-confirmed interface edit.
// Persisted (not just in memory) so a LinkGuard restart mid-window doesn't
// silently turn an unconfirmed change permanent — see spec 19/07 §6.
type PendingInterfaceChange struct {
	ID           string    `json:"id"`
	Interface    string    `json:"interface"`
	OldConfig    string    `json:"old_config"` // JSON: ManagedInterface before this change (or "" if newly adopted)
	OldFiles     string    `json:"old_files"`  // JSON: []ConfigFileSnapshot to restore on rollback
	NewConfig    string    `json:"new_config"` // JSON: ManagedInterface being applied
	DeadlineUnix int64     `json:"deadline_unix"`
	CreatedAt    time.Time `json:"created_at"`
}
```

- [ ] **Step 5: Add the repository methods**

Em `internal/storage/repository.go`, adicione:

```go
// ─── Managed interfaces ───────────────────────────────────────────────────────

// UpsertManagedInterface creates or updates the desired config for an interface.
func (db *DB) UpsertManagedInterface(m ManagedInterface) error {
	_, err := db.conn.Exec(`
		INSERT INTO managed_interfaces (name, kind, addr_mode, cidr, gateway, description, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			kind = excluded.kind, addr_mode = excluded.addr_mode, cidr = excluded.cidr,
			gateway = excluded.gateway, description = excluded.description, updated_at = excluded.updated_at`,
		m.Name, m.Kind, m.AddrMode, m.CIDR, m.Gateway, m.Description, time.Now())
	return err
}

// GetManagedInterface returns the desired config for one interface, or nil if
// it isn't managed.
func (db *DB) GetManagedInterface(name string) (*ManagedInterface, error) {
	var m ManagedInterface
	err := db.conn.QueryRow(`
		SELECT name, kind, addr_mode, cidr, gateway, description, updated_at
		FROM managed_interfaces WHERE name = ?`, name).
		Scan(&m.Name, &m.Kind, &m.AddrMode, &m.CIDR, &m.Gateway, &m.Description, &m.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListManagedInterfaces returns every interface the admin has adopted.
func (db *DB) ListManagedInterfaces() ([]ManagedInterface, error) {
	rows, err := db.conn.Query(`
		SELECT name, kind, addr_mode, cidr, gateway, description, updated_at
		FROM managed_interfaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ManagedInterface{}
	for rows.Next() {
		var m ManagedInterface
		if err := rows.Scan(&m.Name, &m.Kind, &m.AddrMode, &m.CIDR, &m.Gateway, &m.Description, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ─── Pending interface changes ────────────────────────────────────────────────

// CreatePendingInterfaceChange records an applied-but-unconfirmed change.
// Fails if the interface already has one pending (UNIQUE constraint) — the
// caller (netif.Service) must surface this as "confirm or roll back the
// existing change first."
func (db *DB) CreatePendingInterfaceChange(p PendingInterfaceChange) error {
	_, err := db.conn.Exec(`
		INSERT INTO pending_interface_changes (id, interface, old_config, old_files, new_config, deadline_unix, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Interface, p.OldConfig, p.OldFiles, p.NewConfig, p.DeadlineUnix, time.Now())
	return err
}

// GetPendingInterfaceChange returns the pending change for one interface, or
// nil if there isn't one.
func (db *DB) GetPendingInterfaceChange(iface string) (*PendingInterfaceChange, error) {
	var p PendingInterfaceChange
	err := db.conn.QueryRow(`
		SELECT id, interface, old_config, old_files, new_config, deadline_unix, created_at
		FROM pending_interface_changes WHERE interface = ?`, iface).
		Scan(&p.ID, &p.Interface, &p.OldConfig, &p.OldFiles, &p.NewConfig, &p.DeadlineUnix, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPendingInterfaceChanges returns every pending change — used by the
// expiry sweep and by the frontend's polling endpoint.
func (db *DB) ListPendingInterfaceChanges() ([]PendingInterfaceChange, error) {
	rows, err := db.conn.Query(`
		SELECT id, interface, old_config, old_files, new_config, deadline_unix, created_at
		FROM pending_interface_changes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PendingInterfaceChange{}
	for rows.Next() {
		var p PendingInterfaceChange
		if err := rows.Scan(&p.ID, &p.Interface, &p.OldConfig, &p.OldFiles, &p.NewConfig, &p.DeadlineUnix, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePendingInterfaceChange removes a pending change — called on confirm
// (change accepted) or after a rollback (change undone), either way it's
// resolved.
func (db *DB) DeletePendingInterfaceChange(iface string) error {
	_, err := db.conn.Exec(`DELETE FROM pending_interface_changes WHERE interface = ?`, iface)
	return err
}
```

Confirme que `database/sql` já está importado em `repository.go` (é usado por `sql.ErrNoRows` em métodos vizinhos como `GetAIReport`) — se não estiver, adicione `"database/sql"` ao bloco de import.

- [ ] **Step 6: Run test to verify it passes**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/storage/... -v`
Expected: PASS (todos os testes do pacote)

- [ ] **Step 7: Commit**

```bash
git add internal/storage/storage.go internal/storage/models.go internal/storage/repository.go internal/storage/netif_test.go
git commit -m "feat(storage): tabelas managed_interfaces e pending_interface_changes"
```

---

### Task 3: `internal/netif/networkd` — `Render` (puro)

**Files:**
- Create: `internal/netif/networkd/networkd.go`
- Test: `internal/netif/networkd/networkd_test.go`

**Interfaces:**
- Consumes: `netif.Iface`, `netif.AddrMode`, `netif.AddrModeStatic`/`AddrModeDHCP`/`AddrModeNone` (Fase 1 + Task 1)
- Produces: `type ConfigFile struct{ Path, Content string }`; `func Render(i netif.Iface, dir string) ConfigFile` (`dir=""` uses the package default `/etc/systemd/network`; a non-empty `dir` overrides it — this is how tests and `Service.networkDir` avoid ever touching the real system path)

- [ ] **Step 1: Write the failing test**

Create `internal/netif/networkd/networkd_test.go`:

```go
package networkd

import (
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netif"
)

func TestRenderStaticAddressing(t *testing.T) {
	f := Render(netif.Iface{
		Name: "eth0", Kind: netif.KindPhysical, AddrMode: netif.AddrModeStatic,
		CIDR: "192.168.3.3/24", Gateway: "192.168.3.1",
	}, "")
	if f.Path != "/etc/systemd/network/10-eth0.network" {
		t.Errorf("path errado: %q", f.Path)
	}
	want := "# managed by linkguard\n\n[Match]\nName=eth0\n\n[Network]\nAddress=192.168.3.3/24\nGateway=192.168.3.1\n"
	if f.Content != want {
		t.Errorf("conteúdo errado:\n--- got ---\n%s\n--- want ---\n%s", f.Content, want)
	}
}

func TestRenderStaticNoGateway(t *testing.T) {
	f := Render(netif.Iface{Name: "eth2", Kind: netif.KindPhysical, AddrMode: netif.AddrModeStatic, CIDR: "10.0.0.2/24"}, "")
	if strings.Contains(f.Content, "Gateway=") {
		t.Errorf("não deveria ter linha Gateway= quando Gateway está vazio:\n%s", f.Content)
	}
	if !strings.Contains(f.Content, "Address=10.0.0.2/24") {
		t.Errorf("esperava Address=10.0.0.2/24:\n%s", f.Content)
	}
}

func TestRenderDHCP(t *testing.T) {
	f := Render(netif.Iface{Name: "eth1", Kind: netif.KindPhysical, AddrMode: netif.AddrModeDHCP}, "")
	want := "# managed by linkguard\n\n[Match]\nName=eth1\n\n[Network]\nDHCP=yes\n"
	if f.Content != want {
		t.Errorf("conteúdo errado:\n--- got ---\n%s\n--- want ---\n%s", f.Content, want)
	}
}

func TestRenderNone(t *testing.T) {
	f := Render(netif.Iface{Name: "eth3", Kind: netif.KindPhysical, AddrMode: netif.AddrModeNone}, "")
	want := "# managed by linkguard\n\n[Match]\nName=eth3\n\n[Network]\n"
	if f.Content != want {
		t.Errorf("conteúdo errado:\n--- got ---\n%s\n--- want ---\n%s", f.Content, want)
	}
}

func TestRenderPathUsesPrefix10ForPhysical(t *testing.T) {
	f := Render(netif.Iface{Name: "wlp2s0", Kind: netif.KindPhysical, AddrMode: netif.AddrModeDHCP}, "")
	if f.Path != "/etc/systemd/network/10-wlp2s0.network" {
		t.Errorf("path errado: %q", f.Path)
	}
}

func TestRenderRespectsDirOverride(t *testing.T) {
	f := Render(netif.Iface{Name: "eth0", Kind: netif.KindPhysical, AddrMode: netif.AddrModeDHCP}, "/tmp/some-test-dir")
	if f.Path != "/tmp/some-test-dir/10-eth0.network" {
		t.Errorf("path errado: %q", f.Path)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/networkd/... -v`
Expected: FAIL — o pacote `networkd` não existe ainda.

- [ ] **Step 3: Write Render**

Create `internal/netif/networkd/networkd.go`:

```go
// Package networkd implements the systemd-networkd Provider for netif —
// rendering and applying interface addressing config. Fase 2 only handles
// physical interfaces (prefix "10-"); VLAN ("20-") and bridge ("30-") prefixes
// are reserved for Fase 3, per spec 19/07 §5.3.
package networkd

import (
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/netif"
)

const defaultNetworkDir = "/etc/systemd/network"

// ConfigFile is one rendered systemd-networkd unit file.
type ConfigFile struct {
	Path    string
	Content string
}

// Render produces the .network file for a physical interface. Pure — no I/O,
// safe to call for a preview without touching the system. Every file carries
// the "# managed by linkguard" header (spec 19/07 §5.3) — Apply (Task 4) only
// ever deletes a file that has this exact header, never anything else.
//
// dir overrides the target directory — pass "" in production to use
// defaultNetworkDir ("/etc/systemd/network"); tests pass a t.TempDir() so
// they never touch the real system path. Service (Task 5) is the only
// production caller and always forwards its own configurable networkDir.
func Render(i netif.Iface, dir string) ConfigFile {
	if dir == "" {
		dir = defaultNetworkDir
	}
	var body strings.Builder
	body.WriteString("# managed by linkguard\n\n")
	body.WriteString("[Match]\n")
	fmt.Fprintf(&body, "Name=%s\n\n", i.Name)
	body.WriteString("[Network]\n")

	switch i.AddrMode {
	case netif.AddrModeStatic:
		fmt.Fprintf(&body, "Address=%s\n", i.CIDR)
		if i.Gateway != "" {
			fmt.Fprintf(&body, "Gateway=%s\n", i.Gateway)
		}
	case netif.AddrModeDHCP:
		body.WriteString("DHCP=yes\n")
	case netif.AddrModeNone:
		// Sem Address=/DHCP= — interface sobe sem endereço IP.
	}

	return ConfigFile{
		Path:    fmt.Sprintf("%s/10-%s.network", dir, i.Name),
		Content: body.String(),
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/networkd/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netif/networkd/networkd.go internal/netif/networkd/networkd_test.go
git commit -m "feat(networkd): Render puro de arquivo .network pra interface física"
```

---

### Task 4: `internal/netif/networkd` — `Apply` (escrita atômica + reload)

**Files:**
- Modify: `internal/netif/networkd/networkd.go`
- Modify: `internal/netif/networkd/networkd_test.go`

**Interfaces:**
- Consumes: `ConfigFile`, `firewall.Executor` (`ExecuteRead`/`Execute`/`IsDryRun`, já usado em `internal/netif/service.go`)
- Produces: `func Apply(ctx context.Context, exec firewall.Executor, f ConfigFile) error`

- [ ] **Step 1: Write the failing test**

Adicione a `internal/netif/networkd/networkd_test.go` (mesmo arquivo, mesmo padrão de `fakeExec` já usado em `internal/netif/service_test.go` — mas aqui o teste escreve em disco de verdade, num diretório temporário, então não precisa de um executor falso pra isso — só falso para o `networkctl reload`):

```go
func TestApplyWritesFileAtomicallyAndReloads(t *testing.T) {
	dir := t.TempDir()
	f := ConfigFile{Path: dir + "/10-eth0.network", Content: "# managed by linkguard\n\n[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"}
	exec := &fakeApplyExec{}

	if err := Apply(context.Background(), exec, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatalf("arquivo não foi escrito: %v", err)
	}
	if string(got) != f.Content {
		t.Errorf("conteúdo escrito errado:\ngot:  %q\nwant: %q", got, f.Content)
	}

	if len(exec.reloadCalls) != 1 {
		t.Fatalf("esperava 1 chamada de reload, veio %d: %+v", len(exec.reloadCalls), exec.reloadCalls)
	}

	// Confirma que não sobrou nenhum arquivo temporário no diretório.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("esperava só o arquivo final no diretório, achei %d entradas: %+v", len(entries), entries)
	}
}

func TestApplySkipsWriteInDryRun(t *testing.T) {
	dir := t.TempDir()
	f := ConfigFile{Path: dir + "/10-eth0.network", Content: "conteudo"}
	exec := &fakeApplyExec{dryRun: true}

	if err := Apply(context.Background(), exec, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
		t.Error("em dry-run o arquivo não deveria ter sido escrito")
	}
	if len(exec.reloadCalls) != 0 {
		t.Errorf("em dry-run não deveria chamar reload, chamou %d vezes", len(exec.reloadCalls))
	}
}

type fakeApplyExec struct {
	dryRun      bool
	reloadCalls []string
}

func (e *fakeApplyExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "networkctl" {
		e.reloadCalls = append(e.reloadCalls, strings.Join(args, " "))
		return "", nil
	}
	return "", fmt.Errorf("comando de escrita inesperado no teste: %s", cmd)
}
func (e *fakeApplyExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	return "", fmt.Errorf("comando de leitura inesperado no teste: %s", cmd)
}
func (e *fakeApplyExec) IsDryRun() bool { return e.dryRun }
```

Adicione os imports que faltam no topo do arquivo de teste: `"context"`, `"os"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/networkd/... -run TestApply -v`
Expected: FAIL — `Apply` não existe ainda.

- [ ] **Step 3: Write Apply**

Em `internal/netif/networkd/networkd.go`, adicione os imports `"context"`, `"os"`, `"path/filepath"` e `"github.com/giovanibalarini/linkguard-fw/internal/firewall"`, e a função:

```go
// Apply writes f atomically (temp file in the same directory, then rename —
// atomic because it's the same filesystem, the first such pattern in this
// codebase) and reloads systemd-networkd. A no-op write in dry-run mode,
// matching the convention every other Provider in this codebase follows
// (see internal/keaunbound.ReloadConfigs).
//
// Fase 2 never removes or changes an interface's type, so `networkctl reload`
// always suffices — `reconfigure` (needed when a .netdev is added/removed)
// is deferred to Fase 3.
func Apply(ctx context.Context, exec firewall.Executor, f ConfigFile) error {
	if exec.IsDryRun() {
		return nil
	}
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, ".linkguard-networkd-*.tmp")
	if err != nil {
		return fmt.Errorf("criar arquivo temporário em %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(f.Content); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("escrever conteúdo temporário: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("fechar arquivo temporário: %w", err)
	}
	if err := os.Rename(tmpPath, f.Path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("mover %s para %s: %w", tmpPath, f.Path, err)
	}

	if _, err := exec.Execute(ctx, "networkctl", "reload"); err != nil {
		return fmt.Errorf("networkctl reload: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/networkd/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netif/networkd/networkd.go internal/netif/networkd/networkd_test.go
git commit -m "feat(networkd): Apply com escrita atômica (temp+rename) e networkctl reload"
```

---

### Task 5: `netif.Service` — preview/apply/confirm/rollback + laço de expiração

**Files:**
- Modify: `internal/netif/service.go`
- Modify: `internal/netif/service_test.go`

**Interfaces:**
- Consumes: `networkd.Render`/`Apply`/`ConfigFile` (Task 3-4), `ValidateIface` (Task 1), `storage.ManagedInterface`/`PendingInterfaceChange` + repository methods (Task 2), `alerts.Service` (`Create(alertType, severity, title, message, linkID string) error` — mesma assinatura genérica já usada por `RuleError` em `internal/alerts/service.go`)
- Produces: `func (s *Service) Preview(ctx context.Context, edit IfaceEdit) (PreviewResult, error)`; `func (s *Service) ApplyChange(ctx context.Context, edit IfaceEdit) (PendingChangeView, error)`; `func (s *Service) Confirm(ctx context.Context, name string) error`; `func (s *Service) Rollback(ctx context.Context, name string) error`; `func (s *Service) ListPending(ctx context.Context) ([]PendingChangeView, error)`; `func (s *Service) RunExpirySweep(ctx context.Context, interval time.Duration)`; `type IfaceEdit struct{ Name, AddrMode, CIDR, Gateway, Description string }`; `type PreviewResult struct{ Files []FileDiff; Warnings []string }`; `type FileDiff struct{ Path, OldContent, NewContent string }`; `type PendingChangeView struct{ Interface string; DeadlineUnix int64 }`

- [ ] **Step 1: Write the failing tests**

Em `internal/netif/service_test.go` (mesmo arquivo da Fase 1 — adicione ao final, mantendo o `fakeExec` e `newTestDB` já existentes), adicione:

```go
func TestServicePreviewShowsOldAndNewContent(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	alertSvc := alerts.NewService(db, nil)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alertSvc) // ver Step 3 sobre por que isso é um setter, não um parâmetro do construtor

	result, err := svc.Preview(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "static", CIDR: "192.168.3.9/24"})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(result.Files) != 1 {
		t.Fatalf("esperava 1 arquivo, veio %d", len(result.Files))
	}
	if !strings.Contains(result.Files[0].NewContent, "Address=192.168.3.9/24") {
		t.Errorf("conteúdo novo não tem o endereço esperado: %q", result.Files[0].NewContent)
	}
}

func TestServicePreviewRejectsInvalidEdit(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db, nil))

	_, err := svc.Preview(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "static", CIDR: "não-é-cidr"})
	if err == nil {
		t.Fatal("esperava erro de validação, não teve nenhum")
	}
}

func TestServiceApplyThenConfirmPersistsManagedInterface(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db, nil))
	svc.networkDir = t.TempDir() // ver Step 3 — permite escrever num diretório de teste em vez de /etc/systemd/network

	pending, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "dhcp"})
	if err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	if pending.Interface != "wlp2s0" {
		t.Fatalf("pending errado: %+v", pending)
	}

	// Antes de confirmar, ainda não deveria estar em managed_interfaces.
	if m, _ := db.GetManagedInterface("wlp2s0"); m != nil {
		t.Error("não deveria estar gerenciada antes do confirm")
	}

	if err := svc.Confirm(context.Background(), "wlp2s0"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	m, err := db.GetManagedInterface("wlp2s0")
	if err != nil || m == nil {
		t.Fatalf("esperava wlp2s0 gerenciada após confirm, veio %+v, err=%v", m, err)
	}
	if m.AddrMode != "dhcp" {
		t.Errorf("addr_mode errado: %q", m.AddrMode)
	}

	// Confirmar já deve ter limpado a mudança pendente.
	if p, _ := db.GetPendingInterfaceChange("wlp2s0"); p != nil {
		t.Error("mudança pendente deveria ter sido removida após confirm")
	}
}

func TestServiceRollbackRestoresOldFileAndDoesNotPersist(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db, nil))
	svc.networkDir = t.TempDir()

	if _, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "dhcp"}); err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	if err := svc.Rollback(context.Background(), "wlp2s0"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if m, _ := db.GetManagedInterface("wlp2s0"); m != nil {
		t.Error("não deveria estar gerenciada após rollback")
	}
	if p, _ := db.GetPendingInterfaceChange("wlp2s0"); p != nil {
		t.Error("mudança pendente deveria ter sido removida após rollback")
	}
}

func TestRunExpirySweepAutoRollsBackExpiredChange(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db, nil))
	svc.networkDir = t.TempDir()

	pending, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "dhcp"})
	if err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	// Força a mudança pendente a já estar vencida, sem esperar o deadline real.
	expired := storage.PendingInterfaceChange{
		ID: "forced", Interface: "wlp2s0",
		OldConfig: "", OldFiles: mustMarshalFiles(t, pending), NewConfig: "{}",
		DeadlineUnix: time.Now().Add(-1 * time.Second).Unix(),
	}
	if err := db.DeletePendingInterfaceChange("wlp2s0"); err != nil {
		t.Fatalf("DeletePendingInterfaceChange: %v", err)
	}
	if err := db.CreatePendingInterfaceChange(expired); err != nil {
		t.Fatalf("CreatePendingInterfaceChange: %v", err)
	}

	svc.sweepExpiredOnce(context.Background())

	if p, _ := db.GetPendingInterfaceChange("wlp2s0"); p != nil {
		t.Error("mudança vencida deveria ter sido removida pelo sweep")
	}
	alertsList, err := db.ListAlerts(false)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	found := false
	for _, a := range alertsList {
		if strings.Contains(a.Message, "wlp2s0") {
			found = true
		}
	}
	if !found {
		t.Error("esperava um alerta mencionando wlp2s0 após rollback automático")
	}
}
```

Adicione os imports que faltam ao topo de `service_test.go`: `"strings"`, `"time"`, `"github.com/giovanibalarini/linkguard-fw/internal/alerts"`, `"github.com/giovanibalarini/linkguard-fw/internal/storage"`.

**Correção obrigatória no `fakeExec` já existente (da Fase 1):** o `fakeExec.Execute` atual só reconhece `ethtool -p` (usado pelo "identificar porta" da Fase 1). Esta tarefa faz `ApplyChange`/`Rollback` chamarem `networkd.Apply`, que executa `exec.Execute(ctx, "networkctl", "reload")` — sem tratar esse caso, todo teste desta tarefa que chama `ApplyChange` falha com "unexpected write command in test: networkctl", não porque a lógica está errada, mas porque o dublê de teste não sabe responder. Localize o `fakeExec.Execute` já existente em `service_test.go` (Fase 1) e estenda-o:

```go
func (e *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "ethtool" && len(args) >= 1 && args[0] == "-p" {
		e.identifyCalls = append(e.identifyCalls, args[1])
		return "", nil
	}
	if cmd == "networkctl" && len(args) >= 1 && args[0] == "reload" {
		return "", nil
	}
	return "", errors.New("unexpected write command in test: " + cmd)
}
```

(Adicione só o novo bloco `if cmd == "networkctl" ...` — o resto do método já existe, não recrie o arquivo do zero.)

Verifique a assinatura real de `alerts.NewService` (`grep -n "^func NewService" internal/alerts/service.go`) e de `db.ListAlerts` (`grep -n "^func (db \*DB) ListAlerts" internal/storage/repository.go`) antes de escrever essas chamadas — ajuste os testes acima para bater exatamente com o que existe, não com o que este texto assume.

Adicione também o helper de teste `mustMarshalFiles`:

```go
func mustMarshalFiles(t *testing.T, p PendingChangeView) string {
	t.Helper()
	// PendingChangeView não carrega os arquivos antigos (isso é interno ao
	// Service) — para este teste específico de sweep, um old_files vazio
	// ([]) é suficiente: o que o teste verifica é que o sweep localiza,
	// reverte e remove a mudança vencida, não o conteúdo exato restaurado
	// (isso já está coberto por TestServiceRollbackRestoresOldFileAndDoesNotPersist).
	return "[]"
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -run 'TestServicePreview|TestServiceApplyThenConfirm|TestServiceRollback|TestRunExpirySweep' -v`
Expected: FAIL — os novos métodos/tipos não existem ainda.

- [ ] **Step 3: Extend the Service**

Em `internal/netif/service.go`, adicione os imports `"encoding/json"` (se ainda não importado), `"time"`, `"github.com/google/uuid"` (confirme que já é dependência do projeto — `grep -n uuid go.mod`; se já é usada por `internal/storage` para IDs, é seguro assumir aqui também), `"github.com/giovanibalarini/linkguard-fw/internal/alerts"`, `"github.com/giovanibalarini/linkguard-fw/internal/netif/networkd"`.

Adicione ao struct `Service` dois campos novos:

```go
type Service struct {
	exec       firewall.Executor
	db         *storage.DB
	linkSvc    *links.Service
	alertSvc   *alerts.Service
	networkDir string // sobreposto em teste; produção usa o default do pacote networkd
}
```

`alertSvc` vira um setter, não um parâmetro do construtor (`NewService`), pra não quebrar a assinatura já usada em `cmd/linkguard-fw/main.go` e nos testes da Fase 1 (`NewService(exec, db, linkSvc)`) — quem monta o `Service` de verdade chama `SetAlertService` logo em seguida (Task 6 cuida disso no `main.go`):

```go
// SetAlertService wires the alert sink used when an auto-rollback fires.
// Separate from NewService to avoid changing that constructor's signature
// for the read-only Fase 1 callers/tests that don't need it.
func (s *Service) SetAlertService(a *alerts.Service) {
	s.alertSvc = a
}
```

Adicione os novos tipos e métodos:

```go
// IfaceEdit is the set of fields an admin can change for a physical
// interface in Fase 2 — addressing only.
type IfaceEdit struct {
	Name        string
	AddrMode    string
	CIDR        string
	Gateway     string
	Description string
}

// FileDiff is one config file's before/after content, for the review screen.
type FileDiff struct {
	Path        string `json:"path"`
	OldContent  string `json:"old_content"`
	NewContent  string `json:"new_content"`
}

// PreviewResult is what the review screen shows before applying.
type PreviewResult struct {
	Files    []FileDiff `json:"files"`
	Warnings []string   `json:"warnings"`
}

// PendingChangeView is the API-facing shape of an in-flight, unconfirmed change.
type PendingChangeView struct {
	Interface    string `json:"interface"`
	DeadlineUnix int64  `json:"deadline_unix"`
}

func (e IfaceEdit) toIface() Iface {
	return Iface{
		Name: e.Name, Kind: KindPhysical, AddrMode: AddrMode(e.AddrMode),
		CIDR: e.CIDR, Gateway: e.Gateway, Description: e.Description,
	}
}

// rollbackDeadline is how long an applied-but-unconfirmed change waits before
// auto-reverting — spec 19/07 §6 default.
const rollbackDeadline = 90 * time.Second

// oldFileContent reads the current content of a rendered file, or "" if it
// doesn't exist yet (first-ever edit of that interface).
func (s *Service) oldFileContent(path string) string {
	content, err := s.exec.ExecuteRead(context.Background(), "cat", path)
	if err != nil {
		return ""
	}
	return content
}

// Preview validates the edit and shows what would change, without touching
// the system.
func (s *Service) Preview(ctx context.Context, edit IfaceEdit) (PreviewResult, error) {
	iface := edit.toIface()
	if err := ValidateIface(iface); err != nil {
		return PreviewResult{}, err
	}
	newFile := networkd.Render(iface, s.networkDir)
	old := s.oldFileContent(newFile.Path)

	var warnings []string
	// spec 19/07 §10.4: avisar quando a mudança afeta a interface de acesso atual.
	// A Fase 2 não tem como saber com certeza qual interface o admin está usando
	// agora (isso exigiria inspecionar a conexão HTTP recebida, fora do escopo
	// deste Service) — o aviso genérico abaixo cobre o caso mais comum e barato
	// de detectar: a interface é a WAN configurada.
	views, err := s.List(ctx)
	if err == nil {
		for _, v := range views {
			if v.Name == edit.Name && v.Role == RoleWAN {
				warnings = append(warnings, "Esta é uma interface WAN configurada — uma configuração errada pode derrubar o acesso remoto ao painel.")
			}
		}
	}

	return PreviewResult{
		Files:    []FileDiff{{Path: newFile.Path, OldContent: old, NewContent: newFile.Content}},
		Warnings: warnings,
	}, nil
}

// ApplyChange writes the new config, arms the rollback deadline, and returns
// the pending state. The interface only becomes "Managed" on Confirm.
func (s *Service) ApplyChange(ctx context.Context, edit IfaceEdit) (PendingChangeView, error) {
	iface := edit.toIface()
	if err := ValidateIface(iface); err != nil {
		return PendingChangeView{}, err
	}
	if existing, _ := s.db.GetPendingInterfaceChange(edit.Name); existing != nil {
		return PendingChangeView{}, fmt.Errorf("já existe uma mudança pendente para %s — confirme ou reverta antes de aplicar outra", edit.Name)
	}

	newFile := networkd.Render(iface, s.networkDir)
	oldContent := s.oldFileContent(newFile.Path)
	oldFilesJSON, _ := json.Marshal([]FileDiff{{Path: newFile.Path, OldContent: oldContent}})

	oldManaged, _ := s.db.GetManagedInterface(edit.Name)
	oldConfigJSON := "{}"
	if oldManaged != nil {
		b, _ := json.Marshal(oldManaged)
		oldConfigJSON = string(b)
	}
	newConfigJSON, _ := json.Marshal(storage.ManagedInterface{
		Name: edit.Name, Kind: string(KindPhysical), AddrMode: edit.AddrMode,
		CIDR: edit.CIDR, Gateway: edit.Gateway, Description: edit.Description,
	})

	if err := networkd.Apply(ctx, s.exec, newFile); err != nil {
		return PendingChangeView{}, fmt.Errorf("aplicar configuração: %w", err)
	}

	deadline := time.Now().Add(rollbackDeadline)
	err := s.db.CreatePendingInterfaceChange(storage.PendingInterfaceChange{
		ID: uuid.NewString(), Interface: edit.Name,
		OldConfig: oldConfigJSON, OldFiles: string(oldFilesJSON), NewConfig: string(newConfigJSON),
		DeadlineUnix: deadline.Unix(),
	})
	if err != nil {
		return PendingChangeView{}, fmt.Errorf("registrar mudança pendente: %w", err)
	}
	return PendingChangeView{Interface: edit.Name, DeadlineUnix: deadline.Unix()}, nil
}

// Confirm accepts a pending change: it becomes the interface's managed
// config permanently, and the pending record is cleared.
func (s *Service) Confirm(ctx context.Context, name string) error {
	pending, err := s.db.GetPendingInterfaceChange(name)
	if err != nil {
		return err
	}
	if pending == nil {
		return fmt.Errorf("nenhuma mudança pendente para %s", name)
	}
	var newConfig storage.ManagedInterface
	if err := json.Unmarshal([]byte(pending.NewConfig), &newConfig); err != nil {
		return fmt.Errorf("mudança pendente corrompida: %w", err)
	}
	if err := s.db.UpsertManagedInterface(newConfig); err != nil {
		return err
	}
	return s.db.DeletePendingInterfaceChange(name)
}

// Rollback immediately reverts a pending change (manual — the admin clicked
// "Reverter" instead of waiting out the deadline).
func (s *Service) Rollback(ctx context.Context, name string) error {
	pending, err := s.db.GetPendingInterfaceChange(name)
	if err != nil {
		return err
	}
	if pending == nil {
		return fmt.Errorf("nenhuma mudança pendente para %s", name)
	}
	if err := s.restorePendingFiles(ctx, *pending); err != nil {
		return err
	}
	return s.db.DeletePendingInterfaceChange(name)
}

// restorePendingFiles writes back the pre-change file contents recorded in a
// pending change and reloads networkd.
func (s *Service) restorePendingFiles(ctx context.Context, p storage.PendingInterfaceChange) error {
	var files []FileDiff
	if err := json.Unmarshal([]byte(p.OldFiles), &files); err != nil {
		return fmt.Errorf("snapshot de arquivos corrompido: %w", err)
	}
	for _, f := range files {
		if err := networkd.Apply(ctx, s.exec, networkd.ConfigFile{Path: f.Path, Content: f.OldContent}); err != nil {
			return fmt.Errorf("restaurar %s: %w", f.Path, err)
		}
	}
	return nil
}

// ListPending returns every in-flight unconfirmed change — polled by the frontend.
func (s *Service) ListPending(ctx context.Context) ([]PendingChangeView, error) {
	all, err := s.db.ListPendingInterfaceChanges()
	if err != nil {
		return nil, err
	}
	out := make([]PendingChangeView, 0, len(all))
	for _, p := range all {
		out = append(out, PendingChangeView{Interface: p.Interface, DeadlineUnix: p.DeadlineUnix})
	}
	return out, nil
}

// RunExpirySweep runs sweepExpiredOnce on a ticker until ctx is cancelled.
// Persisted state (not an in-process timer) is what makes the deadline
// survive a LinkGuard restart — see this plan's Global Constraints.
func (s *Service) RunExpirySweep(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepExpiredOnce(ctx)
		}
	}
}

func (s *Service) sweepExpiredOnce(ctx context.Context) {
	all, err := s.db.ListPendingInterfaceChanges()
	if err != nil {
		slog.Error("netif: falha ao listar mudanças pendentes", "err", err)
		return
	}
	now := time.Now().Unix()
	for _, p := range all {
		if p.DeadlineUnix > now {
			continue
		}
		slog.Warn("netif: revertendo mudança automaticamente (sem confirmação)", "interface", p.Interface)
		if err := s.restorePendingFiles(ctx, p); err != nil {
			slog.Error("netif: auto-rollback falhou", "interface", p.Interface, "err", err)
			if s.alertSvc != nil {
				_ = s.alertSvc.Create("interface_rollback_failed", "critical",
					"Reversão automática falhou",
					fmt.Sprintf("Interface %s: a reversão automática da configuração falhou (%v) — verifique manualmente.", p.Interface, err), "")
			}
			continue // não remove o registro pendente se a restauração falhou — não perder o rastro
		}
		if err := s.db.DeletePendingInterfaceChange(p.Interface); err != nil {
			slog.Error("netif: falha ao limpar mudança pendente revertida", "interface", p.Interface, "err", err)
		}
		if s.alertSvc != nil {
			_ = s.alertSvc.Create("interface_rollback", "warning",
				"Configuração de interface revertida automaticamente",
				fmt.Sprintf("Interface %s: a mudança aplicada não foi confirmada em %d segundos e foi revertida.", p.Interface, int(rollbackDeadline.Seconds())), "")
		}
	}
}
```

Verifique a assinatura real de `alerts.Service.Create` (`grep -n "^func (s \*Service) Create" internal/alerts/service.go`) e os nomes de `Type*`/`Severity*` constantes antes de finalizar — o texto acima usa strings literais (`"interface_rollback"`, `"critical"`) como aproximação; se o pacote `alerts` exige usar as constantes tipadas (`alerts.TypeRuleError`, `alerts.SeverityCritical`, etc.) em vez de strings soltas, ajuste as chamadas para usar os tipos corretos — não invente uma segunda convenção de severidade.

Adicione também `List()` (já existente da Fase 1) a mesclar `managed_interfaces` — logo após o laço que aplica Role/Alias em `List`, adicione:

```go
	managed, _ := s.db.ListManagedInterfaces()
	managedByName := make(map[string]storage.ManagedInterface, len(managed))
	for _, m := range managed {
		managedByName[m.Name] = m
	}
	for i := range views {
		if m, ok := managedByName[views[i].Name]; ok {
			views[i].Managed = true
			views[i].AddrMode = AddrMode(m.AddrMode)
			views[i].CIDR = m.CIDR
			views[i].Gateway = m.Gateway
			if m.Description != "" {
				views[i].Description = m.Description
			}
		}
	}
```

(Insira isso logo antes do `return views, nil` final de `List`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -v`
Expected: PASS (todos os testes do pacote)

- [ ] **Step 5: Commit**

```bash
git add internal/netif/service.go internal/netif/service_test.go
git commit -m "feat(netif): Service — preview/apply/confirm/rollback + laço de expiração persistido"
```

---

### Task 6: API — rotas + wiring + laço de expiração no boot

**Files:**
- Modify: `internal/api/handlers/netif.go`
- Modify: `internal/api/server.go`
- Modify: `cmd/linkguard-fw/main.go`

**Interfaces:**
- Consumes: `netif.Service.Preview`/`ApplyChange`/`Confirm`/`Rollback`/`ListPending`/`RunExpirySweep`/`SetAlertService` (Task 5)
- Produces: `PUT /api/interfaces/{name}` (preview — ver nota abaixo sobre o verbo), `POST /api/interfaces/apply`, `POST /api/interfaces/confirm`, `POST /api/interfaces/rollback`, `GET /api/interfaces/pending`

**Nota sobre rotas**: a spec 19/07 §11 lista `POST /api/interfaces/preview` (não `PUT /api/interfaces/{name}`) para o preview — este plano segue a spec literal aqui, não o resumo do adendo. `POST /api/interfaces/rollback` (reversão manual) não está na tabela original da spec 19/07, mas é necessário pela decisão deste plano de reaproveitar a UX do `WanBalancing.tsx`, que tem botão "Reverter" — adição pequena e consistente, sinalizada aqui em vez de silenciosa.

- [ ] **Step 1: Add the handler methods**

Em `internal/api/handlers/netif.go`, adicione ao final do arquivo:

```go
// Preview shows what would change for an edit, without applying it.
func (h *NetifHandler) Preview(w http.ResponseWriter, r *http.Request) {
	var edit netif.IfaceEdit
	if err := decodeJSON(r, &edit); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	result, err := h.svc.Preview(r.Context(), edit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Apply writes the new config and starts the confirm-or-rollback window.
func (h *NetifHandler) Apply(w http.ResponseWriter, r *http.Request) {
	var edit netif.IfaceEdit
	if err := decodeJSON(r, &edit); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	pending, err := h.svc.ApplyChange(r.Context(), edit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "interface.apply", "interface:"+edit.Name, "")
	writeJSON(w, http.StatusOK, pending)
}

// Confirm accepts a pending change.
func (h *NetifHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	if err := h.svc.Confirm(r.Context(), body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "interface.confirm", "interface:"+body.Name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Rollback immediately reverts a pending change.
func (h *NetifHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	if err := h.svc.Rollback(r.Context(), body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "interface.rollback", "interface:"+body.Name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Pending lists every in-flight unconfirmed change.
func (h *NetifHandler) Pending(w http.ResponseWriter, r *http.Request) {
	pending, err := h.svc.ListPending(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pending)
}
```

Confirme a assinatura real de `decodeJSON` (`grep -n "^func decodeJSON" internal/api/handlers/helpers.go`) antes de usar — deve bater com o uso já existente em `hosts.go`/`system.go`.

- [ ] **Step 2: Register the routes**

Em `internal/api/server.go`, no bloco onde as rotas de `/api/interfaces` já existem (perto de `r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces", netifH.List)`), adicione:

```go
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/preview", netifH.Preview)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/apply", netifH.Apply)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/confirm", netifH.Confirm)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/rollback", netifH.Rollback)
		r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces/pending", netifH.Pending)
```

- [ ] **Step 3: Wire the alert service and start the expiry sweep in main.go**

Em `cmd/linkguard-fw/main.go`, logo após a linha `netifSvc := netif.NewService(exec, db, linkSvc)` já existente, adicione:

```go
	netifSvc.SetAlertService(alertSvc)
```

(confirme que `alertSvc` já é o nome da variável do `alerts.Service` construído mais acima no arquivo — `grep -n "alerts.NewService" cmd/linkguard-fw/main.go`.)

Perto de onde outros laços em background já são iniciados com `go ...Run(ctx, ...)` (ex.: o monitor de links, o coletor de métricas — `grep -n "go .*\.Run(ctx" cmd/linkguard-fw/main.go`), adicione:

```go
	go netifSvc.RunExpirySweep(ctx, 10*time.Second)
```

- [ ] **Step 4: Verify**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go build ./... && PATH=/home/gov/sdk/go1.25.0/bin:$PATH go vet ./... && PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./...`
Expected: build limpo, vet limpo, todos os testes passando (incluindo os de outros pacotes — confirma que a assinatura de `netif.NewService` não mudou e nada foi desalinhado).

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/netif.go internal/api/server.go cmd/linkguard-fw/main.go
git commit -m "feat(api): preview/apply/confirm/rollback/pending de interfaces + laço de expiração no boot"
```

---

### Task 7: Frontend — formulário de edição (página inteira)

**Files:**
- Create: `web/src/pages/InterfaceEdit.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/pages/Interfaces.tsx`
- Modify: `web/src/types/index.ts`

**Interfaces:**
- Consumes: `Panel` (sub-projeto 1), `IfaceView` (Fase 1), `POST /api/interfaces/preview` (Task 6)
- Produces: rota `/interfaces/:name/edit`; tipos TS `IfaceEdit`, `PreviewResult`, `FileDiff`

- [ ] **Step 1: Adicionar os tipos TS**

Em `web/src/types/index.ts`, adicione (mesmo padrão de campo já usado pelos tipos de Interfaces da Fase 1):

```ts
export interface IfaceEdit {
  name: string;
  addr_mode: 'static' | 'dhcp' | 'none';
  cidr?: string;
  gateway?: string;
  description?: string;
}

export interface FileDiff {
  path: string;
  old_content: string;
  new_content: string;
}

export interface PreviewResult {
  files: FileDiff[];
  warnings: string[];
}

export interface PendingChange {
  interface: string;
  deadline_unix: number;
}
```

Adicione também `cidr?: string;` e `gateway?: string;` à interface `IfaceView` já existente (logo após `addr_mode`), já que a Fase 2 faz `List()` devolver esses campos quando a interface está gerenciada:

```ts
  addr_mode: IfaceAddrMode;
  cidr?: string;
  gateway?: string;
```

- [ ] **Step 2: Registrar a rota**

Em `web/src/App.tsx`, encontre a linha `<Route path="interfaces" element={<Interfaces />} />` e adicione logo abaixo:

```tsx
          <Route path="interfaces/:name/edit" element={<InterfaceEdit />} />
```

Adicione o import `import InterfaceEdit from './pages/InterfaceEdit';` junto aos outros imports de página.

- [ ] **Step 3: Criar o formulário**

Create `web/src/pages/InterfaceEdit.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import type { IfaceAddrMode, IfaceView, PreviewResult } from '../types';

export default function InterfaceEdit() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const [iface, setIface] = useState<IfaceView | null>(null);
  const [addrMode, setAddrMode] = useState<IfaceAddrMode>('dhcp');
  const [cidr, setCidr] = useState('');
  const [gateway, setGateway] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { data } = await client.get<IfaceView[]>('/api/interfaces');
        const found = data.find((i) => i.name === name);
        if (!alive) return;
        if (!found) {
          setError('Interface não encontrada.');
        } else if (found.kind !== 'physical') {
          setError('Só é possível editar interfaces físicas nesta fase.');
        } else {
          setIface(found);
          setAddrMode(found.addr_mode);
          setCidr(found.cidr ?? '');
          setGateway(found.gateway ?? '');
          setDescription(found.description ?? '');
        }
      } catch {
        if (alive) setError('Falha ao carregar a interface.');
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [name]);

  const handleReview = async () => {
    setSubmitting(true);
    setError('');
    try {
      const { data } = await client.post<PreviewResult>('/api/interfaces/preview', {
        name, addr_mode: addrMode, cidr, gateway, description,
      });
      navigate(`/interfaces/${encodeURIComponent(name ?? '')}/review`, { state: { edit: { name, addr_mode: addrMode, cidr, gateway, description }, preview: data } });
    } catch (e) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg || 'Falha ao gerar a prévia.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) return <div className="p-6 text-gray-500">Carregando...</div>;

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <button onClick={() => navigate('/interfaces')} className="flex items-center gap-2 text-gray-400 hover:text-white text-sm">
        <ArrowLeft className="w-4 h-4" /> Voltar
      </button>

      <div>
        <h1 className="text-xl font-bold text-white">Editar {iface?.alias || name}</h1>
        <p className="text-gray-500 text-sm mt-0.5 font-mono">{name}</p>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{error}</div>
      )}

      {iface && (
        <Panel title="Endereçamento">
          <div className="space-y-4">
            <div>
              <label className="label">Modo</label>
              <select className="input w-full" value={addrMode} onChange={(e) => setAddrMode(e.target.value as IfaceAddrMode)}>
                <option value="dhcp">DHCP</option>
                <option value="static">Estático</option>
                <option value="none">Nenhum</option>
              </select>
            </div>
            {addrMode === 'static' && (
              <>
                <div>
                  <label className="label">Endereço (CIDR)</label>
                  <input className="input w-full font-mono" placeholder="192.168.3.3/24" value={cidr} onChange={(e) => setCidr(e.target.value)} />
                </div>
                <div>
                  <label className="label">Gateway (opcional)</label>
                  <input className="input w-full font-mono" placeholder="192.168.3.1" value={gateway} onChange={(e) => setGateway(e.target.value)} />
                </div>
              </>
            )}
            <div>
              <label className="label">Descrição</label>
              <input className="input w-full" placeholder="ex: patch painel P02, sala dos servidores" value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
          </div>
        </Panel>
      )}

      {iface && (
        <button onClick={handleReview} disabled={submitting} className="btn-primary">
          {submitting ? 'Gerando prévia...' : 'Revisar mudanças'}
        </button>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Verify**

Rode `npm run build` (dentro de `web/`, `source ~/.nvm/nvm.sh && nvm use default` primeiro se precisar). Deve passar sem erro de tipo.

- [ ] **Step 5: Commit**

```bash
git add web/src/pages/InterfaceEdit.tsx web/src/App.tsx web/src/pages/Interfaces.tsx web/src/types/index.ts
git commit -m "feat(web): formulário de edição de interface física (página inteira)"
```

---

### Task 8: Frontend — tela de revisão (diff) + aplicar

**Files:**
- Create: `web/src/pages/InterfaceReview.tsx`
- Modify: `web/src/App.tsx`

**Interfaces:**
- Consumes: `Panel`/`Tag` (sub-projeto 1), `IfaceEdit`/`PreviewResult`/`FileDiff` (Task 7), `POST /api/interfaces/apply` (Task 6)
- Produces: rota `/interfaces/:name/review`

- [ ] **Step 1: Registrar a rota**

Em `web/src/App.tsx`, adicione junto à rota de edição:

```tsx
          <Route path="interfaces/:name/review" element={<InterfaceReview />} />
```

Import: `import InterfaceReview from './pages/InterfaceReview';`

- [ ] **Step 2: Criar a tela**

Create `web/src/pages/InterfaceReview.tsx`:

```tsx
import { useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, AlertTriangle } from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import Tag from '../components/ui/Tag';
import type { IfaceEdit, PreviewResult, PendingChange } from '../types';

interface LocationState {
  edit: IfaceEdit;
  preview: PreviewResult;
}

export default function InterfaceReview() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState | undefined;
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState('');

  if (!state) {
    return (
      <div className="p-6">
        <p className="text-gray-500 text-sm">
          Nada para revisar. <button onClick={() => navigate(`/interfaces/${name}/edit`)} className="text-blue-400 underline">Volte pro formulário</button>.
        </p>
      </div>
    );
  }

  const { edit, preview } = state;

  const handleApply = async () => {
    setApplying(true);
    setError('');
    try {
      const { data } = await client.post<PendingChange>('/api/interfaces/apply', edit);
      navigate('/interfaces', { state: { justApplied: data } });
    } catch (e) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg || 'Falha ao aplicar.');
    } finally {
      setApplying(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <button onClick={() => navigate(`/interfaces/${name}/edit`)} className="flex items-center gap-2 text-gray-400 hover:text-white text-sm">
        <ArrowLeft className="w-4 h-4" /> Voltar pro formulário
      </button>

      <div>
        <h1 className="text-xl font-bold text-white">Revisar mudanças — {name}</h1>
        <p className="text-gray-500 text-sm mt-0.5">Confira o que vai ser escrito antes de aplicar.</p>
      </div>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{error}</div>}

      {preview.warnings.map((w, i) => (
        <div key={i} className="flex items-start gap-3 px-4 py-3 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-300 text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <span>{w}</span>
        </div>
      ))}

      {preview.files.map((f) => (
        <Panel key={f.path} title={f.path}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            <div>
              <div className="text-gray-500 mb-1 uppercase tracking-wide">Antes</div>
              <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 whitespace-pre-wrap text-gray-400 min-h-[4rem]">
                {f.old_content || '(arquivo não existe ainda)'}
              </pre>
            </div>
            <div>
              <div className="text-gray-500 mb-1 uppercase tracking-wide">Depois</div>
              <pre className="bg-gray-950 border border-emerald-800/50 rounded-lg p-3 whitespace-pre-wrap text-emerald-300 min-h-[4rem]">
                {f.new_content}
              </pre>
            </div>
          </div>
        </Panel>
      ))}

      <div className="flex items-center gap-3">
        <button onClick={handleApply} disabled={applying} className="btn-primary">
          {applying ? 'Aplicando...' : 'Aplicar'}
        </button>
        <Tag variant="warn">Vai pedir confirmação em até 90s ou reverte sozinho</Tag>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Verify**

`npm run build` sem erro.

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/InterfaceReview.tsx web/src/App.tsx
git commit -m "feat(web): tela de revisão (diff) antes de aplicar mudança de interface"
```

---

### Task 9: Frontend — banner de commit/confirm (padrão `WanBalancing.tsx`)

**Files:**
- Modify: `web/src/pages/Interfaces.tsx`

**Interfaces:**
- Consumes: `GET /api/interfaces/pending`, `POST /api/interfaces/confirm`, `POST /api/interfaces/rollback` (Task 6), `PendingChange` (Task 7's types); reproduz a mecânica de `web/src/components/WanBalancing.tsx` (contagem regressiva com `setInterval` de 1s, botões confirmar/reverter)

- [ ] **Step 1: Adicionar o polling e o banner**

Em `web/src/pages/Interfaces.tsx`, adicione ao componente `Interfaces` (junto aos outros `useState`):

```tsx
  const [pending, setPending] = useState<PendingChange[]>([]);
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [actioning, setActioning] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const loadPending = async () => {
      try {
        const { data } = await client.get<PendingChange[]>('/api/interfaces/pending');
        if (alive) setPending(data ?? []);
      } catch {
        /* best-effort */
      }
    };
    loadPending();
    const t = setInterval(loadPending, 3000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  const handleConfirm = async (name: string) => {
    setActioning(name);
    try {
      await client.post('/api/interfaces/confirm', { name });
      setPending((prev) => prev.filter((p) => p.interface !== name));
    } finally {
      setActioning(null);
    }
  };

  const handleRollback = async (name: string) => {
    setActioning(name);
    try {
      await client.post('/api/interfaces/rollback', { name });
      setPending((prev) => prev.filter((p) => p.interface !== name));
    } finally {
      setActioning(null);
    }
  };
```

Adicione o import `import type { PendingChange } from '../types';` (junto ao import de `IfaceView` já existente) e `import Tag, { type TagVariant } from '../components/ui/Tag';` se `Tag` ainda não estiver importado neste arquivo (já deve estar, da Fase 1).

Insira o banner logo abaixo do cabeçalho da página (antes das `Tabs`, mesma posição de destaque que `WanBalancing.tsx` usa pro banner de rollback pendente):

```tsx
      {pending.map((p) => {
        const secondsLeft = Math.max(0, p.deadline_unix - now);
        return (
          <div key={p.interface} className="flex items-center gap-4 px-4 py-3 bg-amber-500/10 border border-amber-500/30 rounded-xl">
            <Tag variant="warn" dot>{secondsLeft}s</Tag>
            <div className="flex-1 text-sm text-amber-200">
              <span className="font-medium">{p.interface}</span> foi alterada e aguarda confirmação.
              Verifique se o acesso continua funcionando antes de confirmar. Em caso de dúvida, reverta.
            </div>
            <button
              onClick={() => handleConfirm(p.interface)}
              disabled={actioning === p.interface}
              className="btn-primary text-xs"
            >
              Confirmar
            </button>
            <button
              onClick={() => handleRollback(p.interface)}
              disabled={actioning === p.interface}
              className="btn-secondary text-xs"
            >
              Reverter
            </button>
          </div>
        );
      })}
```

- [ ] **Step 2: Adicionar link "Editar" na árvore/lista para interfaces físicas**

Ainda em `Interfaces.tsx`, na função `renderRow` (aba Visão geral, da Task 9 da Fase 1) e na tabela da aba "Interfaces" (Task 8 da Fase 1), adicione um link "editar" ao lado do botão "identificar" já existente para interfaces físicas:

```tsx
                    {i.kind === 'physical' && (
                      <Link to={`/interfaces/${encodeURIComponent(i.name)}/edit`} className="text-xs text-gray-500 hover:text-gray-300">
                        editar
                      </Link>
                    )}
```

Adicione o import `import { Link } from 'react-router-dom';`.

- [ ] **Step 3: Verify**

`npm run build` sem erro.

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/Interfaces.tsx
git commit -m "feat(web): banner de commit/confirm + link editar (padrão WanBalancing)"
```

---

### Task 10: Verificação visual final (máquina com `systemd-networkd` ativo)

**Files:**
- Nenhum arquivo de produto — só verificação.

**Interfaces:**
- Consumes: build completo do backend (Tasks 1-6) + frontend (Tasks 7-9)

- [ ] **Step 1: Preparar uma máquina de teste com `systemd-networkd` de verdade**

Diferente da verificação da Fase 1 (que rodou contra qualquer máquina, já que era só leitura), esta fase precisa de uma máquina onde `systemd-networkd` esteja **ativo** para provar que `Apply` realmente muda o comportamento da rede — a máquina de desenvolvimento local provavelmente usa NetworkManager, não `networkd`, e a produção ainda está em `ifupdown` (ver Global Constraints). Opções, em ordem de preferência: uma VM/container descartável só para este teste (`systemd-networkd` pode ser habilitado nela sem risco), ou, na ausência de uma, documentar explicitamente que só a metade "arquivo escrito corretamente + commit/confirm funciona" foi verificada, e que o efeito real em rede fica pendente até haver uma máquina assim disponível — não invente um ambiente que não existe.

- [ ] **Step 2: Se uma máquina com `networkd` estiver disponível — build, seed, Playwright**

Mesma técnica das fases anteriores (repo inteiro copiado, build isolado, binário próprio, dados semeados). Cenário mínimo: uma interface física de teste (pode ser uma interface virtual dummy criada só para o teste, `ip link add dummy0 type dummy`, já que o objetivo é provar que o `Apply`+`networkctl reload` tem efeito, não testar hardware real) com `systemd-networkd` gerenciando-a. Edite via UI (DHCP→estático ou vice-versa), confirme que `ip addr show dummy0` reflete a mudança depois do apply, confirme que o banner de commit/confirm aparece e some ao clicar "Confirmar", confirme que **não** confirmar por 90s reverte sozinho (`ip addr show dummy0` volta ao estado anterior) e gera um alerta real em `/alerts`.

- [ ] **Step 3: Verificar sobrevivência a restart (o requisito mais importante desta fase)**

Aplique uma mudança (sem confirmar), então reinicie o processo do LinkGuard (`systemctl restart linkguard-fw` ou equivalente no ambiente de teste) **antes** do deadline expirar. Confirme, via `GET /api/interfaces/pending`, que a mudança pendente ainda aparece depois do restart (prova que está no SQLite, não em memória) e que ela ainda expira/reverte corretamente depois disso — este é o requisito que a spec 19/07 §6 chama explicitamente de não-óbvio e que o mecanismo já existente em `internal/balancer` (só em memória) **não** cumpre.

- [ ] **Step 4: Verificar em produção só o que é seguro verificar lá**

Contra o servidor de produção real (onde `networkd` está inativo): confirme que o formulário de edição, a tela de revisão (diff renderiza corretamente contra o estado real importado), e o botão "Aplicar" funcionam sem erro — os arquivos `.network` devem aparecer em `/etc/systemd/network/` com o conteúdo certo (`cat` remoto via SSH, leitura apenas), e o banner de commit/confirm deve aparecer e funcionar (confirmar/reverter mudam o estado no banco corretamente). **Não** espere nem verifique que a rede de produção realmente mudou de comportamento — isso é exatamente o que Global Constraints já avisa que não vai acontecer até a migração.

- [ ] **Step 5: Corrigir o que for encontrado, limpar, confirmar `git status` limpo**

Mesmo processo já estabelecido nas fases anteriores.

- [ ] **Step 6: Commit (só se a verificação exigiu correções)**

---

## Auto-revisão do plano

**Cobertura do spec (Fase 2, spec 19/07 §14 linha 2 + adendo `2026-07-28-interfaces-fase2-design-system.md`):** modelo estendido (Task 1) · `Provider` systemd-networkd Render/Apply (Tasks 3-4) · commit/confirm persistido sobrevivendo a restart (Tasks 2, 5) · preview de diff (Tasks 5, 8) · edição de interface física (Tasks 7-9) · alertas em rollback automático (Task 5) · reuso da UX do `WanBalancing.tsx` (Task 9) · verificação com efeito real comprovado numa máquina com `networkd` (Task 10).

**Desvios documentados do texto literal da spec 19/07, sinalizados nas Global Constraints e nas notas de tarefa** (não silenciosos): laço de expiração persistido em vez do padrão em-memória do `internal/balancer` existente; `POST /api/interfaces/rollback` adicionado (não estava na tabela original de rotas da spec) pra bater com a UX reaproveitada; "Adotar" virou implícito no primeiro apply+confirm em vez de um passo separado; camada de teste em network namespace privilegiado (spec §13) fica fora deste primeiro corte, registrada como débito técnico.

**Placeholders:** nenhum "TBD" — todo passo tem código completo. Onde o plano pede uma verificação de assinatura real antes de prosseguir (Task 5's `alerts.Create`, Task 6's `decodeJSON`/variável `alertSvc`), é checagem de integração de baixo risco, não lacuna de especificação — mesmo padrão já usado nos planos anteriores desta série.

**Consistência de tipos:** `IfaceEdit`/`PreviewResult`/`FileDiff`/`PendingChangeView` (Go, Task 5) espelham `IfaceEdit`/`PreviewResult`/`FileDiff`/`PendingChange` (TS, Tasks 7-9) campo a campo. `networkd.ConfigFile{Path,Content}` (Task 3) é consumido por `Service.ApplyChange`/`restorePendingFiles` (Task 5) sem redefinição paralela.
