# Reconciliação no boot + vigias de deriva Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fazer o LinkGuard reconciliar em todo boot o estado que ele aplica (regra de NAT, `resolv.conf`) a partir da fonte de verdade, e vigiar no painel quando o aplicado divergir da realidade viva — incluindo atualizações de pacote pendentes — para que o operador descubra problemas olhando o painel, não o SSH.

**Architecture:** Duas frentes complementares. **Ação:** `nftables.Service.ReconcileMasquerade` roda em todo boot e em toda mutação de Link (hoje `EnsureTable` só cria a tabela na primeira vez e nunca mais reconcilia); `keaunbound.Service.EnsureResolvConf` fixa `nameserver 127.0.0.1` e ensina o `dhclient` a não sobrescrever. **Visibilidade:** quatro health-checks novos em `internal/monitoring` (`firewall-nat`, `wan-interface`, `dns-resolver`, `system-updates`) comparam aplicado vs realidade e acendem no painel + alertam, seguindo o padrão `observe`/`ensureMeta`/par-de-alertas já existente.

**Tech Stack:** Go 1.25 (backend), React/TypeScript + Vite (frontend), nftables, apt (somente leitura), SQLite via `internal/storage`.

## Global Constraints

- **Nunca** rodar `apt-get update`/`install`/`upgrade` a partir do processo do LinkGuard — só leitura do cache já mantido pelo `apt-daily.timer` do Debian (mesma decisão já documentada em `timesync.EnsureEnabled` sobre gerenciador de pacotes dentro de serviço de longa duração).
- Todo comando `apt` roda com `LC_ALL=C` — verificado ao vivo na produção: sem isso a saída vem traduzida (`atualizável de:` em vez de `upgradable from:`) e o parser quebra silenciosamente.
- Usar `dist-upgrade` (não `upgrade`) para enumerar pendências — verificado ao vivo: `apt-get --just-print upgrade` retorna **zero** para o security-update de kernel pendente na produção, enquanto `dist-upgrade` retorna as duas linhas corretas.
- `ReconcileMasquerade` faz `flush chain inet linkguard postrouting` antes de escrever — **nunca** `nft -f` sobre o arquivo inteiro (verificado ao vivo: `nft -f` soma regras em vez de substituir, foi o que criou a regra duplicada em produção).
- `ReconcileMasquerade` **nunca** faz flush da tabela inteira — `host_wan`, `blocklist`, `blocked_hosts`, `user_rules` e `prerouting_dnat` não podem ser tocados.
- Nomes de interface sempre validados por `reIface` antes de entrar em texto passado ao `nft` (anti-injeção, padrão já existente no pacote).
- Nenhum dado falso no painel: quando a informação necessária para um check não está disponível, o item reporta problema/desconhecido — nunca "ok" otimista.
- TDD real no backend: teste que falha primeiro, depois a implementação mínima.
- Fakes de teste dedicados por comando; não reaproveitar `fakeNftExec` genérico (lição desta sessão: parsers quebram com `""`).

---

### Task 1: `ReconcileMasquerade` em `internal/nftables`

**Files:**
- Create: `internal/nftables/reconcile.go`
- Create: `internal/nftables/reconcile_test.go`

**Interfaces:**
- Consumes: `Service`/`s.exec` (já existentes, `internal/nftables/service.go`); `Family`/`Table` consts (`service.go:21-22`); `reIface` (`service.go:471`); `sanitizeInterfaces` (`internal/nftables/bootstrap.go`); `Service.Persist(ctx) error` (`service.go:201`).
- Produces: `func (s *Service) ReconcileMasquerade(ctx context.Context, wanInterfaces []string) error` — usado pela Task 2 (wiring) e pela Task 5 (health-check compara contra o mesmo conjunto).

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/nftables/reconcile_test.go`:

```go
package nftables

import (
	"context"
	"strings"
	"testing"
)

// fakeReconcileExec records every command so the test can assert the exact
// nft invocations. Dedicated to this file: the package's other fakes answer
// different command shapes, and reusing a generic one would hide which nft
// subcommand actually ran — the whole point of these assertions.
type fakeReconcileExec struct {
	dryRun   bool
	executed []string
	execErr  error
}

func (e *fakeReconcileExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.executed = append(e.executed, strings.Join(append([]string{cmd}, args...), " "))
	return "", e.execErr
}
func (e *fakeReconcileExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	return "", nil
}
func (e *fakeReconcileExec) IsDryRun() bool { return e.dryRun }

func ranCommand(executed []string, want string) bool {
	for _, c := range executed {
		if c == want {
			return true
		}
	}
	return false
}

// TestReconcileMasqueradeFlushesBeforeAdding is the regression test for the
// real production bug this feature exists to fix: `nft -f` on the persisted
// ruleset ADDS rules instead of replacing them, so a stale masquerade line
// referencing a renamed interface (enp4s0 after the NIC became enp5s0)
// survived alongside the new one. Reconciliation must flush the chain first
// so the result is exactly one masquerade rule matching current reality.
func TestReconcileMasqueradeFlushesBeforeAdding(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0", "enp5s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}

	wantFlush := "nft flush chain inet linkguard postrouting"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("missing %q; ran: %v", wantFlush, exec.executed)
	}
	wantAdd := `nft add rule inet linkguard postrouting oifname { "enp2s0", "enp5s0" } masquerade`
	if !ranCommand(exec.executed, wantAdd) {
		t.Errorf("missing %q; ran: %v", wantAdd, exec.executed)
	}
	// Order matters: flushing after adding would wipe the new rule.
	flushIdx, addIdx := -1, -1
	for i, c := range exec.executed {
		if c == wantFlush {
			flushIdx = i
		}
		if c == wantAdd {
			addIdx = i
		}
	}
	if flushIdx > addIdx {
		t.Errorf("flush ran after add (would erase the new rule); ran: %v", exec.executed)
	}
}

// TestReconcileMasqueradeNeverFlushesTheWholeTable guards the elements that
// live in the same table but must survive: host_wan, blocklist,
// blocked_hosts, user_rules and prerouting_dnat.
func TestReconcileMasqueradeNeverFlushesTheWholeTable(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush table") || strings.Contains(c, "flush ruleset") {
			t.Errorf("must never flush the table/ruleset (would drop host_wan/blocklist/user_rules), ran: %q", c)
		}
	}
}

func TestReconcileMasqueradeIsIdempotent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	exec.executed = nil
	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first) != len(exec.executed) {
		t.Errorf("second run issued a different command set:\nfirst=%v\nsecond=%v", first, exec.executed)
	}
}

// TestReconcileMasqueradeSanitizesInterfaces: an invalid name must never be
// interpolated into text handed to `nft` (command injection guard, same
// rule the bootstrap path already applies).
func TestReconcileMasqueradeSanitizesInterfaces(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0", "evil; rm -rf /"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "evil") || strings.Contains(c, "rm -rf") {
			t.Errorf("invalid interface reached the nft command: %q", c)
		}
	}
}

// TestReconcileMasqueradeWithNoWANsLeavesChainEmpty: with zero configured
// WANs there is nothing legitimate to masquerade on; the chain is flushed
// and left empty rather than getting a malformed empty-set rule.
func TestReconcileMasqueradeWithNoWANsLeavesChainEmpty(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), nil); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	if !ranCommand(exec.executed, "nft flush chain inet linkguard postrouting") {
		t.Errorf("expected the chain to still be flushed; ran: %v", exec.executed)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "masquerade") {
			t.Errorf("expected no masquerade rule with zero WANs, ran: %q", c)
		}
	}
}

func TestReconcileMasqueradeNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade in dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands in dry-run, ran: %v", exec.executed)
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
cd /home/gov/Documentos/Projetos/gbtech/repos/linkguard-fw
export PATH=$HOME/sdk/go1.25.0/bin:$PATH
go test ./internal/nftables/... -run TestReconcileMasquerade -v
```

Esperado: `FAIL` — `undefined: (*Service).ReconcileMasquerade`.

- [ ] **Step 3: Implementar**

Criar `internal/nftables/reconcile.go`:

```go
package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// masqueradeChain is the chain whose sole content is the WAN masquerade
// rule (verified against the live production ruleset: nothing else is ever
// written there — port forwards live in prerouting_dnat, filtering in
// forward/user_rules). That is what makes flush-then-rewrite safe here.
const masqueradeChain = "postrouting"

// ReconcileMasquerade re-derives the WAN masquerade (NAT) rule from the
// currently configured WAN interfaces, on every boot and on every link
// mutation — not just once at bootstrap.
//
// Why this exists: EnsureTable only creates `table inet linkguard` when it
// is missing, so on an already-provisioned box it is a no-op and the
// masquerade rule keeps whatever interface names it was born with. In
// production on 2026-08-10 a NIC was renamed by a PCI reshuffle
// (enp4s0 -> enp5s0) and the stale rule silently stopped matching, taking
// WAN1's NAT down until an operator added an iptables rule by hand.
//
// It flushes the chain before writing because `nft -f` (and `nft add`)
// ACCUMULATE rules rather than replacing them — the same production ruleset
// ended up with two masquerade lines, one of them referencing an interface
// that no longer existed. Flushing only this chain (never the table or the
// ruleset) keeps host_wan / blocklist / blocked_hosts / user_rules /
// prerouting_dnat untouched.
//
// Idempotent by construction: the same WAN set always yields the same two
// commands and the same final chain contents. A no-op in dry-run mode, same
// convention as the rest of the package.
func (s *Service) ReconcileMasquerade(ctx context.Context, wanInterfaces []string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	ifaces := sanitizeInterfaces(wanInterfaces)

	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, Table, masqueradeChain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", masqueradeChain, err)
	}
	if len(ifaces) == 0 {
		// No configured WANs: an empty chain is the correct end state — an
		// `oifname { }` rule would be malformed, and masquerading everything
		// would be worse than masquerading nothing.
		slog.Warn("nenhuma interface WAN válida configurada; regra de NAT ficou vazia", "requested", wanInterfaces)
		return nil
	}

	quoted := make([]string, len(ifaces))
	for i, iface := range ifaces {
		quoted[i] = fmt.Sprintf("%q", iface)
	}
	set := fmt.Sprintf("{ %s }", strings.Join(quoted, ", "))
	if _, err := s.exec.Execute(ctx, "nft", "add", "rule", Family, Table, masqueradeChain,
		"oifname", set, "masquerade"); err != nil {
		return fmt.Errorf("aplicar regra de masquerade: %w", err)
	}

	slog.Info("regra de NAT reconciliada a partir das WANs configuradas", "interfaces", ifaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("regra de NAT reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/nftables/
go test ./internal/nftables/... -v
```

Esperado: `gofmt -l` sem saída; `PASS` em tudo (novos e pré-existentes).

- [ ] **Step 5: Commit**

```bash
git add internal/nftables/reconcile.go internal/nftables/reconcile_test.go
git commit -m "feat(nftables): reconcile the WAN masquerade rule from configured links"
```

---

### Task 2: Ligar a reconciliação ao boot e às mutações de Link

**Files:**
- Modify: `cmd/linkguard-fw/main.go`
- Modify: `internal/api/handlers/links.go`
- Modify: `internal/api/server.go:183`
- Create: `internal/api/handlers/links_reconcile_test.go`

**Interfaces:**
- Consumes: `nftables.Service.ReconcileMasquerade` (Task 1); `db.GetLinks() ([]storage.Link, error)` (`internal/storage/repository.go:15`); `linkSvc.List()` (já existente).
- Produces: reconciliação disparada no boot e em create/update/delete/auto-detect de Link.

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/api/handlers/links_reconcile_test.go`:

```go
package handlers

import (
	"context"
	"strings"
	"testing"
)

// reconcileSpyExec records nft invocations so the test can prove a link
// mutation actually re-applied the NAT rule.
type reconcileSpyExec struct{ executed []string }

func (e *reconcileSpyExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.executed = append(e.executed, strings.Join(append([]string{cmd}, args...), " "))
	return "", nil
}
func (e *reconcileSpyExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	return "", nil
}
func (e *reconcileSpyExec) IsDryRun() bool { return false }

func (e *reconcileSpyExec) sawMasqueradeFor(iface string) bool {
	for _, c := range e.executed {
		if strings.Contains(c, "masquerade") && strings.Contains(c, iface) {
			return true
		}
	}
	return false
}

// TestReconcileNATAfterLinkChangeUsesCurrentInterfaces is the regression
// test for the second half of the 2026-08-10 gap: even with boot-time
// reconciliation, editing a link's interface in the UI left the firewall's
// NAT rule pointing at the old one, because nothing in the link mutation
// path ever touched nftables.
func TestReconcileNATAfterLinkChangeUsesCurrentInterfaces(t *testing.T) {
	db := newTestDB(t)
	if err := db.CreateLink(&storage.Link{ID: "l1", Name: "WAN1", Interface: "enp5s0", Weight: 1, Enabled: true}); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	exec := &reconcileSpyExec{}
	h := &LinksHandler{db: db, nftSvc: nftables.NewService(exec)}

	h.reconcileNAT(context.Background())

	if !exec.sawMasqueradeFor("enp5s0") {
		t.Errorf("expected the NAT rule to be rebuilt with enp5s0; ran: %v", exec.executed)
	}
}

// TestReconcileNATSkipsDisabledLinks: a disabled link is not a live WAN and
// must not appear in the masquerade set.
func TestReconcileNATSkipsDisabledLinks(t *testing.T) {
	db := newTestDB(t)
	if err := db.CreateLink(&storage.Link{ID: "l1", Name: "WAN1", Interface: "enp5s0", Weight: 1, Enabled: true}); err != nil {
		t.Fatalf("seed enabled: %v", err)
	}
	if err := db.CreateLink(&storage.Link{ID: "l2", Name: "WAN2", Interface: "enp9s0", Weight: 1, Enabled: false}); err != nil {
		t.Fatalf("seed disabled: %v", err)
	}
	exec := &reconcileSpyExec{}
	h := &LinksHandler{db: db, nftSvc: nftables.NewService(exec)}

	h.reconcileNAT(context.Background())

	if !exec.sawMasqueradeFor("enp5s0") {
		t.Errorf("enabled link missing from the NAT rule; ran: %v", exec.executed)
	}
	if exec.sawMasqueradeFor("enp9s0") {
		t.Errorf("disabled link must not be masqueraded; ran: %v", exec.executed)
	}
}
```

Adicionar ao bloco de import do arquivo, além de `context`/`strings`/`testing`:

```go
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
```

O helper `newTestDB(t)` já existe no pacote de teste `handlers` — confirmar o nome real antes de usar (`grep -rn "func newTestDB" internal/api/handlers/`); se não existir, criar com o mesmo padrão de `netsvc_lastapply_test.go`:

```go
func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/api/handlers/... -run TestReconcileNAT -v
```

Esperado: `FAIL` — `LinksHandler` não tem campo `nftSvc` nem método `reconcileNAT`.

- [ ] **Step 3: Implementar**

Em `internal/api/handlers/links.go`, trocar a struct e o construtor:

```go
type LinksHandler struct {
	svc    *links.Service
	db     *storage.DB
	nftSvc *nftables.Service
}

// NewLinksHandler creates the handler. nftSvc is needed because changing a
// link's interface must also rebuild the firewall's NAT rule — before
// 2026-08-10 nothing did, so an edited link left the masquerade rule
// pointing at the previous interface.
func NewLinksHandler(svc *links.Service, db *storage.DB, nftSvc *nftables.Service) *LinksHandler {
	return &LinksHandler{svc: svc, db: db, nftSvc: nftSvc}
}

// reconcileNAT rebuilds the masquerade rule from the currently enabled WAN
// links. Best-effort: a failure here is logged (and surfaced by the
// firewall-nat health check) but never fails the link operation the admin
// just performed.
func (h *LinksHandler) reconcileNAT(ctx context.Context) {
	if h.nftSvc == nil {
		return
	}
	ls, err := h.db.GetLinks()
	if err != nil {
		slog.Warn("não foi possível carregar links para reconciliar a regra de NAT", "err", err)
		return
	}
	ifaces := make([]string, 0, len(ls))
	for _, l := range ls {
		if l.Enabled && l.Interface != "" {
			ifaces = append(ifaces, l.Interface)
		}
	}
	if err := h.nftSvc.ReconcileMasquerade(ctx, ifaces); err != nil {
		slog.Warn("não foi possível reconciliar a regra de NAT após mudança de link", "err", err)
	}
}
```

Adicionar `"context"`, `"log/slog"` e `"github.com/giovanibalarini/linkguard-fw/internal/nftables"` ao bloco de import se ainda não estiverem.

Em seguida, chamar `h.reconcileNAT(r.Context())` imediatamente antes do `writeJSON` de sucesso em **cada** handler mutante de link deste arquivo: `Create`, `Update`, `Delete` e o de auto-detecção (`AutoDetect`, o que chama `h.svc.DiscoverAndSyncWANLinks()` na linha ~101). Ler o arquivo e adicionar em cada um — não presumir os nomes sem conferir.

Em `internal/api/server.go:183`, passar o serviço:

```go
		linksH := handlers.NewLinksHandler(s.linkSvc, s.db, s.nftSvc)
```

Em `cmd/linkguard-fw/main.go`, no bloco de bootstrap do nftables (por volta da linha 246-268), adicionar a reconciliação **depois** do bloco `if nftSvc.EnsureTable(...) { ... }`, dentro do mesmo `else` que já carregou `configuredLinks`:

```go
		// Reconcile the masquerade rule on EVERY boot, not just when the table
		// had to be created. EnsureTable is a no-op on an already-provisioned
		// box, so before this the NAT rule kept whatever interface names it was
		// born with — in production a renamed NIC (enp4s0 -> enp5s0) silently
		// took WAN1's NAT down until an operator intervened by hand.
		enabledWANs := make([]string, 0, len(configuredLinks))
		for _, l := range configuredLinks {
			if l.Enabled && l.Interface != "" {
				enabledWANs = append(enabledWANs, l.Interface)
			}
		}
		if err := nftSvc.ReconcileMasquerade(ctx, enabledWANs); err != nil {
			slog.Warn("não foi possível reconciliar a regra de NAT no boot", "err", err)
		}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/api/handlers/ internal/api/ cmd/
go test ./internal/api/... -v
go build ./...
go vet ./...
```

Esperado: `PASS` em tudo; build e vet limpos.

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/links.go internal/api/handlers/links_reconcile_test.go internal/api/server.go cmd/linkguard-fw/main.go
git commit -m "feat(links): rebuild the NAT rule on boot and on every link change"
```

---

### Task 3: `EnsureResolvConf` — LinkGuard vira dono do resolver

**Files:**
- Modify: `internal/keaunbound/keaunbound.go`
- Modify: `internal/keaunbound/keaunbound_test.go`
- Modify: `cmd/linkguard-fw/main.go`
- Modify: `deploy/linkguard-fw.service`

**Interfaces:**
- Consumes: `keaunbound.Service`/`s.exec` (já existentes); `NewService(exec)` (`keaunbound.go:43`).
- Produces: `func (s *Service) EnsureResolvConf()` — chamado no startup, junto de `EnsureKeaDirReadable`.

- [ ] **Step 1: Escrever o teste que falha**

Adicionar ao final de `internal/keaunbound/keaunbound_test.go`:

```go
// TestEnsureResolvConfPointsAtLocalUnbound is the regression test for a real
// production finding on 2026-08-10: /etc/resolv.conf pointed at the ISP's
// nameservers instead of the local unbound. Nothing in the codebase managed
// that file at all — the WAN's dhclient rewrites it on every lease renewal —
// so the appliance silently stopped using its own resolver (losing the DNS
// blocklist and query visibility that unbound provides).
func TestEnsureResolvConfPointsAtLocalUnbound(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver 189.40.0.1\nnameserver 189.40.0.2\n"), 0o644); err != nil {
		t.Fatalf("seed resolv.conf: %v", err)
	}
	s := NewService(&recExec{})
	s.resolvConf = resolv
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")

	s.EnsureResolvConf()

	got, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "nameserver 127.0.0.1") {
		t.Errorf("resolv.conf does not point at the local resolver:\n%s", got)
	}
	if strings.Contains(string(got), "189.40.0.1") {
		t.Errorf("ISP nameserver survived:\n%s", got)
	}
	if !strings.Contains(string(got), "# managed by linkguard") {
		t.Errorf("missing the managed-by header:\n%s", got)
	}
}

// TestEnsureResolvConfSupersedesDhclient: rewriting resolv.conf alone is not
// enough — the next DHCP lease renewal would overwrite it again. The fix has
// to tell dhclient itself to stop proposing the ISP's servers.
func TestEnsureResolvConfSupersedesDhclient(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	if err := os.WriteFile(dhclient, []byte("send host-name = gethostname();\n"), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf()

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("dhclient.conf missing the supersede directive:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

// TestEnsureResolvConfDoesNotDuplicateSupersede: it runs on every boot, so a
// second run must not keep appending the same line.
func TestEnsureResolvConfDoesNotDuplicateSupersede(t *testing.T) {
	dir := t.TempDir()
	s := NewService(&recExec{})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")

	s.EnsureResolvConf()
	s.EnsureResolvConf()

	got, err := os.ReadFile(s.dhclientConf)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := strings.Count(string(got), "supersede domain-name-servers"); n != 1 {
		t.Errorf("supersede directive appears %d times, want 1:\n%s", n, got)
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/keaunbound/... -run TestEnsureResolvConf -v
```

Esperado: `FAIL` — `s.resolvConf`/`s.dhclientConf` e `EnsureResolvConf` não existem.

- [ ] **Step 3: Implementar**

Em `internal/keaunbound/keaunbound.go`, adicionar às constantes existentes (bloco `const` da linha 23):

```go
	ResolvConfPath   = "/etc/resolv.conf"
	DhclientConfPath = "/etc/dhcp/dhclient.conf"
```

Adicionar os dois campos à struct `Service` e ao `NewService`:

```go
type Service struct {
	exec         firewall.Executor
	keaConf      string
	unboundConf  string
	keaBin       string
	resolvConf   string
	dhclientConf string
}

func NewService(exec firewall.Executor) *Service {
	return &Service{
		exec:         exec,
		keaConf:      KeaConfPath,
		unboundConf:  UnboundConfPath,
		keaBin:       keaBinDefault,
		resolvConf:   ResolvConfPath,
		dhclientConf: DhclientConfPath,
	}
}
```

Adicionar o método, logo depois de `EnsureKeaDirReadable`:

```go
// EnsureResolvConf makes the box actually use its own resolver (unbound on
// 127.0.0.1) instead of whatever nameservers the WAN's DHCP lease proposes.
//
// Found in production on 2026-08-10: /etc/resolv.conf pointed at the ISP,
// and nothing in this codebase managed that file — so the appliance was
// silently bypassing its own DNS, losing the blocklist and the query
// visibility unbound provides. Rewriting resolv.conf alone would not hold:
// dhclient rewrites it on every lease renewal, which is why this also adds
// a `supersede domain-name-servers` directive so dhclient stops proposing
// the ISP's servers in the first place (working with dhclient rather than
// fighting it).
//
// Self-heals on every start, like the other Ensure* calls. Best-effort: a
// failure is logged and surfaced by the dns-resolver health check rather
// than blocking startup.
func (s *Service) EnsureResolvConf() {
	const body = "# managed by linkguard\nnameserver 127.0.0.1\n"
	if err := os.WriteFile(s.resolvConf, []byte(body), 0o644); err != nil {
		slog.Warn("não foi possível apontar o resolv.conf para o resolver local", "path", s.resolvConf, "err", err)
	} else {
		slog.Info("resolv.conf apontando para o resolver local (unbound)", "path", s.resolvConf)
	}

	const directive = "supersede domain-name-servers 127.0.0.1;"
	current, err := os.ReadFile(s.dhclientConf)
	if err != nil && !os.IsNotExist(err) {
		slog.Warn("não foi possível ler a config do dhclient; o DNS do provedor pode voltar na renovação do lease", "path", s.dhclientConf, "err", err)
		return
	}
	if strings.Contains(string(current), directive) {
		return // already in place — this runs on every boot
	}
	updated := string(current)
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += "\n# managed by linkguard — mantém o resolver local mesmo após renovação de lease\n" + directive + "\n"
	if err := os.WriteFile(s.dhclientConf, []byte(updated), 0o644); err != nil {
		slog.Warn("não foi possível fixar o DNS local na config do dhclient", "path", s.dhclientConf, "err", err)
	}
}
```

Adicionar `"strings"` ao bloco de import se ainda não estiver (`os`, `log/slog` já estão).

Em `cmd/linkguard-fw/main.go`, ao lado da chamada existente `keaSvc.EnsureKeaDirReadable()` (por volta da linha 280):

```go
	keaSvc.EnsureResolvConf()
```

Em `deploy/linkguard-fw.service`, atualizar a linha `ReadWritePaths=` e seu comentário:

```
# Writable paths so the app can persist generated configs: nftables (firewall),
# Kea (DHCP), unbound (DNS), the conntrack-accounting sysctl drop-in, the
# stable-interface-name .link files, the NTP (chrony) drop-in, and the
# resolver/dhclient files that keep DNS pointed at the local unbound.
ReadWritePaths=/var/lib/linkguard-fw /etc/linkguard-fw /etc/nftables.conf /etc/kea /etc/unbound /etc/sysctl.d /etc/systemd/network /etc/chrony/conf.d /etc/resolv.conf /etc/dhcp
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/keaunbound/ cmd/
go test ./internal/keaunbound/... -v
go build ./...
go vet ./...
```

Esperado: `PASS` em tudo, build e vet limpos.

- [ ] **Step 5: Commit**

```bash
git add internal/keaunbound/keaunbound.go internal/keaunbound/keaunbound_test.go cmd/linkguard-fw/main.go deploy/linkguard-fw.service
git commit -m "feat(dns): own /etc/resolv.conf so the box always uses the local resolver"
```

---

### Task 4: `internal/sysupdates` — pacotes pendentes de atualização

**Files:**
- Create: `internal/sysupdates/sysupdates.go`
- Create: `internal/sysupdates/sysupdates_test.go`

**Interfaces:**
- Consumes: `firewall.Executor` (já existente).
- Produces: `type Package struct{ Name, CurrentVersion, NewVersion, Origin string; Security bool }`; `type Report struct{ Total, Security int; Packages []Package }`; `func Check(ctx context.Context, exec firewall.Executor) (Report, error)`; `func parseAptOutput(out string) Report` — usados pela Task 5 (health-check) e Task 6 (endpoint da lista).

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/sysupdates/sysupdates_test.go`:

```go
package sysupdates

import (
	"context"
	"strings"
	"testing"
)

// fakeExec answers the one command this package runs. Dedicated to this
// package on purpose: a generic fake that returns "" for everything would
// make "no updates" and "apt failed" indistinguishable, which is exactly
// the distinction these tests exist to protect.
type fakeExec struct {
	out     string
	err     error
	lastCmd string
}

func (e *fakeExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	e.lastCmd = strings.Join(append([]string{cmd}, args...), " ")
	return e.out, e.err
}
func (e *fakeExec) IsDryRun() bool { return false }

// realProductionSample is the verbatim output captured from the production
// firewall on 2026-08-10, which had a pending kernel SECURITY update. Using
// the real bytes (not an invented string) is deliberate: two separate
// production-only parsing traps were found this way — see the assertions in
// TestCheckForcesCLocaleAndDistUpgrade.
const realProductionSample = `Inst linux-image-6.12.101+deb13-amd64 (6.12.101-1 Debian-Security:13/stable-security [amd64])
Inst linux-image-amd64 [6.12.94-1] (6.12.101-1 Debian-Security:13/stable-security [amd64])
Conf linux-image-6.12.101+deb13-amd64 (6.12.101-1 Debian-Security:13/stable-security [amd64])
Conf linux-image-amd64 (6.12.101-1 Debian-Security:13/stable-security [amd64])
`

func TestParseAptOutputRealSecurityUpdate(t *testing.T) {
	rep := parseAptOutput(realProductionSample)

	if rep.Total != 2 {
		t.Errorf("Total = %d, want 2 (only the Inst lines, never Conf)", rep.Total)
	}
	if rep.Security != 2 {
		t.Errorf("Security = %d, want 2 (both from Debian-Security)", rep.Security)
	}
	var upgraded *Package
	for i := range rep.Packages {
		if rep.Packages[i].Name == "linux-image-amd64" {
			upgraded = &rep.Packages[i]
		}
	}
	if upgraded == nil {
		t.Fatalf("linux-image-amd64 missing from %+v", rep.Packages)
	}
	if upgraded.CurrentVersion != "6.12.94-1" {
		t.Errorf("CurrentVersion = %q, want %q", upgraded.CurrentVersion, "6.12.94-1")
	}
	if upgraded.NewVersion != "6.12.101-1" {
		t.Errorf("NewVersion = %q, want %q", upgraded.NewVersion, "6.12.101-1")
	}
	if !upgraded.Security {
		t.Errorf("expected Security=true for a Debian-Security origin: %+v", upgraded)
	}
}

// A brand-new package (no [current] bracket) must still parse — that is the
// shape of the kernel's companion package in the real sample above.
func TestParseAptOutputNewPackageHasNoCurrentVersion(t *testing.T) {
	rep := parseAptOutput(realProductionSample)
	for _, p := range rep.Packages {
		if p.Name == "linux-image-6.12.101+deb13-amd64" {
			if p.CurrentVersion != "" {
				t.Errorf("CurrentVersion = %q, want empty for a newly installed package", p.CurrentVersion)
			}
			if p.NewVersion != "6.12.101-1" {
				t.Errorf("NewVersion = %q, want %q", p.NewVersion, "6.12.101-1")
			}
			return
		}
	}
	t.Fatalf("new package missing from %+v", rep.Packages)
}

func TestParseAptOutputNonSecurityUpdate(t *testing.T) {
	sample := "Inst curl [8.14.1-1] (8.14.2-1 Debian:13/stable [amd64])\n"
	rep := parseAptOutput(sample)

	if rep.Total != 1 {
		t.Fatalf("Total = %d, want 1", rep.Total)
	}
	if rep.Security != 0 {
		t.Errorf("Security = %d, want 0 for a plain Debian origin", rep.Security)
	}
	if rep.Packages[0].Security {
		t.Errorf("expected Security=false: %+v", rep.Packages[0])
	}
}

func TestParseAptOutputNothingPending(t *testing.T) {
	rep := parseAptOutput("")

	if rep.Total != 0 || rep.Security != 0 {
		t.Errorf("expected an empty report, got %+v", rep)
	}
	if rep.Packages == nil {
		t.Error("Packages is nil — would marshal as JSON null instead of []")
	}
}

// TestCheckForcesCLocaleAndDistUpgrade guards the two production-only traps
// found while designing this: (1) apt's output is localized — on the real
// box it came back in Portuguese ("atualizável de:"), so the parser must
// force LC_ALL=C; (2) `apt-get --just-print upgrade` reported ZERO for the
// pending kernel security update (kernel upgrades pull in a new package),
// while dist-upgrade reported it correctly. Using the wrong verb would have
// silently under-reported exactly the updates that matter most.
func TestCheckForcesCLocaleAndDistUpgrade(t *testing.T) {
	e := &fakeExec{out: realProductionSample}

	if _, err := Check(context.Background(), e); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.Contains(e.lastCmd, "LC_ALL=C") {
		t.Errorf("command must force the C locale, got: %q", e.lastCmd)
	}
	if !strings.Contains(e.lastCmd, "dist-upgrade") {
		t.Errorf("command must use dist-upgrade, got: %q", e.lastCmd)
	}
	if strings.Contains(e.lastCmd, "update") {
		t.Errorf("must never run `apt-get update` from inside the service, got: %q", e.lastCmd)
	}
}

// A failing apt must surface as an error, never as a cheerful "0 updates" —
// no fake data in the panel.
func TestCheckReportsErrorInsteadOfFakingZero(t *testing.T) {
	e := &fakeExec{err: errBoom{}}

	if _, err := Check(context.Background(), e); err == nil {
		t.Fatal("expected an error when apt fails, got nil (would show a false 'up to date')")
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
cd /home/gov/Documentos/Projetos/gbtech/repos/linkguard-fw
export PATH=$HOME/sdk/go1.25.0/bin:$PATH
go test ./internal/sysupdates/... -v
```

Esperado: `FAIL` — o pacote não existe ainda (`no Go files` / `undefined: Check`).

- [ ] **Step 3: Implementar**

Criar `internal/sysupdates/sysupdates.go`:

```go
// Package sysupdates reports which system packages have pending updates,
// highlighting security ones — so an operator sees "this firewall is
// missing a kernel security update" on the panel instead of discovering it
// over SSH.
//
// Read-only by design: it never runs `apt-get update`, `install` or
// `upgrade`. Refreshing the package lists is left to Debian's own
// apt-daily.timer, and applying updates is an operator decision — an
// unattended upgrade on a border firewall can restart networking and drop
// the link. This mirrors the same call made in timesync.EnsureEnabled about
// not driving a package manager from inside a long-running service.
package sysupdates

import (
	"context"
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// securityOrigin is the APT origin marker Debian stamps on security
// updates, e.g. "Debian-Security:13/stable-security".
const securityOrigin = "Debian-Security"

// Package is one pending package update.
type Package struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version"` // empty when the package is newly pulled in
	NewVersion     string `json:"new_version"`
	Origin         string `json:"origin"`
	Security       bool   `json:"security"`
}

// Report summarises the pending updates.
type Report struct {
	Total    int       `json:"total"`
	Security int       `json:"security"`
	Packages []Package `json:"packages"`
}

// Check enumerates pending updates from apt's already-cached package lists.
//
// Two production-verified details are load-bearing here. LC_ALL=C: apt's
// output is localized, and on the real box it came back in Portuguese, which
// silently defeats any English-keyed parsing. dist-upgrade (not upgrade):
// `apt-get --just-print upgrade` reported zero pending changes for a real
// pending kernel security update, because kernel upgrades pull in a new
// package; dist-upgrade reports it. Using `upgrade` would under-report
// precisely the updates that matter most on a firewall.
func Check(ctx context.Context, exec firewall.Executor) (Report, error) {
	out, err := exec.ExecuteRead(ctx, "env", "LC_ALL=C", "apt-get", "--just-print", "dist-upgrade")
	if err != nil {
		return Report{}, fmt.Errorf("consultar atualizações pendentes: %w", err)
	}
	return parseAptOutput(out), nil
}

// parseAptOutput extracts the pending packages from apt's simulation
// output. Only `Inst` lines count — `Conf` lines describe the configuration
// step of the very same packages and would double every count.
//
// Line shapes handled (both real, from the production capture):
//
//	Inst linux-image-amd64 [6.12.94-1] (6.12.101-1 Debian-Security:13/stable-security [amd64])
//	Inst linux-image-6.12.101+deb13-amd64 (6.12.101-1 Debian-Security:13/stable-security [amd64])
//
// The second has no `[current]` bracket because the package is new, not
// upgraded. Anything it cannot parse is skipped rather than guessed at.
func parseAptOutput(out string) Report {
	rep := Report{Packages: []Package{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "Inst "))

		name, rest, ok := strings.Cut(rest, " ")
		if !ok || name == "" {
			continue
		}
		pkg := Package{Name: name}

		// Optional "[current-version]" before the parenthesised part.
		if strings.HasPrefix(rest, "[") {
			if cur, tail, found := strings.Cut(strings.TrimPrefix(rest, "["), "]"); found {
				pkg.CurrentVersion = strings.TrimSpace(cur)
				rest = strings.TrimSpace(tail)
			}
		}

		// "(new-version Origin:suite/pocket [arch])"
		inner, _, found := strings.Cut(strings.TrimPrefix(rest, "("), ")")
		if !found {
			continue
		}
		fields := strings.Fields(inner)
		if len(fields) == 0 {
			continue
		}
		pkg.NewVersion = fields[0]
		if len(fields) > 1 {
			pkg.Origin = fields[1]
		}
		pkg.Security = strings.Contains(pkg.Origin, securityOrigin)

		rep.Packages = append(rep.Packages, pkg)
		rep.Total++
		if pkg.Security {
			rep.Security++
		}
	}
	return rep
}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/sysupdates/
go test ./internal/sysupdates/... -v
go build ./...
go vet ./...
```

Esperado: `gofmt -l` sem saída; `PASS` em todos os testes; build e vet limpos.

- [ ] **Step 5: Validar o parser contra a produção real**

Confirmar que o parser concorda com a máquina de verdade (o mesmo comando que o código roda):

```bash
ssh gov@192.168.3.3 "su -c 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; env LC_ALL=C apt-get --just-print dist-upgrade | grep \"^Inst\"'"
```

Esperado hoje: duas linhas `Inst` referentes ao kernel, ambas com origem
`Debian-Security` — exatamente a amostra usada no teste. Se a saída divergir
em formato, ajustar o parser **e** o teste com a saída real (nunca inventar
o formato).

- [ ] **Step 6: Commit**

```bash
git add internal/sysupdates/
git commit -m "feat(sysupdates): report pending package updates, flagging security ones"
```

---

### Task 5a: Pares de alerta novos em `internal/alerts`

**Files:**
- Modify: `internal/alerts/service.go`
- Modify: `internal/alerts/service_test.go`

**Interfaces:**
- Consumes: `Service.Create`/`AutoResolve`/`createRecovery` (já existentes, `service.go:87`).
- Produces: `FirewallNATDrift(detail string) error`/`FirewallNATOK() error`; `WANInterfaceMissing(detail string) error`/`WANInterfaceOK() error`; `DNSResolverDrift(detail string) error`/`DNSResolverOK() error`; `SecurityUpdatesPending(detail string) error`/`SecurityUpdatesNone() error` — consumidos pela Task 5b.

- [ ] **Step 1: Escrever o teste que falha**

Adicionar ao final de `internal/alerts/service_test.go` (conferir antes o
helper de DB de teste já usado no arquivo e reaproveitá-lo — não criar outro):

```go
// TestConfigDriftAlertPairsResolveEachOther guards the contract every
// paired alert in this package follows: the recovery side must auto-resolve
// its problem counterpart, otherwise a fixed problem stays red forever on
// the panel — which would defeat the whole point of these watchers.
func TestConfigDriftAlertPairsResolveEachOther(t *testing.T) {
	cases := []struct {
		name        string
		problemType string
		raise       func(*Service) error
		recover     func(*Service) error
	}{
		{"firewall-nat", TypeFirewallNATDrift,
			func(s *Service) error { return s.FirewallNATDrift("enp4s0 não existe") },
			func(s *Service) error { return s.FirewallNATOK() }},
		{"wan-interface", TypeWANInterfaceMissing,
			func(s *Service) error { return s.WANInterfaceMissing("WAN VIVO -> enp4s0") },
			func(s *Service) error { return s.WANInterfaceOK() }},
		{"dns-resolver", TypeDNSResolverDrift,
			func(s *Service) error { return s.DNSResolverDrift("189.40.0.1") },
			func(s *Service) error { return s.DNSResolverOK() }},
		{"security-updates", TypeSecurityUpdatesPending,
			func(s *Service) error { return s.SecurityUpdatesPending("2 pacotes") },
			func(s *Service) error { return s.SecurityUpdatesNone() }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDB(t)
			s := NewService(db)

			if err := tc.raise(s); err != nil {
				t.Fatalf("raise: %v", err)
			}
			open, err := db.GetAlerts(false, 50)
			if err != nil {
				t.Fatalf("GetAlerts: %v", err)
			}
			if !hasOpenAlertOfType(open, tc.problemType) {
				t.Fatalf("expected an open %s alert, got %+v", tc.problemType, open)
			}

			if err := tc.recover(s); err != nil {
				t.Fatalf("recover: %v", err)
			}
			open, err = db.GetAlerts(false, 50)
			if err != nil {
				t.Fatalf("GetAlerts: %v", err)
			}
			if hasOpenAlertOfType(open, tc.problemType) {
				t.Errorf("%s should have been auto-resolved by its recovery call", tc.problemType)
			}
		})
	}
}

func hasOpenAlertOfType(alerts []storage.Alert, alertType string) bool {
	for _, a := range alerts {
		if a.Type == alertType && !a.Resolved {
			return true
		}
	}
	return false
}

// TestSecurityUpdatesPendingIsWarningNotCritical: a pending update is a
// maintenance signal, not an outage — raising it as Critical would train the
// operator to ignore Critical alerts.
func TestSecurityUpdatesPendingIsWarningNotCritical(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.SecurityUpdatesPending("2 pacotes"); err != nil {
		t.Fatalf("SecurityUpdatesPending: %v", err)
	}
	open, err := db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == TypeSecurityUpdatesPending && a.Severity != SeverityWarning {
			t.Errorf("severity = %q, want %q", a.Severity, SeverityWarning)
		}
	}
}
```

Os nomes acima já foram conferidos contra o código real: o helper de DB é
`openTestDB(t)` (`internal/alerts/service_test.go:11`) e a listagem é
`db.GetAlerts(unresolvedOnly bool, limit int) ([]storage.Alert, error)`
(`internal/storage/repository.go:113`). Usar exatamente esses — não criar
helper novo.

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/alerts/... -run 'TestConfigDrift|TestSecurityUpdates' -v
```

Esperado: `FAIL` — `undefined: TypeFirewallNATDrift` e os oito métodos novos.

- [ ] **Step 3: Implementar**

Em `internal/alerts/service.go`, adicionar ao bloco de constantes de tipo
(logo depois de `TypeJournalOK`):

```go
	TypeFirewallNATDrift       = "firewall_nat_drift"
	TypeFirewallNATOK          = "firewall_nat_ok"
	TypeWANInterfaceMissing    = "wan_interface_missing"
	TypeWANInterfaceOK         = "wan_interface_ok"
	TypeDNSResolverDrift       = "dns_resolver_drift"
	TypeDNSResolverOK          = "dns_resolver_ok"
	TypeSecurityUpdatesPending = "security_updates_pending"
	TypeSecurityUpdatesNone    = "security_updates_none"
```

E os oito métodos, junto dos demais pares (depois de `JournalOK`):

```go
// FirewallNATDrift raises a critical alert when the live masquerade rule no
// longer matches the configured WAN links — the exact failure that took
// WAN1's NAT down in production on 2026-08-10 with no signal on the panel.
// Critical because, unlike a degraded disk, it means traffic is not being
// translated right now.
func (s *Service) FirewallNATDrift(detail string) error {
	return s.Create(TypeFirewallNATDrift, SeverityCritical, "Regra de NAT inconsistente",
		"A regra de NAT ativa não corresponde às WANs configuradas: "+detail, "")
}

// FirewallNATOK clears FirewallNATDrift and notifies recovery.
func (s *Service) FirewallNATOK() error {
	s.AutoResolve(TypeFirewallNATDrift, "")
	return s.createRecovery(TypeFirewallNATOK, "Regra de NAT consistente",
		"A regra de NAT voltou a corresponder às WANs configuradas.", "")
}

// WANInterfaceMissing raises a critical alert when a configured WAN link
// points at a network interface that does not exist on the box — typically
// after a NIC rename (PCI reshuffle), which is what happened in production.
func (s *Service) WANInterfaceMissing(detail string) error {
	return s.Create(TypeWANInterfaceMissing, SeverityCritical, "Interface WAN inexistente",
		"Um link WAN aponta para uma interface que não existe: "+detail, "")
}

// WANInterfaceOK clears WANInterfaceMissing and notifies recovery.
func (s *Service) WANInterfaceOK() error {
	s.AutoResolve(TypeWANInterfaceMissing, "")
	return s.createRecovery(TypeWANInterfaceOK, "Interfaces WAN consistentes",
		"Todos os links WAN apontam para interfaces existentes.", "")
}

// DNSResolverDrift raises a warning when the box is not using its own
// resolver — it still resolves names, so it is not an outage, but the DNS
// blocklist and query visibility are silently bypassed.
func (s *Service) DNSResolverDrift(detail string) error {
	return s.Create(TypeDNSResolverDrift, SeverityWarning, "Resolver DNS externo em uso",
		"O sistema não está usando o resolver local (unbound): "+detail, "")
}

// DNSResolverOK clears DNSResolverDrift and notifies recovery.
func (s *Service) DNSResolverOK() error {
	s.AutoResolve(TypeDNSResolverDrift, "")
	return s.createRecovery(TypeDNSResolverOK, "Resolver DNS local em uso",
		"O sistema voltou a usar o resolver local (unbound).", "")
}

// SecurityUpdatesPending raises a warning when security updates are waiting
// to be installed. Warning, not Critical: it is a maintenance signal, and
// crying Critical over routine patching trains the operator to ignore
// Critical alerts.
func (s *Service) SecurityUpdatesPending(detail string) error {
	return s.Create(TypeSecurityUpdatesPending, SeverityWarning, "Atualizações de segurança pendentes",
		"Há atualizações de segurança do sistema aguardando instalação: "+detail, "")
}

// SecurityUpdatesNone clears SecurityUpdatesPending and notifies recovery.
func (s *Service) SecurityUpdatesNone() error {
	s.AutoResolve(TypeSecurityUpdatesPending, "")
	return s.createRecovery(TypeSecurityUpdatesNone, "Sem atualizações de segurança pendentes",
		"Não há atualizações de segurança aguardando instalação.", "")
}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/alerts/
go test ./internal/alerts/... -v
```

Esperado: `PASS` em tudo.

- [ ] **Step 5: Commit**

```bash
git add internal/alerts/service.go internal/alerts/service_test.go
git commit -m "feat(alerts): add config-drift and pending-security-update alert pairs"
```

---

### Task 5b: Vigias de deriva no `internal/monitoring`

**Files:**
- Create: `internal/monitoring/driftchecks.go`
- Create: `internal/monitoring/driftchecks_test.go`
- Modify: `internal/monitoring/collector.go`

**Interfaces:**
- Consumes: `Collector` (campos `db`, `exec`, `alertSvc`, `nowFn`, `health`, `healthMu`); `observe`/`ensureMeta`/`transDown`/`transUp` (`healthchecks.go`); os pares de alerta da Task 5a; `db.GetLinks()`; `nftables.Family`/`Table` (`internal/nftables`).
- Produces: `func (c *Collector) checkWANInterfaces()`, `func (c *Collector) checkFirewallNAT()`, `func (c *Collector) checkDNSResolver()` — chamados no tick do `Run`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/monitoring/driftchecks_test.go`:

```go
package monitoring

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// driftExec answers the specific read commands the drift checks issue,
// keyed by the full command line, and reports which interfaces "exist".
type driftExec struct {
	responses map[string]string
	err       error
}

func (e *driftExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *driftExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if e.err != nil {
		return "", e.err
	}
	return e.responses[strings.Join(append([]string{cmd}, args...), " ")], nil
}
func (e *driftExec) IsDryRun() bool { return false }

// TestCheckWANInterfacesFlagsMissingInterface is the regression test for the
// 2026-08-10 incident: a WAN link kept pointing at enp4s0 after the NIC was
// renamed to enp5s0, and nothing on the panel said so. This watcher is what
// would have caught it at boot.
func TestCheckWANInterfacesFlagsMissingInterface(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp4s0", true)
	c.ifaceExists = func(name string) bool { return name == "enp5s0" }

	c.checkWANInterfaces()
	c.checkWANInterfaces() // downConfirm=2: the outage is declared on the confirming tick

	if up := c.healthUp("wan:interface"); up {
		t.Error("wan:interface should be down when a link points at a missing interface")
	}
}

func TestCheckWANInterfacesHealthyWhenAllPresent(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.ifaceExists = func(name string) bool { return name == "enp5s0" }

	c.checkWANInterfaces()

	if up := c.healthUp("wan:interface"); !up {
		t.Error("wan:interface should be up when every link's interface exists")
	}
}

// A disabled link is not a live WAN — it must not raise an alert.
func TestCheckWANInterfacesIgnoresDisabledLinks(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VELHA", "enp9s0", false)
	c.ifaceExists = func(name string) bool { return false }

	c.checkWANInterfaces()
	c.checkWANInterfaces()

	if up := c.healthUp("wan:interface"); !up {
		t.Error("a disabled link must not mark wan:interface as down")
	}
}

// TestCheckFirewallNATFlagsStaleRule: the live rule still references the old
// interface while the configured link moved on — precisely the state
// production was left in.
func TestCheckFirewallNATFlagsStaleRule(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.exec = &driftExec{responses: map[string]string{
		"nft list chain inet linkguard postrouting": `table inet linkguard {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname { "enp2s0", "enp4s0" } masquerade
	}
}`,
	}}

	c.checkFirewallNAT()
	c.checkFirewallNAT()

	if up := c.healthUp("firewall:nat"); up {
		t.Error("firewall:nat should be down when the live rule omits a configured WAN")
	}
}

func TestCheckFirewallNATHealthyWhenRuleMatches(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.exec = &driftExec{responses: map[string]string{
		"nft list chain inet linkguard postrouting": `		oifname { "enp5s0" } masquerade`,
	}}

	c.checkFirewallNAT()

	if up := c.healthUp("firewall:nat"); !up {
		t.Error("firewall:nat should be up when the live rule covers every configured WAN")
	}
}

// No configured WANs means there is nothing to verify — the watcher must not
// invent a problem (and must not claim health either; it simply stays out of
// the way).
func TestCheckFirewallNATSkipsWhenNoWANsConfigured(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &driftExec{responses: map[string]string{}}

	c.checkFirewallNAT()

	if _, known := c.healthState("firewall:nat"); known {
		t.Error("firewall:nat must not be reported at all when no WAN is configured")
	}
}

func TestCheckDNSResolverFlagsExternalResolver(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "nameserver 189.40.0.1\n")

	c.checkDNSResolver()
	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); up {
		t.Error("dns:resolver should be down when resolv.conf points at an external server")
	}
}

func TestCheckDNSResolverHealthyOnLocalResolver(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "# managed by linkguard\nnameserver 127.0.0.1\n")

	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); !up {
		t.Error("dns:resolver should be up when resolv.conf points at 127.0.0.1")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}
```

Os helpers `newDriftTestCollector`, `seedLink`, `healthUp` e `healthState`
precisam existir. Antes de escrevê-los, procurar equivalentes já no pacote
(`grep -rn "func newTestCollector\|func.*Collector(t \*testing.T)" internal/monitoring/*_test.go`)
e **reaproveitar** o que houver, adaptando só o que faltar. Se não houver,
adicionar ao mesmo arquivo:

```go
func newDriftTestCollector(t *testing.T) *Collector {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	c := NewCollector(db, nil, alerts.NewService(db), &driftExec{responses: map[string]string{}}, nil)
	c.nowFn = func() int64 { return 1 }
	return c
}

func seedLink(t *testing.T, c *Collector, name, iface string, enabled bool) {
	t.Helper()
	if err := c.db.CreateLink(&storage.Link{ID: name, Name: name, Interface: iface, Weight: 1, Enabled: enabled}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
}

// healthUp reports the item's current up/down state; healthState also
// reports whether the item exists at all.
func (c *Collector) healthUp(key string) bool {
	up, _ := c.healthState(key)
	return up
}

func (c *Collector) healthState(key string) (up, known bool) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	st := c.health[key]
	if st == nil {
		return false, false
	}
	return st.up, true
}
```

(`healthUp`/`healthState` são helpers só-de-teste — devem ficar no arquivo
`_test.go`, nunca no código de produção.)

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/monitoring/... -run 'TestCheckWANInterfaces|TestCheckFirewallNAT|TestCheckDNSResolver' -v
```

Esperado: `FAIL` — `c.ifaceExists`, `c.resolvConfPath` e os três métodos não existem.

- [ ] **Step 3: Implementar**

Criar `internal/monitoring/driftchecks.go`:

```go
package monitoring

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// Config drift watchers.
//
// Why this file exists: on 2026-08-10 a NIC rename left a WAN link pointing
// at an interface that no longer existed and the firewall's masquerade rule
// stranded on the old name. Every existing health check stayed green —
// `systemctl is-active nftables` was perfectly happy serving a stale rule —
// so the operator only found it by SSHing in. These checks close that blind
// spot: they compare what LinkGuard APPLIED against what the system
// actually LOOKS LIKE, which no other check in this package does.
//
// All three are read-only and cheap enough for the 30s collector tick.

// defaultResolvConfPath is the file checkDNSResolver reads; overridden in tests.
const defaultResolvConfPath = "/etc/resolv.conf"

// enabledWANInterfaces returns the interfaces of every enabled WAN link —
// the source of truth both checkWANInterfaces and checkFirewallNAT compare
// reality against.
func (c *Collector) enabledWANInterfaces() []string {
	ls, err := c.db.GetLinks()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		if l.Enabled && l.Interface != "" {
			out = append(out, l.Interface)
		}
	}
	return out
}

// interfaceExists reports whether the kernel currently has this interface.
// Uses /sys/class/net directly (no exec) — a rename shows up immediately.
func interfaceExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

// checkWANInterfaces verifies every enabled WAN link points at an interface
// the kernel actually has. This is the watcher that would have caught the
// 2026-08-10 incident the moment the box came up.
func (c *Collector) checkWANInterfaces() {
	ls, err := c.db.GetLinks()
	if err != nil {
		return // cannot evaluate this tick; don't invent a verdict
	}
	exists := c.ifaceExists
	if exists == nil {
		exists = interfaceExists
	}

	var missing []string
	for _, l := range ls {
		if !l.Enabled || l.Interface == "" {
			continue
		}
		if !exists(l.Interface) {
			missing = append(missing, fmt.Sprintf("%s -> %s", l.Name, l.Interface))
		}
	}

	tr := c.observe("wan:interface", len(missing) == 0, c.nowFn())
	c.ensureMeta("wan:interface", "wan-interface", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.WANInterfaceMissing(strings.Join(missing, ", "))
	case transUp:
		_ = c.alertSvc.WANInterfaceOK()
	}
}

// checkFirewallNAT verifies the LIVE masquerade rule covers exactly the
// configured WAN interfaces. `systemctl is-active nftables` cannot see this:
// the service is happily active while the rule inside it is stale.
func (c *Collector) checkFirewallNAT() {
	wans := c.enabledWANInterfaces()
	if len(wans) == 0 {
		return // nothing configured to verify against
	}
	out, err := c.exec.ExecuteRead(context.Background(), "nft", "list", "chain",
		nftables.Family, nftables.Table, "postrouting")
	if err != nil {
		return // table/chain unreadable this tick — no verdict rather than a false one
	}

	var missing []string
	for _, iface := range wans {
		if !strings.Contains(out, `"`+iface+`"`) {
			missing = append(missing, iface)
		}
	}
	detail := ""
	if len(missing) > 0 {
		detail = "faltando na regra: " + strings.Join(missing, ", ")
	}

	tr := c.observe("firewall:nat", len(missing) == 0, c.nowFn())
	c.ensureMeta("firewall:nat", "firewall-nat", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.FirewallNATDrift(detail)
	case transUp:
		_ = c.alertSvc.FirewallNATOK()
	}
}

// checkDNSResolver verifies the box resolves through its own unbound rather
// than the ISP's servers — the drift found in production, caused by
// dhclient rewriting resolv.conf on lease renewal.
func (c *Collector) checkDNSResolver() {
	path := c.resolvConfPath
	if path == "" {
		path = defaultResolvConfPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return // unreadable this tick; no verdict
	}

	local := false
	var external []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		addr := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
		if addr == "127.0.0.1" || addr == "::1" {
			local = true
		} else if addr != "" {
			external = append(external, addr)
		}
	}

	tr := c.observe("dns:resolver", local && len(external) == 0, c.nowFn())
	c.ensureMeta("dns:resolver", "dns-resolver", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.DNSResolverDrift(strings.Join(external, ", "))
	case transUp:
		_ = c.alertSvc.DNSResolverOK()
	}
}
```

Em `internal/monitoring/collector.go`, adicionar dois campos à struct
`Collector` (junto de `bootIDFn`, que já segue esse padrão de override em teste):

```go
	ifaceExists    func(string) bool // overridable in tests; nil means the real /sys/class/net check
	resolvConfPath string            // overridable in tests; empty means defaultResolvConfPath
```

E chamar os três checks dentro do bloco `if cfg.Enabled { ... }` do `Run`,
logo depois de `c.checkSMART(cfg)`:

```go
			c.checkWANInterfaces()
			c.checkFirewallNAT()
			c.checkDNSResolver()
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/monitoring/
go test ./internal/monitoring/... -v
go build ./...
go vet ./...
```

Esperado: `PASS` em tudo (novos e pré-existentes); build e vet limpos.

- [ ] **Step 5: Commit**

```bash
git add internal/monitoring/driftchecks.go internal/monitoring/driftchecks_test.go internal/monitoring/collector.go
git commit -m "feat(monitoring): watch for NAT/WAN-interface/DNS-resolver config drift"
```

---

### Task 5c: `UpdatesScheduler` — vigia de atualizações pendentes

**Files:**
- Create: `internal/monitoring/updatescheck.go`
- Create: `internal/monitoring/updatescheck_test.go`
- Modify: `internal/monitoring/config.go`
- Modify: `cmd/linkguard-fw/main.go`

**Interfaces:**
- Consumes: `sysupdates.Check`/`Report` (Task 4); `Collector` (`db`, `exec`, `alertSvc`, `nowFn`, `observe`, `ensureMeta`); `alerts.SecurityUpdatesPending`/`SecurityUpdatesNone` (Task 5a); padrão de `JournalScheduler` (`internal/monitoring/journalcheck.go`).
- Produces: `type UpdatesScheduler struct{...}`; `func NewUpdatesScheduler(col *Collector) *UpdatesScheduler`; `func (u *UpdatesScheduler) Run(ctx context.Context)`; `func (u *UpdatesScheduler) RunOnce(ctx context.Context)`; `func (c *Collector) LastUpdatesReport() sysupdates.Report` — consumido pelo endpoint da Task 6.

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/monitoring/updatescheck_test.go`:

```go
package monitoring

import (
	"context"
	"strings"
	"testing"
)

type updatesExec struct{ out string }

func (e *updatesExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *updatesExec) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return e.out, nil
}
func (e *updatesExec) IsDryRun() bool { return false }

const securitySample = "Inst linux-image-amd64 [6.12.94-1] (6.12.101-1 Debian-Security:13/stable-security [amd64])\n"
const plainSample = "Inst curl [8.14.1-1] (8.14.2-1 Debian:13/stable [amd64])\n"

// The panel must light up for ANY pending update — that is the operator's
// stated need ("eu deveria só olhar para ele") — so the health item goes
// down on a plain update too.
func TestUpdatesSchedulerPanelReflectsAnyPendingUpdate(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: plainSample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	if up := c.healthUp("system:updates"); up {
		t.Error("system:updates should be down while any update is pending")
	}
}

// But a push notification only fires for SECURITY updates — routine
// packages would spam the operator into ignoring the channel.
func TestUpdatesSchedulerAlertsOnlyForSecurityUpdates(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: plainSample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	open, err := c.db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range open {
		if a.Type == alerts.TypeSecurityUpdatesPending {
			t.Error("a non-security update must not raise the security alert")
		}
	}
}

func TestUpdatesSchedulerAlertsOnSecurityUpdate(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: securitySample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())
	u.RunOnce(context.Background())

	open, err := c.db.GetAlerts(false, 50)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	found := false
	for _, a := range open {
		if a.Type == alerts.TypeSecurityUpdatesPending {
			found = true
			if !strings.Contains(a.Message, "linux-image-amd64") {
				t.Errorf("alert should name the pending package, got: %q", a.Message)
			}
		}
	}
	if !found {
		t.Error("expected a pending-security-update alert")
	}
}

// The last report is cached so the UI can list the packages without paying
// for an apt call on every page load.
func TestUpdatesSchedulerCachesTheReportForTheUI(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &updatesExec{out: securitySample}
	u := NewUpdatesScheduler(c)

	u.RunOnce(context.Background())

	rep := c.LastUpdatesReport()
	if rep.Total != 1 || rep.Security != 1 {
		t.Fatalf("cached report = %+v, want Total=1 Security=1", rep)
	}
	if len(rep.Packages) != 1 || rep.Packages[0].Name != "linux-image-amd64" {
		t.Errorf("cached packages = %+v", rep.Packages)
	}
}
```

Adicionar `"github.com/giovanibalarini/linkguard-fw/internal/alerts"` ao import do arquivo.

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/monitoring/... -run TestUpdatesScheduler -v
```

Esperado: `FAIL` — `NewUpdatesScheduler`/`LastUpdatesReport` não existem.

- [ ] **Step 3: Implementar**

Criar `internal/monitoring/updatescheck.go`:

```go
package monitoring

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/sysupdates"
)

// updatesLastRunSettingKey persists the unix timestamp of the last check so
// the interval survives restarts (mirrors journalLastVerifySettingKey).
const updatesLastRunSettingKey = "sysupdates_last_run"

// updatesTickInterval is how often the scheduler wakes to decide whether it
// is time to check for real — coarse, like JournalScheduler's.
const updatesTickInterval = 1 * time.Hour

// UpdatesScheduler periodically reports pending system package updates.
//
// It runs on its own ticker rather than inside the Collector's 30s loop
// because shelling out to apt is comparatively slow, and pending updates
// change on the order of days — not seconds.
//
// Deliberate split between panel and notification: the health item goes down
// for ANY pending update (so the operator sees it just by looking at the
// dashboard, which is the whole point), but a push alert only fires for
// SECURITY updates — routine package churn would train the operator to
// ignore the notification channel.
type UpdatesScheduler struct {
	col *Collector
}

// NewUpdatesScheduler creates a scheduler bound to an existing Collector
// (reuses its db/exec/alertSvc/health bookkeeping).
func NewUpdatesScheduler(col *Collector) *UpdatesScheduler {
	return &UpdatesScheduler{col: col}
}

// Run starts the scheduler loop and blocks until ctx is done.
func (u *UpdatesScheduler) Run(ctx context.Context) {
	slog.Info("system updates scheduler started", "tick_interval", updatesTickInterval)
	ticker := time.NewTicker(updatesTickInterval)
	defer ticker.Stop()

	u.maybeRun(ctx) // check once at startup instead of waiting a full tick
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.maybeRun(ctx)
		}
	}
}

func (u *UpdatesScheduler) maybeRun(ctx context.Context) {
	cfg := LoadConfig(u.col.db)
	if !cfg.Enabled {
		return
	}
	interval := time.Duration(cfg.UpdatesCheckIntervalHours) * time.Hour
	last := u.lastRun()
	if last != 0 && time.Since(time.Unix(last, 0)) < interval {
		return
	}
	u.RunOnce(ctx)
}

// RunOnce checks for pending updates immediately and updates the health item
// and (for security updates) the alert.
func (u *UpdatesScheduler) RunOnce(ctx context.Context) {
	rep, err := sysupdates.Check(ctx, u.col.exec)
	_ = u.col.db.SetSetting(updatesLastRunSettingKey, strconv.FormatInt(time.Now().Unix(), 10))
	if err != nil {
		slog.Warn("não foi possível verificar atualizações do sistema", "err", err)
		return // no verdict rather than a false "up to date"
	}

	u.col.setLastUpdatesReport(rep)

	tr := u.col.observe("system:updates", rep.Total == 0, u.col.nowFn())
	u.col.ensureMeta("system:updates", "system-updates", "resource")

	if rep.Security > 0 {
		if tr == transDown {
			_ = u.col.alertSvc.SecurityUpdatesPending(describeUpdates(rep))
		}
		return
	}
	if tr == transUp {
		_ = u.col.alertSvc.SecurityUpdatesNone()
	}
}

// describeUpdates renders a short, operator-readable summary naming the
// security packages (capped so a large backlog doesn't produce a wall of
// text in a Telegram/e-mail notification).
func describeUpdates(rep sysupdates.Report) string {
	const maxNamed = 5
	names := make([]string, 0, maxNamed)
	for _, p := range rep.Packages {
		if !p.Security {
			continue
		}
		if len(names) == maxNamed {
			names = append(names, "…")
			break
		}
		names = append(names, p.Name)
	}
	return fmt.Sprintf("%d de segurança (de %d no total): %s",
		rep.Security, rep.Total, strings.Join(names, ", "))
}

func (u *UpdatesScheduler) lastRun() int64 {
	raw, _ := u.col.db.GetSetting(updatesLastRunSettingKey)
	v, _ := strconv.ParseInt(raw, 10, 64)
	return v
}
```

Adicionar ao `Collector` (em `collector.go`) o cache do último relatório,
protegido pelo mutex já existente:

```go
	lastUpdates sysupdates.Report // last pending-updates report, for the UI
```

e os dois acessores (no mesmo arquivo, junto dos outros métodos do Collector):

```go
// setLastUpdatesReport caches the most recent pending-updates report so the
// UI can list packages without paying for an apt call per page load.
func (c *Collector) setLastUpdatesReport(rep sysupdates.Report) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.lastUpdates = rep
}

// LastUpdatesReport returns the cached pending-updates report.
func (c *Collector) LastUpdatesReport() sysupdates.Report {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	return c.lastUpdates
}
```

Em `internal/monitoring/config.go`, adicionar o campo à `Config` e seu default
em `LoadConfig` (seguir exatamente o padrão de clamp dos campos existentes,
ex.: `JournalVerifyIntervalDays`):

```go
	UpdatesCheckIntervalHours int `json:"updates_check_interval_hours"`
```

com default `6` e clamp mínimo de `1` (um intervalo zero faria a checagem
rodar a cada tick de uma hora sem necessidade).

Em `cmd/linkguard-fw/main.go`, junto do `journalSched` (linhas ~194 e ~287):

```go
	updatesSched := monitoring.NewUpdatesScheduler(metricsCollector)
```
```go
	go updatesSched.Run(ctx)
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/monitoring/ cmd/
go test ./internal/monitoring/... -v
go build ./...
go vet ./...
```

Esperado: `PASS` em tudo; build e vet limpos.

- [ ] **Step 5: Commit**

```bash
git add internal/monitoring/updatescheck.go internal/monitoring/updatescheck_test.go internal/monitoring/collector.go internal/monitoring/config.go cmd/linkguard-fw/main.go
git commit -m "feat(monitoring): watch pending system updates, alerting on security ones"
```

---

### Task 6: Endpoint da lista de atualizações + rótulos no painel

**Files:**
- Modify: `internal/api/handlers/monitoring.go`
- Create: `internal/api/handlers/monitoring_updates_test.go`
- Modify: `internal/api/server.go`
- Modify: `web/src/types/index.ts`
- Modify: `web/src/components/SystemHealth.tsx`

**Interfaces:**
- Consumes: `MonitoringHandler` (já existente, `internal/api/handlers/monitoring.go:11` — já carrega `col *monitoring.Collector`, nenhum wiring novo é necessário); `Collector.LastUpdatesReport()` (Task 5c); `auth.PermSystemRead`; `writeJSON`.
- Produces: `GET /api/system/updates`; tipos TS `PendingPackage`/`UpdatesReport`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/api/handlers/monitoring_updates_test.go`:

```go
package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TestUpdatesReturnsEmptyPackagesNotNull guards the same JSON contract the
// rest of this codebase follows: a nil slice marshals to `null` and breaks
// the frontend's .map(). A fresh box that has never run the check must
// return an empty list, not null.
func TestUpdatesReturnsEmptyPackagesNotNull(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	col := monitoring.NewCollector(db, nil, alerts.NewService(db), &fakeEmptyIfaceExec{}, nil)
	h := NewMonitoringHandler(col, db)

	r := httptest.NewRequest("GET", "/api/system/updates", nil)
	w := httptest.NewRecorder()
	h.Updates(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var got struct {
		Total    int  `json:"total"`
		Security int  `json:"security"`
		Packages []any `json:"packages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v — body: %s", err, w.Body.String())
	}
	if got.Packages == nil {
		t.Errorf("packages is null; expected [] — body: %s", w.Body.String())
	}
}
```

`fakeEmptyIfaceExec` já existe em `internal/api/handlers/netif_test.go` (mesmo
pacote) e serve aqui — confirmar com
`grep -rn "fakeEmptyIfaceExec" internal/api/handlers/` antes de usar; se não
existir mais, criar um fake local mínimo em vez de reaproveitar `fakeNftExec`.

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/api/handlers/... -run TestUpdatesReturnsEmpty -v
```

Esperado: `FAIL` — `h.Updates` não existe.

- [ ] **Step 3: Implementar**

Em `internal/api/handlers/monitoring.go`, adicionar logo depois de `Health`:

```go
// Updates returns the most recent pending system-updates report, so the
// panel can list exactly which packages are waiting (and which of them are
// security updates) without shelling out to apt on every page load — the
// scheduler refreshes this on its own cadence.
func (h *MonitoringHandler) Updates(w http.ResponseWriter, r *http.Request) {
	rep := h.col.LastUpdatesReport()
	if rep.Packages == nil {
		rep.Packages = []sysupdates.Package{}
	}
	writeJSON(w, http.StatusOK, rep)
}
```

Adicionar `"github.com/giovanibalarini/linkguard-fw/internal/sysupdates"` ao
bloco de import do arquivo.

Em `internal/api/server.go`, logo depois da rota de health já existente
(linha ~265):

```go
		r.With(require(auth.PermSystemRead)).Get("/api/system/updates", monH.Updates)
```

Em `web/src/types/index.ts`, junto dos tipos de monitoramento (perto de
`HealthItem`):

```ts
export interface PendingPackage {
  name: string;
  current_version: string;
  new_version: string;
  origin: string;
  security: boolean;
}
export interface UpdatesReport { total: number; security: number; packages: PendingPackage[]; }
```

Em `web/src/components/SystemHealth.tsx`, acrescentar os quatro rótulos ao
mapa `LABEL` existente:

```tsx
  'firewall-nat': 'Regra de NAT',
  'wan-interface': 'Interfaces WAN',
  'dns-resolver': 'Resolver DNS',
  'system-updates': 'Atualizações do sistema',
```

E, no mesmo componente, uma seção colapsada que só aparece quando há
atualizações pendentes (padrão "resumo + expandir" já preferido no projeto,
em vez de um card grande sempre visível). Adicionar ao topo do componente:

```tsx
  const [updates, setUpdates] = useState<UpdatesReport | null>(null);
  const [showUpdates, setShowUpdates] = useState(false);
```

Carregar junto do health, dentro do mesmo `useEffect`/`load` já existente
(logo após o `setItems`):

```tsx
      try { const { data } = await client.get<UpdatesReport>('/api/system/updates'); if (alive) setUpdates(data); }
      catch { /* best-effort, igual ao health */ }
```

E renderizar, logo depois do grid de itens, antes de fechar o `<Panel>`:

```tsx
      {updates && updates.total > 0 && (
        <div className="mt-3 pt-3 border-t border-gray-800/50">
          <button onClick={() => setShowUpdates(!showUpdates)} className="text-sm text-gray-400 hover:text-white">
            {updates.total} atualização(ões) pendente(s)
            {updates.security > 0 && <span className="text-amber-400"> — {updates.security} de segurança</span>}
            <span className="text-gray-600"> {showUpdates ? '▲' : '▼'}</span>
          </button>
          {showUpdates && (
            <div className="mt-2 space-y-1">
              {updates.packages.map((p) => (
                <div key={p.name} className="flex items-center justify-between text-xs">
                  <span className={p.security ? 'text-amber-400' : 'text-gray-400'}>{p.name}</span>
                  <span className="text-gray-600 font-mono">{p.current_version || '—'} → {p.new_version}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
```

Atualizar o import de tipos do arquivo para incluir `UpdatesReport`.

- [ ] **Step 4: Verificar backend e build do frontend**

```bash
gofmt -l internal/api/
go test ./internal/api/... -v
go build ./... && go vet ./...
export PATH=$HOME/.nvm/versions/node/v22.21.1/bin:$PATH
cd web && npm run build
```

Esperado: `PASS` em tudo; build do frontend limpo (`tsc -b && vite build`).

- [ ] **Step 5: Teste manual na VM de teste**

Reaproveitar `~/linkguard-testvm/` (`./recreate.sh`, `./ssh.sh`,
`./destroy.sh`). Se `make deb` falhar no `npm install` por causa do
`web/node_modules` de dono root (problema pré-existente do repositório), usar
o contorno já empregado nesta sessão: `cd web && npm run build` direto, depois
`go build` e replicar os passos de empacotamento do alvo `deb:` do `Makefile`.

Roteiro (o valor real desta task é provar o ciclo completo):
1. Instalar o `.deb` na VM e logar no painel.
2. **Provar o vigia de interface**: apontar um Link para uma interface
   inexistente — `sqlite3 /var/lib/linkguard-fw/linkguard.db "UPDATE links SET interface='enp99s0' WHERE id=(SELECT id FROM links LIMIT 1);"` — reiniciar
   o serviço, esperar dois ticks do coletor (~60s) e confirmar que
   "Interfaces WAN" fica vermelho no painel e que o alerta aparece.
3. **Provar a reconciliação de NAT**: com o Link apontando para uma interface
   real, reiniciar o serviço e confirmar via
   `nft list chain inet linkguard postrouting` que existe **exatamente uma**
   regra de masquerade, com as interfaces corretas (é o teste real da correção
   da duplicação).
4. **Provar o resolver**: escrever `nameserver 8.8.8.8` em `/etc/resolv.conf`,
   reiniciar o serviço e confirmar que o arquivo volta para `127.0.0.1`, que
   `/etc/dhcp/dhclient.conf` ganhou o `supersede` (uma vez só) e que o item
   "Resolver DNS" fica verde.
5. **Provar o vigia de updates**: confirmar que "Atualizações do sistema"
   aparece e que a lista expande com os pacotes reais da VM.
6. `./destroy.sh`.

- [ ] **Step 6: Commit**

```bash
git add internal/api/handlers/monitoring.go internal/api/handlers/monitoring_updates_test.go internal/api/server.go web/src/types/index.ts web/src/components/SystemHealth.tsx
git commit -m "feat(ui): surface config drift and pending updates on the health panel"
```

---

## Depois deste plano

Fora de escopo (documentado na spec §7): aplicar atualizações
automaticamente, auto-curar `links.interface` por MAC, migração
ifupdown→networkd (Fase B) e o proxy tipo Squid pedido como próxima fase.

Ação operacional recomendada, separada deste plano: aplicar a nomeação
estável por MAC (Fase A, já implementada) em produção e reiniciar — estanca
na fonte a causa mais comum de deriva de interface, enquanto os vigias desta
entrega cobrem o resto.
