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

## Tarefas restantes (a detalhar antes de executar)

Escopo já fechado; serão detalhadas com código completo, no mesmo padrão das
Tasks 1–4, antes de irem para execução:

- **Task 5 — vigias em `internal/monitoring`**: `checkFirewallNAT` (regra
  viva bate com as WANs configuradas e todas existem em `/sys/class/net`),
  `checkWANInterfaces` (todo link habilitado aponta para interface
  existente), `checkDNSResolver` (`resolv.conf` = 127.0.0.1) no tick de 30s;
  `UpdatesScheduler` (padrão `JournalScheduler`, intervalo 6h) consumindo
  `sysupdates.Check` (Task 4). Quatro pares de alerta novos em
  `internal/alerts`. Painel acende com qualquer pendência; alerta só é
  **empurrado** quando houver atualização de **segurança** (evita spam sem
  perder visibilidade).
- **Task 6 — frontend**: rótulos em `SystemHealth.tsx` (`firewall-nat`
  "Regra de NAT", `wan-interface` "Interfaces WAN", `dns-resolver`
  "Resolver DNS", `system-updates` "Atualizações do sistema") e a lista
  expansível de pacotes pendentes via novo endpoint
  `GET /api/system/updates` (permissão `PermSystemRead`), seguindo a
  preferência já registrada por resumo colapsado + expandir.
