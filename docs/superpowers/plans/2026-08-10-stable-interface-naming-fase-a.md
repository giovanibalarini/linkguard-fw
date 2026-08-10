# Nomeação Estável de Interface por MAC (Fase A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gerar um arquivo `.link` do systemd por interface WAN física conhecida, casado por endereço MAC, para que o nome da interface pare de mudar quando hardware é adicionado/removido (o que quebrou a topologia de rede numa migração real em 2026-08-10).

**Architecture:** Reaproveita 100% o padrão já estabelecido em `internal/netif/networkd` (pacote `Render`/`Apply` pra `.network`, Fase 2): uma nova função pura `RenderLink` gera o conteúdo do arquivo `.link`, uma nova `WriteLinkFile` escreve atomicamente (sem `networkctl reload` — `.link` só pega no boot). O `Service` de `internal/netif` ganha a lógica de "quais interfaces são elegíveis e qual nome estável cada uma recebe", expondo preview (`GET`) e apply (`POST`) via API, com uma seção nova na tela de Interfaces existente.

**Tech Stack:** Go 1.25 (backend), React/TypeScript + Vite (frontend), SQLite via `internal/storage`, systemd `.link` files.

## Global Constraints

- Escopo desta fase: **só interfaces físicas com `Role == RoleWAN`** (associadas a um `links.Link` configurado). Membros de bridge LAN ficam fora — a spec (`docs/superpowers/specs/2026-08-10-networkd-cutover-and-fase3-design.md` §5) explica por quê: participação em bridge ainda não é um conceito de primeira classe no modelo, isso chega com a Fase C.
- `.link` **nunca** tem efeito sem reboot — nenhuma linha de código nesta fase deve chamar `networkctl reload` nem qualquer coisa que tente re-disparar a interface ao vivo (decisão explícita da spec §3: recriar uma NIC de produção com tráfego passando não é seguro).
- Nome de interface do kernel tem limite rígido de 15 caracteres (`IFNAMSIZ-1`) — todo nome gerado tem que caber nisso, sempre, sem truncar silenciosamente pra um valor inválido.
- Todo arquivo escrito no disco carrega o cabeçalho `# managed by linkguard` (mesma convenção já usada em `Render`/`Apply` de `.network`).
- TDD real: teste que falha primeiro, depois a implementação mínima pra passar.

---

### Task 1: `RenderLink` e `WriteLinkFile` em `internal/netif/networkd`

**Files:**
- Create: `internal/netif/networkd/link.go`
- Create: `internal/netif/networkd/link_test.go`

**Interfaces:**
- Consumes: `ConfigFile{Path, Content}` (já existe em `internal/netif/networkd/networkd.go`); `defaultNetworkDir` (const já existente, `"/etc/systemd/network"`); `firewall.Executor` (interface já existente, método `IsDryRun() bool`).
- Produces: `func RenderLink(mac, name, dir string) ConfigFile` e `func WriteLinkFile(exec firewall.Executor, f ConfigFile) error` — usados pela Task 2.

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/netif/networkd/link_test.go`:

```go
package networkd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reuses fakeApplyExec, already defined in networkd_test.go (same package,
// same test binary) for Render/Apply's own tests — no new fake executor
// type needed. fakeApplyExec.Execute only special-cases "networkctl"
// (recording to reloadCalls) and errors on anything else, which is exactly
// right here: WriteLinkFile must never call Execute at all (it only checks
// IsDryRun before doing its own os.* calls directly), so reusing it doubles
// as proof that no unexpected command gets shelled out.

func TestRenderLinkMatchesByMACAndPinsName(t *testing.T) {
	f := RenderLink("b8:ca:3a:fc:d6:03", "lg-wan-vivo", "/etc/systemd/network")

	if want := "/etc/systemd/network/10-lg-wan-vivo.link"; f.Path != want {
		t.Errorf("Path = %q, want %q", f.Path, want)
	}
	for _, want := range []string{
		"# managed by linkguard",
		"[Match]",
		"MACAddress=b8:ca:3a:fc:d6:03",
		"[Link]",
		"Name=lg-wan-vivo",
	} {
		if !strings.Contains(f.Content, want) {
			t.Errorf("content missing %q:\n%s", want, f.Content)
		}
	}
}

func TestRenderLinkDefaultsDir(t *testing.T) {
	f := RenderLink("aa:bb:cc:dd:ee:ff", "lg-test", "")
	if !strings.HasPrefix(f.Path, defaultNetworkDir+"/") {
		t.Errorf("Path = %q, want prefix %q", f.Path, defaultNetworkDir+"/")
	}
}

func TestWriteLinkFileWritesContentAtomically(t *testing.T) {
	dir := t.TempDir()
	f := RenderLink("b8:ca:3a:fc:d6:03", "lg-wan-vivo", dir)
	exec := &fakeApplyExec{}

	if err := WriteLinkFile(exec, f); err != nil {
		t.Fatalf("WriteLinkFile: %v", err)
	}

	got, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != f.Content {
		t.Errorf("file content = %q, want %q", got, f.Content)
	}
	// No stray temp file left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected exactly 1 file in %s, got %d: %v", dir, len(entries), entries)
	}
	if len(exec.reloadCalls) != 0 {
		t.Error("WriteLinkFile must never call `networkctl reload` — .link only takes effect on reboot (spec §3)")
	}
}

func TestWriteLinkFileNoopInDryRun(t *testing.T) {
	dir := t.TempDir()
	f := RenderLink("b8:ca:3a:fc:d6:03", "lg-wan-vivo", filepath.Join(dir, "sub"))

	if err := WriteLinkFile(&fakeApplyExec{dryRun: true}, f); err != nil {
		t.Fatalf("WriteLinkFile in dry-run: %v", err)
	}
	if _, err := os.Stat(f.Path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected no file written in dry-run, got err=%v", err)
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
cd /home/gov/Documentos/Projetos/gbtech/repos/linkguard-fw
export PATH=$HOME/sdk/go1.25.0/bin:$PATH
go test ./internal/netif/networkd/... -run 'TestRenderLink|TestWriteLinkFile' -v
```

Esperado: `FAIL` — `RenderLink`/`WriteLinkFile` não existem ainda (`undefined: RenderLink`).

- [ ] **Step 3: Implementar**

Criar `internal/netif/networkd/link.go`:

```go
// Package networkd (this file): .link files pin a persistent kernel
// interface name to a physical NIC's MAC address, independent of PCI slot
// position — see
// docs/superpowers/specs/2026-08-10-networkd-cutover-and-fase3-design.md §3.
// Separate from Render/Apply (.network) because .link files have different
// semantics: read by udev at coldplug, never hot-reloaded, so writing one
// never calls `networkctl reload`.
package networkd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// RenderLink produces a systemd .link file that pins name to whatever
// physical NIC currently has mac. Pure — no I/O, mirrors Render's
// signature/style: dir "" means defaultNetworkDir in production, tests pass
// a t.TempDir().
func RenderLink(mac, name, dir string) ConfigFile {
	if dir == "" {
		dir = defaultNetworkDir
	}
	var body strings.Builder
	body.WriteString("# managed by linkguard\n\n")
	body.WriteString("[Match]\n")
	fmt.Fprintf(&body, "MACAddress=%s\n\n", mac)
	body.WriteString("[Link]\n")
	fmt.Fprintf(&body, "Name=%s\n", name)

	return ConfigFile{
		Path:    fmt.Sprintf("%s/10-%s.link", dir, name),
		Content: body.String(),
	}
}

// WriteLinkFile writes a .link file atomically (temp file + rename, same
// pattern as Apply) but deliberately does NOT call `networkctl reload` —
// .link files are read by udev at coldplug, not by networkd's live reload,
// so they only take effect after a reboot. Re-triggering a live production
// NIC with traffic passing is explicitly out of scope (spec §3) — always
// reboot, never re-trigger. A no-op in dry-run mode, same convention as
// Apply/Remove.
func WriteLinkFile(exec firewall.Executor, f ConfigFile) error {
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
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("ajustar permissão do arquivo temporário: %w", err)
	}
	if err := os.Rename(tmpPath, f.Path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("mover %s para %s: %w", tmpPath, f.Path, err)
	}
	return nil
}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/netif/networkd/... -v
```

Esperado: `PASS` em todos os testes do pacote (os novos e os já existentes de `Render`/`Apply`/`Remove`).

- [ ] **Step 5: Commit**

```bash
git add internal/netif/networkd/link.go internal/netif/networkd/link_test.go
git commit -m "feat(netif): render+write systemd .link files pinned by MAC"
```

---

### Task 2: Cálculo do nome estável em `internal/netif`

**Files:**
- Create: `internal/netif/stablenames.go`
- Create: `internal/netif/stablenames_test.go`

**Interfaces:**
- Consumes: `Service` struct e `NewService` (já existentes, `internal/netif/service.go`); `Service.List(ctx) ([]IfaceView, error)` (já existente); `s.linkSvc.List() ([]storage.Link, error)` (já existente, `internal/links`); `IfaceView{Name, Kind, Role, Live LiveState}`, `LiveState{MAC string}`, `KindPhysical`, `RoleWAN` (todos já existentes em `internal/netif/netif.go`); `networkd.RenderLink`, `networkd.WriteLinkFile` (Task 1).
- Produces: `type StableNameEntry struct{ Interface, MAC, LinkName, StableName string }`; `func (s *Service) StableNames(ctx) ([]StableNameEntry, error)`; `func (s *Service) ApplyStableNames(ctx) ([]StableNameEntry, error)` — usados pela Task 3 (handlers).

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/netif/stablenames_test.go`:

```go
package netif

import (
	"context"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TestStableNamesOnlyCoversPhysicalWANWithKnownMAC is the regression test
// for the 2026-08-10 incident: enp5s0 (WAN1) silently became enp4s0 after a
// hardware change, and the whole LAN/WAN topology had to be rebuilt by hand.
// wlp2s0 (sampleLinkJSON, MAC f4:8c:50:1b:c3:b2) is configured as a WAN
// Link named "WAN" — must get a stable "lg-wan" name. enp0s31f6 has no
// configured Link — must be skipped entirely (not WAN).
func TestStableNamesOnlyCoversPhysicalWANWithKnownMAC(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	if err := linkSvc.Create(&storage.Link{ID: "wan1", Name: "WAN", Interface: "wlp2s0", Weight: 1}); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	svc := NewService(exec, db, linkSvc)

	entries, err := svc.StableNames(context.Background())
	if err != nil {
		t.Fatalf("StableNames: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 entry (only wlp2s0 is WAN), got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Interface != "wlp2s0" {
		t.Errorf("Interface = %q, want %q", e.Interface, "wlp2s0")
	}
	if e.MAC != "f4:8c:50:1b:c3:b2" {
		t.Errorf("MAC = %q, want %q", e.MAC, "f4:8c:50:1b:c3:b2")
	}
	if e.LinkName != "WAN" {
		t.Errorf("LinkName = %q, want %q", e.LinkName, "WAN")
	}
	if e.StableName != "lg-wan" {
		t.Errorf("StableName = %q, want %q", e.StableName, "lg-wan")
	}
}

// TestStableIfaceNameTruncatesToKernelLimit is the regression test for a
// real correctness gap: Linux interface names are capped at IFNAMSIZ-1 (15
// chars). A long, perfectly reasonable admin-chosen Link name like "WAN
// Fibra Principal Sede" must never produce a name the kernel would reject —
// it has to be truncated deterministically instead.
func TestStableIfaceNameTruncatesToKernelLimit(t *testing.T) {
	got := stableIfaceName("WAN Fibra Principal Sede", "aa:bb:cc:dd:ee:ff", map[string]bool{})
	if len(got) > maxIfaceName {
		t.Errorf("stableIfaceName produced %q (%d chars), exceeds kernel limit of %d", got, len(got), maxIfaceName)
	}
	if got[:3] != "lg-" {
		t.Errorf("stableIfaceName = %q, expected lg- prefix", got)
	}
}

// TestStableIfaceNameDisambiguatesCollisions is the regression test for two
// Links whose names slugify to the same value (e.g. "WAN Vivo" and
// "wan-vivo" both -> "wan-vivo") — the second one must not silently
// overwrite the first's .link file with a colliding MACAddress= match.
func TestStableIfaceNameDisambiguatesCollisions(t *testing.T) {
	seen := map[string]bool{}
	first := stableIfaceName("WAN Vivo", "b8:ca:3a:fc:d6:03", seen)
	seen[first] = true
	second := stableIfaceName("wan-vivo", "f4:f2:6d:05:e2:f0", seen)

	if first == second {
		t.Fatalf("expected distinct names for colliding slugs, both got %q", first)
	}
	if len(second) > maxIfaceName {
		t.Errorf("disambiguated name %q (%d chars) exceeds kernel limit of %d", second, len(second), maxIfaceName)
	}
}

func TestApplyStableNamesWritesLinkFiles(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	if err := linkSvc.Create(&storage.Link{ID: "wan1", Name: "WAN", Interface: "wlp2s0", Weight: 1}); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	svc := NewService(exec, db, linkSvc)
	svc.networkDir = dir

	entries, err := svc.ApplyStableNames(context.Background())
	if err != nil {
		t.Fatalf("ApplyStableNames: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	wantPath := dir + "/10-lg-wan.link"
	content, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("expected .link file at %s: %v", wantPath, err)
	}
	if !strings.Contains(string(content), "MACAddress=f4:8c:50:1b:c3:b2") {
		t.Errorf(".link file missing expected MACAddress line:\n%s", content)
	}
}
```

O `import` no topo de `stablenames_test.go` precisa de `"os"` e `"strings"` além de `"context"`/`"testing"` (usados por `os.ReadFile`/`strings.Contains` acima):

```go
import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/netif/... -run 'TestStableNames|TestStableIfaceName|TestApplyStableNames' -v
```

Esperado: `FAIL` — `StableNames`, `stableIfaceName`, `maxIfaceName`, `ApplyStableNames` não existem ainda.

- [ ] **Step 3: Implementar**

Criar `internal/netif/stablenames.go`:

```go
// This file: Fase A da nomeação estável de interface — ver
// docs/superpowers/specs/2026-08-10-networkd-cutover-and-fase3-design.md §3.
// Escopo desta fase: só interfaces físicas com Role == RoleWAN. Membro de
// bridge LAN fica de fora — participação em bridge ainda não é um conceito
// de primeira classe no modelo (chega na Fase C), então não há um jeito
// confiável de saber "este membro deveria ter nome estável" sem inferir a
// partir do estado vivo do kernel, o que essa fase evita de propósito.
package netif

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/netif/networkd"
)

// maxIfaceName is IFNAMSIZ-1, o limite rígido do kernel Linux pro nome de
// uma interface de rede. Todo nome gerado por esta fase tem que caber aqui,
// sempre — não existe truncamento "silencioso" aceitável, o kernel rejeita
// (ou trunca de um jeito imprevisível) um rename além disso.
const maxIfaceName = 15

// StableNameEntry is one physical WAN interface eligible for a persistent,
// MAC-matched kernel name.
type StableNameEntry struct {
	Interface  string `json:"interface"`
	MAC        string `json:"mac"`
	LinkName   string `json:"link_name"`
	StableName string `json:"stable_name"`
}

// StableNames previews the stable name every eligible interface would get,
// without writing anything.
func (s *Service) StableNames(ctx context.Context) ([]StableNameEntry, error) {
	views, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	wanLinkNames, err := s.wanLinkNamesByInterface()
	if err != nil {
		return nil, err
	}
	return stableNameEntries(views, wanLinkNames), nil
}

// ApplyStableNames writes the .link file for every eligible interface.
// Best-effort per file: one failure doesn't block the rest — every error is
// joined and returned so the caller can report exactly which interfaces
// didn't get a stable name, while the ones that succeeded still take
// effect after the next reboot (this never applies live — see
// networkd.WriteLinkFile).
func (s *Service) ApplyStableNames(ctx context.Context) ([]StableNameEntry, error) {
	entries, err := s.StableNames(ctx)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, e := range entries {
		f := networkd.RenderLink(e.MAC, e.StableName, s.networkDir)
		if err := networkd.WriteLinkFile(s.exec, f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Interface, err))
		}
	}
	return entries, errors.Join(errs...)
}

func (s *Service) wanLinkNamesByInterface() (map[string]string, error) {
	linksList, err := s.linkSvc.List()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	out := make(map[string]string, len(linksList))
	for _, l := range linksList {
		out[l.Interface] = l.Name
	}
	return out, nil
}

// stableNameEntries computes, but does not write, the stable name for every
// eligible interface — shared by StableNames and ApplyStableNames.
func stableNameEntries(views []IfaceView, wanLinkNames map[string]string) []StableNameEntry {
	seen := make(map[string]bool, len(views))
	var entries []StableNameEntry
	for _, v := range views {
		if v.Kind != KindPhysical || v.Role != RoleWAN || v.Live.MAC == "" {
			continue
		}
		linkName, ok := wanLinkNames[v.Name]
		if !ok {
			continue
		}
		stable := stableIfaceName(linkName, v.Live.MAC, seen)
		seen[stable] = true
		entries = append(entries, StableNameEntry{
			Interface:  v.Name,
			MAC:        v.Live.MAC,
			LinkName:   linkName,
			StableName: stable,
		})
	}
	return entries
}

// stableIfaceName derives a kernel-safe, human-readable interface name from
// a link's admin-chosen name — "WAN VIVO" -> "lg-wan-vivo" — truncated to
// fit maxIfaceName, and disambiguated against seen (already-assigned names
// in this batch) by appending a short MAC-derived suffix on collision.
func stableIfaceName(linkName, mac string, seen map[string]bool) string {
	const prefix = "lg-"
	slug := slugify(linkName)
	budget := maxIfaceName - len(prefix)
	if len(slug) > budget {
		slug = slug[:budget]
	}
	name := prefix + slug
	if !seen[name] {
		return name
	}
	suffix := strings.ReplaceAll(mac, ":", "")
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	budget = maxIfaceName - len(prefix) - len(suffix) - 1
	if budget < 0 {
		budget = 0
	}
	if len(slug) > budget {
		slug = slug[:budget]
	}
	return prefix + slug + "-" + suffix
}

// slugify converts a human-chosen name into a lowercase, hyphen-separated
// token safe for a systemd/kernel interface name.
func slugify(s string) string {
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevHyphen = false
		default:
			if !prevHyphen && b.Len() > 0 {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/netif/... -v
```

Esperado: `PASS` em todos os testes do pacote (novos e pré-existentes — `stablenames.go` não muda nenhum comportamento de `List`/`Preview`/`Apply` já existente).

- [ ] **Step 5: Commit**

```bash
git add internal/netif/stablenames.go internal/netif/stablenames_test.go
git commit -m "feat(netif): compute stable MAC-matched names for WAN interfaces"
```

---

### Task 3: Endpoints da API

**Files:**
- Modify: `internal/api/handlers/netif.go`
- Modify: `internal/api/server.go`
- Test: `internal/api/handlers/netif_test.go` (criar se não existir)

**Interfaces:**
- Consumes: `netif.Service.StableNames`/`ApplyStableNames` (Task 2); `writeJSON`, `writeInternalError`, `auditAction` (já existentes em `internal/api/handlers/helpers.go`); `auth.PermInterfacesRead`/`PermInterfacesWrite` (já existentes).
- Produces: `GET /api/interfaces/stable-names`, `POST /api/interfaces/stable-names/apply` — consumidos pela Task 4 (frontend).

- [ ] **Step 1: Escrever o teste que falha**

Verificar primeiro se `internal/api/handlers/netif_test.go` já existe:

```bash
ls internal/api/handlers/netif_test.go 2>&1
```

Se não existir, criar com este conteúdo (se existir, adicionar as duas funções de teste abaixo ao arquivo existente, reaproveitando os imports que já estiverem lá):

```go
package handlers_test

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/netif"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestStableNamesReturnsEmptyListNotNull(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	linkSvc := links.NewService(db)
	svc := netif.NewService(&fakeNftExec{ruleset: "table inet linkguard {}\n"}, db, linkSvc)
	h := handlers.NewNetifHandler(svc, db)

	r := httptest.NewRequest("GET", "/api/interfaces/stable-names", nil)
	w := httptest.NewRecorder()
	h.StableNames(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if w.Body.String() == "null\n" {
		t.Error("expected [], got null — frontend .map() would crash on this")
	}
}
```

`fakeNftExec` já existe em `internal/api/handlers/nftables_snapshot_test.go` (mesmo pacote de teste `handlers_test`) — reaproveitado aqui sem redefinir. Ele serve porque `netif.Service.List` só precisa de um `firewall.Executor` que responda a `ip -j link/addr show` e `cat /proc/net/dev`; sem nenhum link WAN configurado, a lista de interfaces físicas vem vazia (o "ip -j" real da máquina de teste não é mockado aqui — `ExecuteRead` do `fakeNftExec` devolve `""` pra qualquer comando que não seja `nft list ruleset`, e `parseLinks("")`/`parseAddrs("")` retornam listas vazias, não erro) — o teste teria zero entradas de qualquer forma, e é exatamente esse caso vazio que ele verifica.

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/api/handlers/... -run TestStableNamesReturnsEmptyListNotNull -v
```

Esperado: `FAIL` — `h.StableNames` não existe (`NetifHandler` não tem esse método ainda).

- [ ] **Step 3: Implementar**

Em `internal/api/handlers/netif.go`, adicionar (perto dos outros métodos do mesmo handler, ex.: logo após `Pending`):

```go
// StableNames previews the persistent MAC-matched names Fase A would
// assign to configured WAN interfaces — see
// docs/superpowers/specs/2026-08-10-networkd-cutover-and-fase3-design.md §3.
func (h *NetifHandler) StableNames(w http.ResponseWriter, r *http.Request) {
	entries, err := h.svc.StableNames(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if entries == nil {
		entries = []netif.StableNameEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// ApplyStableNames writes the .link files. This never takes effect until
// the next reboot (see WriteLinkFile) — requires_reboot=true in the
// response tells the frontend to say so explicitly instead of implying it
// already happened.
func (h *NetifHandler) ApplyStableNames(w http.ResponseWriter, r *http.Request) {
	entries, err := h.svc.ApplyStableNames(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "apply", "interfaces/stable-names", fmt.Sprintf("%d", len(entries)))
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":         entries,
		"requires_reboot": true,
	})
}
```

Se `"fmt"` ainda não estiver importado em `internal/api/handlers/netif.go`, adicionar ao bloco de import existente.

Em `internal/api/server.go`, adicionar as duas rotas logo após a linha existente `r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces/pending", netifH.Pending)` (mesmo bloco de rotas de `/api/interfaces/*`):

```go
r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces/stable-names", netifH.StableNames)
r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/stable-names/apply", netifH.ApplyStableNames)
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/api/handlers/... -v
go build ./...
go vet ./...
```

Esperado: `PASS` em tudo, `go build`/`go vet` limpos.

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/netif.go internal/api/handlers/netif_test.go internal/api/server.go
git commit -m "feat(api): expose GET/POST /api/interfaces/stable-names"
```

---

### Task 4: Seção "Nomes estáveis" na tela de Interfaces

**Files:**
- Modify: `web/src/pages/Interfaces.tsx`
- Modify: `web/src/types/index.ts`

**Interfaces:**
- Consumes: `GET /api/interfaces/stable-names`, `POST /api/interfaces/stable-names/apply` (Task 3); `client` (axios wrapper já existente, `web/src/api/client.ts`); `Panel` (já existente, `web/src/components/ui/Panel.tsx`).
- Produces: nada consumido por outra task — é a ponta final da fatia.

- [ ] **Step 1: Adicionar o tipo no frontend**

Em `web/src/types/index.ts`, logo após a definição de `IfaceView` (linha ~482, antes de `PendingChange`):

```ts
export interface StableNameEntry {
  interface: string;
  mac: string;
  link_name: string;
  stable_name: string;
}
```

- [ ] **Step 2: Adicionar estado e efeito de carga em `Interfaces.tsx`**

Junto aos outros `useState` no topo do componente (perto de `const [pending, setPending] = useState<PendingChange[]>([]);`):

```tsx
const [stableNames, setStableNames] = useState<StableNameEntry[]>([]);
const [applyingStable, setApplyingStable] = useState(false);
const [stableApplied, setStableApplied] = useState(false);
```

Atualizar o import de tipos no topo do arquivo:

```tsx
import type { IfaceView, PendingChange, StableNameEntry } from '../types';
```

Junto aos outros `useEffect` que carregam dado da API (perto do que carrega `pending`):

```tsx
useEffect(() => {
  (async () => {
    try {
      const { data } = await client.get<StableNameEntry[]>('/api/interfaces/stable-names');
      setStableNames(data);
    } catch {
      // silencioso — igual ao padrão já usado pro carregamento de `pending` acima:
      // uma falha aqui não deve travar o resto da tela.
    }
  })();
}, []);

const applyStableNames = async () => {
  setApplyingStable(true);
  try {
    await client.post('/api/interfaces/stable-names/apply');
    setStableApplied(true);
  } catch {
    // erro real de escrita em disco é raro (permissão, disco cheio) — o
    // handler já loga o detalhe real via writeInternalError; a UI só
    // precisa não travar.
  } finally {
    setApplyingStable(false);
  }
};
```

- [ ] **Step 3: Renderizar o painel**

Dentro do bloco `{tab === 'overview' && (...)}`, logo depois do `</Panel>` que fecha "Painel traseiro" (linha ~282) e antes do `)}` que fecha o bloco condicional da aba:

```tsx
{stableNames.length > 0 && (
  <Panel title="Nomes estáveis por MAC">
    <p className="text-gray-500 text-sm mb-3">
      Fixa o nome de cada interface WAN pelo endereço MAC da placa, não pela
      posição física no computador — troca de hardware não muda mais o nome.
      Só tem efeito depois de um <b>reboot</b>.
    </p>
    <div className="space-y-2 mb-3">
      {stableNames.map((e) => (
        <div key={e.interface} className="flex items-center justify-between text-sm border-b border-gray-800/50 last:border-0 py-1.5">
          <span className="text-gray-400">{e.link_name}</span>
          <span className="text-gray-600 font-mono text-xs">{e.mac}</span>
          <span className="text-white font-mono">{e.interface} → {e.stable_name}</span>
        </div>
      ))}
    </div>
    {stableApplied ? (
      <p className="text-green-400 text-sm">Aplicado — reinicie a máquina para os nomes valerem.</p>
    ) : (
      <button onClick={applyStableNames} disabled={applyingStable} className="btn-primary text-sm disabled:opacity-50">
        {applyingStable ? 'Aplicando…' : 'Aplicar (requer reboot)'}
      </button>
    )}
  </Panel>
)}
```

- [ ] **Step 4: Verificar que compila**

```bash
export PATH=$HOME/.nvm/versions/node/v22.21.1/bin:$PATH
cd web && npm run build
```

Esperado: build limpo (`tsc -b && vite build` sem erro).

- [ ] **Step 5: Testar manualmente com Playwright na VM de teste**

Reaproveitar `~/linkguard-testvm/` (já configurada, ver memória `linkguard-test-vm`): `./recreate.sh`, instalar o `.deb` novo, restaurar um `linkguard.db` com pelo menos um `Link` configurado, logar no painel, abrir Interfaces → aba Visão geral, confirmar que a seção "Nomes estáveis por MAC" aparece com a entrada esperada, clicar "Aplicar", confirmar a mensagem de sucesso e — via SSH na VM — que o arquivo `.link` foi escrito em `/etc/systemd/network/` com o conteúdo esperado.

- [ ] **Step 6: Commit**

```bash
git add web/src/pages/Interfaces.tsx web/src/types/index.ts
git commit -m "feat(ui): show and apply stable MAC-matched interface names"
```

---

## Depois deste plano

Este plano cobre só a Fase A. A Fase B (corte ifupdown→networkd em produção) e a Fase C (criar VLAN/bridge) do spec `2026-08-10-networkd-cutover-and-fase3-design.md` continuam como specs/planos separados e futuros — Fase B em particular precisa de uma janela de manutenção própria, não deploy no fluxo normal.
