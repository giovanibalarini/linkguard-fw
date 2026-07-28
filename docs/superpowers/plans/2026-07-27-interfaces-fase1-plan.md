# Interfaces — Fase 1 (visão geral somente leitura) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dar ao LinkGuard uma visão real e diagnosticável da topologia de rede (física, VLAN, bridge) — árvore de topologia, listagem, estado físico ao vivo, identificação de porta — sem escrever nada na configuração de rede.

**Architecture:** Novo pacote `internal/netif` (modelo + importador puro a partir de `ip -j`) espelhando o padrão já usado em `internal/netsvc`/`internal/hosts`. Zero persistência nesta fase — tudo é derivado ao vivo do kernel a cada requisição, como `internal/hosts` já faz para o inventário de hosts. `Interfaces.tsx` (hoje só gráfico de tráfego) vira uma casca com abas; o gráfico existente muda de arquivo, não de comportamento.

**Tech Stack:** Go 1.25 (`internal/netif`, chi router), React+TypeScript+Vite (Tabs novo do sistema de design do sub-projeto 1).

## Global Constraints

- **Escopo é só a Fase 1** da spec `docs/superpowers/specs/2026-07-19-network-interface-management-design.md`: modelo, importador, classificação de ruído, visão geral+listagem somente leitura, diagnóstico físico, identificar porta. Nada de `Provider.Apply`, commit/confirm, VLAN/bridge criação, histórico ou deriva de verdade — isso são as Fases 2-4, em planos futuros.
- **Nenhuma escrita de rede.** A única ação de escrita desta fase é "piscar LED" (`ethtool -p`), que não muda configuração nenhuma — só identifica fisicamente. Fica atrás de `interfaces.write` e é registrada em auditoria, igual a qualquer outra ação de escrita do produto.
- **Nunca dado fabricado.** `GET /api/interfaces/drift` retorna lista vazia nesta fase (deriva de verdade é Fase 4) — o frontend não deve tratar isso como "nenhuma interface tem deriva ainda com certeza", mas simplesmente não exibir nenhum indicador de deriva agora (a UI desta fase não tem conceito de deriva na tela).
- **Desvio documentado do texto literal da spec de 19/07, decidido ao escrever este plano:** a spec (§7) lista `networkctl -j` como uma das três fontes do importador. A máquina de produção **ainda roda `ifupdown`, não `systemd-networkd`** (a migração é spec futura separada, citada na própria spec de 19/07 §14) — `networkctl` não é confiável para diagnóstico hoje. `ip -d -j link show` já traz tudo que a Fase 1 precisa para tipo/pai/membros (`linkinfo.info_kind`, `master`), e `ip -j addr show` já marca o endereço como `dynamic:true`/ausente — o suficiente para inferir `AddrMode` sem depender do `networkctl`. Esta fase usa **só `ip -d -j link show` + `ip -j addr show`** (confirmado empiricamente nesta máquina de dev — ver amostras reais nas Tasks 1-2). `networkctl` volta a ser avaliado quando a migração do servidor de produção acontecer.
- **`Tabs` (sistema de design, sub-projeto 1) é construído aqui** — esta é a primeira tela com abas de verdade.
- **Sem framework de teste unitário no frontend** (mesmo padrão do sub-projeto 1) — verificação é `npm run build` por tarefa + Playwright local no final. Backend usa `go test`, prefixado com `PATH=/home/gov/sdk/go1.25.0/bin:$PATH` (obrigatório neste ambiente — `go` não está no PATH padrão).
- **Sem chassi visual de portas físicas** (decidido no adendo de 27/07 via comparativo visual) — árvore + tabela cobrem a mesma necessidade por ora.
- **Interfaces de sistema** (`lo`, `docker*`, `br-<hex>`, `veth*`, `tun*`, `tap*`, `wg*`) ficam ocultas por padrão, agrupadas com opção de exibir — spec §7.1.
- **Alias reusa `interface_aliases`** (setting key já existente, usado por `/api/system/interface-aliases`) — não criar mecanismo paralelo. **Role (WAN/LAN)** é derivado cruzando com `internal/links.Service.List()` (interfaces que já são um `Link` configurado) e com o `netsvc.Config.Interface` (a bridge que serve DHCP/DNS) — nunca um heurístico novo; é rótulo, não comportamento (spec §5.1).

---

### Task 1: `internal/netif` — modelo + classificação de ruído (puro)

**Files:**
- Create: `internal/netif/netif.go`
- Test: `internal/netif/netif_test.go`

**Interfaces:**
- Produces: `type Kind string` (`KindPhysical`/`KindVLAN`/`KindBridge`), `type AddrMode string` (`AddrModeStatic`/`AddrModeDHCP`/`AddrModeNone`), `type Role string` (`RoleWAN`/`RoleLAN`/`RoleUnassigned`), `type Address struct{ Family, IP, CIDR string }`, `type Iface struct{...}`, `type LiveState struct{...}`, `type IfaceView struct{ Iface; Live LiveState }`, `func isSystemInterface(name string) bool`

- [ ] **Step 1: Write the failing test for system-interface classification**

Create `internal/netif/netif_test.go`:

```go
package netif

import "testing"

func TestIsSystemInterface(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"lo", true},
		{"docker0", true},
		{"br-0293233c552c", true}, // docker's hash-named bridges — real name captured on this dev machine
		{"veth3f8a21b", true},
		{"tun0", true},
		{"tap0", true},
		{"wg0", true},
		{"eth0", false},
		{"wlp2s0", false},
		{"br10", false}, // LAN bridge the admin created — NOT a docker br-<hex>
		{"vlan100", false},
	}
	for _, c := range cases {
		if got := isSystemInterface(c.name); got != c.want {
			t.Errorf("isSystemInterface(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -run TestIsSystemInterface -v`
Expected: FAIL — `isSystemInterface` (and the package) doesn't exist yet.

- [ ] **Step 3: Write the model and classification function**

Create `internal/netif/netif.go`:

```go
// Package netif models network interfaces (physical, VLAN, bridge) as
// first-class entities. Phase 1 is read-only: the model is derived live from
// kernel state via `ip -j`, never written back. Applying configuration
// (systemd-networkd) is a later phase — see
// docs/superpowers/specs/2026-07-19-network-interface-management-design.md.
package netif

import "strings"

// Kind identifies what an interface is.
type Kind string

const (
	KindPhysical Kind = "physical"
	KindVLAN     Kind = "vlan"
	KindBridge   Kind = "bridge"
)

// AddrMode describes how an interface gets its IPv4 address.
type AddrMode string

const (
	AddrModeStatic AddrMode = "static"
	AddrModeDHCP   AddrMode = "dhcp"
	AddrModeNone   AddrMode = "none"
)

// Role is a display label, not behavior — the real WAN/LAN designation comes
// from links.Link (WAN) and netsvc.Config (LAN), which this package's
// Service cross-references. Never treated as authoritative on its own.
type Role string

const (
	RoleWAN        Role = "wan"
	RoleLAN        Role = "lan"
	RoleUnassigned Role = "unassigned"
)

// Address is one IP address observed live on an interface.
type Address struct {
	Family string `json:"family"` // "ipv4" | "ipv6"
	IP     string `json:"ip"`
	CIDR   string `json:"cidr"`
}

// Iface is one network interface. Name is the stable identifier — the same
// string internal/links.Link.Interface and DHCP config already reference.
// This is the core model that will eventually be persisted (Phase 2+);
// Managed is always false in Phase 1 (nothing is adopted yet).
type Iface struct {
	Name        string   `json:"name"`
	Kind        Kind     `json:"kind"`
	Alias       string   `json:"alias,omitempty"`
	Description string   `json:"description,omitempty"`
	Parent      string   `json:"parent,omitempty"`  // vlan: parent NIC name
	VLANID      int      `json:"vlan_id,omitempty"` // vlan: 1-4094
	Members     []string `json:"members,omitempty"` // bridge: member interface names
	AddrMode    AddrMode `json:"addr_mode"`
	Role        Role     `json:"role"`
	Managed     bool     `json:"managed"`
}

// LiveState is diagnostic data read fresh from the kernel on every request —
// deliberately never persisted alongside Iface (spec §9.1).
type LiveState struct {
	Carrier   bool      `json:"carrier"`
	Speed     string    `json:"speed,omitempty"` // e.g. "1000M full"; empty if down or not physical
	MAC       string    `json:"mac,omitempty"`
	MTU       int       `json:"mtu,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
	RxErrors  uint64    `json:"rx_errors"`
	TxErrors  uint64    `json:"tx_errors"`
	RxDropped uint64    `json:"rx_dropped"`
	TxDropped uint64    `json:"tx_dropped"`
	System    bool      `json:"system"` // classified as noise (docker/veth/tun/etc) — hidden by default
}

// IfaceView is the model + live state combined — the shape the API returns.
type IfaceView struct {
	Iface
	Live LiveState `json:"live"`
}

// systemPrefixes are interface name prefixes that mark "system noise" —
// spec §7.1. lo is an exact match, the rest are prefixes.
var systemPrefixes = []string{"docker", "br-", "veth", "tun", "tap", "wg"}

// isSystemInterface reports whether name is system/infrastructure noise that
// should be grouped and hidden by default, rather than a network interface an
// admin manages. Deliberately conservative: "br-<hex>" (docker's
// auto-generated bridge names) is noise, but "br10" (an admin-named LAN
// bridge) is not — the distinction is the literal "br-" prefix, not "br"
// alone.
func isSystemInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range systemPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -run TestIsSystemInterface -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netif/netif.go internal/netif/netif_test.go
git commit -m "feat(netif): modelo Iface/LiveState + classificação de interface de sistema"
```

---

### Task 2: `internal/netif` — parser de `ip -j link`/`ip -j addr`

**Files:**
- Create: `internal/netif/parser.go`
- Test: `internal/netif/parser_test.go`

**Interfaces:**
- Consumes: `Kind`, `AddrMode`, `Address`, `LiveState`, `isSystemInterface` (Task 1)
- Produces: `func parseLinks(ipLinkJSON string) ([]parsedLink, error)`, `func parseAddrs(ipAddrJSON string) (map[string][]addrInfo, error)`, `func mergeLinks(links []parsedLink, addrs map[string][]addrInfo) []IfaceView` (unexported types `parsedLink`/`addrInfo` — internal to the package, consumed by `Service` in Task 3 via `mergeLinks`)

- [ ] **Step 1: Write the failing test with real captured JSON**

Create `internal/netif/parser_test.go`. The samples below are real output captured with `ip -d -j link show` / `ip -j addr show` on a development machine (trimmed to the interfaces that exercise each case — loopback, a system bridge, a physical NIC with a DHCP IPv4 address, and a down NIC with no address):

```go
package netif

import "testing"

// Real sample captured from `ip -d -j link show` (trimmed to 4 representative
// interfaces: loopback, a down physical NIC, an up physical NIC, and a
// docker-managed bridge — the last is exactly the "br-<hex>" noise case).
const sampleLinkJSON = `[
{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00"},
{"ifindex":2,"ifname":"enp0s31f6","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"8c:04:ba:1a:1f:34"},
{"ifindex":3,"ifname":"wlp2s0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"f4:8c:50:1b:c3:b2"},
{"ifindex":11,"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"16:9e:0e:d5:f5:55","linkinfo":{"info_kind":"bridge","info_data":{"stp_state":0}}}
]`

// Real sample captured from `ip -j addr show`, same 4 interfaces. wlp2s0 has
// a DHCP-assigned IPv4 (dynamic:true) plus IPv6 addresses; the others have no
// addr_info entries (enp0s31f6 is a down physical NIC with nothing
// configured, docker0/lo omitted from this trimmed sample for brevity since
// their addressing isn't exercised by this test).
const sampleAddrJSON = `[
{"ifindex":2,"ifname":"enp0s31f6","addr_info":[]},
{"ifindex":3,"ifname":"wlp2s0","addr_info":[{"family":"inet","local":"192.168.3.61","prefixlen":24,"scope":"global","dynamic":true},{"family":"inet6","local":"fd41:4da5:216d:9457:1039:fad7:8cb:1996","prefixlen":64,"scope":"global","temporary":true,"dynamic":true}]}
]`

func TestParseLinks(t *testing.T) {
	links, err := parseLinks(sampleLinkJSON)
	if err != nil {
		t.Fatalf("parseLinks: %v", err)
	}
	if len(links) != 4 {
		t.Fatalf("expected 4 links, got %d", len(links))
	}

	byName := make(map[string]parsedLink, len(links))
	for _, l := range links {
		byName[l.Name] = l
	}

	if lo := byName["lo"]; lo.Kind != KindPhysical {
		t.Errorf("lo: expected KindPhysical (no linkinfo.info_kind), got %v", lo.Kind)
	}
	if wl := byName["wlp2s0"]; !wl.Carrier {
		t.Errorf("wlp2s0: expected carrier=true (LOWER_UP flag present), got false")
	}
	if en := byName["enp0s31f6"]; en.Carrier {
		t.Errorf("enp0s31f6: expected carrier=false (NO-CARRIER flag), got true")
	}
	if dk := byName["docker0"]; dk.Kind != KindBridge {
		t.Errorf("docker0: expected KindBridge (linkinfo.info_kind=bridge), got %v", dk.Kind)
	}
}

func TestParseAddrs(t *testing.T) {
	addrs, err := parseAddrs(sampleAddrJSON)
	if err != nil {
		t.Fatalf("parseAddrs: %v", err)
	}
	wl := addrs["wlp2s0"]
	if len(wl) != 2 {
		t.Fatalf("wlp2s0: expected 2 addresses, got %d: %+v", len(wl), wl)
	}
	var sawDynamicIPv4 bool
	for _, a := range wl {
		if a.Family == "inet" && a.Dynamic {
			sawDynamicIPv4 = true
		}
	}
	if !sawDynamicIPv4 {
		t.Error("wlp2s0: expected a dynamic (DHCP) IPv4 address_info entry")
	}
	if len(addrs["enp0s31f6"]) != 0 {
		t.Errorf("enp0s31f6: expected no addresses, got %+v", addrs["enp0s31f6"])
	}
}

func TestMergeLinksDerivesAddrModeAndSystemFlag(t *testing.T) {
	links, err := parseLinks(sampleLinkJSON)
	if err != nil {
		t.Fatalf("parseLinks: %v", err)
	}
	addrs, err := parseAddrs(sampleAddrJSON)
	if err != nil {
		t.Fatalf("parseAddrs: %v", err)
	}
	views := mergeLinks(links, addrs)

	byName := make(map[string]IfaceView, len(views))
	for _, v := range views {
		byName[v.Name] = v
	}

	if wl := byName["wlp2s0"]; wl.AddrMode != AddrModeDHCP {
		t.Errorf("wlp2s0: expected AddrModeDHCP (dynamic:true address), got %v", wl.AddrMode)
	}
	if en := byName["enp0s31f6"]; en.AddrMode != AddrModeNone {
		t.Errorf("enp0s31f6: expected AddrModeNone (no addresses), got %v", en.AddrMode)
	}
	if dk := byName["docker0"]; !dk.Live.System {
		t.Error("docker0: expected Live.System=true")
	}
	if wl := byName["wlp2s0"]; wl.Live.System {
		t.Error("wlp2s0: expected Live.System=false")
	}
	if len(views) != 4 {
		t.Fatalf("expected 4 views, got %d", len(views))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -run 'TestParseLinks|TestParseAddrs|TestMergeLinks' -v`
Expected: FAIL — `parseLinks`/`parseAddrs`/`mergeLinks`/`parsedLink`/`addrInfo` don't exist yet.

- [ ] **Step 3: Write the parser**

Create `internal/netif/parser.go`:

```go
package netif

import (
	"encoding/json"
	"fmt"
)

// rawLink mirrors the fields `ip -d -j link show` emits that this package
// needs. Many fields in the real output are ignored (qdisc, txqlen, group,
// etc.) — encoding/json silently drops unknown keys, which is exactly what
// we want here.
type rawLink struct {
	IfIndex  int      `json:"ifindex"`
	IfName   string   `json:"ifname"`
	Flags    []string `json:"flags"`
	MTU      int      `json:"mtu"`
	Address  string   `json:"address"`
	LinkType string   `json:"link_type"`
	Master   string   `json:"master,omitempty"`
	LinkInfo *struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			ID int `json:"id"` // vlan tag, only present when info_kind="vlan"
		} `json:"info_data"`
	} `json:"linkinfo,omitempty"`
}

// parsedLink is one interface as understood from `ip -d -j link show`, before
// address information is merged in.
type parsedLink struct {
	Name    string
	Kind    Kind
	Parent  string // vlan: not derivable from `ip -j link` alone; left empty here, filled by importer from ifindex->name lookup if needed by a later phase
	VLANID  int
	MAC     string
	MTU     int
	Carrier bool
	Master  string // bridge this interface is a member of, if any
}

// parseLinks parses `ip -d -j link show` JSON output into parsedLink records.
func parseLinks(ipLinkJSON string) ([]parsedLink, error) {
	var raw []rawLink
	if err := json.Unmarshal([]byte(ipLinkJSON), &raw); err != nil {
		return nil, fmt.Errorf("parsing ip -j link output: %w", err)
	}
	out := make([]parsedLink, 0, len(raw))
	for _, r := range raw {
		kind := KindPhysical
		vlanID := 0
		if r.LinkInfo != nil {
			switch r.LinkInfo.InfoKind {
			case "bridge":
				kind = KindBridge
			case "vlan":
				kind = KindVLAN
				vlanID = r.LinkInfo.InfoData.ID
			}
		}
		carrier := false
		for _, f := range r.Flags {
			if f == "LOWER_UP" {
				carrier = true
			}
		}
		out = append(out, parsedLink{
			Name:    r.IfName,
			Kind:    kind,
			VLANID:  vlanID,
			MAC:     r.Address,
			MTU:     r.MTU,
			Carrier: carrier,
			Master:  r.Master,
		})
	}
	return out, nil
}

// rawAddrEntity mirrors one interface's entry in `ip -j addr show` output.
type rawAddrEntity struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
		Dynamic   bool   `json:"dynamic"`
	} `json:"addr_info"`
}

// addrInfo is one address observed on an interface, with the DHCP/static
// signal (Dynamic) that `ip -j addr` already reports.
type addrInfo struct {
	Family  string // "inet" | "inet6"
	IP      string
	CIDR    string
	Dynamic bool
}

// parseAddrs parses `ip -j addr show` JSON output into a map keyed by
// interface name.
func parseAddrs(ipAddrJSON string) (map[string][]addrInfo, error) {
	var raw []rawAddrEntity
	if err := json.Unmarshal([]byte(ipAddrJSON), &raw); err != nil {
		return nil, fmt.Errorf("parsing ip -j addr output: %w", err)
	}
	out := make(map[string][]addrInfo, len(raw))
	for _, r := range raw {
		var addrs []addrInfo
		for _, a := range r.AddrInfo {
			addrs = append(addrs, addrInfo{
				Family:  a.Family,
				IP:      a.Local,
				CIDR:    fmt.Sprintf("%s/%d", a.Local, a.Prefixlen),
				Dynamic: a.Dynamic,
			})
		}
		out[r.IfName] = addrs
	}
	return out, nil
}

// mergeLinks combines parsed links and addresses into the API-facing
// IfaceView, deriving AddrMode from whether the primary IPv4 address (if
// any) is marked dynamic — see this plan's Global Constraints for why this
// replaces a `networkctl` dependency. Bridge membership (Members) is
// computed here as a second pass: any link whose Master equals a bridge's
// name is that bridge's member.
func mergeLinks(links []parsedLink, addrs map[string][]addrInfo) []IfaceView {
	membersByBridge := make(map[string][]string)
	for _, l := range links {
		if l.Master != "" {
			membersByBridge[l.Master] = append(membersByBridge[l.Master], l.Name)
		}
	}

	views := make([]IfaceView, 0, len(links))
	for _, l := range links {
		linkAddrs := addrs[l.Name]
		addrMode := AddrModeNone
		var addresses []Address
		for _, a := range linkAddrs {
			addresses = append(addresses, Address{Family: familyLabel(a.Family), IP: a.IP, CIDR: a.CIDR})
			if a.Family == "inet" {
				if a.Dynamic {
					addrMode = AddrModeDHCP
				} else {
					addrMode = AddrModeStatic
				}
			}
		}

		views = append(views, IfaceView{
			Iface: Iface{
				Name:     l.Name,
				Kind:     l.Kind,
				VLANID:   l.VLANID,
				Members:  membersByBridge[l.Name],
				AddrMode: addrMode,
				Role:     RoleUnassigned, // filled in by Service, which knows configured Links/LAN interface
				Managed:  false,          // nothing is adopted in Phase 1
			},
			Live: LiveState{
				Carrier:   l.Carrier,
				MAC:       l.MAC,
				MTU:       l.MTU,
				Addresses: addresses,
				System:    isSystemInterface(l.Name),
			},
		})
	}
	return views
}

func familyLabel(ipFamily string) string {
	if ipFamily == "inet6" {
		return "ipv6"
	}
	return "ipv4"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -v`
Expected: PASS (all of Task 1 and Task 2's tests)

- [ ] **Step 5: Commit**

```bash
git add internal/netif/parser.go internal/netif/parser_test.go
git commit -m "feat(netif): parser de ip -j link/addr com amostra real capturada"
```

---

### Task 3: `internal/netif` — Service (importador ao vivo + diagnóstico + identificar porta)

**Files:**
- Create: `internal/netif/service.go`
- Test: `internal/netif/service_test.go`

**Interfaces:**
- Consumes: `firewall.Executor` (`internal/firewall`, `ExecuteRead(ctx, cmd, args...) (string, error)` / `Execute(ctx, cmd, args...) (string, error)`), `*storage.DB` (`GetSetting(key string) (string, error)`), `*links.Service` (`List() ([]storage.Link, error)`, `storage.Link.Interface` field), `netsvc.Config` (`json.Unmarshal` from `db.GetSetting("netsvc_config")`, fallback `netsvc.DefaultConfig()`), `parseLinks`/`parseAddrs`/`mergeLinks` (Task 2)
- Produces: `type Service struct{...}`, `func NewService(exec firewall.Executor, db *storage.DB, linkSvc *links.Service) *Service`, `func (s *Service) List(ctx context.Context) ([]IfaceView, error)`, `func (s *Service) Identify(ctx context.Context, name string, seconds int) error`

- [ ] **Step 1: Write the failing test with a fake Executor**

Create `internal/netif/service_test.go`:

```go
package netif

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// fakeExec is a minimal firewall.Executor test double that returns canned
// output per command, mirroring the pattern already used in
// internal/keaunbound/keaunbound_test.go's recExec.
type fakeExec struct {
	linkJSON string
	addrJSON string
	identifyCalls []string
}

func (e *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "ethtool" && len(args) >= 1 && args[0] == "-p" {
		e.identifyCalls = append(e.identifyCalls, args[1])
		return "", nil
	}
	return "", errors.New("unexpected write command in test: " + cmd)
}

func (e *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "ip" && len(args) >= 2 && args[1] == "link" {
		return e.linkJSON, nil
	}
	if cmd == "ip" && len(args) >= 2 && args[1] == "addr" {
		return e.addrJSON, nil
	}
	return "", errors.New("unexpected read command in test: " + cmd)
}

func (e *fakeExec) IsDryRun() bool { return false }

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

func TestServiceListAssignsRoleFromConfiguredLinks(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	if err := linkSvc.Create(&storage.Link{ID: "wan1", Name: "WAN", Interface: "wlp2s0", Weight: 1}); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	svc := NewService(exec, db, linkSvc)
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	byName := make(map[string]IfaceView, len(views))
	for _, v := range views {
		byName[v.Name] = v
	}
	if wl := byName["wlp2s0"]; wl.Role != RoleWAN {
		t.Errorf("wlp2s0: expected RoleWAN (matches configured Link.Interface), got %v", wl.Role)
	}
	if en := byName["enp0s31f6"]; en.Role != RoleUnassigned {
		t.Errorf("enp0s31f6: expected RoleUnassigned (no Link, not the LAN bridge), got %v", en.Role)
	}
}

func TestServiceListAppliesStoredAlias(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	if err := db.SetSetting("interface_aliases", `{"wlp2s0":"WAN Principal"}`); err != nil {
		t.Fatalf("seed alias: %v", err)
	}
	linkSvc := links.NewService(db)

	svc := NewService(exec, db, linkSvc)
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, v := range views {
		if v.Name == "wlp2s0" && v.Alias != "WAN Principal" {
			t.Errorf("expected alias 'WAN Principal', got %q", v.Alias)
		}
	}
}

func TestServiceIdentifyRunsEthtoolPing(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)

	if err := svc.Identify(context.Background(), "wlp2s0", 5); err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if len(exec.identifyCalls) != 1 || exec.identifyCalls[0] != "wlp2s0" {
		t.Errorf("expected one ethtool -p call for wlp2s0, got %+v", exec.identifyCalls)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -run TestService -v`
Expected: FAIL — `Service`/`NewService` don't exist yet. (If `storage.Open`/`links.NewService`/`storage.Link` field names differ slightly from what's assumed here, adjust the test to match the real signatures — check `internal/storage/repository.go` and `internal/links/service.go` before assuming a mismatch is a bug in this plan.)

- [ ] **Step 3: Write the Service**

Create `internal/netif/service.go`:

```go
package netif

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const interfaceAliasSettingKey = "interface_aliases" // same key as internal/api/handlers/system.go — do not duplicate the mechanism, only this small read
const netsvcConfigSettingKey = "netsvc_config"        // same key as internal/api/handlers/netsvc.go

// Service builds the live interface inventory: kernel state (via `ip -j`)
// merged with configured Role (from links.Service and the DHCP/DNS LAN
// interface) and stored aliases. Nothing here is persisted — every List call
// re-derives the model from the running system, same approach as
// internal/hosts.Service.List.
type Service struct {
	exec    firewall.Executor
	db      *storage.DB
	linkSvc *links.Service
}

// NewService creates a netif Service.
func NewService(exec firewall.Executor, db *storage.DB, linkSvc *links.Service) *Service {
	return &Service{exec: exec, db: db, linkSvc: linkSvc}
}

// List returns every interface the kernel currently knows about, with Role
// and Alias filled in.
func (s *Service) List(ctx context.Context) ([]IfaceView, error) {
	linkOut, err := s.exec.ExecuteRead(ctx, "ip", "-d", "-j", "link", "show")
	if err != nil {
		return nil, fmt.Errorf("ip link show: %w", err)
	}
	addrOut, err := s.exec.ExecuteRead(ctx, "ip", "-j", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("ip addr show: %w", err)
	}

	links_, err := parseLinks(linkOut)
	if err != nil {
		return nil, err
	}
	addrs, err := parseAddrs(addrOut)
	if err != nil {
		return nil, err
	}
	views := mergeLinks(links_, addrs)

	wanNames, lanNames := s.roleSets()
	aliases := s.aliases()

	for i := range views {
		name := views[i].Name
		switch {
		case wanNames[name]:
			views[i].Role = RoleWAN
		case lanNames[name]:
			views[i].Role = RoleLAN
		}
		if a, ok := aliases[name]; ok {
			views[i].Alias = a
		}
	}
	return views, nil
}

// Identify blinks the physical port's LED via `ethtool -p` so an admin
// standing at the rack can find it. Only meaningful for physical NICs — the
// caller (handler) is responsible for rejecting VLAN/bridge names before
// calling this, per spec §9.2.
func (s *Service) Identify(ctx context.Context, name string, seconds int) error {
	_, err := s.exec.Execute(ctx, "ethtool", "-p", name, strconv.Itoa(seconds))
	return err
}

// roleSets returns the interface names that count as WAN (any interface
// referenced by a configured Link) and LAN (the interface netsvc.Config
// serves DHCP/DNS on). Role is a label — see spec §5.1 — so a lookup miss is
// not an error, it just leaves the interface Unassigned.
func (s *Service) roleSets() (wan, lan map[string]bool) {
	wan = map[string]bool{}
	lan = map[string]bool{}

	if configuredLinks, err := s.linkSvc.List(); err == nil {
		for _, l := range configuredLinks {
			wan[l.Interface] = true
		}
	}

	cfg := netsvc.DefaultConfig()
	if raw, err := s.db.GetSetting(netsvcConfigSettingKey); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	if cfg.Interface != "" {
		lan[cfg.Interface] = true
	}
	return wan, lan
}

// aliases returns the stored interface_aliases map. Reuses the exact same
// setting key /api/system/interface-aliases already writes to — spec §15
// explicitly forbids a second alias mechanism.
func (s *Service) aliases() map[string]string {
	raw, err := s.db.GetSetting(interfaceAliasSettingKey)
	if err != nil || raw == "" {
		return map[string]string{}
	}
	var aliases map[string]string
	if err := json.Unmarshal([]byte(raw), &aliases); err != nil {
		return map[string]string{}
	}
	return aliases
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./internal/netif/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/netif/service.go internal/netif/service_test.go
git commit -m "feat(netif): Service — importador ao vivo, papel WAN/LAN, alias, identificar porta"
```

---

### Task 4: RBAC — permissões `interfaces.read`/`interfaces.write`

**Files:**
- Modify: `internal/auth/permissions.go`

**Interfaces:**
- Produces: `auth.PermInterfacesRead`, `auth.PermInterfacesWrite` (consumed by Task 5's routes)

- [ ] **Step 1: Adicionar as constantes de permissão**

Em `internal/auth/permissions.go`, no bloco `const` de leitura (junto a `PermVPNRead`), adicione:

```go
	PermInterfacesRead Permission = "interfaces.read"
```

No bloco de escrita (junto a `PermVPNWrite`), adicione:

```go
	PermInterfacesWrite Permission = "interfaces.write" // editar interface, identificar porta fisicamente
```

- [ ] **Step 2: Adicionar ao Catalog**

No slice `Catalog`, junto às entradas de VPN, adicione:

```go
	{PermInterfacesRead, "Interfaces", "Ver interfaces", "Topologia de rede, estado físico e diagnóstico"},
	{PermInterfacesWrite, "Interfaces", "Gerenciar interfaces", "Identificar porta fisicamente (piscar LED)"},
```

(A descrição de `PermInterfacesWrite` é deliberadamente restrita ao que a Fase 1 realmente faz — "identificar porta" — porque editar/aplicar config de rede é Fase 2 e vai expandir esta descrição quando existir.)

- [ ] **Step 3: Adicionar a `readOnlyPermissions()` e ao papel Operador**

No `switch` de `readOnlyPermissions()`, adicione `PermInterfacesRead` à lista de `case`.

Em `DefaultRoles`, no papel `role-operator`, adicione `PermInterfacesRead, PermInterfacesWrite` à lista de `Permissions` (operação do dia a dia inclui identificar uma porta fisicamente).

- [ ] **Step 4: Verificar que compila**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go build ./...`
Expected: sem erros.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/permissions.go
git commit -m "feat(auth): permissões interfaces.read/interfaces.write"
```

---

### Task 5: API — handler + rotas + wiring

**Files:**
- Create: `internal/api/handlers/netif.go`
- Modify: `internal/api/server.go`
- Modify: `cmd/linkguard-fw/main.go`

**Interfaces:**
- Consumes: `netif.Service` (Task 3), `netif.IfaceView` (Task 1), `auth.PermInterfacesRead`/`PermInterfacesWrite` (Task 4), padrão de handler existente (`writeJSON`/`writeError`/`decodeJSON`/`auditAction` de `internal/api/handlers/helpers.go` e `hosts.go`)
- Produces: `GET /api/interfaces`, `GET /api/interfaces/drift`, `POST /api/interfaces/{name}/identify`

- [ ] **Step 1: Criar o handler**

Create `internal/api/handlers/netif.go`:

```go
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/netif"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// NetifHandler handles the read-only interface inventory (Phase 1).
type NetifHandler struct {
	svc *netif.Service
	db  *storage.DB
}

// NewNetifHandler creates a NetifHandler.
func NewNetifHandler(svc *netif.Service, db *storage.DB) *NetifHandler {
	return &NetifHandler{svc: svc, db: db}
}

// List returns every interface the kernel currently knows about.
func (h *NetifHandler) List(w http.ResponseWriter, r *http.Request) {
	views, err := h.svc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if views == nil {
		views = []netif.IfaceView{}
	}
	writeJSON(w, http.StatusOK, views)
}

// Drift is a Phase 1 stub — real drift detection ships in Phase 4 (spec
// §14). Always returns an empty list: the frontend must not render this as
// "confirmed no drift", only as "this feature isn't built yet" (no UI
// surface in Phase 1 reads this endpoint — it exists so the route is stable
// once Phase 4 lands).
func (h *NetifHandler) Drift(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []struct{}{})
}

// Identify blinks a physical port's LED (`ethtool -p`) so an admin at the
// rack can find it. Rejects VLAN/bridge names — identification only makes
// sense for a real physical port.
func (h *NetifHandler) Identify(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "interface name is required")
		return
	}

	views, err := h.svc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var found *netif.IfaceView
	for i := range views {
		if views[i].Name == name {
			found = &views[i]
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "interface not found")
		return
	}
	if found.Kind != netif.KindPhysical {
		writeError(w, http.StatusBadRequest, "only physical interfaces can be identified")
		return
	}

	if err := h.svc.Identify(r.Context(), name, 10); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "interface.identify", "interface:"+name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
```

- [ ] **Step 2: Verificar a assinatura real de `auditAction` antes de prosseguir**

Rode `grep -n "^func auditAction" internal/api/handlers/*.go` — a chamada acima assume a mesma assinatura de 4 argumentos usada em `hosts.go` (`auditAction(h.db, r, action, target, detail)`). Se a assinatura real for diferente, ajuste a chamada em `Identify` para bater exatamente — não prossiga com uma assinatura adivinhada.

- [ ] **Step 3: Adicionar o service ao `Server`**

Em `internal/api/server.go`:

1. Adicione o import: `"github.com/giovanibalarini/linkguard-fw/internal/netif"`
2. No `struct Server`, adicione um campo junto a `hostSvc`: `netifSvc    *netif.Service`
3. Na assinatura de `New(...)`, adicione o parâmetro `netifSvc *netif.Service` logo após `hostSvc *hosts.Service` (mesma posição relativa nos dois lugares — assinatura e literal do struct — para não trocar a ordem dos demais parâmetros já existentes)
4. No literal `s := &Server{...}`, adicione `netifSvc:    netifSvc,` junto a `hostSvc:     hostSvc,`

- [ ] **Step 4: Registrar as rotas**

Ainda em `server.go`, no bloco onde as rotas de hosts são registradas (perto de `r.With(require(auth.PermHostsRead)).Get("/api/hosts", hostsH.List)`), adicione:

```go
		netifH := handlers.NewNetifHandler(s.netifSvc, s.db)
		r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces", netifH.List)
		r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces/drift", netifH.Drift)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/{name}/identify", netifH.Identify)
```

- [ ] **Step 5: Construir o service e atualizar a chamada em `main.go`**

Em `cmd/linkguard-fw/main.go`, próximo de onde `hostSvc` é construído (`hosts.NewService(...)`), adicione:

```go
	netifSvc := netif.NewService(exec, db, linkSvc)
```

(confirme o nome exato da variável do `links.Service` já construído no arquivo — grep por `hosts.NewService(` para ver quais variáveis são passadas e reusar os mesmos nomes.)

Adicione o import `"github.com/giovanibalarini/linkguard-fw/internal/netif"`.

Na chamada `server := api.New(...)`, adicione `netifSvc` como argumento logo após `hostSvc` (mesma posição usada no `New()` da Task 5, Passo 3) — a lista de argumentos é posicional, então a ordem tem que bater exatamente com a assinatura.

- [ ] **Step 6: Verificar que compila e os testes de todo o módulo passam**

Run: `PATH=/home/gov/sdk/go1.25.0/bin:$PATH go build ./... && PATH=/home/gov/sdk/go1.25.0/bin:$PATH go vet ./... && PATH=/home/gov/sdk/go1.25.0/bin:$PATH go test ./...`
Expected: build limpo, vet limpo, todos os testes (incluindo os pré-existentes de outros pacotes) passando.

- [ ] **Step 7: Commit**

```bash
git add internal/api/handlers/netif.go internal/api/server.go cmd/linkguard-fw/main.go
git commit -m "feat(api): GET /api/interfaces, GET /api/interfaces/drift, POST /api/interfaces/{name}/identify"
```

---

### Task 6: Frontend — componente `Tabs`

**Files:**
- Create: `web/src/components/ui/Tabs.tsx`

**Interfaces:**
- Produces: `export interface TabItem { id: string; label: string }`; `export default function Tabs({ items, active, onChange }: { items: TabItem[]; active: string; onChange: (id: string) => void })`

- [ ] **Step 1: Criar o componente**

Crie `web/src/components/ui/Tabs.tsx`:

```tsx
export interface TabItem {
  id: string;
  label: string;
}

interface TabsProps {
  items: TabItem[];
  active: string;
  onChange: (id: string) => void;
}

export default function Tabs({ items, active, onChange }: TabsProps) {
  return (
    <div className="flex gap-1 border-b border-gray-800 overflow-x-auto" role="tablist">
      {items.map((item) => {
        const isActive = item.id === active;
        return (
          <button
            key={item.id}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(item.id)}
            className={`px-4 py-2 text-sm font-medium whitespace-nowrap border-b-2 transition-colors ${
              isActive
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
}
```

- [ ] **Step 2: Verificar visualmente**

No `npm run dev`, teste temporariamente:

```tsx
const [tab, setTab] = useState('a');
<Tabs items={[{ id: 'a', label: 'Aba A' }, { id: 'b', label: 'Aba B' }]} active={tab} onChange={setTab} />
```

Confirme que clicar troca a aba ativa (sublinhado azul) e remova a linha de teste.

- [ ] **Step 3: Commit**

```bash
git add web/src/components/ui/Tabs.tsx
git commit -m "feat(web): componente Tabs"
```

---

### Task 7: Frontend — extrair `InterfaceTraffic.tsx` de `Interfaces.tsx`

**Files:**
- Create: `web/src/components/InterfaceTraffic.tsx`
- Modify (temporário — vira casca na Task 8): `web/src/pages/Interfaces.tsx`

**Interfaces:**
- Produces: `export default function InterfaceTraffic()` — mesmo comportamento do `Interfaces.tsx` atual, sem nenhuma mudança de lógica

- [ ] **Step 1: Mover o conteúdo atual, renomeando só a função**

`web/src/pages/Interfaces.tsx` hoje (538 linhas) é inteiramente a visão de tráfego — não há uma "parte de tráfego" para separar do resto porque o resto ainda não existe. Este passo é uma mudança de local, não de lógica:

1. Copie o conteúdo completo de `web/src/pages/Interfaces.tsx` para um novo arquivo `web/src/components/InterfaceTraffic.tsx`
2. No novo arquivo, troque `export default function Interfaces()` por `export default function InterfaceTraffic()` — é a única mudança de código permitida neste passo
3. Ajuste imports relativos que mudam por causa da nova localização (`web/src/pages/` → `web/src/components/`): `from '../api/client'` continua igual (mesma profundidade), `from '../types'` continua igual — confirme com `npm run build` no passo 3 que nenhum import quebrou

- [ ] **Step 2: Deixar `Interfaces.tsx` como um passthrough temporário**

Para não quebrar a rota (`/interfaces`, já registrada em `web/src/App.tsx`) enquanto a Task 8 ainda não escreveu a casca de verdade, troque o conteúdo de `web/src/pages/Interfaces.tsx` por:

```tsx
import InterfaceTraffic from '../components/InterfaceTraffic';

export default function Interfaces() {
  return <InterfaceTraffic />;
}
```

Isso é intencionalmente descartável — a Task 8 substitui todo este arquivo pela casca com abas.

- [ ] **Step 3: Verificar que nada mudou pro usuário**

Rode `npm run build`. Se possível (backend local ou remoto disponível), abra `/interfaces` no `npm run dev` e confirme que o comportamento é idêntico a antes da mudança — mesmos gráficos, mesma pausa/retomada, mesmo RX/TX ao vivo. Se não houver backend disponível neste passo, confirme ao menos por leitura de diff que o conteúdo movido é byte-idêntico ao original (só o nome da função mudou).

- [ ] **Step 4: Commit**

```bash
git add web/src/components/InterfaceTraffic.tsx web/src/pages/Interfaces.tsx
git commit -m "refactor(web): extrai InterfaceTraffic.tsx de Interfaces.tsx (sem mudança de comportamento)"
```

---

### Task 8: Frontend — casca de `Interfaces.tsx` com abas + aba "Interfaces" (listagem)

**Files:**
- Modify: `web/src/pages/Interfaces.tsx` (substitui o passthrough da Task 7)
- Modify: `web/src/types/index.ts`

**Interfaces:**
- Consumes: `Tabs`/`TabItem` (Task 6), `InterfaceTraffic` (Task 7), `Panel`/`Tag` (sub-projeto 1), `GET /api/interfaces` (Task 5)
- Produces: tipos TS `Kind`, `AddrMode`, `Role`, `IfaceAddress`, `IfaceLive`, `IfaceView` espelhando o JSON do Go (Task 1); a aba "Visão geral" fica placeholder nesta tarefa (Task 9 a implementa) para não bloquear a listagem, que é independente

- [ ] **Step 1: Adicionar os tipos TypeScript**

Em `web/src/types/index.ts`, adicione (os nomes de campo em `snake_case` batem com as tags `json:"..."` do Go definidas na Task 1):

```ts
export type IfaceKind = 'physical' | 'vlan' | 'bridge';
export type IfaceAddrMode = 'static' | 'dhcp' | 'none';
export type IfaceRole = 'wan' | 'lan' | 'unassigned';

export interface IfaceAddress {
  family: 'ipv4' | 'ipv6';
  ip: string;
  cidr: string;
}

export interface IfaceLiveState {
  carrier: boolean;
  speed?: string;
  mac?: string;
  mtu?: number;
  addresses?: IfaceAddress[];
  rx_errors: number;
  tx_errors: number;
  rx_dropped: number;
  tx_dropped: number;
  system: boolean;
}

export interface IfaceView {
  name: string;
  kind: IfaceKind;
  alias?: string;
  description?: string;
  parent?: string;
  vlan_id?: number;
  members?: string[];
  addr_mode: IfaceAddrMode;
  role: IfaceRole;
  managed: boolean;
  live: IfaceLiveState;
}
```

- [ ] **Step 2: Escrever a casca com abas**

Substitua `web/src/pages/Interfaces.tsx` inteiro (o passthrough da Task 7) por:

```tsx
import { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import client from '../api/client';
import InterfaceTraffic from '../components/InterfaceTraffic';
import Tabs, { type TabItem } from '../components/ui/Tabs';
import Tag, { type TagVariant } from '../components/ui/Tag';
import type { IfaceView } from '../types';

const TABS: TabItem[] = [
  { id: 'overview', label: 'Visão geral' },
  { id: 'list', label: 'Interfaces' },
  { id: 'vlans', label: 'VLANs' },
  { id: 'bridges', label: 'Bridges' },
  { id: 'traffic', label: 'Tráfego' },
];

const kindLabel: Record<string, string> = { physical: 'física', vlan: 'vlan', bridge: 'bridge' };
const roleTag: Record<string, { label: string; variant: TagVariant }> = {
  wan: { label: 'WAN', variant: 'ok' },
  lan: { label: 'LAN', variant: 'neutral' },
  unassigned: { label: 'não atribuída', variant: 'idle' },
};

export default function Interfaces() {
  const [tab, setTab] = useState('overview');
  const [ifaces, setIfaces] = useState<IfaceView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [query, setQuery] = useState('');
  const [showSystem, setShowSystem] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { data } = await client.get<IfaceView[]>('/api/interfaces');
        if (alive) {
          setIfaces(data ?? []);
          setError(false);
        }
      } catch {
        if (alive) setError(true);
      } finally {
        if (alive) setLoading(false);
      }
    };
    load();
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const visible = ifaces.filter((i) => showSystem || !i.live.system);
  const filtered = visible.filter((i) => {
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return (
      i.name.toLowerCase().includes(q) ||
      (i.alias ?? '').toLowerCase().includes(q) ||
      (i.description ?? '').toLowerCase().includes(q)
    );
  });
  const hiddenSystemCount = ifaces.length - visible.length;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Interfaces</h1>
        <p className="text-gray-500 text-sm mt-0.5">
          Estado físico e topologia da rede.
        </p>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          Falha ao carregar interfaces.
        </div>
      )}

      <Tabs items={TABS} active={tab} onChange={setTab} />

      {tab === 'overview' && (
        <div className="card text-gray-500 text-sm">
          {/* Implementado na próxima tarefa deste plano — árvore de topologia. */}
          Árvore de topologia — em construção nesta mesma fase (próxima tarefa).
        </div>
      )}

      {tab === 'list' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="buscar por nome, apelido ou descrição"
                className="input pl-9 w-full"
              />
            </div>
            {hiddenSystemCount > 0 && (
              <button
                onClick={() => setShowSystem((v) => !v)}
                className="text-xs text-gray-500 hover:text-gray-300"
              >
                {showSystem ? 'ocultar' : 'mostrar'} {hiddenSystemCount} interfaces de sistema
              </button>
            )}
          </div>

          {loading ? (
            <div className="text-gray-500 text-sm">Carregando...</div>
          ) : (
            <div className="card overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">Interface</th>
                    <th className="pb-3 pr-4 font-medium">Tipo</th>
                    <th className="pb-3 pr-4 font-medium">Endereço</th>
                    <th className="pb-3 pr-4 font-medium">Físico</th>
                    <th className="pb-3 font-medium">Papel</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((i) => {
                    const roleCfg = roleTag[i.role] ?? roleTag.unassigned;
                    const physAbnormal = !i.live.carrier || i.live.rx_errors > 0 || i.live.tx_errors > 0;
                    return (
                      <tr key={i.name} className="table-row">
                        <td className="py-3 pr-4">
                          <div className="text-white font-medium">{i.alias || i.name}</div>
                          {i.alias && <div className="text-gray-500 text-xs font-mono">{i.name}</div>}
                        </td>
                        <td className="py-3 pr-4 text-gray-400">{kindLabel[i.kind] ?? i.kind}</td>
                        <td className="py-3 pr-4 text-gray-400 font-mono">
                          {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                        </td>
                        <td className="py-3 pr-4">
                          {i.kind === 'physical' ? (
                            <Tag variant={physAbnormal ? 'warn' : 'ok'} dot>
                              {i.live.carrier ? 'link ativo' : 'sem link'}
                            </Tag>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </td>
                        <td className="py-3">
                          <Tag variant={roleCfg.variant}>{roleCfg.label}</Tag>
                        </td>
                      </tr>
                    );
                  })}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-gray-500">
                        Nenhuma interface encontrada.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'vlans' && (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-3 pr-4 font-medium">Nome</th>
                <th className="pb-3 pr-4 font-medium">Pai</th>
                <th className="pb-3 pr-4 font-medium">Tag</th>
                <th className="pb-3 font-medium">Endereço</th>
              </tr>
            </thead>
            <tbody>
              {visible.filter((i) => i.kind === 'vlan').map((i) => (
                <tr key={i.name} className="table-row">
                  <td className="py-3 pr-4 text-white">{i.alias || i.name}</td>
                  <td className="py-3 pr-4 text-gray-400 font-mono">{i.parent ?? '—'}</td>
                  <td className="py-3 pr-4 text-gray-400 font-mono">{i.vlan_id ?? '—'}</td>
                  <td className="py-3 text-gray-400 font-mono">
                    {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                  </td>
                </tr>
              ))}
              {visible.filter((i) => i.kind === 'vlan').length === 0 && (
                <tr>
                  <td colSpan={4} className="py-6 text-center text-gray-500">Nenhuma VLAN detectada.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'bridges' && (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-3 pr-4 font-medium">Nome</th>
                <th className="pb-3 pr-4 font-medium">Membros</th>
                <th className="pb-3 font-medium">Endereço</th>
              </tr>
            </thead>
            <tbody>
              {visible.filter((i) => i.kind === 'bridge').map((i) => (
                <tr key={i.name} className="table-row">
                  <td className="py-3 pr-4 text-white">{i.alias || i.name}</td>
                  <td className="py-3 pr-4 text-gray-400 font-mono">{(i.members ?? []).join(', ') || '—'}</td>
                  <td className="py-3 text-gray-400 font-mono">
                    {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                  </td>
                </tr>
              ))}
              {visible.filter((i) => i.kind === 'bridge').length === 0 && (
                <tr>
                  <td colSpan={3} className="py-6 text-center text-gray-500">Nenhuma bridge detectada.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'traffic' && <InterfaceTraffic />}
    </div>
  );
}
```

- [ ] **Step 3: Verificar**

Rode `npm run build`. Depois, se houver backend disponível, `npm run dev`: confirme que as 5 abas trocam corretamente, que "Interfaces" lista as interfaces reais com busca funcionando, que "VLANs"/"Bridges" mostram estado vazio corretamente quando não há nenhuma (sem erro), e que "Tráfego" continua idêntico ao comportamento anterior (é literalmente o componente da Task 7 sem mudança).

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/Interfaces.tsx web/src/types/index.ts
git commit -m "feat(web): Interfaces.tsx — casca com abas, listagem, VLANs, Bridges"
```

---

### Task 9: Frontend — aba "Visão geral" (árvore de topologia + identificar porta)

**Files:**
- Modify: `web/src/pages/Interfaces.tsx`

**Interfaces:**
- Consumes: `Panel`/`Tag` (sub-projeto 1), `IfaceView[]` (já carregado na Task 8), `POST /api/interfaces/{name}/identify` (Task 5)

- [ ] **Step 1: Implementar a árvore**

Em `web/src/pages/Interfaces.tsx`, adicione uma função de agrupamento antes do componente (junto às constantes `TABS`/`kindLabel`/`roleTag` já existentes):

```tsx
// Groups by the Role the backend already computed (spec §5.1: Role is a
// label, never re-derived on the frontend). The only extra step here is
// keeping a LAN bridge's members (e.g. eth2/eth3 under br10) out of
// "Não atribuídas" — they're rendered nested under their bridge instead of
// twice.
function groupByRole(ifaces: IfaceView[]) {
  const wan = ifaces.filter((i) => i.role === 'wan');
  const lan = ifaces.filter((i) => i.role === 'lan');
  const memberNames = new Set(lan.flatMap((i) => i.members ?? []));
  const unassigned = ifaces.filter((i) => i.role === 'unassigned' && !memberNames.has(i.name));
  return { wan, lan, unassigned, memberNames };
}
```

Adicione o estado de identificação e a função de disparo dentro do componente `Interfaces` (junto aos outros `useState`):

```tsx
  const [identifying, setIdentifying] = useState<string | null>(null);

  const handleIdentify = async (name: string) => {
    setIdentifying(name);
    try {
      await client.post(`/api/interfaces/${encodeURIComponent(name)}/identify`);
    } finally {
      setTimeout(() => setIdentifying((cur) => (cur === name ? null : cur)), 10000);
    }
  };
```

Substitua o placeholder da aba "overview" (da Task 8) por:

```tsx
      {tab === 'overview' && (
        <Panel title="Painel traseiro">
          {(() => {
            const { wan, lan, unassigned } = groupByRole(visible);
            const systemIfaces = ifaces.filter((i) => i.live.system);
            const byName = new Map(visible.map((i) => [i.name, i]));
            const renderRow = (i: IfaceView, indent = false) => {
              const physAbnormal = i.kind === 'physical' && (!i.live.carrier || i.live.rx_errors > 0);
              return (
                <div
                  key={i.name}
                  className={`flex items-center justify-between gap-3 py-2 border-b border-gray-800/50 last:border-0 ${indent ? 'pl-6' : ''}`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-white text-sm truncate">{i.alias || i.name}</span>
                    {i.alias && <span className="text-gray-600 text-xs font-mono">{i.name}</span>}
                    {i.kind !== 'physical' && (
                      <span className="text-gray-600 text-xs">
                        {i.kind === 'vlan' ? `vlan · tag ${i.vlan_id}` : 'bridge'}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    {i.kind === 'physical' && (
                      <Tag variant={physAbnormal ? 'warn' : 'ok'} dot>
                        {i.live.carrier ? 'link ativo' : 'sem link'}
                      </Tag>
                    )}
                    {i.kind === 'physical' && (
                      <button
                        onClick={() => handleIdentify(i.name)}
                        disabled={identifying === i.name}
                        className="text-xs text-gray-500 hover:text-gray-300 disabled:text-blue-400"
                      >
                        {identifying === i.name ? 'piscando…' : 'identificar'}
                      </button>
                    )}
                  </div>
                </div>
              );
            };
            return (
              <div className="space-y-4">
                {wan.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">WAN</div>
                    {wan.map((i) => renderRow(i))}
                  </div>
                )}
                {lan.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">LAN</div>
                    {lan.map((i) => (
                      <div key={i.name}>
                        {renderRow(i)}
                        {(i.members ?? []).map((m) => {
                          const member = byName.get(m);
                          return member ? renderRow(member, true) : null;
                        })}
                      </div>
                    ))}
                  </div>
                )}
                {unassigned.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Não atribuídas</div>
                    {unassigned.map((i) => renderRow(i))}
                  </div>
                )}
                {wan.length === 0 && lan.length === 0 && unassigned.length === 0 && (
                  <p className="text-gray-500 text-sm">Nenhuma interface detectada.</p>
                )}
                {systemIfaces.length > 0 && !showSystem && (
                  <button onClick={() => setShowSystem(true)} className="text-xs text-gray-600 hover:text-gray-400">
                    {systemIfaces.length} interfaces de sistema ocultas · mostrar
                  </button>
                )}
              </div>
            );
          })()}
        </Panel>
      )}
```

- [ ] **Step 2: Verificar**

`npm run build` sem erro. Se backend disponível, `npm run dev`: confirme que a árvore agrupa corretamente (uma interface real desta máquina de dev, `wlp2s0`, some sem `role` configurada — para testar WAN/LAN de verdade é preciso um `Link`/config de LAN reais, o que só existe contra um backend com dados semeados, mesmo padrão da Task 10 do sub-projeto 1). Clique em "identificar" numa interface física e confirme que o botão mostra "piscando…" por alguns segundos (a chamada real ao `ethtool -p` só tem efeito visível com hardware de verdade — em dev, confirme ao menos que a requisição sai sem erro 4xx/5xx).

- [ ] **Step 3: Commit**

```bash
git add web/src/pages/Interfaces.tsx
git commit -m "feat(web): Interfaces.tsx — árvore de topologia + identificar porta"
```

---

### Task 10: Verificação visual final (Playwright, dados reais/semeados)

**Files:**
- Nenhum arquivo de produto — só verificação, mesma técnica das últimas iterações.

**Interfaces:**
- Consumes: build completo do frontend (Tasks 6-9) + backend com Fase 1 (Tasks 1-5)

- [ ] **Step 1: Build local e semear dados**

Mesma técnica já validada (ver relatório da Task 10 do sub-projeto 1, `web/design-system-painel`): copiar frontend+backend pra um diretório `/tmp` isolado (nunca tocar o checkout real), buildar, subir o binário. Diferença desta vez: não há necessidade de semear nada via SQLite para o `netif` em si (é 100% ao vivo, sem tabela própria) — os dados vêm da própria máquina onde o teste roda (interfaces reais, `ip -j link/addr`). Semeie só o que a Fase 1 cruza: um `storage.Link` real apontando pra uma interface de verdade da máquina de teste (para ver a badge "WAN" na árvore), e o `netsvc_config` com uma interface LAN real (para ver a badge "LAN").

- [ ] **Step 2: Navegar e verificar (Playwright, chromium headless)**

Login `admin`/`admin`. Na página `/interfaces`, confirme:
- As 5 abas trocam corretamente
- "Visão geral": interface marcada como Link aparece em WAN com a tag certa; a interface da config LAN aparece em LAN; o resto aparece em "Não atribuídas"; interfaces de sistema (docker, veth, etc, se existirem na máquina de teste) começam ocultas com o contador certo, e "mostrar" revela elas
- "Interfaces": a busca filtra por nome/alias; interface com carrier=false mostra tag `warn`/"sem link"
- "VLANs"/"Bridges": mostram estado vazio corretamente se a máquina de teste não tiver nenhuma (sem erro, sem fabricar linha)
- "Tráfego": idêntico ao comportamento já validado no sub-projeto 1 (é o mesmo componente, só remontado)
- Clicar "identificar" numa interface física não gera erro (mesmo que o LED físico não exista para piscar num ambiente de teste)
- Nenhum texto cortado/sobreposto/invisível (mesma checagem de `getBoundingClientRect()` de zero-width já estabelecida)

- [ ] **Step 3: Corrigir o que for encontrado, reverter patches temporários, confirmar `git status` limpo no checkout real**

Mesmo processo já estabelecido nas últimas iterações — sem exceção.

- [ ] **Step 4: Commit (só se a verificação exigiu correções)**

Se nenhuma correção foi necessária, não crie commit — é tarefa só de verificação.

---

## Auto-revisão do plano

**Cobertura do spec (Fase 1, `2026-07-19-network-interface-management-design.md` §14 linha 1 + adendo `2026-07-27-interfaces-fase1-design-system.md`):** modelo (Task 1) · importador ip -j (Task 2) · classificação de ruído (Task 1) · Role WAN/LAN via cruzamento real, nunca heurístico (Task 3) · alias reusando `interface_aliases` (Task 3) · API + RBAC (Tasks 4-5) · identificar porta com auditoria (Task 5, 9) · `Tabs` como primeiro consumidor real (Task 6) · `InterfaceTraffic.tsx` extraído sem mudar comportamento (Task 7) · abas Visão geral/Interfaces/VLANs/Bridges/Tráfego (Tasks 8-9) · verificação visual final (Task 10). `drift` fica como stub vazio explicitamente documentado, não implementado — Fase 4.

**Placeholders:** nenhum "TBD" — todo passo tem código completo. As duas únicas ressalvas explícitas (Passo 2 da Task 3 pedindo para checar assinaturas reais antes de prosseguir, e o mesmo na Task 5) são pontos de verificação contra código real que este plano não pôde 100% confirmar sem executar (a exata assinatura de `auditAction` e o nome da variável `linkSvc` já construída em `main.go`) — não são lacunas de especificação, são checagens de integração de baixo risco antes de codificar.

**Consistência de tipos:** `IfaceView`/`Iface`/`LiveState` (Go, Task 1) usam as mesmas tags JSON que `IfaceView`/`IfaceLiveState`/`IfaceAddress` (TS, Task 8) espelham campo a campo. `parsedLink`/`addrInfo` (Task 2, não exportados) são consumidos só por `mergeLinks` na mesma tarefa — nenhuma tarefa posterior depende deles diretamente, só de `IfaceView`.
