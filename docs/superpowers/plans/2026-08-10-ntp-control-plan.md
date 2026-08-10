# Controle de NTP no LinkGuard FW Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dar ao LinkGuard FW controle real de NTP — configurar servidores customizados, controlar o fuso horário, ver status detalhado de sincronização, e instalar o `chrony` sob demanda quando ausente — tudo pelo painel, sem SSH.

**Architecture:** Mesmo padrão já usado por DHCP/DNS (`internal/netsvc`/`internal/keaunbound`): um `Config` persistido como JSON na tabela genérica de settings, um handler HTTP com auto-apply debounced, e uma página própria no painel. `internal/timesync` (hoje só 2 funções) cresce para um `Service` completo, sem alterar `EnsureEnabled`/`IsSynced` (que continuam sendo a única fonte de verdade do alerta Vigia). O LinkGuard nunca toca no `/etc/chrony/chrony.conf` do pacote Debian — só escreve/remove um arquivo próprio via `confdir /etc/chrony/conf.d` (recurso já suportado pelo config padrão do Debian). Instalar o `chrony` roda via `systemd-run`, fora do sandbox do próprio processo do LinkGuard.

**Tech Stack:** Go 1.25 (backend), React/TypeScript + Vite (frontend), SQLite via `internal/storage` (tabela genérica `settings`, sem tabela nova), `chrony`/`timedatectl`/`systemd-run` (system).

## Global Constraints

- O LinkGuard **nunca** escreve em `/etc/chrony/chrony.conf` (arquivo do pacote Debian) — só em `/etc/chrony/conf.d/linkguard.conf`, com o cabeçalho `# managed by linkguard`.
- `internal/timesync.EnsureEnabled` e `internal/timesync.IsSynced` (já existentes) **não mudam** — nenhuma assinatura, nenhum comportamento. O `checkNTP`/alertas `ntp_unsynced`/`ntp_synced` (feature Vigia) continuam a única fonte de verdade pra detecção de sincronização; o código novo só reusa `IsSynced` pra exibir.
- Instalar o `chrony` é **sempre uma ação manual explícita** (botão), nunca automática/no boot — via `systemd-run --pipe --wait -- apt-get install ...`, nunca `apt`/`dpkg` chamado diretamente pelo processo do LinkGuard.
- Fuso horário é sempre escolhido por um `<select>` populado por `timedatectl list-timezones`, nunca um campo de texto livre — evita erro de digitação gerando um fuso inválido.
- `Servers`/`Timezone` vazios = "não gerenciado" — o LinkGuard não sobrescreve nada, comportamento idêntico ao de hoje (pool padrão do Debian, fuso já configurado no SO).
- Reload gracioso via `systemctl reload-or-restart chrony` — nunca SIGHUP cru, nunca restart incondicional de outros serviços.
- TDD real: teste que falha primeiro, depois a implementação mínima pra passar.
- Toda struct/slice retornada em JSON que pode ficar vazia deve serializar como `[]`/`{}`, nunca `null` (regra já reforçada nesta sessão: um `null` onde o frontend espera array quebra `.map()`/`.join()`).

---

### Task 1: `internal/timesync` — Config, chrony drop-in, status, instalar

**Files:**
- Modify: `internal/timesync/timesync.go`
- Modify: `internal/timesync/timesync_test.go`

**Interfaces:**
- Consumes: `firewall.Executor` (já existente, `internal/firewall/executor.go` — métodos `Execute`/`ExecuteRead`/`IsDryRun`). `EnsureEnabled`/`IsSynced` (já existentes neste mesmo arquivo, inalteradas — `Status` chama `IsSynced` internamente).
- Produces (usados pela Task 2): `type Config struct{ Servers []string; Timezone string }`; `func DefaultConfig() Config`; `type StatusInfo struct{ Installed, Synced bool; Stratum int; OffsetSecs float64; Source string }`; `type Service struct{...}`; `func NewService(exec firewall.Executor) *Service`; `func (s *Service) ReloadConfig(ctx context.Context, c Config) error`; `func (s *Service) Status(ctx context.Context) StatusInfo`; `func (s *Service) ListTimezones(ctx context.Context) ([]string, error)`; `func (s *Service) InstallChrony(ctx context.Context) error`; `func GenerateChronyConf(c Config) string` (pura, exportada pra facilitar teste direto); `func ParseChronycTracking(out string) (stratum int, offsetSecs float64, source string)` (pura, exportada).

- [ ] **Step 1: Escrever o teste que falha**

Substituir o conteúdo de `internal/timesync/timesync_test.go` por:

```go
package timesync

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeExec is a minimal firewall.Executor test double dedicated to this
// package. Deliberately NOT internal/api/handlers' fakeNftExec — that fake
// returns "" for any non-nft command, which breaks this package's parsers
// (an empty string isn't valid input for "yes"/"no" checks or chronyc
// tracking parsing). This fake returns exactly the text each test
// configures per command.
type fakeExec struct {
	dryRun    bool
	responses map[string]string // "cmd arg1 arg2" -> ExecuteRead output
	execErr   error             // returned by Execute for every call, if set
	readErr   error             // returned by ExecuteRead for every call, if set
	executed  []string          // records every Execute call (not ExecuteRead)
}

func (e *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.executed = append(e.executed, strings.Join(append([]string{cmd}, args...), " "))
	return "", e.execErr
}
func (e *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if e.readErr != nil {
		return "", e.readErr
	}
	key := strings.Join(append([]string{cmd}, args...), " ")
	return e.responses[key], nil
}
func (e *fakeExec) IsDryRun() bool { return e.dryRun }

func containsExecuted(executed []string, want string) bool {
	for _, e := range executed {
		if e == want {
			return true
		}
	}
	return false
}

// TestDefaultConfigServersIsEmptySliceNotNil is the regression test for the
// same class of bug already found once this session (internal/netif's
// stable-names GET handler): a nil slice marshals to JSON `null`, which
// crashes a frontend `.join(', ')`/`.map()` call expecting an array.
func TestDefaultConfigServersIsEmptySliceNotNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Servers == nil {
		t.Error("DefaultConfig().Servers is nil — would marshal as JSON null")
	}
}

func TestGenerateChronyConfRendersServersWithHeader(t *testing.T) {
	content := GenerateChronyConf(Config{Servers: []string{"192.36.143.130", "c.ntp.br"}})
	for _, want := range []string{
		"# managed by linkguard",
		"server 192.36.143.130 iburst",
		"server c.ntp.br iburst",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("content missing %q:\n%s", want, content)
		}
	}
}

func TestReloadConfigWritesDropinWhenServersSet(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf")
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: confPath}

	err := s.ReloadConfig(context.Background(), Config{Servers: []string{"c.ntp.br"}})
	if err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "server c.ntp.br iburst") {
		t.Errorf("drop-in missing expected server line:\n%s", got)
	}
	if !containsExecuted(exec.executed, "systemctl reload-or-restart chrony") {
		t.Errorf("expected reload-or-restart chrony, got %v", exec.executed)
	}
}

func TestReloadConfigRemovesDropinWhenServersEmpty(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf")
	if err := os.WriteFile(confPath, []byte("# managed by linkguard\nserver old.example iburst\n"), 0o644); err != nil {
		t.Fatalf("seed WriteFile: %v", err)
	}
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: confPath}

	if err := s.ReloadConfig(context.Background(), Config{}); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("expected drop-in removed when Servers is empty, got err=%v", err)
	}
	if !containsExecuted(exec.executed, "systemctl reload-or-restart chrony") {
		t.Errorf("expected reload-or-restart chrony even when removing, got %v", exec.executed)
	}
}

func TestReloadConfigRemovingAbsentDropinIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf") // never created
	s := &Service{exec: &fakeExec{}, confPath: confPath}

	if err := s.ReloadConfig(context.Background(), Config{}); err != nil {
		t.Fatalf("ReloadConfig on absent drop-in must be idempotent, got: %v", err)
	}
}

func TestReloadConfigSetsTimezoneWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: filepath.Join(dir, "linkguard.conf")}

	if err := s.ReloadConfig(context.Background(), Config{Timezone: "America/Sao_Paulo"}); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	if !containsExecuted(exec.executed, "timedatectl set-timezone America/Sao_Paulo") {
		t.Errorf("expected timedatectl set-timezone call, got %v", exec.executed)
	}
}

func TestReloadConfigNoopWriteInDryRun(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf")
	s := &Service{exec: &fakeExec{dryRun: true}, confPath: confPath}

	if err := s.ReloadConfig(context.Background(), Config{Servers: []string{"c.ntp.br"}}); err != nil {
		t.Fatalf("ReloadConfig in dry-run: %v", err)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("expected no file written in dry-run, got err=%v", err)
	}
}

// TestParseChronycTrackingRealSample uses a real `chronyc tracking` capture
// taken from production during this session's investigation.
func TestParseChronycTrackingRealSample(t *testing.T) {
	sample := `Reference ID    : C41A61AD (2800:1e0:1080:a::82)
Stratum         : 2
Ref time (UTC)  : Mon Aug 10 13:04:01 2026
System time     : 0.000009313 seconds slow of NTP time
Last offset     : -0.000160444 seconds
RMS offset      : 0.000097272 seconds
Frequency       : 5.836 ppm slow
Residual freq   : -0.003 ppm
Skew            : 0.041 ppm
Root delay      : 0.048532970 seconds
Root dispersion : 0.001106995 seconds
Update interval : 1027.4 seconds
Leap status     : Normal
`
	stratum, offsetSecs, source := ParseChronycTracking(sample)
	if stratum != 2 {
		t.Errorf("stratum = %d, want 2", stratum)
	}
	if !strings.Contains(source, "C41A61AD") {
		t.Errorf("source = %q, want it to contain the reference ID", source)
	}
	wantOffset := -0.000009313
	if diff := offsetSecs - wantOffset; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("offsetSecs = %v, want ~%v", offsetSecs, wantOffset)
	}
}

func TestStatusReportsNotInstalledWhenUnitMissing(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"systemctl list-unit-files --no-legend chrony.service": "",
	}}
	s := &Service{exec: exec, confPath: "/unused"}

	st := s.Status(context.Background())
	if st.Installed {
		t.Error("Installed = true, want false when the unit is missing")
	}
	if st.Synced {
		t.Error("Synced = true, want false when not installed")
	}
}

func TestStatusReportsSyncedAndDetailWhenInstalled(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"systemctl list-unit-files --no-legend chrony.service": "chrony.service                        enabled",
		"timedatectl show --property=NTPSynchronized --value":  "yes",
		"chronyc tracking": "Reference ID    : C41A61AD (2800:1e0:1080:a::82)\nStratum         : 2\nSystem time     : 0.000009313 seconds slow of NTP time\n",
	}}
	s := &Service{exec: exec, confPath: "/unused"}

	st := s.Status(context.Background())
	if !st.Installed {
		t.Fatal("Installed = false, want true")
	}
	if !st.Synced {
		t.Error("Synced = false, want true")
	}
	if st.Stratum != 2 {
		t.Errorf("Stratum = %d, want 2", st.Stratum)
	}
	if !strings.Contains(st.Source, "C41A61AD") {
		t.Errorf("Source = %q, want it to contain the reference ID", st.Source)
	}
}

func TestListTimezonesParsesNewlineSeparatedOutput(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"timedatectl list-timezones": "America/Sao_Paulo\nAmerica/New_York\nUTC\n",
	}}
	s := &Service{exec: exec, confPath: "/unused"}

	zones, err := s.ListTimezones(context.Background())
	if err != nil {
		t.Fatalf("ListTimezones: %v", err)
	}
	want := []string{"America/Sao_Paulo", "America/New_York", "UTC"}
	if len(zones) != len(want) {
		t.Fatalf("got %d zones, want %d: %v", len(zones), len(want), zones)
	}
	for i, z := range want {
		if zones[i] != z {
			t.Errorf("zones[%d] = %q, want %q", i, zones[i], z)
		}
	}
}

// TestListTimezonesReturnsEmptySliceNotNilOnEmptyOutput is the regression
// test for a real bug caught during this plan's self-review: with zero
// timezone lines, ListTimezones used to leave its result at the nil zero
// value (no error), which the handler's `if err != nil` nil-guard (Task 2)
// does not catch — producing "timezones":null in the API response.
func TestListTimezonesReturnsEmptySliceNotNilOnEmptyOutput(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"timedatectl list-timezones": "",
	}}
	s := &Service{exec: exec, confPath: "/unused"}

	zones, err := s.ListTimezones(context.Background())
	if err != nil {
		t.Fatalf("ListTimezones: %v", err)
	}
	if zones == nil {
		t.Error("zones is nil, want a non-nil empty slice")
	}
	if len(zones) != 0 {
		t.Errorf("zones = %v, want empty", zones)
	}
}

func TestInstallChronyRunsSystemdRun(t *testing.T) {
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: "/unused"}

	if err := s.InstallChrony(context.Background()); err != nil {
		t.Fatalf("InstallChrony: %v", err)
	}
	want := "systemd-run --pipe --wait -- apt-get install -y --no-install-recommends chrony"
	if !containsExecuted(exec.executed, want) {
		t.Errorf("expected %q, got %v", want, exec.executed)
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
cd /home/gov/Documentos/Projetos/gbtech/repos/linkguard-fw
export PATH=$HOME/sdk/go1.25.0/bin:$PATH
go test ./internal/timesync/... -v
```

Esperado: `FAIL` — `Config`, `DefaultConfig`, `Service`, `GenerateChronyConf`, `ParseChronycTracking` etc. não existem ainda (`undefined: ...`).

- [ ] **Step 3: Implementar**

Substituir o conteúdo de `internal/timesync/timesync.go` por:

```go
// Package timesync makes LinkGuard the owner of the box's NTP time
// synchronization — the same "own this runtime prerequisite" pattern already
// used for IPv4 forwarding (routes.EnsureForwarding) and conntrack
// accounting (hosttraffic.EnsureAccounting).
//
// EnsureEnabled/IsSynced below are unchanged since this package's original
// version and remain the ONLY thing the Vigia alert/health-check
// (internal/monitoring/healthchecks.go, checkNTP) calls — Service (added
// 2026-08-10) is a separate, additive admin-control surface: it reuses
// IsSynced for display but never duplicates sync detection. See
// docs/superpowers/specs/2026-08-10-ntp-control-design.md.
package timesync

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// EnsureEnabled turns on chrony (NTP time sync) if the systemd unit is
// installed, so the clock stays correct without any manual step. It never
// installs the chrony package itself — only enables it if already present —
// because running a package manager from inside a long-running service is a
// different, riskier category of action than flipping a switch on software
// that's already there (apt lock contention, unattended-upgrades). It's a
// no-op in dry-run mode via Execute's own dry-run handling — no separate
// check needed here.
func EnsureEnabled(ctx context.Context, exec firewall.Executor) {
	out, err := exec.ExecuteRead(ctx, "systemctl", "list-unit-files", "--no-legend", "chrony.service")
	if err != nil || !strings.Contains(out, "chrony.service") {
		slog.Info("chrony not installed; skipping NTP auto-enable (install chrony to enable time sync)")
		return
	}
	if _, err := exec.Execute(ctx, "systemctl", "enable", "--now", "chrony"); err != nil {
		slog.Warn("could not enable chrony; NTP time sync will not be configured", "err", err)
	}
}

// IsSynced reports whether the system clock is currently NTP-synchronized,
// via systemd-timedated's own view of clock state — this works regardless of
// which NTP client owns the sync (chrony or systemd-timesyncd), so the
// caller never needs to know which one is installed.
func IsSynced(ctx context.Context, exec firewall.Executor) bool {
	out, err := exec.ExecuteRead(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "yes"
}

// chronyDropinPath is the LinkGuard-managed chrony drop-in. Debian's
// packaged /etc/chrony/chrony.conf already contains `confdir
// /etc/chrony/conf.d` — LinkGuard never touches chrony.conf itself, only
// this file, so the vendor's own defaults (driftfile, rtcsync, makestep,
// etc.) are never at risk of being dropped by a LinkGuard-generated file.
const chronyDropinPath = "/etc/chrony/conf.d/linkguard.conf"

// Config holds the admin-editable NTP settings. Empty fields mean
// "unmanaged" — Servers empty falls back to the Debian package's own pool
// default; Timezone empty leaves the OS's already-configured zone alone.
type Config struct {
	Servers  []string `json:"servers"`
	Timezone string   `json:"timezone"`
}

// DefaultConfig is the "unmanaged" starting state — identical to today's
// behaviour before this feature existed (EnsureEnabled already turns on
// chrony with the Debian default pool). Servers is an empty slice, not nil,
// so it marshals to JSON `[]` rather than `null`.
func DefaultConfig() Config {
	return Config{Servers: []string{}}
}

// StatusInfo is the read-only NTP status shown in the panel.
type StatusInfo struct {
	Installed  bool    `json:"installed"`
	Synced     bool    `json:"synced"`
	Stratum    int     `json:"stratum,omitempty"`
	OffsetSecs float64 `json:"offset_secs,omitempty"`
	Source     string  `json:"source,omitempty"`
}

// Service owns the NTP admin-control surface: applying Config, reporting
// detailed status, listing timezones, and installing chrony on demand.
type Service struct {
	exec     firewall.Executor
	confPath string // overridden in tests; production uses chronyDropinPath
}

// NewService creates the NTP control service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec, confPath: chronyDropinPath}
}

// GenerateChronyConf renders the LinkGuard-managed chrony drop-in from the
// configured NTP servers. Pure — no I/O. Only meaningful when
// len(c.Servers) > 0 — ReloadConfig removes the drop-in entirely instead of
// calling this when Servers is empty, so chronyd falls back to the Debian
// package's own default pool untouched.
func GenerateChronyConf(c Config) string {
	var b strings.Builder
	b.WriteString("# managed by linkguard\n\n")
	for _, srv := range c.Servers {
		fmt.Fprintf(&b, "server %s iburst\n", srv)
	}
	return b.String()
}

// ReloadConfig applies Servers (drop-in write/remove) and Timezone, then
// reloads chrony gracefully via systemd's reload-or-restart — same
// convention as keaunbound.Service.ReloadConfigs (internal/keaunbound), not
// a raw SIGHUP or an unconditional restart. File writes are skipped in
// dry-run mode; Execute calls always go through (RealExecutor itself
// handles dry-run by logging instead of running).
func (s *Service) ReloadConfig(ctx context.Context, c Config) error {
	if !s.exec.IsDryRun() {
		if len(c.Servers) == 0 {
			if err := os.Remove(s.confPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remover %s: %w", s.confPath, err)
			}
		} else {
			if err := os.WriteFile(s.confPath, []byte(GenerateChronyConf(c)), 0o644); err != nil {
				return fmt.Errorf("escrever %s: %w", s.confPath, err)
			}
		}
	}
	if c.Timezone != "" {
		if _, err := s.exec.Execute(ctx, "timedatectl", "set-timezone", c.Timezone); err != nil {
			return fmt.Errorf("definir fuso horário: %w", err)
		}
	}
	if _, err := s.exec.Execute(ctx, "systemctl", "reload-or-restart", "chrony"); err != nil {
		return fmt.Errorf("recarregar chrony: %w", err)
	}
	return nil
}

// ParseChronycTracking parses `chronyc tracking` output into its most
// useful display fields. Best-effort: a field chronyc omits is left at its
// zero value.
func ParseChronycTracking(out string) (stratum int, offsetSecs float64, source string) {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "Reference ID":
			source = val
		case "Stratum":
			stratum, _ = strconv.Atoi(val)
		case "System time":
			fields := strings.Fields(val)
			if len(fields) > 0 {
				f, _ := strconv.ParseFloat(fields[0], 64)
				if strings.Contains(val, "slow") {
					f = -f
				}
				offsetSecs = f
			}
		}
	}
	return stratum, offsetSecs, source
}

// Status reports the current chrony install/sync/detail state for display.
// Reuses IsSynced (unchanged, see package doc) for the `synced` field —
// never re-implements sync detection; Vigia's checkNTP remains the single
// source of truth for alerting.
func (s *Service) Status(ctx context.Context) StatusInfo {
	installed, _ := s.exec.ExecuteRead(ctx, "systemctl", "list-unit-files", "--no-legend", "chrony.service")
	st := StatusInfo{Installed: strings.Contains(installed, "chrony.service")}
	if !st.Installed {
		return st
	}
	st.Synced = IsSynced(ctx, s.exec)
	out, err := s.exec.ExecuteRead(ctx, "chronyc", "tracking")
	if err == nil {
		st.Stratum, st.OffsetSecs, st.Source = ParseChronycTracking(out)
	}
	return st
}

// ListTimezones returns every IANA timezone name systemd knows about, for
// populating a <select> in the UI — never a free-text field, to avoid a
// typo silently producing an invalid `timedatectl set-timezone` call.
// Always returns a non-nil slice on success (even zero matches), so a
// caller marshaling it to JSON never emits `null` for a field the frontend
// expects to `.map()` over.
func (s *Service) ListTimezones(ctx context.Context) ([]string, error) {
	out, err := s.exec.ExecuteRead(ctx, "timedatectl", "list-timezones")
	if err != nil {
		return nil, err
	}
	zones := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			zones = append(zones, line)
		}
	}
	return zones, nil
}

// InstallChrony asks systemd to run apt-get in its own transient,
// unhardened unit — never inside this process's own sandbox, which would
// need ReadWritePaths widened across most of the package-management
// filesystem (/var/lib/dpkg, /var/cache/apt, /usr, ...) to work. Only ever
// triggered by an explicit admin action (never automatic/on startup), same
// safety property EnsureEnabled already relies on for "no silent apt".
func (s *Service) InstallChrony(ctx context.Context) error {
	_, err := s.exec.Execute(ctx, "systemd-run", "--pipe", "--wait",
		"--", "apt-get", "install", "-y", "--no-install-recommends", "chrony")
	return err
}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/timesync/
go test ./internal/timesync/... -v
```

Esperado: `gofmt -l` sem saída (nada mal formatado); `PASS` em todos os testes.

- [ ] **Step 5: Commit**

```bash
git add internal/timesync/timesync.go internal/timesync/timesync_test.go
git commit -m "feat(timesync): NTP control service (servers, timezone, status, install)"
```

---

### Task 2: API — handler, permissões, rotas, deploy

**Files:**
- Create: `internal/api/handlers/ntp.go`
- Create: `internal/api/handlers/ntp_test.go`
- Modify: `internal/auth/permissions.go`
- Modify: `internal/api/server.go`
- Modify: `deploy/linkguard-fw.service`

**Interfaces:**
- Consumes: `timesync.Config`/`DefaultConfig`/`StatusInfo`/`Service`/`NewService` (Task 1); `writeJSON`/`writeError`/`writeInternalError`/`decodeJSON`/`auditAction` (já existentes, `internal/api/handlers/helpers.go`); `autoApplier`/`newAutoApplier`/`autoApplyDelay` (já existentes, `internal/api/handlers/autoapply.go` e `netsvc.go`); `applyStatus` struct (já existente, `internal/api/handlers/netsvc.go` — reaproveitado, não duplicado); `alerts.Service.RuleError(msg string) error` (já existente); `db.GetSetting`/`SetSetting(key, value string)` (já existentes, `internal/storage/repository.go:864,874`).
- Produces: `GET /api/ntp`, `PUT /api/ntp/config`, `POST /api/ntp/apply`, `POST /api/ntp/install-chrony` — consumidos pela Task 3 (frontend). `auth.PermNTPRead`/`PermNTPWrite`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `internal/api/handlers/ntp_test.go`:

```go
package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
)

// fakeTimesyncExec is a minimal firewall.Executor test double dedicated to
// this file — not internal/api/handlers' fakeNftExec, which returns "" for
// any non-nft command and breaks internal/timesync's parsers (see that
// package's own fakeExec doc comment for the same reasoning).
type fakeTimesyncExec struct{ dryRun bool }

func (e *fakeTimesyncExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *fakeTimesyncExec) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *fakeTimesyncExec) IsDryRun() bool { return e.dryRun }

func newTestNTPHandler(t *testing.T) *NTPHandler {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	svc := timesync.NewService(&fakeTimesyncExec{dryRun: true})
	return NewNTPHandler(db, svc, nil)
}

func TestGetNTPReturnsEmptyServersAndTimezonesNotNull(t *testing.T) {
	h := newTestNTPHandler(t)
	r := httptest.NewRequest("GET", "/api/ntp", nil)
	w := httptest.NewRecorder()
	h.GetNTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	// Compacting through json.Unmarshal/Marshal (instead of matching the raw
	// body string) avoids brittleness from key ordering while still proving
	// neither field serialized as null.
	var v any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	compact, _ := json.Marshal(v)
	body := string(compact)
	if !strings.Contains(body, `"servers":[]`) {
		t.Errorf("expected servers:[] not null in body: %s", body)
	}
	if !strings.Contains(body, `"timezones":[]`) {
		t.Errorf("expected timezones:[] not null in body: %s", body)
	}
}

func TestUpdateNTPConfigRejectsInvalidServer(t *testing.T) {
	h := newTestNTPHandler(t)
	body := `{"servers":["evil; rm -rf /"],"timezone":""}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

func TestUpdateNTPConfigPersistsAndRoundTrips(t *testing.T) {
	h := newTestNTPHandler(t)
	body := `{"servers":["c.ntp.br","192.36.143.130"],"timezone":"America/Sao_Paulo"}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	cfg := h.getConfig()
	if len(cfg.Servers) != 2 || cfg.Servers[0] != "c.ntp.br" {
		t.Errorf("Servers = %v, want [c.ntp.br 192.36.143.130]", cfg.Servers)
	}
	if cfg.Timezone != "America/Sao_Paulo" {
		t.Errorf("Timezone = %q, want America/Sao_Paulo", cfg.Timezone)
	}
}

func TestApplyRunsReloadAndRecordsStatus(t *testing.T) {
	h := newTestNTPHandler(t)
	if got := h.lastApplyStatus(); got != nil {
		t.Fatalf("expected nil last_apply before any apply, got %+v", got)
	}

	r := httptest.NewRequest("POST", "/api/ntp/apply", nil)
	w := httptest.NewRecorder()
	h.Apply(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	got := h.lastApplyStatus()
	if got == nil || !got.OK {
		t.Fatalf("expected a successful last_apply, got %+v", got)
	}
}

func TestInstallChronyReturns200OnSuccess(t *testing.T) {
	h := newTestNTPHandler(t)
	r := httptest.NewRequest("POST", "/api/ntp/install-chrony", nil)
	w := httptest.NewRecorder()
	h.InstallChrony(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/api/handlers/... -run TestGetNTP -v
```

Esperado: `FAIL` — `NTPHandler`/`NewNTPHandler` não existem ainda.

- [ ] **Step 3: Implementar**

Criar `internal/api/handlers/ntp.go`:

```go
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
)

const ntpCfgKey = "ntp_config"
const ntpApplyStatusKey = "ntp_last_apply"

// reNTPServer guards values rendered into the chrony drop-in via string
// formatting — hostname or IP, no spaces/quotes/control characters.
var reNTPServer = regexp.MustCompile(`^[a-zA-Z0-9.:-]{1,253}$`)

func validNTPServer(s string) bool { return reNTPServer.MatchString(s) }

// NTPHandler manages NTP server/timezone config through internal/timesync.
// Same auto-apply-on-save pattern as NetsvcHandler (DHCP/DNS,
// internal/api/handlers/netsvc.go) — reuses its applyStatus type and
// autoApplier/autoApplyDelay rather than duplicating them.
type NTPHandler struct {
	db       *storage.DB
	svc      *timesync.Service
	alertSvc *alerts.Service
	applier  *autoApplier
}

// NewNTPHandler creates an NTPHandler. Saving config auto-applies
// (debounced), matching NetsvcHandler's convention.
func NewNTPHandler(db *storage.DB, svc *timesync.Service, alertSvc *alerts.Service) *NTPHandler {
	h := &NTPHandler{db: db, svc: svc, alertSvc: alertSvc}
	h.applier = newAutoApplier(autoApplyDelay, func() { _ = h.doReload(context.Background()) })
	return h
}

func (h *NTPHandler) getConfig() timesync.Config {
	cfg := timesync.DefaultConfig()
	if raw, _ := h.db.GetSetting(ntpCfgKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

func (h *NTPHandler) saveConfig(c timesync.Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return h.db.SetSetting(ntpCfgKey, string(b))
}

// lastApplyStatus returns the persisted result of the most recent apply, or
// nil if nothing has been applied yet — same "never attempted" vs "attempted
// and failed" distinction as NetsvcHandler.lastApplyStatus.
func (h *NTPHandler) lastApplyStatus() *applyStatus {
	raw, _ := h.db.GetSetting(ntpApplyStatusKey)
	if raw == "" {
		return nil
	}
	var st applyStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil
	}
	return &st
}

// doReload applies the current config and records the result, shared by
// the debounced auto-apply and the manual "Aplicar agora" button.
func (h *NTPHandler) doReload(ctx context.Context) error {
	err := h.svc.ReloadConfig(ctx, h.getConfig())
	st := applyStatus{OK: err == nil, At: time.Now().Unix()}
	if err != nil {
		st.Error = err.Error()
		if h.alertSvc != nil {
			_ = h.alertSvc.RuleError("Falha ao aplicar configuração de NTP: " + err.Error())
		}
	}
	if b, mErr := json.Marshal(st); mErr == nil {
		_ = h.db.SetSetting(ntpApplyStatusKey, string(b))
	}
	return err
}

func (h *NTPHandler) scheduleApply() {
	if h.applier != nil {
		h.applier.schedule()
	}
}

// GetNTP returns the current config, live status, available timezones, and
// last-apply result in one payload.
func (h *NTPHandler) GetNTP(w http.ResponseWriter, r *http.Request) {
	zones, err := h.svc.ListTimezones(r.Context())
	if err != nil {
		zones = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":     h.getConfig(),
		"status":     h.svc.Status(r.Context()),
		"timezones":  zones,
		"last_apply": h.lastApplyStatus(),
	})
}

// UpdateNTPConfig updates servers/timezone and schedules the debounced
// auto-apply.
func (h *NTPHandler) UpdateNTPConfig(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Servers  []string `json:"servers"`
		Timezone string   `json:"timezone"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	servers := []string{}
	for _, srv := range b.Servers {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if !validNTPServer(srv) {
			writeError(w, http.StatusBadRequest, "servidor NTP inválido: "+srv)
			return
		}
		servers = append(servers, srv)
	}
	cfg := timesync.Config{Servers: servers, Timezone: strings.TrimSpace(b.Timezone)}
	if err := h.saveConfig(cfg); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "ntp.config", "ntp", "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, cfg)
}

// Apply is the "Aplicar agora" button: reloads immediately, bypassing the
// debounce.
func (h *NTPHandler) Apply(w http.ResponseWriter, r *http.Request) {
	if err := h.doReload(r.Context()); err != nil {
		writeInternalError(w, fmt.Errorf("falha ao aplicar: %w", err))
		return
	}
	auditAction(h.db, r, "ntp.apply", "ntp", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "aplicado"})
}

// InstallChrony is the explicit "Instalar chrony" button — never automatic,
// see timesync.Service.InstallChrony's doc comment.
func (h *NTPHandler) InstallChrony(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.InstallChrony(r.Context()); err != nil {
		writeInternalError(w, fmt.Errorf("falha ao instalar chrony: %w", err))
		return
	}
	auditAction(h.db, r, "ntp.install_chrony", "ntp", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "instalado"})
}
```

Em `internal/auth/permissions.go`, adicionar ao bloco de leitura (depois de `PermInterfacesRead`):

```go
	PermNTPRead        Permission = "ntp.read"
```

Ao bloco de escrita (depois de `PermInterfacesWrite`):

```go
	PermNTPWrite Permission = "ntp.write" // config de servidores/timezone, aplicar, instalar chrony
```

Ao `Catalog` (depois das duas entradas de `PermInterfacesRead`/`PermInterfacesWrite`):

```go
	{PermNTPRead, "NTP", "Ver NTP", "Ver status de sincronização, servidores configurados e fuso horário"},
	{PermNTPWrite, "NTP", "Gerenciar NTP", "Configurar servidores/fuso horário, aplicar e instalar o chrony"},
```

Ao `switch` de `readOnlyPermissions()`, adicionar `PermNTPRead` à lista de `case`:

```go
		case PermDashboardRead, PermMonitoringRead, PermLogsRead,
			PermLinksRead, PermRoutesRead, PermFirewallRead,
			PermHostsRead, PermSystemRead, PermDHCPRead, PermDNSRead, PermInterfacesRead, PermNTPRead:
```

À lista de permissões do `role-operator` em `DefaultRoles`, adicionar `PermNTPRead, PermNTPWrite,`:

```go
		Permissions: []Permission{
			PermDashboardRead, PermMonitoringRead, PermLogsRead,
			PermLinksRead, PermLinksWrite,
			PermRoutesRead, PermRoutesWrite,
			PermFirewallRead, PermFirewallWrite,
			PermHostsRead, PermHostsBlock, PermHostsAssign,
			PermSystemRead,
			PermDHCPRead, PermDHCPWrite, PermDNSRead, PermDNSWrite,
			PermInterfacesRead, PermInterfacesWrite,
			PermNTPRead, PermNTPWrite,
		},
```

(`role-admin` usa `allPermissions()` — inclui `PermNTPRead`/`PermNTPWrite` automaticamente, sem mudança.)

Em `internal/api/server.go`, adicionar ao bloco de imports (ordem alfabética, junto dos outros `internal/*`):

```go
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
```

E, logo depois do bloco `// DNS query log (unbound journal; opt-in via DNS log_queries)` (por volta da linha 330), adicionar:

```go
		// NTP (chrony) — status, servidores customizados, timezone, instalar sob demanda
		ntpSvc := timesync.NewService(s.exec)
		ntpH := handlers.NewNTPHandler(s.db, ntpSvc, s.alertSvc)
		r.With(require(auth.PermNTPRead)).Get("/api/ntp", ntpH.GetNTP)
		r.With(require(auth.PermNTPWrite)).Put("/api/ntp/config", ntpH.UpdateNTPConfig)
		r.With(require(auth.PermNTPWrite)).Post("/api/ntp/apply", ntpH.Apply)
		r.With(require(auth.PermNTPWrite)).Post("/api/ntp/install-chrony", ntpH.InstallChrony)
```

Em `deploy/linkguard-fw.service`, trocar a linha `ReadWritePaths=` (e o comentário acima) por:

```
# Writable paths so the app can persist generated configs: nftables (firewall),
# Kea (DHCP), unbound (DNS), the conntrack-accounting sysctl drop-in, the
# stable-interface-name .link files (Fase A: nomes estáveis por MAC), and the
# NTP (chrony) drop-in.
ReadWritePaths=/var/lib/linkguard-fw /etc/linkguard-fw /etc/nftables.conf /etc/kea /etc/unbound /etc/sysctl.d /etc/systemd/network /etc/chrony/conf.d
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
gofmt -l internal/api/handlers/ internal/auth/ internal/api/
go test ./internal/api/handlers/... ./internal/auth/... -v
go build ./...
go vet ./...
```

Esperado: `gofmt -l` sem saída; `PASS` em tudo; `go build`/`go vet` limpos.

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/ntp.go internal/api/handlers/ntp_test.go internal/auth/permissions.go internal/api/server.go deploy/linkguard-fw.service
git commit -m "feat(api): expose NTP config/status/apply/install endpoints"
```

---

### Task 3: Frontend — página "Ntp"

**Files:**
- Modify: `web/src/types/index.ts`
- Create: `web/src/pages/Ntp.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/components/Layout.tsx`
- Modify: `web/src/i18n/index.tsx`

**Interfaces:**
- Consumes: `GET /api/ntp`, `PUT /api/ntp/config`, `POST /api/ntp/apply`, `POST /api/ntp/install-chrony` (Task 2); `client` (axios wrapper, `web/src/api/client.ts`); `Panel` (`web/src/components/ui/Panel.tsx`); `useAuth().can(perm: string)` (`web/src/context/AuthContext`).
- Produces: nada consumido por outra task — ponta final da fatia.

- [ ] **Step 1: Adicionar os tipos**

Em `web/src/types/index.ts`, logo depois de `DNSData` (linha ~279):

```ts
export interface NTPConfig { servers: string[]; timezone: string; }
export interface NTPStatus { installed: boolean; synced: boolean; stratum?: number; offset_secs?: number; source?: string; }
export interface NTPData { config: NTPConfig; status: NTPStatus; timezones: string[]; last_apply?: LastApply; }
```

- [ ] **Step 2: Criar a página**

Criar `web/src/pages/Ntp.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { RefreshCw, Clock, Play, Download } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import Panel from '../components/ui/Panel';
import type { NTPData, NTPConfig } from '../types';

export default function Ntp() {
  const { can } = useAuth();
  const canWrite = can('ntp.write');
  const [data, setData] = useState<NTPData | null>(null);
  const [cfg, setCfg] = useState<NTPConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const fetchData = async () => {
    setLoading(true); setError(false);
    try {
      const res = await client.get<NTPData>('/api/ntp');
      setData(res.data); setCfg(res.data.config);
    } catch { setError(true); } finally { setLoading(false); }
  };
  useEffect(() => { fetchData(); }, []);

  const run = async (fn: () => Promise<any>, ok: string) => {
    setBusy(true); setMsg('');
    try { await fn(); if (ok) setMsg(ok); await fetchData(); }
    catch (e: any) { setMsg(`Erro: ${e.response?.data?.error || e.message}`); }
    finally { setBusy(false); }
  };

  const saveConfig = () => cfg && run(() => client.put('/api/ntp/config', { servers: cfg.servers, timezone: cfg.timezone }), 'Config de NTP salva — aplicando automaticamente.');
  const apply = () => run(() => client.post('/api/ntp/apply'), 'Aplicado com sucesso.');
  const installChrony = () => run(() => client.post('/api/ntp/install-chrony'), 'chrony instalado.');

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">NTP</h1>
          <p className="text-gray-500 text-sm">Sincronização de horário — servidores, fuso horário e status</p>
        </div>
        <div className="flex gap-2">
          {canWrite && <button onClick={apply} disabled={busy} title="Salvar já aplica sozinho; use para forçar agora" className="btn-secondary flex items-center gap-2 disabled:opacity-50"><Play className="w-4 h-4" /> Aplicar agora</button>}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Atualizar</button>
        </div>
      </div>

      {data?.last_apply && !data.last_apply.ok && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          Última aplicação automática falhou: {data.last_apply.error || 'erro desconhecido'}. Corrija e use "Aplicar agora".
        </div>
      )}

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">Falha ao carregar. <button onClick={fetchData} className="underline">Tentar novamente</button></div>}
      {msg && <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>}

      {loading || !cfg ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : (
        <>
          <Panel title={<span className="flex items-center gap-2"><Clock className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Status</span></span>}>
            {!data?.status.installed ? (
              <div className="space-y-3">
                <p className="text-gray-400 text-sm">O chrony (serviço de sincronização NTP) não está instalado nesta máquina.</p>
                {canWrite && (
                  <button onClick={installChrony} disabled={busy} className="btn-primary flex items-center gap-2 disabled:opacity-50"><Download className="w-4 h-4" /> Instalar chrony</button>
                )}
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                <div>
                  <div className="text-gray-500">Sincronizado</div>
                  <div className={data?.status.synced ? 'text-green-400' : 'text-red-400'}>{data?.status.synced ? 'Sim' : 'Não'}</div>
                </div>
                <div>
                  <div className="text-gray-500">Stratum</div>
                  <div className="text-white">{data?.status.stratum ?? '—'}</div>
                </div>
                <div>
                  <div className="text-gray-500">Offset</div>
                  <div className="text-white font-mono">{data?.status.offset_secs != null ? `${(data.status.offset_secs * 1000).toFixed(3)} ms` : '—'}</div>
                </div>
                <div>
                  <div className="text-gray-500">Fonte</div>
                  <div className="text-white font-mono truncate">{data?.status.source || '—'}</div>
                </div>
              </div>
            )}
          </Panel>

          <Panel title={<span className="flex items-center gap-2"><Clock className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Configuração</span></span>}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="label">Servidores NTP (separados por vírgula)</label>
                <input className="input w-full" placeholder="a.ntp.br, b.ntp.br (vazio = pool padrão do Debian)" value={cfg.servers.join(', ')} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, servers: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
                <p className="text-xs text-gray-600 mt-1">Vazio = usa o pool padrão do Debian, sem gerenciar nada.</p>
              </div>
              <div>
                <label className="label">Fuso horário</label>
                <select className="input w-full" value={cfg.timezone} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, timezone: e.target.value })}>
                  <option value="">Não gerenciar (mantém o que já está configurado)</option>
                  {data?.timezones.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
                </select>
              </div>
            </div>
            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </Panel>
        </>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Registrar a rota**

Em `web/src/App.tsx`, adicionar o import junto dos outros de `pages/`:

```tsx
import Ntp from './pages/Ntp';
```

E a rota, logo depois de `<Route path="dns" element={<Dns />} />`:

```tsx
          <Route path="ntp" element={<Ntp />} />
```

- [ ] **Step 4: Adicionar ao menu**

Em `web/src/components/Layout.tsx`, adicionar `Clock` ao import de ícones existente (linha ~9, junto de `Globe, Sparkles, SlidersHorizontal`):

```tsx
  Menu, X, AlertTriangle, Cable, Server, Globe, Sparkles, SlidersHorizontal, Clock,
```

E o item de menu no grupo `rede`, logo depois de `{ to: '/dns', ... }`:

```tsx
      { to: '/ntp', label: 'nav.ntp', icon: Clock, perm: ['ntp.read'] },
```

Em `web/src/i18n/index.tsx`, adicionar `'nav.ntp': 'NTP',` nos dois blocos de tradução, junto de `'nav.dns'` (linhas ~23 e ~65 — mesmo texto nos dois idiomas, "NTP" não muda).

- [ ] **Step 5: Verificar que compila**

```bash
export PATH=$HOME/.nvm/versions/node/v22.21.1/bin:$PATH
cd web && npm run build
```

Esperado: build limpo (`tsc -b && vite build` sem erro).

- [ ] **Step 6: Testar manualmente na VM de teste**

Reaproveitar `~/linkguard-testvm/` (`./recreate.sh`, `./ssh.sh`, `./destroy.sh` — ver memória `linkguard-test-vm`). A base da VM provavelmente não tem `chrony` instalado, o que cobre o caminho "instalar" de graça:

1. `./recreate.sh`, buildar o `.deb` (`make deb` — se `npm install` falhar por `web/node_modules` de dono errado de uma sessão anterior, rodar `cd web && npm run build` direto, sem `npm install`, igual foi feito na Fase A desta mesma sessão), copiar pra VM via `scp`, instalar com `dpkg -i`.
2. Logar no painel, abrir "NTP" no menu.
3. Confirmar que aparece o aviso "chrony não está instalado" com o botão "Instalar chrony" (a menos que a imagem base já tenha chrony — nesse caso pular pro passo 5).
4. Clicar "Instalar chrony", confirmar que depois de instalar a tela muda pro status normal (sincronizado/stratum/offset/fonte).
5. Configurar um servidor customizado (ex.: `c.ntp.br`), salvar, confirmar via SSH que `/etc/chrony/conf.d/linkguard.conf` tem o conteúdo esperado com o cabeçalho `# managed by linkguard`.
6. Limpar o campo de servidores, salvar, confirmar via SSH que o arquivo foi removido.
7. Escolher um fuso horário diferente no `<select>`, salvar, confirmar via SSH (`timedatectl status`) que o fuso mudou imediatamente (sem reboot).
8. `./destroy.sh`.

- [ ] **Step 7: Commit**

```bash
git add web/src/types/index.ts web/src/pages/Ntp.tsx web/src/App.tsx web/src/components/Layout.tsx web/src/i18n/index.tsx
git commit -m "feat(ui): NTP page (servers, timezone, status, install chrony)"
```

---

## Depois deste plano

Nada fica pendente de propósito além do já documentado como fora de escopo na
spec (§12): autenticação NTP/NTS, o LinkGuard virar servidor NTP pra LAN, e
qualquer mudança no alerta Vigia — todos explicitamente não pedidos.
