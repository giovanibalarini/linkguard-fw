# Vigia: NTP, SMART, boot lento e journal corrompido — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Estender a feature "Vigia" (`internal/monitoring`) com 4 checks novos — NTP
(auto-configurado + monitorado), SMART do disco (saúde + setores realocados + temperatura),
boot lento, e journal corrompido — reusando o motor de transição/anti-flap já existente, sem
UI nova.

**Architecture:** Dois pacotes novos e pequenos e leaf (`internal/timesync`,
`internal/disksmart`) fazem a leitura/ação de sistema; `internal/monitoring/healthchecks.go`
ganha os checks que os chamam e alimentam o `observe()`/`ensureMeta()` já existente;
`internal/alerts/service.go` ganha os pares de alerta; um novo `internal/monitoring/journalcheck.go`
roda `journalctl --verify` numa agenda semanal própria (fora do tick de 30s); `main.go` chama a
nova `Ensure*` no boot e sobe o novo scheduler; frontend ganha só rótulos/campos novos no que já
existe.

**Tech Stack:** Go 1.25 (backend), React+TypeScript+Vite+Tailwind (frontend), SQLite.

## Global Constraints

- Todo comando de sistema roda via `firewall.Executor` (`Execute` pra mutação — respeita
  dry-run; `ExecuteRead` pra leitura — sempre roda), nunca `exec.Command` direto. Array de args,
  nunca string de shell.
- LinkGuard nunca instala pacote via `apt` de dentro do binário — só habilita o que já está
  presente (`chrony`).
- Todos os checks novos entram debaixo do mesmo `cfg.Enabled` (interruptor mestre único),
  **exceto** a leitura/gravação (não o alerta) do boot-time, que precisa rodar sempre no
  primeiro tick pra não usar um uptime obsoleto se o toggle for reativado depois — ver Task 6.
- Severidades: `SeverityWarning` (NTP dessincronizado, SMART degradado/quente, boot lento,
  journal corrompido) e `SeverityCritical` (SMART falhou no autodiagnóstico geral) — únicos dois
  níveis usados, seguindo o padrão já estabelecido no arquivo.
- Textos de alerta em PT-BR, formatados com `fmt.Sprintf`, citando o valor medido — mesmo padrão
  de `DiskFull`/`HighCPU`.
- TDD real no backend: teste que falha primeiro, depois implementação mínima.
- `go build ./...` e `go test ./...` limpos ao final de cada task.

---

### Task 1: `internal/timesync` — LinkGuard assume o NTP

**Files:**
- Create: `internal/timesync/timesync.go`
- Test: `internal/timesync/timesync_test.go`

**Interfaces:**
- Produces: `EnsureEnabled(ctx context.Context, exec firewall.Executor)`,
  `IsSynced(ctx context.Context, exec firewall.Executor) bool` — usados pelo Task 5
  (`checkNTP`) e Task 8 (`main.go`).

- [ ] **Step 1: Escrever os testes que falham**

```go
package timesync

import (
	"context"
	"testing"
)

type fakeExec struct {
	unitFilesOut string
	enableCalled bool
	enableErr    error
	syncedOut    string
	syncedErr    error
}

func (f *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "systemctl" && len(args) == 3 && args[0] == "enable" && args[1] == "--now" && args[2] == "chrony" {
		f.enableCalled = true
		return "", f.enableErr
	}
	return "", nil
}
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "systemctl" && len(args) == 3 && args[0] == "list-unit-files" {
		return f.unitFilesOut, nil
	}
	if cmd == "timedatectl" {
		return f.syncedOut, f.syncedErr
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool { return false }

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

func TestEnsureEnabledCallsSystemctlWhenInstalled(t *testing.T) {
	fe := &fakeExec{unitFilesOut: "chrony.service                       enabled         enabled\n"}
	EnsureEnabled(context.Background(), fe)
	if !fe.enableCalled {
		t.Fatal("expected systemctl enable --now chrony to be called")
	}
}

func TestEnsureEnabledSkipsWhenNotInstalled(t *testing.T) {
	fe := &fakeExec{unitFilesOut: ""}
	EnsureEnabled(context.Background(), fe)
	if fe.enableCalled {
		t.Fatal("expected systemctl enable NOT to be called when chrony.service is absent")
	}
}

func TestIsSyncedTrue(t *testing.T) {
	fe := &fakeExec{syncedOut: "yes\n"}
	if !IsSynced(context.Background(), fe) {
		t.Fatal("expected IsSynced=true")
	}
}

func TestIsSyncedFalse(t *testing.T) {
	fe := &fakeExec{syncedOut: "no\n"}
	if IsSynced(context.Background(), fe) {
		t.Fatal("expected IsSynced=false")
	}
}

func TestIsSyncedErrorIsFalse(t *testing.T) {
	fe := &fakeExec{syncedErr: errBoom{}}
	if IsSynced(context.Background(), fe) {
		t.Fatal("expected IsSynced=false on exec error")
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/timesync/... -v`
Expected: FAIL — `undefined: EnsureEnabled` / `undefined: IsSynced` (o pacote ainda não existe).

- [ ] **Step 3: Implementar**

```go
// Package timesync makes LinkGuard the owner of the box's NTP time
// synchronization — the same "own this runtime prerequisite" pattern already
// used for IPv4 forwarding (routes.EnsureForwarding) and conntrack
// accounting (hosttraffic.EnsureAccounting).
package timesync

import (
	"context"
	"log/slog"
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
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/timesync/... -v`
Expected: PASS — todos os 5 testes.

- [ ] **Step 5: Commit**

```bash
git add internal/timesync/
git commit -m "feat(timesync): LinkGuard habilita e monitora NTP via chrony"
```

---

### Task 2: `internal/disksmart` — leitura do SMART do disco raiz

**Files:**
- Create: `internal/disksmart/disksmart.go`
- Test: `internal/disksmart/disksmart_test.go`

**Interfaces:**
- Produces: `type Report struct { Passed bool; ReallocatedSectors int; TemperatureC int }`,
  `DetectRootDisk(ctx, exec) (string, error)`, `Read(ctx, exec, device string) (Report, error)`
  — usados pelo Task 5 (`checkSMART`).

- [ ] **Step 1: Escrever os testes que falham**

```go
package disksmart

import (
	"context"
	"strings"
	"testing"
)

type fakeExec struct {
	findmntOut  string
	lsblkOut    string
	smartctlOut string
	smartctlErr error
}

func (f *fakeExec) Execute(_ context.Context, _ string, _ ...string) (string, error) { return "", nil }
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	switch cmd {
	case "findmnt":
		return f.findmntOut, nil
	case "lsblk":
		return f.lsblkOut, nil
	case "smartctl":
		return f.smartctlOut, f.smartctlErr
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool { return false }

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

func TestDetectRootDiskStripsPartition(t *testing.T) {
	fe := &fakeExec{findmntOut: "/dev/sda2\n", lsblkOut: "sda\n"}
	dev, err := DetectRootDisk(context.Background(), fe)
	if err != nil {
		t.Fatal(err)
	}
	if dev != "/dev/sda" {
		t.Fatalf("got %q, want /dev/sda", dev)
	}
}

func TestDetectRootDiskWholeDiskNoParent(t *testing.T) {
	fe := &fakeExec{findmntOut: "/dev/sda\n", lsblkOut: ""}
	dev, err := DetectRootDisk(context.Background(), fe)
	if err != nil {
		t.Fatal(err)
	}
	if dev != "/dev/sda" {
		t.Fatalf("got %q, want /dev/sda", dev)
	}
}

const sampleSmartctlJSON = `{
  "smart_status": {"passed": true},
  "ata_smart_attributes": {
    "table": [
      {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 0}},
      {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 35}}
    ]
  }
}`

func TestReadParsesHealthAndAttributes(t *testing.T) {
	fe := &fakeExec{smartctlOut: sampleSmartctlJSON}
	r, err := Read(context.Background(), fe, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Passed {
		t.Error("expected Passed=true")
	}
	if r.ReallocatedSectors != 0 {
		t.Errorf("ReallocatedSectors = %d, want 0", r.ReallocatedSectors)
	}
	if r.TemperatureC != 35 {
		t.Errorf("TemperatureC = %d, want 35", r.TemperatureC)
	}
}

const failingSmartctlJSON = `{
  "smart_status": {"passed": false},
  "ata_smart_attributes": {
    "table": [
      {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 12}},
      {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 58}}
    ]
  }
}`

func TestReadDetectsFailureAndDegradedAttributes(t *testing.T) {
	fe := &fakeExec{smartctlOut: failingSmartctlJSON}
	r, err := Read(context.Background(), fe, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if r.Passed {
		t.Error("expected Passed=false")
	}
	if r.ReallocatedSectors != 12 {
		t.Errorf("ReallocatedSectors = %d, want 12", r.ReallocatedSectors)
	}
	if r.TemperatureC != 58 {
		t.Errorf("TemperatureC = %d, want 58", r.TemperatureC)
	}
}

func TestReadErrorPropagates(t *testing.T) {
	fe := &fakeExec{smartctlErr: errBoom{}}
	_, err := Read(context.Background(), fe, "/dev/sda")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "/dev/sda") {
		t.Errorf("error should mention device: %v", err)
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/disksmart/... -v`
Expected: FAIL — pacote ainda não existe.

- [ ] **Step 3: Implementar**

```go
// Package disksmart reads S.M.A.R.T. health data for the disk backing the
// root filesystem.
package disksmart

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Report is the subset of `smartctl -x -j <device>` the Vigia SMART checks
// need: the overall self-assessed health verdict, reallocated sector count,
// and current temperature.
type Report struct {
	Passed             bool
	ReallocatedSectors int
	TemperatureC       int
}

type smartctlOutput struct {
	SmartStatus struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	AtaSmartAttributes struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value int `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
}

const (
	attrReallocatedSectorCt = 5
	attrTemperatureCelsius  = 194
)

// DetectRootDisk finds the whole-disk block device backing the root
// filesystem (e.g. "/dev/sda2" -> "/dev/sda"), via findmnt + lsblk's own
// parent-device lookup — never hardcoded or string-guessed, same philosophy
// as the project's interface/route parsers. A root that is already a
// whole-disk device (no parent) is returned as-is.
func DetectRootDisk(ctx context.Context, exec firewall.Executor) (string, error) {
	part, err := exec.ExecuteRead(ctx, "findmnt", "-no", "SOURCE", "/")
	if err != nil {
		return "", fmt.Errorf("findmnt root device: %w", err)
	}
	part = strings.TrimSpace(part)
	if part == "" {
		return "", fmt.Errorf("findmnt returned empty root device")
	}
	parent, err := exec.ExecuteRead(ctx, "lsblk", "-ndo", "pkname", part)
	if err != nil {
		return "", fmt.Errorf("lsblk parent of %s: %w", part, err)
	}
	name := strings.TrimSpace(parent)
	if name == "" {
		return part, nil
	}
	return "/dev/" + name, nil
}

// Read runs `smartctl -x -j <device>` and parses its JSON output. JSON
// (not the text table) so parsing never depends on smartctl's
// column-alignment/wording across versions.
func Read(ctx context.Context, exec firewall.Executor, device string) (Report, error) {
	out, err := exec.ExecuteRead(ctx, "smartctl", "-x", "-j", device)
	if err != nil {
		return Report{}, fmt.Errorf("smartctl %s: %w", device, err)
	}
	var parsed smartctlOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return Report{}, fmt.Errorf("parse smartctl JSON for %s: %w", device, err)
	}
	r := Report{Passed: parsed.SmartStatus.Passed}
	for _, attr := range parsed.AtaSmartAttributes.Table {
		switch attr.ID {
		case attrReallocatedSectorCt:
			r.ReallocatedSectors = attr.Raw.Value
		case attrTemperatureCelsius:
			r.TemperatureC = attr.Raw.Value
		}
	}
	return r, nil
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/disksmart/... -v`
Expected: PASS — todos os 5 testes.

- [ ] **Step 5: Commit**

```bash
git add internal/disksmart/
git commit -m "feat(disksmart): leitura de SMART do disco raiz via smartctl -x -j"
```

---

### Task 3: `internal/alerts` — pares de alerta pros 4 checks novos

**Files:**
- Modify: `internal/alerts/service.go`
- Test: `internal/alerts/service_test.go` (estender)

**Interfaces:**
- Produces: `TypeNTPUnsynced`, `TypeNTPSynced`, `TypeDiskSMARTFail`, `TypeDiskSMARTOK`,
  `TypeDiskSMARTDegraded`, `TypeDiskSMARTHot`, `TypeSlowBoot`, `TypeJournalCorrupt`,
  `TypeJournalOK` (constantes); `NTPUnsynced() error`, `NTPSynced() error`,
  `DiskSMARTFail() error`, `DiskSMARTOK() error`, `DiskSMARTDegraded(count float64) error`,
  `DiskSMARTNormal(count float64) error`, `DiskSMARTHot(tempC float64) error`,
  `DiskSMARTCool(tempC float64) error`, `SlowBoot(seconds float64) error`,
  `JournalCorrupt(detail string) error`, `JournalOK() error` — usados pelo Task 5
  (`healthchecks.go`) e Task 7 (`journalcheck.go`). `DiskSMARTDegraded`/`DiskSMARTNormal` e
  `DiskSMARTHot`/`DiskSMARTCool` têm assinatura `func(float64) error` de propósito — encaixam
  direto no parâmetro `high, normal func(float64) error` de `Collector.checkResource` (Task 5),
  sem wrapper nenhum.

- [ ] **Step 1: Escrever os testes que falham**

Adicionar a `internal/alerts/service_test.go`:

```go
func TestNTPUnsyncedIsWarning(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.NTPUnsynced(); err != nil {
		t.Fatal(err)
	}
	if len(fn.normal) != 1 || fn.normal[0] != "warning|Relógio dessincronizado" {
		t.Errorf("normal notifies = %v", fn.normal)
	}
}

func TestNTPSyncedDeliversViaRecovery(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.NTPSynced(); err != nil {
		t.Fatal(err)
	}
	if len(fn.recovery) != 1 {
		t.Errorf("expected 1 recovery notify, got %v", fn.recovery)
	}
}

func TestDiskSMARTFailIsCritical(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.DiskSMARTFail(); err != nil {
		t.Fatal(err)
	}
	if len(fn.normal) != 1 || fn.normal[0] != "critical|Disco: falha no SMART" {
		t.Errorf("normal notifies = %v", fn.normal)
	}
}

func TestDiskSMARTDegradedCitesCount(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.DiskSMARTDegraded(3); err != nil {
		t.Fatal(err)
	}
	alertsList, _ := db.GetAlerts(false, 0)
	if len(alertsList) != 1 || !strings.Contains(alertsList[0].Message, "3") {
		t.Errorf("expected message to cite the count, got %+v", alertsList)
	}
}

func TestDiskSMARTHotCitesTemp(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.DiskSMARTHot(60); err != nil {
		t.Fatal(err)
	}
	alertsList, _ := db.GetAlerts(false, 0)
	if len(alertsList) != 1 || !strings.Contains(alertsList[0].Message, "60") {
		t.Errorf("expected message to cite the temperature, got %+v", alertsList)
	}
}

func TestSlowBootCitesSeconds(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.SlowBoot(245); err != nil {
		t.Fatal(err)
	}
	alertsList, _ := db.GetAlerts(false, 0)
	if len(alertsList) != 1 || alertsList[0].Severity != SeverityWarning || !strings.Contains(alertsList[0].Message, "245") {
		t.Errorf("expected a warning citing the duration, got %+v", alertsList)
	}
}

func TestJournalCorruptCitesDetail(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	if err := s.JournalCorrupt("system@abc.journal~ invalid object"); err != nil {
		t.Fatal(err)
	}
	alertsList, _ := db.GetAlerts(false, 0)
	if len(alertsList) != 1 || !strings.Contains(alertsList[0].Message, "system@abc.journal~") {
		t.Errorf("expected message to cite the detail, got %+v", alertsList)
	}
}

func TestJournalOKDeliversViaRecovery(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.JournalOK(); err != nil {
		t.Fatal(err)
	}
	if len(fn.recovery) != 1 {
		t.Errorf("expected 1 recovery notify, got %v", fn.recovery)
	}
}
```

Adicionar `"strings"` ao bloco de imports do arquivo de teste se ainda não estiver lá (confira
com `grep -n '"strings"' internal/alerts/service_test.go`).

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/alerts/... -run 'TestNTP|TestDiskSMART|TestSlowBoot|TestJournal' -v`
Expected: FAIL — `s.NTPUnsynced undefined` etc (nenhum dos métodos existe ainda).

- [ ] **Step 3: Implementar**

Em `internal/alerts/service.go`, adicionar ao bloco de constantes (depois de `TypeBackupFailed`):

```go
	TypeNTPUnsynced       = "ntp_unsynced"
	TypeNTPSynced         = "ntp_synced"
	TypeDiskSMARTFail     = "disk_smart_fail"
	TypeDiskSMARTOK       = "disk_smart_ok"
	TypeDiskSMARTDegraded = "disk_smart_degraded"
	TypeDiskSMARTHot      = "disk_smart_hot"
	TypeSlowBoot          = "slow_boot"
	TypeJournalCorrupt    = "journal_corrupt"
	TypeJournalOK         = "journal_ok"
```

Adicionar `"strings"` NÃO é necessário aqui (só no teste, se precisar). Adicionar os métodos no
final do arquivo, antes ou depois de `BackupSucceeded` (mesma seção de "checks de
infraestrutura"):

```go
// NTPUnsynced raises a warning when the system clock is not NTP-synchronized
// — a silent degradation (logs, TLS, TOTP 2FA all depend on correct time),
// not a service outage, hence Warning not Critical.
func (s *Service) NTPUnsynced() error {
	return s.Create(TypeNTPUnsynced, SeverityWarning, "Relógio dessincronizado",
		"O relógio do sistema não está sincronizado via NTP.", "")
}

// NTPSynced clears NTPUnsynced and notifies recovery.
func (s *Service) NTPSynced() error {
	s.AutoResolve(TypeNTPUnsynced, "")
	return s.createRecovery(TypeNTPSynced, "Relógio sincronizado",
		"O relógio do sistema voltou a sincronizar via NTP.", "")
}

// DiskSMARTFail raises a critical alert when the disk's own S.M.A.R.T.
// self-assessment reports failure — the strongest signal this package
// raises, since the drive firmware itself is reporting trouble.
func (s *Service) DiskSMARTFail() error {
	return s.Create(TypeDiskSMARTFail, SeverityCritical, "Disco: falha no SMART",
		"O disco reporta falha no autodiagnóstico SMART — considere substituí-lo.", "")
}

// DiskSMARTOK clears DiskSMARTFail and notifies recovery.
func (s *Service) DiskSMARTOK() error {
	s.AutoResolve(TypeDiskSMARTFail, "")
	return s.createRecovery(TypeDiskSMARTOK, "Disco: SMART normalizado",
		"O disco voltou a passar no autodiagnóstico SMART.", "")
}

// DiskSMARTDegraded raises a warning when the disk's reallocated-sector count
// crosses the configured threshold — an earlier, softer signal than
// DiskSMARTFail. Signature matches Collector.checkResource's `high`
// callback.
func (s *Service) DiskSMARTDegraded(count float64) error {
	return s.Create(TypeDiskSMARTDegraded, SeverityWarning, "Disco: setores realocados",
		fmt.Sprintf("O disco reporta %.0f setor(es) realocado(s) via SMART.", count), "")
}

// DiskSMARTNormal clears DiskSMARTDegraded and notifies recovery. Signature
// matches Collector.checkResource's `normal` callback.
func (s *Service) DiskSMARTNormal(count float64) error {
	s.AutoResolve(TypeDiskSMARTDegraded, "")
	return s.createRecovery(TypeDiskSMARTDegraded, "Disco: setores realocados normalizados",
		fmt.Sprintf("Contagem de setores realocados voltou a %.0f.", count), "")
}

// DiskSMARTHot raises a warning when disk temperature crosses the configured
// threshold. Signature matches Collector.checkResource's `high` callback.
func (s *Service) DiskSMARTHot(tempC float64) error {
	return s.Create(TypeDiskSMARTHot, SeverityWarning, "Disco: temperatura alta",
		fmt.Sprintf("Temperatura do disco em %.0f°C.", tempC), "")
}

// DiskSMARTCool clears DiskSMARTHot and notifies recovery. Signature matches
// Collector.checkResource's `normal` callback.
func (s *Service) DiskSMARTCool(tempC float64) error {
	s.AutoResolve(TypeDiskSMARTHot, "")
	return s.createRecovery(TypeDiskSMARTHot, "Disco: temperatura normalizada",
		fmt.Sprintf("Temperatura do disco voltou a %.0f°C.", tempC), "")
}

// SlowBoot raises a one-time warning when the box takes longer than the
// configured threshold to reach its first monitoring tick. There is no
// recovery counterpart: a slow boot can't un-happen, only the next reboot
// can be fast.
func (s *Service) SlowBoot(seconds float64) error {
	return s.Create(TypeSlowBoot, SeverityWarning, "Boot lento",
		fmt.Sprintf("O sistema levou %.0fs para o LinkGuard ficar pronto neste boot.", seconds), "")
}

// JournalCorrupt raises a warning when a periodic `journalctl --verify` finds
// corruption — degrades observability, not an operational outage, hence
// Warning.
func (s *Service) JournalCorrupt(detail string) error {
	return s.Create(TypeJournalCorrupt, SeverityWarning, "Logs do sistema corrompidos",
		"journalctl --verify encontrou corrupção: "+detail, "")
}

// JournalOK clears JournalCorrupt and notifies recovery (a corrupted journal
// file rotating out of retention is enough to "heal" this on its own).
func (s *Service) JournalOK() error {
	s.AutoResolve(TypeJournalCorrupt, "")
	return s.createRecovery(TypeJournalOK, "Logs do sistema normalizados",
		"journalctl --verify não encontra mais corrupção nos logs.", "")
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/alerts/... -v`
Expected: PASS — todos os testes do pacote, incluindo os novos.

- [ ] **Step 5: Commit**

```bash
git add internal/alerts/service.go internal/alerts/service_test.go
git commit -m "feat(alerts): pares de alerta pra NTP, SMART, boot lento e journal corrompido"
```

---

### Task 4: `internal/monitoring/config.go` — 4 campos novos

**Files:**
- Modify: `internal/monitoring/config.go`
- Test: `internal/monitoring/config_test.go` (estender)

**Interfaces:**
- Produces: `Config.SMARTReallocatedThreshold int` (default `0`), `Config.SMARTTempThresholdC
  int` (default `55`), `Config.BootTimeThresholdSec int` (default `180`),
  `Config.JournalVerifyIntervalDays int` (default `7`) — usados pelos Tasks 5 e 7.

- [ ] **Step 1: Escrever os testes que falham**

Adicionar a `internal/monitoring/config_test.go`:

```go
func TestLoadConfigNewFieldDefaults(t *testing.T) {
	db := openTestDB(t)
	c := LoadConfig(db)
	if c.SMARTReallocatedThreshold != 0 {
		t.Errorf("SMARTReallocatedThreshold default = %d, want 0", c.SMARTReallocatedThreshold)
	}
	if c.SMARTTempThresholdC != 55 {
		t.Errorf("SMARTTempThresholdC default = %d, want 55", c.SMARTTempThresholdC)
	}
	if c.BootTimeThresholdSec != 180 {
		t.Errorf("BootTimeThresholdSec default = %d, want 180", c.BootTimeThresholdSec)
	}
	if c.JournalVerifyIntervalDays != 7 {
		t.Errorf("JournalVerifyIntervalDays default = %d, want 7", c.JournalVerifyIntervalDays)
	}
}

func TestLoadConfigClampsInvalidNewThresholds(t *testing.T) {
	db := openTestDB(t)
	bad := Config{Enabled: true, DiskThresholdPct: 90, SMARTTempThresholdC: -5, BootTimeThresholdSec: 0, JournalVerifyIntervalDays: -1}
	if err := SaveConfig(db, bad); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db)
	if got.SMARTTempThresholdC != 55 {
		t.Errorf("SMARTTempThresholdC should clamp to default 55, got %d", got.SMARTTempThresholdC)
	}
	if got.BootTimeThresholdSec != 180 {
		t.Errorf("BootTimeThresholdSec should clamp to default 180, got %d", got.BootTimeThresholdSec)
	}
	if got.JournalVerifyIntervalDays != 7 {
		t.Errorf("JournalVerifyIntervalDays should clamp to default 7, got %d", got.JournalVerifyIntervalDays)
	}
}

func TestLoadConfigPreservesZeroReallocatedThreshold(t *testing.T) {
	db := openTestDB(t)
	// 0 is a legitimate, meaningful value here ("alert on any reallocated
	// sector") — must NOT be clamped away like the other thresholds.
	in := Config{Enabled: true, DiskThresholdPct: 90, SMARTReallocatedThreshold: 0, SMARTTempThresholdC: 55, BootTimeThresholdSec: 180, JournalVerifyIntervalDays: 7}
	if err := SaveConfig(db, in); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db)
	if got.SMARTReallocatedThreshold != 0 {
		t.Errorf("SMARTReallocatedThreshold should stay 0, got %d", got.SMARTReallocatedThreshold)
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/monitoring/... -run TestLoadConfig -v`
Expected: FAIL — `unknown field SMARTReallocatedThreshold in struct literal` (campos não existem
ainda).

- [ ] **Step 3: Implementar**

Substituir o conteúdo de `internal/monitoring/config.go` por:

```go
package monitoring

import (
	"encoding/json"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const configKey = "monitoring"

// Config is the persisted monitoring/alerting configuration. Absence of the
// settings key means "all defaults" — monitoring is ON out of the box.
type Config struct {
	Enabled                   bool     `json:"enabled"`
	Services                  []string `json:"services"`
	DiskThresholdPct          int      `json:"disk_threshold_pct"`
	SMARTReallocatedThreshold int      `json:"smart_reallocated_threshold"`
	SMARTTempThresholdC       int      `json:"smart_temp_threshold_c"`
	BootTimeThresholdSec      int      `json:"boot_time_threshold_sec"`
	JournalVerifyIntervalDays int      `json:"journal_verify_interval_days"`
}

func defaults() Config {
	return Config{
		Enabled:                   true,
		Services:                  []string{"kea-dhcp4-server", "unbound", "nftables"},
		DiskThresholdPct:          90,
		SMARTReallocatedThreshold: 0,
		SMARTTempThresholdC:       55,
		BootTimeThresholdSec:      180,
		JournalVerifyIntervalDays: 7,
	}
}

// LoadConfig returns the persisted config, or zero-config defaults if unset.
func LoadConfig(db *storage.DB) Config {
	raw, err := db.GetSetting(configKey)
	if err != nil || raw == "" {
		return defaults()
	}
	c := defaults()
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return defaults()
	}
	if c.DiskThresholdPct <= 0 || c.DiskThresholdPct > 100 {
		c.DiskThresholdPct = 90
	}
	if c.SMARTTempThresholdC <= 0 {
		c.SMARTTempThresholdC = 55
	}
	if c.BootTimeThresholdSec <= 0 {
		c.BootTimeThresholdSec = 180
	}
	if c.JournalVerifyIntervalDays <= 0 {
		c.JournalVerifyIntervalDays = 7
	}
	// SMARTReallocatedThreshold is intentionally NOT clamped: 0 is its
	// meaningful default (alert on any reallocated sector at all), not a
	// sentinel for "unset" the way the other thresholds treat 0.
	return c
}

// SaveConfig persists the config.
func SaveConfig(db *storage.DB, c Config) error {
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return db.SetSetting(configKey, string(out))
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/monitoring/... -v`
Expected: PASS — todos os testes do pacote (os pré-existentes de `config_test.go` continuam
passando, mais os 3 novos).

- [ ] **Step 5: Commit**

```bash
git add internal/monitoring/config.go internal/monitoring/config_test.go
git commit -m "feat(monitoring): campos de configuração pra SMART, boot lento e journal"
```

---

### Task 5: `internal/monitoring/healthchecks.go` — os 3 checks contínuos (NTP, SMART, boot)

**Files:**
- Modify: `internal/monitoring/healthchecks.go`
- Modify: `internal/monitoring/healthchecks_test.go` (estender `fakeExec` — ver Step 1)
- Modify: `internal/tsdb/schema.go`

**Interfaces:**
- Consumes: `timesync.EnsureEnabled`/`IsSynced` (Task 1), `disksmart.DetectRootDisk`/`Read`
  (Task 2), `alerts.NTPUnsynced`/`NTPSynced`/`DiskSMARTFail`/`DiskSMARTOK`/
  `DiskSMARTDegraded`/`DiskSMARTNormal`/`DiskSMARTHot`/`DiskSMARTCool`/`SlowBoot` (Task 3),
  `Config.SMARTReallocatedThreshold`/`SMARTTempThresholdC`/`BootTimeThresholdSec` (Task 4).
- Produces: `func (c *Collector) checkNTP()`, `func (c *Collector) checkSMART(cfg Config)`,
  `func (c *Collector) checkBootTime(uptimeSeconds float64, cfg Config)` — chamados pelo Task 6
  (`collector.go`). `fakeExec` em `healthchecks_test.go` ganha suporte a `timedatectl`,
  `findmnt`, `lsblk`, `smartctl` (além do `systemctl is-active` que já tinha) — o Task 7
  (`journalcheck.go`) reaproveita esse MESMO `fakeExec` estendendo com `journalctl`, então essa
  extensão precisa cobrir os comandos de forma genérica o bastante (ver Step 1).

- [ ] **Step 1: Escrever os testes que falham**

Em `internal/monitoring/healthchecks_test.go`, substituir o `fakeExec` existente (que hoje só
entende `systemctl is-active`) por uma versão estendida — mantém o comportamento atual e
adiciona os comandos novos:

```go
type fakeExec struct {
	active       map[string]bool
	ntpSynced    string // valor de retorno de `timedatectl show ...` ("yes"/"no")
	findmntOut   string
	lsblkOut     string
	smartctlOut  string
	smartctlErr  error
	journalOut   string
	journalErr   error
}

func (f *fakeExec) Execute(_ context.Context, _ string, _ ...string) (string, error) { return "", nil }
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	switch cmd {
	case "systemctl":
		if len(args) == 2 && args[0] == "is-active" {
			if f.active[args[1]] {
				return "active\n", nil
			}
			return "inactive\n", assertErr{}
		}
	case "timedatectl":
		return f.ntpSynced, nil
	case "findmnt":
		return f.findmntOut, nil
	case "lsblk":
		return f.lsblkOut, nil
	case "smartctl":
		return f.smartctlOut, f.smartctlErr
	case "journalctl":
		return f.journalOut, f.journalErr
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool { return false }
```

(A alteração é mecânica: mesmos dois métodos, `active` e o `case "systemctl"` idênticos ao que
já existia, só adicionando os `case`s novos ao `switch`.)

Adicionar os testes novos no mesmo arquivo:

```go
func TestCheckNTPRaisesOnSecondUnsynced(t *testing.T) {
	fe := &fakeExec{ntpSynced: "yes\n"}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkNTP() // synced -> no alert
	fe.ntpSynced = "no\n"
	c.checkNTP() // 1st unsynced -> suppressed
	c.checkNTP() // 2nd unsynced -> alert

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeNTPUnsynced {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 ntp_unsynced alert, got %d", n)
	}
}

const passingSmartJSON = `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":0}},{"id":194,"raw":{"value":35}}]}}`
const failingSmartJSON = `{"smart_status":{"passed":false},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":9}},{"id":194,"raw":{"value":60}}]}}`

func TestCheckSMARTRaisesHealthFailOnSecondReading(t *testing.T) {
	fe := &fakeExec{findmntOut: "/dev/sda2\n", lsblkOut: "sda\n", smartctlOut: passingSmartJSON}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	cfg := Config{SMARTReallocatedThreshold: 0, SMARTTempThresholdC: 55}

	c.checkSMART(cfg) // passed -> no alert
	fe.smartctlOut = failingSmartJSON
	c.checkSMART(cfg) // 1st fail -> suppressed
	c.checkSMART(cfg) // 2nd fail -> alert

	al, _ := db.GetAlerts(false, 0)
	var health, realloc, hot int
	for _, a := range al {
		switch a.Type {
		case alerts.TypeDiskSMARTFail:
			health++
		case alerts.TypeDiskSMARTDegraded:
			realloc++
		case alerts.TypeDiskSMARTHot:
			hot++
		}
	}
	if health != 1 {
		t.Errorf("expected exactly 1 disk_smart_fail alert, got %d", health)
	}
	if realloc != 1 {
		t.Errorf("expected exactly 1 disk_smart_degraded alert (9 > 0 threshold), got %d", realloc)
	}
	if hot != 1 {
		t.Errorf("expected exactly 1 disk_smart_hot alert (60 >= 55 threshold), got %d", hot)
	}
}

func TestCheckSMARTReadErrorSkipsTickWithoutAlert(t *testing.T) {
	fe := &fakeExec{findmntOut: "/dev/sda2\n", lsblkOut: "sda\n", smartctlErr: assertErr{}}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkSMART(Config{SMARTReallocatedThreshold: 0, SMARTTempThresholdC: 55})

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("a read error should not raise a false SMART-fail alert, got %d alerts", len(al))
	}
}

func TestCheckBootTimeOnlyRunsOnce(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock()}
	cfg := Config{Enabled: true, BootTimeThresholdSec: 180}

	c.checkBootTime(200, cfg) // slow boot -> alert
	c.checkBootTime(5, cfg)   // second call must be a no-op (bootChecked guard)

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeSlowBoot {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 slow_boot alert (second call must be ignored), got %d", n)
	}
}

func TestCheckBootTimeFastBootNoAlert(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkBootTime(20, Config{Enabled: true, BootTimeThresholdSec: 180})

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("a fast boot must not alert, got %d alerts", len(al))
	}
}

func TestCheckBootTimeRespectsDisabledToggle(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, health: map[string]*itemState{}, nowFn: seqClock()}

	c.checkBootTime(300, Config{Enabled: false, BootTimeThresholdSec: 180})

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("cfg.Enabled=false must suppress the alert even on a slow boot, got %d alerts", len(al))
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/monitoring/... -run 'TestCheckNTP|TestCheckSMART|TestCheckBootTime' -v`
Expected: FAIL — `c.checkNTP undefined` / `c.checkSMART undefined` / `c.checkBootTime undefined`
/ `c.bootChecked undefined` (nada disso existe ainda).

- [ ] **Step 3: Implementar**

Em `internal/tsdb/schema.go`, adicionar duas entradas a `nativeSteps` (linha ~11-15):

```go
var nativeSteps = map[string]int{
	"link.":  10,
	"sys.":   30,
	"if.":    1,
	"smart.": 30,
	"boot.":  3600,
}
```

Em `internal/monitoring/healthchecks.go`, adicionar aos imports:

```go
import (
	"context"
	"log/slog"
	"regexp"

	"github.com/giovanibalarini/linkguard-fw/internal/disksmart"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
)
```

Adicionar `bootChecked bool` ao struct `itemState`? NÃO — esse campo vai no `Collector`, não no
`itemState` (é estado do próprio coletor, não de um item monitorado). Isso é feito no Task 6
(`collector.go`), não aqui — este arquivo só usa `c.bootChecked` (referência ao campo que o
Task 6 declara).

Adicionar ao final de `internal/monitoring/healthchecks.go`:

```go
// checkNTP verifies the system clock is NTP-synchronized and raises/clears
// alerts.TypeNTPUnsynced on a confirmed transition.
func (c *Collector) checkNTP() {
	up := timesync.IsSynced(context.Background(), c.exec)
	now := c.nowFn()
	tr := c.observe("ntp:sync", up, now)
	c.ensureMeta("ntp:sync", "ntp-sync", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.NTPUnsynced()
	case transUp:
		_ = c.alertSvc.NTPSynced()
	}
}

// checkSMART reads the root disk's SMART status once and applies three
// checks from that single reading: overall health (boolean, via observe()
// directly), reallocated sector count and temperature (both threshold-based,
// routed through the existing checkResource — same "lower is healthier"
// polarity as CPU/mem/disk). A read failure (tool missing, disk not found)
// is treated as "unknown for this tick" and skipped entirely, rather than
// raising a false SMART-fail alert — see the design spec's Casos de borda.
func (c *Collector) checkSMART(cfg Config) {
	ctx := context.Background()
	device, err := disksmart.DetectRootDisk(ctx, c.exec)
	if err != nil {
		slog.Warn("smart: could not detect root disk", "err", err)
		return
	}
	report, err := disksmart.Read(ctx, c.exec, device)
	if err != nil {
		slog.Warn("smart: read failed", "device", device, "err", err)
		return
	}

	now := c.nowFn()
	tr := c.observe("smart:health", report.Passed, now)
	c.ensureMeta("smart:health", "smart-health", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.DiskSMARTFail()
	case transUp:
		_ = c.alertSvc.DiskSMARTOK()
	}

	if c.rec != nil {
		c.rec.Gauge("smart.reallocated", "", float64(report.ReallocatedSectors))
		c.rec.Gauge("smart.temp_c", "", float64(report.TemperatureC))
	}

	// checkResource's polarity is `pct < thresholdPct` (strictly less-than).
	// SMARTReallocatedThreshold defaults to 0 meaning "any reallocated sector
	// at all is a problem" — passing threshold+1 turns the strict "<" into
	// the intended "<= threshold is healthy" without changing
	// checkResource's shared comparison logic.
	c.checkResource("smart:realloc", "Setores realocados", float64(report.ReallocatedSectors),
		cfg.SMARTReallocatedThreshold+1, c.alertSvc.DiskSMARTDegraded, c.alertSvc.DiskSMARTNormal)
	c.checkResource("smart:temp", "Temperatura do disco", float64(report.TemperatureC),
		cfg.SMARTTempThresholdC, c.alertSvc.DiskSMARTHot, c.alertSvc.DiskSMARTCool)
}

// checkBootTime runs at most once per process lifetime (guarded by
// c.bootChecked — /proc/uptime only grows, so re-checking on a later tick
// would measure "how long the process has been running", not "how long the
// boot took"). uptimeSeconds is the system uptime at the moment this first
// tick fires (caller passes sys.UptimeSeconds from the same collect() pass).
//
// Unlike every other check in this file, the alert here is fired directly
// from the freshly-computed `up` value, NOT from observe()'s returned
// transition — observe()'s anti-flap model requires a SECOND confirming
// reading before a first-ever "down" fires, which never happens for a check
// that only ever runs once. observe()/ensureMeta() are still called so the
// item shows up on the dashboard panel and is bookkept consistently with
// every other item.
//
// cfg.Enabled gates the ALERT, but not the measurement/bookkeeping above it:
// gating the whole function would let a later re-enable of monitoring fire
// this using a stale (much larger) uptime reading instead of the real boot
// duration. The caller (collect(), Task 6) calls this unconditionally.
func (c *Collector) checkBootTime(uptimeSeconds float64, cfg Config) {
	c.healthMu.Lock()
	if c.bootChecked {
		c.healthMu.Unlock()
		return
	}
	c.bootChecked = true
	c.healthMu.Unlock()

	up := uptimeSeconds < float64(cfg.BootTimeThresholdSec)
	c.observe("boot:time", up, c.nowFn())
	c.ensureMeta("boot:time", "boot-time", "resource")
	if c.rec != nil {
		c.rec.Gauge("boot.seconds", "", uptimeSeconds)
	}
	if !up && cfg.Enabled {
		_ = c.alertSvc.SlowBoot(uptimeSeconds)
	}
}
```

Note: `regexp` já estava importado no arquivo original (`serviceNameRe`) — não duplicar o
import, só confirmar que continua lá junto dos novos.

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/monitoring/... ./internal/tsdb/... -v`
Expected: PASS — todos os testes de `internal/monitoring` (novos e pré-existentes) e
`internal/tsdb`.

- [ ] **Step 5: Commit**

```bash
git add internal/monitoring/healthchecks.go internal/monitoring/healthchecks_test.go internal/tsdb/schema.go
git commit -m "feat(monitoring): checks de NTP, SMART e boot lento"
```

---

### Task 6: `internal/monitoring/collector.go` — wiring dos 3 checks + campo `bootChecked`

**Files:**
- Modify: `internal/monitoring/collector.go`

**Interfaces:**
- Consumes: `Collector.checkNTP()`, `Collector.checkSMART(cfg)`,
  `Collector.checkBootTime(uptimeSeconds, cfg)` (Task 5).
- Produces: `Collector.bootChecked bool` (novo campo, protegido por `healthMu` — já referenciado
  pelo Task 5).

Esta task é só wiring mecânico dentro de `collect()` — 4 linhas chamando métodos que o Task 5 já
testou e cobriu por completo (incluindo o comportamento de "só roda uma vez" de
`checkBootTime`, via `TestCheckBootTimeOnlyRunsOnce`). Não introduz nenhum novo teste próprio:
testar `collect()` de ponta a ponta exigiria um `*metrics.Metrics` real (`metrics.New` pede um
`prometheus.Registerer`) e um `system.Collector` real (só existe dentro de `NewCollector`,
nenhum teste do pacote hoje passa por aí — todos usam o struct literal `&Collector{...}`
direto), o que testaria só a fiação, não lógica nova — risco desproporcional ao tamanho da
mudança. A garantia aqui vem da suíte completa não quebrar (Step 2) mais a revisão de código.

**Nota (corrigido após a execução do Task 5):** o campo `Collector.bootChecked bool` — que este
texto originalmente listava como sendo adicionado aqui — já foi adicionado pelo Task 5 (era
necessário pra `healthchecks.go` compilar, já que Go exige que o campo exista em algum arquivo
do pacote; o Task 5 não podia esperar o Task 6 pra isso). Confirme com `grep -n "bootChecked"
internal/monitoring/collector.go` que o campo já está lá antes de prosseguir — se por algum
motivo não estiver, adicione-o você mesmo (mesma declaração: `bootChecked bool` no struct
`Collector`, protegido por `healthMu`), mas o esperado é que já exista. Este task só cuida da
fiação em `collect()` abaixo.

- [ ] **Step 1: Implementar**

Em `collect()`, adicionar as três chamadas novas. Trocar:

```go
		// Resource threshold alerts — transition-based with anti-flap (fire once
		// on crossing, recover once, transient spikes suppressed) instead of
		// re-firing every tick while over the threshold.
		//
		// Gated by cfg.Enabled — the "Me avise de qualquer queda" master toggle.
		// By product decision it is a single switch: turning it off silences ALL
		// alerts (services, links AND the box's own cpu/mem/disk), for the
		// simplest mental model. Default is on.
		if cfg.Enabled {
			c.checkResource("resource:cpu", "CPU", sys.CPUPercent, 90, c.alertSvc.HighCPU, c.alertSvc.CPUNormal)
			c.checkResource("resource:mem", "Memória", sys.MemPercent, 90, c.alertSvc.HighMemory, c.alertSvc.MemoryNormal)
			c.checkResource("resource:disk", "Disco", sys.DiskPercent, cfg.DiskThresholdPct, c.alertSvc.DiskFull, c.alertSvc.DiskCleared)
		}
	}

	if cfg.Enabled {
		c.checkServices(cfg)
	}
```

por:

```go
		// Resource threshold alerts — transition-based with anti-flap (fire once
		// on crossing, recover once, transient spikes suppressed) instead of
		// re-firing every tick while over the threshold.
		//
		// Gated by cfg.Enabled — the "Me avise de qualquer queda" master toggle.
		// By product decision it is a single switch: turning it off silences ALL
		// alerts (services, links AND the box's own cpu/mem/disk), for the
		// simplest mental model. Default is on.
		if cfg.Enabled {
			c.checkResource("resource:cpu", "CPU", sys.CPUPercent, 90, c.alertSvc.HighCPU, c.alertSvc.CPUNormal)
			c.checkResource("resource:mem", "Memória", sys.MemPercent, 90, c.alertSvc.HighMemory, c.alertSvc.MemoryNormal)
			c.checkResource("resource:disk", "Disco", sys.DiskPercent, cfg.DiskThresholdPct, c.alertSvc.DiskFull, c.alertSvc.DiskCleared)
			c.checkNTP()
			c.checkSMART(cfg)
		}

		// Boot-time is measured once per process lifetime (see
		// checkBootTime's own doc comment) — deliberately called
		// unconditionally, NOT inside `if cfg.Enabled`, because gating it
		// would let a later re-enable of monitoring fire the alert using a
		// stale (much larger) uptime reading instead of the real boot
		// duration. checkBootTime itself still respects cfg.Enabled before
		// raising the alert.
		c.checkBootTime(sys.UptimeSeconds, cfg)
	}

	if cfg.Enabled {
		c.checkServices(cfg)
	}
```

- [ ] **Step 2: Rodar a suíte inteira do pacote e confirmar que não regrediu**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go build ./... && go test ./internal/monitoring/... -v`
Expected: build limpo, PASS em todos os testes do pacote (os do Task 5 incluídos — nada muda de
comportamento nos testes existentes, só passam a ser exercitados via `collect()` também).

- [ ] **Step 3: Commit**

```bash
git add internal/monitoring/collector.go
git commit -m "feat(monitoring): liga NTP/SMART/boot-lento ao loop de coleta"
```

---

### Task 7: `internal/monitoring/journalcheck.go` — verificação semanal de integridade do journal

**Files:**
- Create: `internal/monitoring/journalcheck.go`
- Test: `internal/monitoring/journalcheck_test.go`

**Interfaces:**
- Consumes: `alerts.JournalCorrupt`/`JournalOK` (Task 3), `Config.JournalVerifyIntervalDays`
  (Task 4), `Collector.observe`/`ensureMeta`/`db`/`exec`/`alertSvc`/`nowFn` (já existentes),
  `fakeExec` estendido do Task 5 (adiciona só o `case "journalctl"`, já presente no fakeExec do
  Task 5 — reaproveitar, não recriar).
- Produces: `type JournalScheduler struct{...}`, `NewJournalScheduler(col *Collector)
  *JournalScheduler`, `(j *JournalScheduler) Run(ctx context.Context)`, `(j *JournalScheduler)
  RunOnce(ctx context.Context)` — usados pelo Task 8 (`main.go`).

- [ ] **Step 1: Escrever os testes que falham**

Criar `internal/monitoring/journalcheck_test.go`:

```go
package monitoring

import (
	"context"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
)

func TestJournalRunOnceRaisesOnSecondCorruptRun(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	fe := &fakeExec{journalOut: "PASS: /var/log/journal/foo/system.journal\n"}
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	j := NewJournalScheduler(c)

	j.RunOnce(context.Background()) // clean -> no alert
	fe.journalOut = "FAIL: /var/log/journal/foo/system@abc.journal~ (Mensagem inválida)\n"
	j.RunOnce(context.Background()) // 1st corrupt -> suppressed (anti-flap)
	j.RunOnce(context.Background()) // 2nd corrupt -> alert

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeJournalCorrupt {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 journal_corrupt alert, got %d", n)
	}
}

func TestJournalRunOnceRecoversAfterClean(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	fe := &fakeExec{journalOut: "FAIL: something\n"}
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	j := NewJournalScheduler(c)

	j.RunOnce(context.Background()) // 1st corrupt -> suppressed
	j.RunOnce(context.Background()) // 2nd corrupt -> alert
	fe.journalOut = "PASS: everything\n"
	j.RunOnce(context.Background()) // clean -> recovery

	al, _ := db.GetAlerts(false, 0)
	var open int
	for _, a := range al {
		if a.Type == alerts.TypeJournalCorrupt && a.ResolvedAt == nil {
			open++
		}
	}
	if open != 0 {
		t.Fatalf("expected the journal_corrupt alert to be auto-resolved, %d still open", open)
	}
}

func TestJournalMaybeRunSkipsBeforeInterval(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	fe := &fakeExec{journalOut: "PASS: ok\n"}
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	j := NewJournalScheduler(c)

	j.RunOnce(context.Background()) // establishes journalLastVerifySettingKey = now
	before := j.lastVerify()
	j.maybeRun(context.Background()) // interval (7 days default) hasn't elapsed -> must not re-run
	after := j.lastVerify()
	if before != after {
		t.Fatalf("maybeRun ran again before the configured interval elapsed: before=%d after=%d", before, after)
	}
}

func TestJournalMaybeRunSkipsWhenDisabled(t *testing.T) {
	db := openTestDB(t)
	if err := SaveConfig(db, Config{Enabled: false, JournalVerifyIntervalDays: 7}); err != nil {
		t.Fatal(err)
	}
	as := alerts.NewService(db)
	fe := &fakeExec{journalOut: "FAIL: something\n"}
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	j := NewJournalScheduler(c)

	j.maybeRun(context.Background())

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("cfg.Enabled=false must skip the check entirely, got %d alerts", len(al))
	}
}
```

`storage.Alert` (em `internal/storage/models.go`) já tem `ResolvedAt *time.Time` — confirmado,
o teste acima usa esse campo real, nenhum ajuste necessário.

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/monitoring/... -run TestJournal -v`
Expected: FAIL — `undefined: NewJournalScheduler` (arquivo ainda não existe).

- [ ] **Step 3: Implementar**

Criar `internal/monitoring/journalcheck.go`:

```go
package monitoring

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// journalLastVerifySettingKey persists the unix timestamp of the last
// journalctl --verify run, so JournalScheduler knows whether it's time to
// run again across restarts (mirrors backup.LastRunSettingKey).
const journalLastVerifySettingKey = "journal_last_verify"

// journalTickInterval is how often JournalScheduler wakes up to check
// whether it's time to run for real — coarse, matching backup.Scheduler's
// tickInterval, since day-granularity scheduling doesn't need anything
// finer.
const journalTickInterval = 1 * time.Hour

// JournalScheduler periodically runs `journalctl --verify` and alerts if it
// finds corruption. It runs on its own ticker, separate from Collector's 30s
// loop, because `journalctl --verify` is slow on a large/busy journal (seen
// taking tens of seconds in production) — running it inside the 30s tick
// would stall every other check for that long. It shares the Collector's
// observe()/ensureMeta() bookkeeping (same package, unexported fields
// reachable directly) so the journal-integrity item gets anti-flap dedup and
// shows up on the dashboard panel for free, like every other check — the
// tradeoff is that a corrupt-journal alert only fires on the SECOND
// consecutive weekly finding (worst case ~1 extra week of delay), which is
// acceptable given this alert is explicitly Warning-severity /
// "degrades observability, not an outage" (see the design spec).
type JournalScheduler struct {
	col *Collector
}

// NewJournalScheduler creates a JournalScheduler bound to an existing
// Collector (reuses its db/exec/alertSvc/health map).
func NewJournalScheduler(col *Collector) *JournalScheduler {
	return &JournalScheduler{col: col}
}

// Run starts the scheduler loop and blocks until ctx is done.
func (j *JournalScheduler) Run(ctx context.Context) {
	slog.Info("journal integrity scheduler started", "tick_interval", journalTickInterval)
	ticker := time.NewTicker(journalTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.maybeRun(ctx)
		}
	}
}

// maybeRun checks the master toggle and the configured interval against the
// last-run timestamp, and calls RunOnce only if it's actually time.
func (j *JournalScheduler) maybeRun(ctx context.Context) {
	cfg := LoadConfig(j.col.db)
	if !cfg.Enabled {
		return
	}
	interval := time.Duration(cfg.JournalVerifyIntervalDays) * 24 * time.Hour
	last := j.lastVerify()
	if last != 0 && time.Since(time.Unix(last, 0)) < interval {
		return
	}
	j.RunOnce(ctx)
}

// RunOnce runs `journalctl --verify` immediately and raises/clears
// alerts.TypeJournalCorrupt on a confirmed transition (see the anti-flap
// tradeoff documented on JournalScheduler).
func (j *JournalScheduler) RunOnce(ctx context.Context) {
	out, err := j.col.exec.ExecuteRead(ctx, "journalctl", "--verify")
	_ = j.col.db.SetSetting(journalLastVerifySettingKey, strconv.FormatInt(time.Now().Unix(), 10))

	combined := out
	if err != nil {
		combined += " " + err.Error()
	}
	clean := !strings.Contains(combined, "FAIL")

	now := j.col.nowFn()
	tr := j.col.observe("journal:integrity", clean, now)
	j.col.ensureMeta("journal:integrity", "journal-integrity", "resource")
	switch tr {
	case transDown:
		_ = j.col.alertSvc.JournalCorrupt(firstFailLine(combined))
	case transUp:
		_ = j.col.alertSvc.JournalOK()
	}
}

func (j *JournalScheduler) lastVerify() int64 {
	raw, _ := j.col.db.GetSetting(journalLastVerifySettingKey)
	v, _ := strconv.ParseInt(raw, 10, 64)
	return v
}

// firstFailLine extracts the first "FAIL:" line from journalctl --verify's
// output for use in the alert message, falling back to a generic message if
// none is found (e.g. the failure came from ExecuteRead's own error, not a
// FAIL: line).
func firstFailLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "FAIL") {
			return strings.TrimSpace(line)
		}
	}
	return "corrupção detectada"
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/monitoring/... -v`
Expected: PASS — todos os testes do pacote.

- [ ] **Step 5: Commit**

```bash
git add internal/monitoring/journalcheck.go internal/monitoring/journalcheck_test.go
git commit -m "feat(monitoring): verificação semanal de integridade do journal"
```

---

### Task 8: `cmd/linkguard-fw/main.go` + `.deb` — wiring final e dependências recomendadas

**Files:**
- Modify: `cmd/linkguard-fw/main.go`
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `timesync.EnsureEnabled` (Task 1), `monitoring.NewJournalScheduler` (Task 7).

- [ ] **Step 1: Implementar** (wiring — não há teste unitário novo aqui; a cobertura já existe
  nos testes dos Tasks 1-7. Verificação é `go build ./...` + teste manual em produção depois do
  deploy, Task final do plano.)

Em `cmd/linkguard-fw/main.go`, adicionar ao bloco de imports (ordem alfabética, junto dos outros
`internal/...`):

```go
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
```

Trocar (linhas ~190-193):

```go
	promReg := prometheus.NewRegistry()
	appMetrics := metrics.New(promReg)
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec, rrdSvc)
	backupSched := backup.NewScheduler(db, secretsSvc, notifySvc, alertSvc, version)
```

por:

```go
	promReg := prometheus.NewRegistry()
	appMetrics := metrics.New(promReg)
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec, rrdSvc)
	backupSched := backup.NewScheduler(db, secretsSvc, notifySvc, alertSvc, version)
	journalSched := monitoring.NewJournalScheduler(metricsCollector)
```

Trocar (linhas ~239-241):

```go
	// Enable conntrack byte accounting so per-host traffic (top talkers) can be
	// computed; without it /proc/net/nf_conntrack has no byte counters.
	trafficSvc.EnsureAccounting()
```

por:

```go
	// Enable conntrack byte accounting so per-host traffic (top talkers) can be
	// computed; without it /proc/net/nf_conntrack has no byte counters.
	trafficSvc.EnsureAccounting()

	// Enable NTP time sync (chrony) if it's installed — LinkGuard owns this
	// the same way it owns the three prerequisites above.
	timesync.EnsureEnabled(ctx, exec)
```

Trocar (linhas ~243-247):

```go
	go monitor.Run(ctx)
	go metricsCollector.Run(ctx, interval)
	go rrdSvc.Run(ctx)
	go balancerSvc.Run(ctx)
	go backupSched.Run(ctx)
```

por:

```go
	go monitor.Run(ctx)
	go metricsCollector.Run(ctx, interval)
	go rrdSvc.Run(ctx)
	go balancerSvc.Run(ctx)
	go backupSched.Run(ctx)
	go journalSched.Run(ctx)
```

Em `.github/workflows/release.yml`, trocar (linha ~106):

```
            Recommends: kea-dhcp-server, unbound
```

por:

```
            Recommends: kea-dhcp-server, unbound, smartmontools, chrony
```

- [ ] **Step 2: Verificar que compila e a suíte inteira passa**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go build ./... && go test ./... -v 2>&1 | tail -60`
Expected: build limpo, suíte inteira (todos os pacotes, incluindo os 4 novos + os alterados)
passa.

- [ ] **Step 3: Commit**

```bash
git add cmd/linkguard-fw/main.go .github/workflows/release.yml
git commit -m "feat: liga EnsureNTP + agendador de journal no main; .deb recomenda smartmontools+chrony"
```

---

### Task 9: Frontend — rótulos e campos de configuração novos

**Files:**
- Modify: `web/src/types/index.ts`
- Modify: `web/src/components/SystemHealth.tsx`
- Modify: `web/src/components/MonitoringSettings.tsx`

**Interfaces:**
- Consumes: os 4 campos JSON novos de `monitoring.Config` (Task 4):
  `smart_reallocated_threshold`, `smart_temp_threshold_c`, `boot_time_threshold_sec`,
  `journal_verify_interval_days`. Nomes das chaves de item no painel (Task 5/6/7):
  `ntp-sync`, `smart-health`, `smart-realloc` (nome de exibição vem de
  `checkResource`'s parâmetro `name`, que já é `"Setores realocados"` — sem chave própria de
  `name` curta pro LABEL map, é o texto completo já), `smart-temp` (idem, `"Temperatura do
  disco"`), `boot-time`, `journal-integrity`.

- [ ] **Step 1: Implementar** (sem teste automatizado — projeto não tem framework de teste no
  frontend; verificação é `npm run build` + revisão visual, ver Step 2)

Em `web/src/types/index.ts`, trocar a linha 419:

```ts
export interface MonitoringConfig { enabled: boolean; services: string[]; disk_threshold_pct: number; }
```

por:

```ts
export interface MonitoringConfig {
  enabled: boolean;
  services: string[];
  disk_threshold_pct: number;
  smart_reallocated_threshold: number;
  smart_temp_threshold_c: number;
  boot_time_threshold_sec: number;
  journal_verify_interval_days: number;
}
```

Em `web/src/components/SystemHealth.tsx`, trocar o mapa `LABEL`:

```tsx
const LABEL: Record<string, string> = {
  'nftables': 'Firewall',
  'kea-dhcp4-server': 'DHCP',
  'unbound': 'DNS',
};
```

por:

```tsx
const LABEL: Record<string, string> = {
  'nftables': 'Firewall',
  'kea-dhcp4-server': 'DHCP',
  'unbound': 'DNS',
  'ntp-sync': 'Sincronização de horário',
  'smart-health': 'Disco (SMART)',
  'boot-time': 'Tempo de boot',
  'journal-integrity': 'Integridade dos logs',
};
```

(`smart:realloc`/`smart:temp` usam como `name` o texto já amigável — `"Setores realocados"`/
`"Temperatura do disco"` — passado direto a `ensureMeta` no Task 5, então não precisam de
entrada no `LABEL`: o componente já faz `LABEL[it.name] ?? it.name`, e o texto cru já é
apresentável.)

Em `web/src/components/MonitoringSettings.tsx`, trocar a constante `empty`:

```tsx
const empty: MonitoringConfig = { enabled: true, services: [], disk_threshold_pct: 90 };
```

por:

```tsx
const empty: MonitoringConfig = {
  enabled: true,
  services: [],
  disk_threshold_pct: 90,
  smart_reallocated_threshold: 0,
  smart_temp_threshold_c: 55,
  boot_time_threshold_sec: 180,
  journal_verify_interval_days: 7,
};
```

E, dentro do bloco `{advanced && (...)}`, adicionar os 4 campos novos depois do campo "Alerta de
disco acima de (%)" existente:

```tsx
          <label className="block text-xs text-gray-400">Alerta de disco acima de (%)
            <input type="number" min={50} max={99} className="input mt-1 w-32" defaultValue={cfg.disk_threshold_pct}
              onBlur={(e) => save({ ...cfg, disk_threshold_pct: Number(e.target.value) })} />
          </label>
          <label className="block text-xs text-gray-400">Alerta de setores realocados (SMART) acima de
            <input type="number" min={0} max={999} className="input mt-1 w-32" defaultValue={cfg.smart_reallocated_threshold}
              onBlur={(e) => save({ ...cfg, smart_reallocated_threshold: Number(e.target.value) })} />
          </label>
          <label className="block text-xs text-gray-400">Alerta de temperatura do disco acima de (°C)
            <input type="number" min={30} max={80} className="input mt-1 w-32" defaultValue={cfg.smart_temp_threshold_c}
              onBlur={(e) => save({ ...cfg, smart_temp_threshold_c: Number(e.target.value) })} />
          </label>
          <label className="block text-xs text-gray-400">Alerta de boot lento acima de (segundos)
            <input type="number" min={30} max={900} className="input mt-1 w-32" defaultValue={cfg.boot_time_threshold_sec}
              onBlur={(e) => save({ ...cfg, boot_time_threshold_sec: Number(e.target.value) })} />
          </label>
          <label className="block text-xs text-gray-400">Verificar integridade dos logs a cada (dias)
            <input type="number" min={1} max={90} className="input mt-1 w-32" defaultValue={cfg.journal_verify_interval_days}
              onBlur={(e) => save({ ...cfg, journal_verify_interval_days: Number(e.target.value) })} />
          </label>
```

- [ ] **Step 2: Verificar que compila**

Run: `export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH" && cd web && npm run build`
Expected: build limpo (`tsc -b && vite build`), sem erro de tipo.

- [ ] **Step 3: Commit**

```bash
git add web/src/types/index.ts web/src/components/SystemHealth.tsx web/src/components/MonitoringSettings.tsx
git commit -m "feat(ui): rótulos e campos de configuração pra NTP/SMART/boot lento/journal"
```

---

## Ordem de execução

Numérica (1→9) é a ordem real de execução. Dependências entre tasks não-adjacentes:
- **Task 5 estende o `fakeExec`** que já existe em `healthchecks_test.go` (criado antes deste
  plano, usado hoje só por `checkServices`) — a extensão precisa ser retrocompatível (mesmo
  campo `active`, mesmo `case "systemctl"`) já que os testes pré-existentes (`TestCheckServicesRaisesOnSecondDown`
  etc.) continuam usando esse mesmo tipo.
- **Task 7 reaproveita o `fakeExec` já estendido pelo Task 5** (usa o `case "journalctl"` que o
  Task 5 já adicionou) — não recriar nem duplicar o tipo.
- **Task 6 depende do Task 5** (chama `checkNTP`/`checkSMART`/`checkBootTime`, que só existem
  depois do Task 5).
- **Task 8 depende dos Tasks 1 e 7** (`timesync.EnsureEnabled`, `monitoring.NewJournalScheduler`).
- Tasks 1, 2, 3, 4 são independentes entre si — podem rodar em qualquer ordem relativa, desde
  que antes do Task 5 (que consome todas as quatro).

Após todas as 9 tasks: revisão final de branch inteira (modelo mais capaz disponível) — atenção
especial a (a) a lógica do `+1` em `checkSMART`'s chamada de `checkResource` pra setores
realocados (fácil de errar a polaridade), (b) o `bootChecked` não ter uma race condition real
(dois `collect()` concorrentes nunca deveriam acontecer dado que `Run()` é um loop single-thread,
mas confirmar), (c) o `journalLastVerifySettingKey` sobrevivendo a restart corretamente — depois
`finishing-a-development-branch` (merge local em `main`), deploy manual (build → `.deb` com
`chrony`/`smartmontools` no `Recommends` → scp → instalar em produção → verificar `/api/health`),
tag `vX.Y.Z` + push, e teste manual em produção: confirmar que os 4 itens novos aparecem no
painel "Saúde do sistema", que o `chrony` foi habilitado (`systemctl is-active chrony`), e que
`GET /api/monitoring/config` retorna os 4 campos novos com os valores default.
