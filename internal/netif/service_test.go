package netif

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// fakeExec is a minimal firewall.Executor test double that returns canned
// output per command, mirroring the pattern already used in
// internal/keaunbound/keaunbound_test.go's recExec.
type fakeExec struct {
	linkJSON      string
	addrJSON      string
	netDev        string
	identifyCalls []string
}

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

func (e *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	// Match by scanning args rather than a fixed index: the real call uses
	// "ip -d -j link show" (two flags before the subcommand) while "ip -j
	// addr show" only has one, so a fixed-index check would only happen to
	// match one of the two.
	if cmd == "ip" && containsArg(args, "link") {
		return e.linkJSON, nil
	}
	if cmd == "ip" && containsArg(args, "addr") {
		return e.addrJSON, nil
	}
	if cmd == "cat" && containsArg(args, "/proc/net/dev") {
		return e.netDev, nil // empty string is fine: parseProcNetDev on "" yields no entries, tests below don't assert on counters
	}
	if cmd == "cat" && len(args) == 1 {
		// oldFileContent's "cat <path>" call. Mirrors RealExecutor: read the
		// real file off disk (networkd.Apply writes with plain os calls, not
		// through this fake), erroring the same way a real missing file would.
		b, err := os.ReadFile(args[0])
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", errors.New("unexpected read command in test: " + cmd)
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func (e *fakeExec) IsDryRun() bool { return false }

// failingReloadExec is like fakeExec but makes every "networkctl reload"
// call fail — used to exercise the sweep's failed-auto-rollback branch
// (restorePendingFiles returning an error).
type failingReloadExec struct {
	fakeExec
}

func (e *failingReloadExec) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	if cmd == "networkctl" && len(args) >= 1 && args[0] == "reload" {
		return "", errors.New("simulated networkctl reload failure")
	}
	return e.fakeExec.Execute(ctx, cmd, args...)
}

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

// TestIfaceEditJSONTagsMatchFrontendSnakeCase round-trips a hand-written
// snake_case JSON body — exactly what the frontend sends to Preview/Apply —
// through encoding/json into IfaceEdit. Without `json:"..."` tags on
// IfaceEdit, Go's case-insensitive fallback fails to match "addr_mode" to
// AddrMode (an underscore is not a casing difference), so every field except
// Name silently decoded as "". This test would have caught that: it fails on
// the untagged struct and passes once the snake_case tags are in place.
func TestIfaceEditJSONTagsMatchFrontendSnakeCase(t *testing.T) {
	body := `{"name":"eth0","addr_mode":"static","cidr":"192.168.3.3/24","gateway":"192.168.3.1","description":"test"}`

	var edit IfaceEdit
	if err := json.Unmarshal([]byte(body), &edit); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if edit.Name != "eth0" {
		t.Errorf("Name: esperava %q, veio %q", "eth0", edit.Name)
	}
	if edit.AddrMode != "static" {
		t.Errorf("AddrMode: esperava %q, veio %q (campo essencial p/ ValidateIface e networkd.Render)", "static", edit.AddrMode)
	}
	if edit.CIDR != "192.168.3.3/24" {
		t.Errorf("CIDR: esperava %q, veio %q", "192.168.3.3/24", edit.CIDR)
	}
	if edit.Gateway != "192.168.3.1" {
		t.Errorf("Gateway: esperava %q, veio %q", "192.168.3.1", edit.Gateway)
	}
	if edit.Description != "test" {
		t.Errorf("Description: esperava %q, veio %q", "test", edit.Description)
	}
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

func TestServiceListMergesErrorDroppedCounters(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON, netDev: sampleProcNetDev}
	db := newTestDB(t)
	linkSvc := links.NewService(db)

	svc := NewService(exec, db, linkSvc)
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	byName := make(map[string]IfaceView, len(views))
	for _, v := range views {
		byName[v.Name] = v
	}
	wl := byName["wlp2s0"]
	if wl.Live.RxDropped != 1 || wl.Live.TxDropped != 44 {
		t.Errorf("wlp2s0: expected RxDropped=1 TxDropped=44 from /proc/net/dev merge, got %+v", wl.Live)
	}
	en := byName["enp0s31f6"]
	if en.Live.TxDropped != 111 {
		t.Errorf("enp0s31f6: expected TxDropped=111 from /proc/net/dev merge, got %+v", en.Live)
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

func mustMarshalFiles(t *testing.T, p PendingChangeView) string {
	t.Helper()
	// PendingChangeView não carrega os arquivos antigos (isso é interno ao
	// Service) — para este teste específico de sweep, um old_files vazio
	// ([]) é suficiente: o que o teste verifica é que o sweep localiza,
	// reverte e remove a mudança vencida, não o conteúdo exato restaurado
	// (isso já está coberto por TestServiceRollbackRestoresOldFileAndDoesNotPersist).
	return "[]"
}

func TestServicePreviewShowsOldAndNewContent(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	alertSvc := alerts.NewService(db)
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
	svc.SetAlertService(alerts.NewService(db))

	_, err := svc.Preview(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "static", CIDR: "não-é-cidr"})
	if err == nil {
		t.Fatal("esperava erro de validação, não teve nenhum")
	}
}

// TestServicePreviewRejectsNameWithNewline covers Finding 2: Name is
// interpolated unescaped into the rendered [Match] body, so a newline must
// be rejected before Preview ever calls networkd.Render.
func TestServicePreviewRejectsNameWithNewline(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))

	_, err := svc.Preview(context.Background(), IfaceEdit{Name: "wlp2s0\nDHCP=no", AddrMode: "dhcp"})
	if err == nil {
		t.Fatal("esperava erro de validação para nome com newline, não teve nenhum")
	}
}

// TestServiceApplyChangeRejectsNameWithSlash covers Finding 2: Name is
// interpolated unescaped into the rendered file path, so a "/" must be
// rejected before ApplyChange ever calls networkd.Render/Apply.
func TestServiceApplyChangeRejectsNameWithSlash(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
	svc.networkDir = t.TempDir()

	_, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "../etc/passwd", AddrMode: "dhcp"})
	if err == nil {
		t.Fatal("esperava erro de validação para nome com barra, não teve nenhum")
	}
}

// TestServicePreviewRejectsNonexistentInterface and
// TestServiceApplyChangeRejectsNonexistentInterface cover Finding 2's second
// half: a syntactically valid Name that isn't in the live interface
// inventory must be rejected, not silently rendered/written.
func TestServicePreviewRejectsNonexistentInterface(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))

	_, err := svc.Preview(context.Background(), IfaceEdit{Name: "eth99-nao-existe", AddrMode: "dhcp"})
	if err == nil {
		t.Fatal("esperava erro para interface inexistente, não teve nenhum")
	}
}

func TestServiceApplyChangeRejectsNonexistentInterface(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
	svc.networkDir = t.TempDir()

	_, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "eth99-nao-existe", AddrMode: "dhcp"})
	if err == nil {
		t.Fatal("esperava erro para interface inexistente, não teve nenhum")
	}
}

// TestServiceApplyChangeRejectsNonPhysicalInterface confirms the small
// Kind==KindPhysical backstop added alongside the existence check: docker0
// in sampleLinkJSON is a real, existing interface, but it's KindBridge, and
// Fase 2 only edits physical interfaces.
func TestServiceApplyChangeRejectsNonPhysicalInterface(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
	svc.networkDir = t.TempDir()

	_, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "docker0", AddrMode: "dhcp"})
	if err == nil {
		t.Fatal("esperava erro ao tentar editar docker0 (não é uma interface física), não teve nenhum")
	}
}

func TestServiceApplyThenConfirmPersistsManagedInterface(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
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
	svc.SetAlertService(alerts.NewService(db))
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

// TestServiceRollbackOfFirstTimeEditRemovesFile covers the Finding 1 fix: a
// pending change on an interface with no prior .network file must, on
// rollback, leave the file *removed* — not written back as an empty file
// (which would apply an unrestricted [Network] block with no address/DHCP
// once a live systemd-networkd reads it).
func TestServiceRollbackOfFirstTimeEditRemovesFile(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
	svc.networkDir = t.TempDir()
	path := filepath.Join(svc.networkDir, "10-wlp2s0.network")

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pré-condição: arquivo não deveria existir antes do ApplyChange, err=%v", err)
	}

	if _, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "dhcp"}); err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("esperava que o ApplyChange tivesse escrito o arquivo: %v", err)
	}

	if err := svc.Rollback(context.Background(), "wlp2s0"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("esperava que o rollback removesse o arquivo (não existia antes da mudança), veio err=%v", err)
	}
}

// TestServiceRollbackWithPriorFileRestoresRealContent is the non-regression
// counterpart of the test above: when a .network file already existed before
// the change, rollback must restore its exact prior content, not remove it.
func TestServiceRollbackWithPriorFileRestoresRealContent(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
	svc.networkDir = t.TempDir()
	path := filepath.Join(svc.networkDir, "10-wlp2s0.network")

	const priorContent = "# managed by linkguard\n\n[Match]\nName=wlp2s0\n\n[Network]\nDHCP=yes\n"
	if err := os.WriteFile(path, []byte(priorContent), 0o644); err != nil {
		t.Fatalf("seed prior file: %v", err)
	}

	if _, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "static", CIDR: "192.168.3.9/24"}); err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(got), "Address=192.168.3.9/24") {
		t.Fatalf("esperava que o ApplyChange tivesse escrito a nova config: %q, err=%v", got, err)
	}

	if err := svc.Rollback(context.Background(), "wlp2s0"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("esperava que o arquivo continuasse existindo após o rollback (havia conteúdo anterior): %v", err)
	}
	if string(restored) != priorContent {
		t.Errorf("conteúdo restaurado errado:\ngot:  %q\nwant: %q", restored, priorContent)
	}
}

func TestRunExpirySweepAutoRollsBackExpiredChange(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
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
	alertsList, err := db.GetAlerts(true, 100)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
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

// TestRunExpirySweepAutoRollbackOfFirstTimeEditRemovesFile is the
// sweep-triggered counterpart of TestServiceRollbackOfFirstTimeEditRemovesFile
// — restorePendingFiles is shared by both Rollback and sweepExpiredOnce, but
// the auto-expiry path is exercised separately here since that's the more
// common real-world trigger (an admin who never confirms).
func TestRunExpirySweepAutoRollbackOfFirstTimeEditRemovesFile(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
	svc.networkDir = t.TempDir()
	path := filepath.Join(svc.networkDir, "10-wlp2s0.network")

	if _, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "dhcp"}); err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("esperava que o ApplyChange tivesse escrito o arquivo: %v", err)
	}

	// Força a mudança pendente (com OldContent="", já que não havia arquivo
	// prévio) a já estar vencida, sem esperar o deadline real.
	oldFilesJSON, err := json.Marshal([]FileDiff{{Path: path, OldContent: ""}})
	if err != nil {
		t.Fatalf("marshal oldFiles: %v", err)
	}
	expired := storage.PendingInterfaceChange{
		ID: "forced", Interface: "wlp2s0",
		OldConfig: "", OldFiles: string(oldFilesJSON), NewConfig: "{}",
		DeadlineUnix: time.Now().Add(-1 * time.Second).Unix(),
	}
	if err := db.DeletePendingInterfaceChange("wlp2s0"); err != nil {
		t.Fatalf("DeletePendingInterfaceChange: %v", err)
	}
	if err := db.CreatePendingInterfaceChange(expired); err != nil {
		t.Fatalf("CreatePendingInterfaceChange: %v", err)
	}

	svc.sweepExpiredOnce(context.Background())

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("esperava que o sweep removesse o arquivo (não existia antes da mudança), veio err=%v", err)
	}
}

func TestRunExpirySweepFailedRollbackKeepsPendingAndAlertsCritical(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	svc := NewService(exec, db, linkSvc)
	svc.SetAlertService(alerts.NewService(db))
	svc.networkDir = t.TempDir()

	if _, err := svc.ApplyChange(context.Background(), IfaceEdit{Name: "wlp2s0", AddrMode: "dhcp"}); err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	// Diferente de TestRunExpirySweepAutoRollsBackExpiredChange, este teste
	// precisa de um old_files não-vazio: restorePendingFiles só chama
	// networkd.Apply (e portanto só aciona o "networkctl reload" que este
	// teste faz falhar) se houver ao menos um arquivo pra restaurar.
	oldFiles, err := json.Marshal([]FileDiff{{
		Path:       filepath.Join(svc.networkDir, "10-wlp2s0.network"),
		OldContent: "# conteúdo anterior de teste\n",
		NewContent: "# conteúdo novo de teste\n",
	}})
	if err != nil {
		t.Fatalf("marshal oldFiles: %v", err)
	}
	// Força a mudança pendente a já estar vencida, sem esperar o deadline real.
	expired := storage.PendingInterfaceChange{
		ID: "forced", Interface: "wlp2s0",
		OldConfig: "", OldFiles: string(oldFiles), NewConfig: "{}",
		DeadlineUnix: time.Now().Add(-1 * time.Second).Unix(),
	}
	if err := db.DeletePendingInterfaceChange("wlp2s0"); err != nil {
		t.Fatalf("DeletePendingInterfaceChange: %v", err)
	}
	if err := db.CreatePendingInterfaceChange(expired); err != nil {
		t.Fatalf("CreatePendingInterfaceChange: %v", err)
	}

	// A partir daqui, o "networkctl reload" (disparado por restorePendingFiles
	// dentro do sweep) passa a falhar — simula uma reversão automática que não
	// consegue se aplicar.
	svc.exec = &failingReloadExec{fakeExec: *exec}

	svc.sweepExpiredOnce(context.Background())

	p, err := db.GetPendingInterfaceChange("wlp2s0")
	if err != nil {
		t.Fatalf("GetPendingInterfaceChange: %v", err)
	}
	if p == nil {
		t.Error("mudança pendente não deveria ter sido removida quando a reversão automática falha")
	}

	alertsList, err := db.GetAlerts(true, 100)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	found := false
	for _, a := range alertsList {
		if strings.Contains(a.Message, "wlp2s0") && a.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Error("esperava um alerta crítico mencionando wlp2s0 após falha na reversão automática")
	}
}
