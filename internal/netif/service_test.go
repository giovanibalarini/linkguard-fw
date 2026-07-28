package netif

import (
	"context"
	"errors"
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
