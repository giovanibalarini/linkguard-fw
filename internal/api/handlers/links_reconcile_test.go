package handlers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// reconcileSpyExec records nft invocations so the test can prove a link
// mutation actually re-applied the NAT rule. execErr, when set, is
// returned by every Execute call — used by ntp_test.go to simulate an nft
// failure and prove the reconcile outcome is surfaced rather than swallowed.
type reconcileSpyExec struct {
	executed []string
	execErr  error
}

func (e *reconcileSpyExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.executed = append(e.executed, strings.Join(append([]string{cmd}, args...), " "))
	return "", e.execErr
}
func (e *reconcileSpyExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	return "", nil
}
func (e *reconcileSpyExec) IsDryRun() bool                              { return false }
func (_ *reconcileSpyExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func (e *reconcileSpyExec) sawMasqueradeFor(iface string) bool {
	for _, c := range e.executed {
		if strings.Contains(c, "masquerade") && strings.Contains(c, iface) {
			return true
		}
	}
	return false
}

// newTestDB opens a fresh sqlite-backed storage.DB in a temp dir, matching
// the pattern used by netsvc_lastapply_test.go.
func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
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

	h.reconcileWANDerived(context.Background())

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

	h.reconcileWANDerived(context.Background())

	if !exec.sawMasqueradeFor("enp5s0") {
		t.Errorf("enabled link missing from the NAT rule; ran: %v", exec.executed)
	}
	if exec.sawMasqueradeFor("enp9s0") {
		t.Errorf("disabled link must not be masqueraded; ran: %v", exec.executed)
	}
}

// TestReconcileWANDerivedTambemLigaAContabilidade: a contabilidade por host
// (#112) deriva da MESMA lista de WANs que o masquerade, e por isso precisa
// mudar junto. Sem isto ela só acompanharia a mudança no boot seguinte — foi
// exatamente o que a bateria G do vm-validate.sh pegou numa instalação nova,
// que nasce sem link nenhum: o admin criava o primeiro link pelo painel e a
// chain de contabilidade não existia até alguém reiniciar o serviço.
func TestReconcileWANDerivedTambemLigaAContabilidade(t *testing.T) {
	db := newTestDB(t)
	if err := db.CreateLink(&storage.Link{ID: "l1", Name: "WAN1", Interface: "enp5s0", Weight: 1, Enabled: true}); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	exec := &reconcileSpyExec{}
	h := &LinksHandler{db: db, nftSvc: nftables.NewService(exec)}

	h.reconcileWANDerived(context.Background())

	var criouChain, escopouRegra bool
	for _, cmd := range exec.executed {
		if strings.Contains(cmd, "add chain") && strings.Contains(cmd, nftables.AcctChain) {
			criouChain = true
		}
		if strings.Contains(cmd, "@"+nftables.AcctUpSet) && strings.Contains(cmd, "enp5s0") {
			escopouRegra = true
		}
	}
	if !criouChain {
		t.Errorf("a chain de contabilidade não foi criada ao mudar link; rodou: %v", exec.executed)
	}
	if !escopouRegra {
		t.Errorf("a regra de contabilidade não foi escopada pela WAN atual; rodou: %v", exec.executed)
	}
}
