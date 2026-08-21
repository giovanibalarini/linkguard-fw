package hosts_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/hosts"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type fakeExec struct{ ruleset string }

func (f *fakeExec) Execute(context.Context, string, ...string) (string, error) { return "", nil }
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "nft" && len(args) >= 2 && args[0] == "list" && args[1] == "ruleset" {
		return f.ruleset, nil
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool                              { return false }
func (_ *fakeExec) WriteFile(string, []byte, os.FileMode) error { return nil }

type fakeNetProvider struct{}

func (fakeNetProvider) Backend() netsvc.Backend { return netsvc.BackendKeaUnbound }
func (fakeNetProvider) GenerateConfigs(netsvc.Config, []netsvc.Reservation, []string, string) ([]netsvc.ConfigFile, error) {
	return nil, nil
}
func (fakeNetProvider) Apply(context.Context, netsvc.Config, []netsvc.Reservation, []string) (string, error) {
	return "", nil
}
func (fakeNetProvider) ReloadConfigs(context.Context, netsvc.Config, []netsvc.Reservation, []string, string) (netsvc.ApplyResult, error) {
	return netsvc.ApplyResult{}, nil
}
func (fakeNetProvider) Leases(context.Context) ([]netsvc.Lease, error) { return nil, nil }

// TestSetBlockedPersistsLiveSnapshot is the regression test for host blocking
// via the Hosts screen: blocking must save a fresh nftables snapshot (not
// just the host_metadata.blocked flag) so a from-scratch install restores
// the block too — see nftables.EnsureTable + LiveSnapshotSettingKey.
func TestSetBlockedPersistsLiveSnapshot(t *testing.T) {
	origConfPath := nftables.ConfPath
	nftables.ConfPath = filepath.Join(t.TempDir(), "nftables.conf")
	t.Cleanup(func() { nftables.ConfPath = origConfPath })

	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.UpsertHostSighting("aa:bb:cc:dd:ee:ff", "192.168.3.50"); err != nil {
		t.Fatalf("UpsertHostSighting: %v", err)
	}

	const wantRuleset = "table inet linkguard {\n\tset blocked_hosts {\n\t\telements = { 192.168.3.50 }\n\t}\n}\n"
	nftSvc := nftables.NewService(&fakeExec{ruleset: wantRuleset})
	svc := hosts.NewService(&fakeExec{ruleset: wantRuleset}, db, nftSvc, fakeNetProvider{})

	if err := svc.SetBlocked(context.Background(), "aa:bb:cc:dd:ee:ff", true); err != nil {
		t.Fatalf("SetBlocked: %v", err)
	}

	got, err := db.GetSetting(nftables.LiveSnapshotSettingKey)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if got != wantRuleset {
		t.Errorf("snapshot not persisted correctly:\ngot:  %q\nwant: %q", got, wantRuleset)
	}
}

// execGravador guarda os comandos, para o teste abaixo poder afirmar o que foi
// escrito no firewall — e não só que nada explodiu.
type execGravador struct {
	fakeExec
	comandos [][]string
}

func (e *execGravador) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.comandos = append(e.comandos, append([]string{cmd}, args...))
	return "", nil
}

func (e *execGravador) contem(sub string) bool {
	for _, c := range e.comandos {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

// TestBloquearHostValeAntesDeConhecerOIP é a asserção que a fase 2 da #119
// existe para garantir.
//
// Antes dela, bloquear um host que ainda não tinha sido visto na rede não
// escrevia NADA no firewall: a flag ficava guardada e o produto esperava o host
// aparecer para traduzir o MAC em IP. E, mesmo depois de aparecer, o bloqueio
// só valia para IPv4 — o mesmo host falando IPv6 atravessava a chain forward
// sem casar com regra nenhuma, com a tela dizendo "bloqueado".
//
// O endereço físico não tem família e não depende de o host ter sido visto.
func TestBloquearHostValeAntesDeConhecerOIP(t *testing.T) {
	origConfPath := nftables.ConfPath
	nftables.ConfPath = filepath.Join(t.TempDir(), "nftables.conf")
	t.Cleanup(func() { nftables.ConfPath = origConfPath })

	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// De propósito SEM UpsertHostSighting: este host nunca foi visto, então não
	// há IP para traduzir.
	e := &execGravador{}
	svc := hosts.NewService(e, db, nftables.NewService(e), fakeNetProvider{})

	if err := svc.SetBlocked(context.Background(), "aa:bb:cc:dd:ee:ff", true); err != nil {
		t.Fatalf("SetBlocked: %v", err)
	}
	if !e.contem("add element inet linkguard blocked_macs { aa:bb:cc:dd:ee:ff }") {
		t.Errorf("o endereço físico não foi bloqueado; comandos: %v", e.comandos)
	}

	e.comandos = nil
	if err := svc.SetBlocked(context.Background(), "aa:bb:cc:dd:ee:ff", false); err != nil {
		t.Fatalf("SetBlocked(false): %v", err)
	}
	if !e.contem("delete element inet linkguard blocked_macs { aa:bb:cc:dd:ee:ff }") {
		t.Errorf("o desbloqueio não tirou o endereço físico; comandos: %v", e.comandos)
	}
}
