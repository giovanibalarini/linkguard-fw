package domainrouting_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/domainrouting"
	"github.com/giovanibalarini/linkguard-fw/internal/domtargets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type fakeRuntime struct {
	mu    sync.Mutex
	last  []domtargets.Alvo
	state domtargets.Estado
}

func (f *fakeRuntime) DefinirAlvos(alvos []domtargets.Alvo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = append([]domtargets.Alvo(nil), alvos...)
}

func (f *fakeRuntime) Estado(context.Context) domtargets.Estado {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

func (f *fakeRuntime) alvo(domain string) (domtargets.Alvo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, target := range f.last {
		if target.Dominio == domain {
			return target, true
		}
	}
	return domtargets.Alvo{}, false
}

func newDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "domain-routing.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func addBlockGroup(t *testing.T, db *storage.DB, enabled bool) {
	t.Helper()
	if err := db.CreateFirewallGroup(&storage.FirewallGroup{
		ID: "system-blocklist", Name: "Destinos bloqueados", Kind: "blocklist", Enabled: enabled,
	}); err != nil {
		t.Fatal(err)
	}
}

func addLink(t *testing.T, db *storage.DB, status string, enabled bool, table int) *storage.Link {
	t.Helper()
	link := &storage.Link{
		ID: "wan-2", Name: "WAN 2", Interface: "wan2", Status: status,
		Enabled: enabled, TableID: table,
	}
	if err := db.CreateLink(link); err != nil {
		t.Fatal(err)
	}
	return link
}

func addActiveRoute(t *testing.T, db *storage.DB, linkID string) *storage.DomainTarget {
	t.Helper()
	target := &storage.DomainTarget{
		Domain: "video.example.com", Capability: storage.DomainCapDirecionar, LinkID: linkID,
	}
	if err := db.CreateDomainTarget(target); err != nil {
		t.Fatal(err)
	}
	if err := db.SetDomainTargetStage(target.ID, storage.DomainStageAtivo); err != nil {
		t.Fatal(err)
	}
	return target
}

func targetView(t *testing.T, state domainrouting.State, domain string) domainrouting.TargetView {
	t.Helper()
	for _, row := range state.Targets {
		if row.Domain == domain {
			return row
		}
	}
	t.Fatalf("target %s não apareceu em %+v", domain, state.Targets)
	return domainrouting.TargetView{}
}

func TestBootGateKeepsActiveIntentSuspendedUntilPrepare(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, true)
	link := addLink(t, db, "online", true, 200)
	addActiveRoute(t, db, link.ID)
	runtime := &fakeRuntime{}
	coordinator := domainrouting.New(db, runtime)

	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := targetView(t, coordinator.State(context.Background()), "video.example.com")
	if before.Stage != storage.DomainStageAtivo || before.EffectiveStage != storage.DomainStageEnsaio ||
		!before.Suspended || before.SuspensionReason != domainrouting.ReasonBootPending {
		t.Fatalf("gate de boot não suspendeu a intenção ativa: %+v", before)
	}
	if got, _ := runtime.alvo(before.Domain); got.Estagio != domtargets.Ensaio {
		t.Fatalf("runtime recebeu estágio %q antes de Prepare", got.Estagio)
	}

	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	afterState := coordinator.State(context.Background())
	after := targetView(t, afterState, "video.example.com")
	if !afterState.Ready || after.EffectiveStage != storage.DomainStageAtivo || after.Suspended || after.Mark != 200 {
		t.Fatalf("Prepare não ativou com a mark atual: state=%+v target=%+v", afterState, after)
	}
	if got, _ := runtime.alvo(after.Domain); got.Estagio != domtargets.Ativo || got.Marca != 200 {
		t.Fatalf("runtime não recebeu alvo ativo/mark 200: %+v", got)
	}
}

func TestHoldClosesAnAlreadyOpenBootGate(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, true)
	link := addLink(t, db, "online", true, 200)
	addActiveRoute(t, db, link.ID)
	runtime := &fakeRuntime{}
	coordinator := domainrouting.New(db, runtime)
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := coordinator.Hold(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := coordinator.State(context.Background())
	row := targetView(t, state, "video.example.com")
	if state.Ready || !row.Suspended || row.SuspensionReason != domainrouting.ReasonBootPending || row.EffectiveStage != storage.DomainStageEnsaio {
		t.Fatalf("Hold não fechou o gate: state=%+v target=%+v", state, row)
	}
	if got, _ := runtime.alvo(row.Domain); got.Estagio != domtargets.Ensaio {
		t.Fatalf("runtime continuou ativo após Hold: %+v", got)
	}
}

func TestWANStatusSuspendsAndReenablesWithoutResurrectingStoredMark(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, true)
	link := addLink(t, db, "online", true, 200)
	addActiveRoute(t, db, link.ID)
	runtime := &fakeRuntime{}
	coordinator := domainrouting.New(db, runtime)
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}

	link.Status = "offline"
	link.TableID = 250
	if err := db.UpdateLink(link); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	offline := targetView(t, coordinator.State(context.Background()), "video.example.com")
	if !offline.Suspended || offline.SuspensionReason != domainrouting.ReasonLinkOffline || offline.EffectiveStage != storage.DomainStageEnsaio {
		t.Fatalf("WAN offline não suspendeu: %+v", offline)
	}
	if got, _ := runtime.alvo(offline.Domain); got.Estagio != domtargets.Ensaio {
		t.Fatalf("runtime continuou ativo com WAN offline: %+v", got)
	}

	link.Status = "degraded"
	if err := db.UpdateLink(link); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	reenabled := targetView(t, coordinator.State(context.Background()), "video.example.com")
	if reenabled.Suspended || reenabled.EffectiveStage != storage.DomainStageAtivo || reenabled.Mark != 250 || reenabled.LinkStatus != "degraded" {
		t.Fatalf("WAN degradada não reabilitou com table_id atual: %+v", reenabled)
	}
	if got, _ := runtime.alvo(reenabled.Domain); got.Marca != 250 {
		t.Fatalf("runtime ressuscitou mark persistida em vez da atual: %+v", got)
	}
}

func TestEveryUnsafeWANStateHasAnObservableSuspensionReason(t *testing.T) {
	tests := []struct {
		name      string
		withLink  bool
		enabled   bool
		status    string
		iface     string
		table     int
		wantCause string
	}{
		{name: "missing", wantCause: domainrouting.ReasonLinkMissing},
		{name: "disabled", withLink: true, enabled: false, status: "online", iface: "wan2", table: 200, wantCause: domainrouting.ReasonLinkDisabled},
		{name: "no interface", withLink: true, enabled: true, status: "online", table: 200, wantCause: domainrouting.ReasonLinkUnconfigured},
		{name: "no table", withLink: true, enabled: true, status: "online", iface: "wan2", wantCause: domainrouting.ReasonLinkUnconfigured},
		{name: "unknown", withLink: true, enabled: true, status: "unknown", iface: "wan2", table: 200, wantCause: domainrouting.ReasonLinkNotReady},
		{name: "offline", withLink: true, enabled: true, status: "offline", iface: "wan2", table: 200, wantCause: domainrouting.ReasonLinkOffline},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newDB(t)
			addBlockGroup(t, db, true)
			if tt.withLink {
				link := &storage.Link{ID: "wan-2", Name: "WAN 2", Interface: tt.iface, Status: tt.status, Enabled: tt.enabled, TableID: tt.table}
				if err := db.CreateLink(link); err != nil {
					t.Fatal(err)
				}
			}
			addActiveRoute(t, db, "wan-2")
			coordinator := domainrouting.New(db, &fakeRuntime{})
			if err := coordinator.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := targetView(t, coordinator.State(context.Background()), "video.example.com")
			if !got.Suspended || got.SuspensionReason != tt.wantCause || got.EffectiveStage != storage.DomainStageEnsaio {
				t.Fatalf("estado inseguro não ficou observável: %+v", got)
			}
		})
	}
}

func TestDisabledBlockGroupSuspendsBlockTargetsAndReenableRestoresIntent(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, false)
	target := &storage.DomainTarget{Domain: "ads.example.com", Capability: storage.DomainCapBarrar}
	if err := db.CreateDomainTarget(target); err != nil {
		t.Fatal(err)
	}
	if err := db.SetDomainTargetStage(target.ID, storage.DomainStageAtivo); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{}
	coordinator := domainrouting.New(db, runtime)
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	disabled := targetView(t, coordinator.State(context.Background()), target.Domain)
	if !disabled.Suspended || disabled.SuspensionReason != domainrouting.ReasonBlockingGroupDisabled {
		t.Fatalf("grupo desligado não suspendeu bloqueio: %+v", disabled)
	}

	if err := db.SetFirewallGroupEnabled("system-blocklist", true); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	enabled := targetView(t, coordinator.State(context.Background()), target.Domain)
	if enabled.Suspended || enabled.EffectiveStage != storage.DomainStageAtivo {
		t.Fatalf("grupo reativado não reabilitou intenção: %+v", enabled)
	}
}

func TestCRUDRequiresExplicitStageAndReturnsKernelObservability(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, true)
	link := addLink(t, db, "online", true, 200)
	runtime := &fakeRuntime{state: domtargets.Estado{
		Vivo: true, KernelLido: true,
		Dominios: []domtargets.EstadoDominio{{
			Dominio: "video.example.com", NoIndice: 2, NoKernel: intPtr(1),
			Rotatividade: 7, DirecionadoV6: 3,
		}},
	}}
	coordinator := domainrouting.New(db, runtime)
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}

	created, err := coordinator.Create(context.Background(), domainrouting.Input{
		Domain: "video.example.com", Capability: storage.DomainCapDirecionar, LinkID: link.ID, Note: "vídeo",
	})
	if err != nil {
		t.Fatal(err)
	}
	row := targetView(t, created, "video.example.com")
	if row.Stage != storage.DomainStageEnsaio || row.EffectiveStage != storage.DomainStageEnsaio {
		t.Fatalf("criação promoveu por acidente: %+v", row)
	}

	promoted, err := coordinator.SetStage(context.Background(), row.ID, storage.DomainStageAtivo)
	if err != nil {
		t.Fatal(err)
	}
	row = targetView(t, promoted, "video.example.com")
	if row.Stage != storage.DomainStageAtivo || row.EffectiveStage != storage.DomainStageAtivo ||
		row.NoKernel == nil || *row.NoKernel != 1 || row.NoIndex != 2 || row.Rotation != 7 || row.RoutedIPv6Discarded != 3 {
		t.Fatalf("promoção/observabilidade incompleta: %+v", row)
	}
	if promoted.RoutingIPv6Supported {
		t.Fatal("API afirmou suporte a direcionamento IPv6")
	}

	updated, err := coordinator.Update(context.Background(), row.ID, domainrouting.Input{
		Domain: "media.example.com", Capability: storage.DomainCapDirecionar, LinkID: link.ID, Note: "editado",
	})
	if err != nil {
		t.Fatal(err)
	}
	row = targetView(t, updated, "media.example.com")
	if row.Stage != storage.DomainStageAtivo || row.Note != "editado" {
		t.Fatalf("edição alterou estágio: %+v", row)
	}

	if _, err := coordinator.Create(context.Background(), domainrouting.Input{
		Domain: "other.example.com", Capability: storage.DomainCapDirecionar, LinkID: "missing",
	}); !errors.Is(err, domainrouting.ErrInvalid) {
		t.Fatalf("link desconhecido não virou ErrInvalid: %v", err)
	}
	if _, err := coordinator.SetStage(context.Background(), row.ID, "talvez"); !errors.Is(err, domainrouting.ErrInvalid) {
		t.Fatalf("stage desconhecido não virou ErrInvalid: %v", err)
	}
	if _, err := coordinator.Delete(context.Background(), row.ID); err != nil {
		t.Fatal(err)
	}
	if len(coordinator.State(context.Background()).Targets) != 0 {
		t.Fatal("delete não retirou alvo da visão/runtime")
	}
}

func intPtr(v int) *int { return &v }
