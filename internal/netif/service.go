package netif

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/netif/networkd"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const interfaceAliasSettingKey = "interface_aliases" // same key as internal/api/handlers/system.go — do not duplicate the mechanism, only this small read
const netsvcConfigSettingKey = "netsvc_config"       // same key as internal/api/handlers/netsvc.go

// Service builds the live interface inventory: kernel state (via `ip -j`)
// merged with configured Role (from links.Service and the DHCP/DNS LAN
// interface) and stored aliases, plus (Fase 2) the preview/apply/confirm/
// rollback orchestration for editing physical interface addressing.
type Service struct {
	exec       firewall.Executor
	db         *storage.DB
	linkSvc    *links.Service
	alertSvc   *alerts.Service
	networkDir string // overridden in tests; production uses the networkd package's default
}

// NewService creates a netif Service.
func NewService(exec firewall.Executor, db *storage.DB, linkSvc *links.Service) *Service {
	return &Service{exec: exec, db: db, linkSvc: linkSvc}
}

// SetAlertService wires the alert sink used when an auto-rollback fires.
// Separate from NewService to avoid changing that constructor's signature
// for the read-only Fase 1 callers/tests that don't need it.
func (s *Service) SetAlertService(a *alerts.Service) {
	s.alertSvc = a
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
	netDevOut, err := s.exec.ExecuteRead(ctx, "cat", "/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("cat /proc/net/dev: %w", err)
	}

	links_, err := parseLinks(linkOut)
	if err != nil {
		return nil, err
	}
	addrs, err := parseAddrs(addrOut)
	if err != nil {
		return nil, err
	}
	counters := parseProcNetDev(netDevOut)
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
		if c, ok := counters[name]; ok {
			views[i].Live.RxErrors = c.RxErrors
			views[i].Live.TxErrors = c.TxErrors
			views[i].Live.RxDropped = c.RxDropped
			views[i].Live.TxDropped = c.TxDropped
		}
	}

	managed, _ := s.db.ListManagedInterfaces()
	managedByName := make(map[string]storage.ManagedInterface, len(managed))
	for _, m := range managed {
		managedByName[m.Name] = m
	}
	for i := range views {
		if m, ok := managedByName[views[i].Name]; ok {
			views[i].Managed = true
			views[i].AddrMode = AddrMode(m.AddrMode)
			views[i].CIDR = m.CIDR
			views[i].Gateway = m.Gateway
			if m.Description != "" {
				views[i].Description = m.Description
			}
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

// IfaceEdit is the set of fields an admin can change for a physical
// interface in Fase 2 — addressing only.
type IfaceEdit struct {
	Name        string `json:"name"`
	AddrMode    string `json:"addr_mode"`
	CIDR        string `json:"cidr"`
	Gateway     string `json:"gateway"`
	Description string `json:"description"`
}

// FileDiff is one config file's before/after content, for the review screen.
type FileDiff struct {
	Path       string `json:"path"`
	OldContent string `json:"old_content"`
	NewContent string `json:"new_content"`
}

// PreviewResult is what the review screen shows before applying.
type PreviewResult struct {
	Files    []FileDiff `json:"files"`
	Warnings []string   `json:"warnings"`
}

// PendingChangeView is the API-facing shape of an in-flight, unconfirmed change.
type PendingChangeView struct {
	Interface    string `json:"interface"`
	DeadlineUnix int64  `json:"deadline_unix"`
}

func (e IfaceEdit) toIface() Iface {
	return Iface{
		Name: e.Name, Kind: KindPhysical, AddrMode: AddrMode(e.AddrMode),
		CIDR: e.CIDR, Gateway: e.Gateway, Description: e.Description,
	}
}

// toSpec converts to networkd.IfaceSpec — the minimal, netif-independent
// shape networkd.Render/Apply need (see the doc comment on IfaceSpec for why
// networkd can't just take a netif.Iface: package netif is this function's
// own caller, so networkd importing netif back would be a cycle).
func (e IfaceEdit) toSpec() networkd.IfaceSpec {
	return networkd.IfaceSpec{
		Name: e.Name, AddrMode: e.AddrMode, CIDR: e.CIDR, Gateway: e.Gateway,
	}
}

// rollbackDeadline is how long an applied-but-unconfirmed change waits before
// auto-reverting — spec 19/07 §6 default.
const rollbackDeadline = 90 * time.Second

// oldFileContent reads the current content of a rendered file, or "" if it
// doesn't exist yet (first-ever edit of that interface).
func (s *Service) oldFileContent(path string) string {
	content, err := s.exec.ExecuteRead(context.Background(), "cat", path)
	if err != nil {
		return ""
	}
	return content
}

// Preview validates the edit and shows what would change, without touching
// the system.
func (s *Service) Preview(ctx context.Context, edit IfaceEdit) (PreviewResult, error) {
	iface := edit.toIface()
	if err := ValidateIface(iface); err != nil {
		return PreviewResult{}, err
	}
	newFile := networkd.Render(edit.toSpec(), s.networkDir)
	old := s.oldFileContent(newFile.Path)

	var warnings []string
	// spec 19/07 §10.4: avisar quando a mudança afeta a interface de acesso atual.
	// A Fase 2 não tem como saber com certeza qual interface o admin está usando
	// agora (isso exigiria inspecionar a conexão HTTP recebida, fora do escopo
	// deste Service) — o aviso genérico abaixo cobre o caso mais comum e barato
	// de detectar: a interface é a WAN configurada.
	views, err := s.List(ctx)
	if err == nil {
		for _, v := range views {
			if v.Name == edit.Name && v.Role == RoleWAN {
				warnings = append(warnings, "Esta é uma interface WAN configurada — uma configuração errada pode derrubar o acesso remoto ao painel.")
			}
		}
	}

	return PreviewResult{
		Files:    []FileDiff{{Path: newFile.Path, OldContent: old, NewContent: newFile.Content}},
		Warnings: warnings,
	}, nil
}

// ApplyChange writes the new config, arms the rollback deadline, and returns
// the pending state. The interface only becomes "Managed" on Confirm.
func (s *Service) ApplyChange(ctx context.Context, edit IfaceEdit) (PendingChangeView, error) {
	iface := edit.toIface()
	if err := ValidateIface(iface); err != nil {
		return PendingChangeView{}, err
	}
	if existing, _ := s.db.GetPendingInterfaceChange(edit.Name); existing != nil {
		return PendingChangeView{}, fmt.Errorf("já existe uma mudança pendente para %s — confirme ou reverta antes de aplicar outra", edit.Name)
	}

	newFile := networkd.Render(edit.toSpec(), s.networkDir)
	oldContent := s.oldFileContent(newFile.Path)
	oldFilesJSON, _ := json.Marshal([]FileDiff{{Path: newFile.Path, OldContent: oldContent}})

	oldManaged, _ := s.db.GetManagedInterface(edit.Name)
	oldConfigJSON := "{}"
	if oldManaged != nil {
		b, _ := json.Marshal(oldManaged)
		oldConfigJSON = string(b)
	}
	newConfigJSON, _ := json.Marshal(storage.ManagedInterface{
		Name: edit.Name, Kind: string(KindPhysical), AddrMode: edit.AddrMode,
		CIDR: edit.CIDR, Gateway: edit.Gateway, Description: edit.Description,
	})

	if err := networkd.Apply(ctx, s.exec, newFile); err != nil {
		return PendingChangeView{}, fmt.Errorf("aplicar configuração: %w", err)
	}

	deadline := time.Now().Add(rollbackDeadline)
	err := s.db.CreatePendingInterfaceChange(storage.PendingInterfaceChange{
		ID: uuid.NewString(), Interface: edit.Name,
		OldConfig: oldConfigJSON, OldFiles: string(oldFilesJSON), NewConfig: string(newConfigJSON),
		DeadlineUnix: deadline.Unix(),
	})
	if err != nil {
		return PendingChangeView{}, fmt.Errorf("registrar mudança pendente: %w", err)
	}
	return PendingChangeView{Interface: edit.Name, DeadlineUnix: deadline.Unix()}, nil
}

// Confirm accepts a pending change: it becomes the interface's managed
// config permanently, and the pending record is cleared.
func (s *Service) Confirm(ctx context.Context, name string) error {
	pending, err := s.db.GetPendingInterfaceChange(name)
	if err != nil {
		return err
	}
	if pending == nil {
		return fmt.Errorf("nenhuma mudança pendente para %s", name)
	}
	var newConfig storage.ManagedInterface
	if err := json.Unmarshal([]byte(pending.NewConfig), &newConfig); err != nil {
		return fmt.Errorf("mudança pendente corrompida: %w", err)
	}
	if err := s.db.UpsertManagedInterface(newConfig); err != nil {
		return err
	}
	return s.db.DeletePendingInterfaceChange(name)
}

// Rollback immediately reverts a pending change (manual — the admin clicked
// "Reverter" instead of waiting out the deadline).
func (s *Service) Rollback(ctx context.Context, name string) error {
	pending, err := s.db.GetPendingInterfaceChange(name)
	if err != nil {
		return err
	}
	if pending == nil {
		return fmt.Errorf("nenhuma mudança pendente para %s", name)
	}
	if err := s.restorePendingFiles(ctx, *pending); err != nil {
		return err
	}
	return s.db.DeletePendingInterfaceChange(name)
}

// restorePendingFiles writes back the pre-change file contents recorded in a
// pending change and reloads networkd.
func (s *Service) restorePendingFiles(ctx context.Context, p storage.PendingInterfaceChange) error {
	var files []FileDiff
	if err := json.Unmarshal([]byte(p.OldFiles), &files); err != nil {
		return fmt.Errorf("snapshot de arquivos corrompido: %w", err)
	}
	for _, f := range files {
		if err := networkd.Apply(ctx, s.exec, networkd.ConfigFile{Path: f.Path, Content: f.OldContent}); err != nil {
			return fmt.Errorf("restaurar %s: %w", f.Path, err)
		}
	}
	return nil
}

// ListPending returns every in-flight unconfirmed change — polled by the frontend.
func (s *Service) ListPending(ctx context.Context) ([]PendingChangeView, error) {
	all, err := s.db.ListPendingInterfaceChanges()
	if err != nil {
		return nil, err
	}
	out := make([]PendingChangeView, 0, len(all))
	for _, p := range all {
		out = append(out, PendingChangeView{Interface: p.Interface, DeadlineUnix: p.DeadlineUnix})
	}
	return out, nil
}

// RunExpirySweep runs sweepExpiredOnce on a ticker until ctx is cancelled.
// Persisted state (not an in-process timer) is what makes the deadline
// survive a LinkGuard restart — see this plan's Global Constraints.
func (s *Service) RunExpirySweep(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepExpiredOnce(ctx)
		}
	}
}

func (s *Service) sweepExpiredOnce(ctx context.Context) {
	all, err := s.db.ListPendingInterfaceChanges()
	if err != nil {
		slog.Error("netif: falha ao listar mudanças pendentes", "err", err)
		return
	}
	now := time.Now().Unix()
	for _, p := range all {
		if p.DeadlineUnix > now {
			continue
		}
		slog.Warn("netif: revertendo mudança automaticamente (sem confirmação)", "interface", p.Interface)
		if err := s.restorePendingFiles(ctx, p); err != nil {
			slog.Error("netif: auto-rollback falhou", "interface", p.Interface, "err", err)
			if s.alertSvc != nil {
				_ = s.alertSvc.Create("interface_rollback_failed", "critical",
					"Reversão automática falhou",
					fmt.Sprintf("Interface %s: a reversão automática da configuração falhou (%v) — verifique manualmente.", p.Interface, err), "")
			}
			continue // não remove o registro pendente se a restauração falhou — não perder o rastro
		}
		if err := s.db.DeletePendingInterfaceChange(p.Interface); err != nil {
			slog.Error("netif: falha ao limpar mudança pendente revertida", "interface", p.Interface, "err", err)
		}
		if s.alertSvc != nil {
			_ = s.alertSvc.Create("interface_rollback", "warning",
				"Configuração de interface revertida automaticamente",
				fmt.Sprintf("Interface %s: a mudança aplicada não foi confirmada em %d segundos e foi revertida.", p.Interface, int(rollbackDeadline.Seconds())), "")
		}
	}
}
