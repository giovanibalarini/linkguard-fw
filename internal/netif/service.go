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
