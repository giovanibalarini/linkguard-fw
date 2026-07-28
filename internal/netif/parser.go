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
