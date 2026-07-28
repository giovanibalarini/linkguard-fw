// Package netif models network interfaces (physical, VLAN, bridge) as
// first-class entities. Phase 1 is read-only: the model is derived live from
// kernel state via `ip -j`, never written back. Applying configuration
// (systemd-networkd) is a later phase — see
// docs/superpowers/specs/2026-07-19-network-interface-management-design.md.
package netif

import "strings"

// Kind identifies what an interface is.
type Kind string

const (
	KindPhysical Kind = "physical"
	KindVLAN     Kind = "vlan"
	KindBridge   Kind = "bridge"
)

// AddrMode describes how an interface gets its IPv4 address.
type AddrMode string

const (
	AddrModeStatic AddrMode = "static"
	AddrModeDHCP   AddrMode = "dhcp"
	AddrModeNone   AddrMode = "none"
)

// Role is a display label, not behavior — the real WAN/LAN designation comes
// from links.Link (WAN) and netsvc.Config (LAN), which this package's
// Service cross-references. Never treated as authoritative on its own.
type Role string

const (
	RoleWAN        Role = "wan"
	RoleLAN        Role = "lan"
	RoleUnassigned Role = "unassigned"
)

// Address is one IP address observed live on an interface.
type Address struct {
	Family string `json:"family"` // "ipv4" | "ipv6"
	IP     string `json:"ip"`
	CIDR   string `json:"cidr"`
}

// Iface is one network interface. Name is the stable identifier — the same
// string internal/links.Link.Interface and DHCP config already reference.
// This is the core model that will eventually be persisted (Phase 2+);
// Managed is always false in Phase 1 (nothing is adopted yet).
type Iface struct {
	Name        string   `json:"name"`
	Kind        Kind     `json:"kind"`
	Alias       string   `json:"alias,omitempty"`
	Description string   `json:"description,omitempty"`
	Parent      string   `json:"parent,omitempty"`  // vlan: parent NIC name
	VLANID      int      `json:"vlan_id,omitempty"` // vlan: 1-4094
	Members     []string `json:"members,omitempty"` // bridge: member interface names
	AddrMode    AddrMode `json:"addr_mode"`
	Role        Role     `json:"role"`
	Managed     bool     `json:"managed"`
}

// LiveState is diagnostic data read fresh from the kernel on every request —
// deliberately never persisted alongside Iface (spec §9.1).
type LiveState struct {
	Carrier   bool      `json:"carrier"`
	Speed     string    `json:"speed,omitempty"` // e.g. "1000M full"; empty if down or not physical
	MAC       string    `json:"mac,omitempty"`
	MTU       int       `json:"mtu,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
	RxErrors  uint64    `json:"rx_errors"`
	TxErrors  uint64    `json:"tx_errors"`
	RxDropped uint64    `json:"rx_dropped"`
	TxDropped uint64    `json:"tx_dropped"`
	System    bool      `json:"system"` // classified as noise (docker/veth/tun/etc) — hidden by default
}

// IfaceView is the model + live state combined — the shape the API returns.
type IfaceView struct {
	Iface
	Live LiveState `json:"live"`
}

// systemPrefixes are interface name prefixes that mark "system noise" —
// spec §7.1. lo is an exact match, the rest are prefixes.
var systemPrefixes = []string{"docker", "br-", "veth", "tun", "tap", "wg"}

// isSystemInterface reports whether name is system/infrastructure noise that
// should be grouped and hidden by default, rather than a network interface an
// admin manages. Deliberately conservative: "br-<hex>" (docker's
// auto-generated bridge names) is noise, but "br10" (an admin-named LAN
// bridge) is not — the distinction is the literal "br-" prefix, not "br"
// alone.
func isSystemInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range systemPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
