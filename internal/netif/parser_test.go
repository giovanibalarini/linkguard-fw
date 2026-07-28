package netif

import "testing"

// Real sample captured from `ip -d -j link show` (trimmed to 6 representative
// interfaces: loopback, a down physical NIC, an up physical NIC, a
// docker-managed bridge — the "br-<hex>" noise case — a second
// docker-managed bridge, and a veth that is a member of that second bridge —
// the real bridge-membership (master) case).
const sampleLinkJSON = `[
{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00"},
{"ifindex":2,"ifname":"enp0s31f6","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"8c:04:ba:1a:1f:34"},
{"ifindex":3,"ifname":"wlp2s0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"f4:8c:50:1b:c3:b2"},
{"ifindex":11,"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"16:9e:0e:d5:f5:55","linkinfo":{"info_kind":"bridge","info_data":{"stp_state":0}}},
{"ifindex":2061,"ifname":"br-0e84d61d9869","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"02:42:8a:1c:9e:77","linkinfo":{"info_kind":"bridge","info_data":{"stp_state":0}}},
{"ifindex":2062,"ifname":"veth593fc8d","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"master":"br-0e84d61d9869","operstate":"UP","link_type":"ether","address":"ba:34:6a:67:14:ed"}
]`

// Real sample captured from `ip -j addr show`, same 6 interfaces. wlp2s0 has
// a DHCP-assigned IPv4 (dynamic:true) plus IPv6 addresses; the others have no
// addr_info entries (enp0s31f6 is a down physical NIC with nothing
// configured; veth593fc8d is a docker bridge member with no address of its
// own; docker0/lo/br-0e84d61d9869 omitted from this trimmed sample for
// brevity since their addressing isn't exercised by this test).
const sampleAddrJSON = `[
{"ifindex":2,"ifname":"enp0s31f6","addr_info":[]},
{"ifindex":3,"ifname":"wlp2s0","addr_info":[{"family":"inet","local":"192.168.3.61","prefixlen":24,"scope":"global","dynamic":true},{"family":"inet6","local":"fd41:4da5:216d:9457:1039:fad7:8cb:1996","prefixlen":64,"scope":"global","temporary":true,"dynamic":true}]},
{"ifindex":2062,"ifname":"veth593fc8d","addr_info":[]}
]`

func TestParseLinks(t *testing.T) {
	links, err := parseLinks(sampleLinkJSON)
	if err != nil {
		t.Fatalf("parseLinks: %v", err)
	}
	if len(links) != 6 {
		t.Fatalf("expected 6 links, got %d", len(links))
	}

	byName := make(map[string]parsedLink, len(links))
	for _, l := range links {
		byName[l.Name] = l
	}

	if lo := byName["lo"]; lo.Kind != KindPhysical {
		t.Errorf("lo: expected KindPhysical (no linkinfo.info_kind), got %v", lo.Kind)
	}
	if wl := byName["wlp2s0"]; !wl.Carrier {
		t.Errorf("wlp2s0: expected carrier=true (LOWER_UP flag present), got false")
	}
	if en := byName["enp0s31f6"]; en.Carrier {
		t.Errorf("enp0s31f6: expected carrier=false (NO-CARRIER flag), got true")
	}
	if dk := byName["docker0"]; dk.Kind != KindBridge {
		t.Errorf("docker0: expected KindBridge (linkinfo.info_kind=bridge), got %v", dk.Kind)
	}
}

func TestParseAddrs(t *testing.T) {
	addrs, err := parseAddrs(sampleAddrJSON)
	if err != nil {
		t.Fatalf("parseAddrs: %v", err)
	}
	wl := addrs["wlp2s0"]
	if len(wl) != 2 {
		t.Fatalf("wlp2s0: expected 2 addresses, got %d: %+v", len(wl), wl)
	}
	var sawDynamicIPv4 bool
	for _, a := range wl {
		if a.Family == "inet" && a.Dynamic {
			sawDynamicIPv4 = true
		}
	}
	if !sawDynamicIPv4 {
		t.Error("wlp2s0: expected a dynamic (DHCP) IPv4 address_info entry")
	}
	if len(addrs["enp0s31f6"]) != 0 {
		t.Errorf("enp0s31f6: expected no addresses, got %+v", addrs["enp0s31f6"])
	}
}

func TestMergeLinksDerivesAddrModeAndSystemFlag(t *testing.T) {
	links, err := parseLinks(sampleLinkJSON)
	if err != nil {
		t.Fatalf("parseLinks: %v", err)
	}
	addrs, err := parseAddrs(sampleAddrJSON)
	if err != nil {
		t.Fatalf("parseAddrs: %v", err)
	}
	views := mergeLinks(links, addrs)

	byName := make(map[string]IfaceView, len(views))
	for _, v := range views {
		byName[v.Name] = v
	}

	if wl := byName["wlp2s0"]; wl.AddrMode != AddrModeDHCP {
		t.Errorf("wlp2s0: expected AddrModeDHCP (dynamic:true address), got %v", wl.AddrMode)
	}
	if en := byName["enp0s31f6"]; en.AddrMode != AddrModeNone {
		t.Errorf("enp0s31f6: expected AddrModeNone (no addresses), got %v", en.AddrMode)
	}
	if dk := byName["docker0"]; !dk.Live.System {
		t.Error("docker0: expected Live.System=true")
	}
	if wl := byName["wlp2s0"]; wl.Live.System {
		t.Error("wlp2s0: expected Live.System=false")
	}

	br := byName["br-0e84d61d9869"]
	var sawVethMember bool
	for _, m := range br.Members {
		if m == "veth593fc8d" {
			sawVethMember = true
		}
	}
	if !sawVethMember {
		t.Errorf("br-0e84d61d9869: expected Members to contain %q, got %+v", "veth593fc8d", br.Members)
	}
	if vt := byName["veth593fc8d"]; !vt.Live.System {
		t.Error("veth593fc8d: expected Live.System=true (veth prefix)")
	}

	if len(views) != 6 {
		t.Fatalf("expected 6 views, got %d", len(views))
	}
}
