package networkd

import (
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netif"
)

func TestRenderStaticAddressing(t *testing.T) {
	f := Render(netif.Iface{
		Name: "eth0", Kind: netif.KindPhysical, AddrMode: netif.AddrModeStatic,
		CIDR: "192.168.3.3/24", Gateway: "192.168.3.1",
	}, "")
	if f.Path != "/etc/systemd/network/10-eth0.network" {
		t.Errorf("path errado: %q", f.Path)
	}
	want := "# managed by linkguard\n\n[Match]\nName=eth0\n\n[Network]\nAddress=192.168.3.3/24\nGateway=192.168.3.1\n"
	if f.Content != want {
		t.Errorf("conteúdo errado:\n--- got ---\n%s\n--- want ---\n%s", f.Content, want)
	}
}

func TestRenderStaticNoGateway(t *testing.T) {
	f := Render(netif.Iface{Name: "eth2", Kind: netif.KindPhysical, AddrMode: netif.AddrModeStatic, CIDR: "10.0.0.2/24"}, "")
	if strings.Contains(f.Content, "Gateway=") {
		t.Errorf("não deveria ter linha Gateway= quando Gateway está vazio:\n%s", f.Content)
	}
	if !strings.Contains(f.Content, "Address=10.0.0.2/24") {
		t.Errorf("esperava Address=10.0.0.2/24:\n%s", f.Content)
	}
}

func TestRenderDHCP(t *testing.T) {
	f := Render(netif.Iface{Name: "eth1", Kind: netif.KindPhysical, AddrMode: netif.AddrModeDHCP}, "")
	want := "# managed by linkguard\n\n[Match]\nName=eth1\n\n[Network]\nDHCP=yes\n"
	if f.Content != want {
		t.Errorf("conteúdo errado:\n--- got ---\n%s\n--- want ---\n%s", f.Content, want)
	}
}

func TestRenderNone(t *testing.T) {
	f := Render(netif.Iface{Name: "eth3", Kind: netif.KindPhysical, AddrMode: netif.AddrModeNone}, "")
	want := "# managed by linkguard\n\n[Match]\nName=eth3\n\n[Network]\n"
	if f.Content != want {
		t.Errorf("conteúdo errado:\n--- got ---\n%s\n--- want ---\n%s", f.Content, want)
	}
}

func TestRenderPathUsesPrefix10ForPhysical(t *testing.T) {
	f := Render(netif.Iface{Name: "wlp2s0", Kind: netif.KindPhysical, AddrMode: netif.AddrModeDHCP}, "")
	if f.Path != "/etc/systemd/network/10-wlp2s0.network" {
		t.Errorf("path errado: %q", f.Path)
	}
}

func TestRenderRespectsDirOverride(t *testing.T) {
	f := Render(netif.Iface{Name: "eth0", Kind: netif.KindPhysical, AddrMode: netif.AddrModeDHCP}, "/tmp/some-test-dir")
	if f.Path != "/tmp/some-test-dir/10-eth0.network" {
		t.Errorf("path errado: %q", f.Path)
	}
}
