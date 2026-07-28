package networkd

import (
	"context"
	"fmt"
	"os"
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

func TestApplyWritesFileAtomicallyAndReloads(t *testing.T) {
	dir := t.TempDir()
	f := ConfigFile{Path: dir + "/10-eth0.network", Content: "# managed by linkguard\n\n[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"}
	exec := &fakeApplyExec{}

	if err := Apply(context.Background(), exec, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatalf("arquivo não foi escrito: %v", err)
	}
	if string(got) != f.Content {
		t.Errorf("conteúdo escrito errado:\ngot:  %q\nwant: %q", got, f.Content)
	}

	if len(exec.reloadCalls) != 1 {
		t.Fatalf("esperava 1 chamada de reload, veio %d: %+v", len(exec.reloadCalls), exec.reloadCalls)
	}

	// Confirma que não sobrou nenhum arquivo temporário no diretório.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("esperava só o arquivo final no diretório, achei %d entradas: %+v", len(entries), entries)
	}
}

func TestApplySkipsWriteInDryRun(t *testing.T) {
	dir := t.TempDir()
	f := ConfigFile{Path: dir + "/10-eth0.network", Content: "conteudo"}
	exec := &fakeApplyExec{dryRun: true}

	if err := Apply(context.Background(), exec, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
		t.Error("em dry-run o arquivo não deveria ter sido escrito")
	}
	if len(exec.reloadCalls) != 0 {
		t.Errorf("em dry-run não deveria chamar reload, chamou %d vezes", len(exec.reloadCalls))
	}
}

type fakeApplyExec struct {
	dryRun      bool
	reloadCalls []string
}

func (e *fakeApplyExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "networkctl" {
		e.reloadCalls = append(e.reloadCalls, strings.Join(args, " "))
		return "", nil
	}
	return "", fmt.Errorf("comando de escrita inesperado no teste: %s", cmd)
}
func (e *fakeApplyExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	return "", fmt.Errorf("comando de leitura inesperado no teste: %s", cmd)
}
func (e *fakeApplyExec) IsDryRun() bool { return e.dryRun }
