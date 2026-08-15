package networkd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRenderStaticAddressing(t *testing.T) {
	f := Render(IfaceSpec{
		Name: "eth0", AddrMode: "static",
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
	f := Render(IfaceSpec{Name: "eth2", AddrMode: "static", CIDR: "10.0.0.2/24"}, "")
	if strings.Contains(f.Content, "Gateway=") {
		t.Errorf("não deveria ter linha Gateway= quando Gateway está vazio:\n%s", f.Content)
	}
	if !strings.Contains(f.Content, "Address=10.0.0.2/24") {
		t.Errorf("esperava Address=10.0.0.2/24:\n%s", f.Content)
	}
}

func TestRenderDHCP(t *testing.T) {
	f := Render(IfaceSpec{Name: "eth1", AddrMode: "dhcp"}, "")
	want := "# managed by linkguard\n\n[Match]\nName=eth1\n\n[Network]\nDHCP=yes\n"
	if f.Content != want {
		t.Errorf("conteúdo errado:\n--- got ---\n%s\n--- want ---\n%s", f.Content, want)
	}
}

func TestRenderNone(t *testing.T) {
	f := Render(IfaceSpec{Name: "eth3", AddrMode: "none"}, "")
	want := "# managed by linkguard\n\n[Match]\nName=eth3\n\n[Network]\n"
	if f.Content != want {
		t.Errorf("conteúdo errado:\n--- got ---\n%s\n--- want ---\n%s", f.Content, want)
	}
}

func TestRenderPathUsesPrefix10ForPhysical(t *testing.T) {
	f := Render(IfaceSpec{Name: "wlp2s0", AddrMode: "dhcp"}, "")
	if f.Path != "/etc/systemd/network/10-wlp2s0.network" {
		t.Errorf("path errado: %q", f.Path)
	}
}

func TestRenderRespectsDirOverride(t *testing.T) {
	f := Render(IfaceSpec{Name: "eth0", AddrMode: "dhcp"}, "/tmp/some-test-dir")
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
	if exec.reloadCalls[0] != "reload" {
		t.Errorf("esperava argumento \"reload\", veio %q", exec.reloadCalls[0])
	}

	info, err := os.Stat(f.Path)
	if err != nil {
		t.Fatalf("stat no arquivo final: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("esperava permissão 0644 no arquivo final, veio %v", info.Mode().Perm())
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

func TestRemoveDeletesFileAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/10-eth0.network"
	if err := os.WriteFile(path, []byte("# managed by linkguard\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	exec := &fakeApplyExec{}

	if err := Remove(context.Background(), exec, path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("esperava que o arquivo fosse removido")
	}
	if len(exec.reloadCalls) != 1 {
		t.Fatalf("esperava 1 chamada de reload, veio %d: %+v", len(exec.reloadCalls), exec.reloadCalls)
	}
}

func TestRemoveIsIdempotentWhenFileAlreadyMissing(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/10-eth0.network" // nunca escrito
	exec := &fakeApplyExec{}

	if err := Remove(context.Background(), exec, path); err != nil {
		t.Fatalf("Remove em arquivo inexistente deveria ser um no-op bem-sucedido, veio: %v", err)
	}
	if len(exec.reloadCalls) != 1 {
		t.Errorf("esperava reload mesmo quando o arquivo já não existia, veio %d chamadas", len(exec.reloadCalls))
	}
}

func TestApplyStillWritesFileButSkipsReloadWhenNetworkdInactive(t *testing.T) {
	dir := t.TempDir()
	f := ConfigFile{Path: dir + "/10-eth0.network", Content: "# managed by linkguard\n\n[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"}
	exec := &fakeApplyExec{networkdInactive: true}

	if err := Apply(context.Background(), exec, f); err != nil {
		t.Fatalf("Apply não deveria falhar num host com networkd inativo (ex.: produção em ifupdown), veio: %v", err)
	}
	got, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatalf("arquivo deveria ter sido escrito mesmo com networkd inativo: %v", err)
	}
	if string(got) != f.Content {
		t.Errorf("conteúdo escrito errado:\ngot:  %q\nwant: %q", got, f.Content)
	}
	if len(exec.reloadCalls) != 0 {
		t.Errorf("com networkd inativo não deveria chamar networkctl reload, chamou %d vezes", len(exec.reloadCalls))
	}
}

func TestApplyStillPropagatesRealReloadFailureWhenNetworkdActive(t *testing.T) {
	dir := t.TempDir()
	f := ConfigFile{Path: dir + "/10-eth0.network", Content: "conteudo"}
	exec := &fakeApplyExec{failReload: true}

	err := Apply(context.Background(), exec, f)
	if err == nil {
		t.Fatal("um reload que falha de verdade com networkd ativo ainda deve ser um erro real, não deveria ser tolerado")
	}
}

func TestRemoveSkipsReloadWhenNetworkdInactive(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/10-eth0.network"
	if err := os.WriteFile(path, []byte("# managed by linkguard\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	exec := &fakeApplyExec{networkdInactive: true}

	if err := Remove(context.Background(), exec, path); err != nil {
		t.Fatalf("Remove não deveria falhar num host com networkd inativo, veio: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("esperava que o arquivo fosse removido mesmo com networkd inativo")
	}
	if len(exec.reloadCalls) != 0 {
		t.Errorf("com networkd inativo não deveria chamar networkctl reload, chamou %d vezes", len(exec.reloadCalls))
	}
}

func TestIsActiveReflectsSystemctlIsActive(t *testing.T) {
	if !IsActive(context.Background(), &fakeApplyExec{}) {
		t.Error("esperava IsActive=true quando systemctl is-active retorna sucesso")
	}
	if IsActive(context.Background(), &fakeApplyExec{networkdInactive: true}) {
		t.Error("esperava IsActive=false quando systemctl is-active falha")
	}
}

func TestRemoveSkipsInDryRun(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/10-eth0.network"
	if err := os.WriteFile(path, []byte("conteudo"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	exec := &fakeApplyExec{dryRun: true}

	if err := Remove(context.Background(), exec, path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("em dry-run o arquivo não deveria ter sido removido")
	}
	if len(exec.reloadCalls) != 0 {
		t.Errorf("em dry-run não deveria chamar reload, chamou %d vezes", len(exec.reloadCalls))
	}
}

// fakeApplyExec defaults to a host where systemd-networkd is active
// (networkdInactive: false) — matching every pre-existing test's assumption
// that "reload" gets called. Set networkdInactive: true to simulate an
// ifupdown host, where `systemctl is-active systemd-networkd` fails and
// reload must be skipped instead of erroring (see TestApply/RemoveSkipsReloadWhenNetworkdInactive).
type fakeApplyExec struct {
	dryRun           bool
	networkdInactive bool
	failReload       bool
	reloadCalls      []string
}

func (e *fakeApplyExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "networkctl" {
		if e.failReload {
			return "", fmt.Errorf("simulated networkctl reload failure")
		}
		e.reloadCalls = append(e.reloadCalls, strings.Join(args, " "))
		return "", nil
	}
	return "", fmt.Errorf("comando de escrita inesperado no teste: %s", cmd)
}
func (e *fakeApplyExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "systemctl" && len(args) == 2 && args[0] == "is-active" && args[1] == "systemd-networkd" {
		if e.networkdInactive {
			return "", fmt.Errorf("inactive")
		}
		return "active\n", nil
	}
	return "", fmt.Errorf("comando de leitura inesperado no teste: %s", cmd)
}
func (e *fakeApplyExec) IsDryRun() bool                              { return e.dryRun }
func (_ *fakeApplyExec) WriteFile(string, []byte, os.FileMode) error { return nil }
