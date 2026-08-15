package keaunbound

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
)

// O dry-run vazava: cada os.WriteFile espalhado pelo pacote precisava lembrar
// de um `if !exec.IsDryRun()` à volta, e o EnsureResolvConf não lembrava em
// NENHUMA das suas duas escritas. Em `--dry-run` numa máquina de verdade, ele
// reescrevia o /etc/resolv.conf e o dhclient.conf.
//
// Com WriteFile no Executor, quem decide é o tipo. Este teste aponta o serviço
// para arquivos que EXISTEM com conteúdo conhecido e exige que continuem
// intactos — presença de arquivo não bastaria, porque o defeito era sobrescrever.
func TestDryRunTouchesNoFileOnDisk(t *testing.T) {
	dir := t.TempDir()
	// Embute o DryRunExecutor de verdade (é dele a semântica de WriteFile que
	// está sendo testada) e só finge o `systemctl is-enabled unbound`.
	//
	// Sem isso o teste passava sem exercitar nada: o ExecuteRead do dry-run roda
	// o comando de verdade, aqui a unidade não está habilitada, e o
	// EnsureResolvConf saía cedo — justamente o caminho que vazava.
	exec := &dryRunUnboundEnabled{DryRunExecutor: firewall.NewDryRunExecutor()}
	s := NewService(exec)

	const sentinela = "NAO PODE SER SOBRESCRITO\n"
	paths := map[string]string{}
	for _, name := range []string{"resolv.conf", "dhclient.conf", "kea-dhcp4.conf", "unbound.conf", "unbound-applied.conf"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(sentinela), 0o644); err != nil {
			t.Fatalf("preparar %s: %v", name, err)
		}
		paths[name] = p
	}
	s.resolvConf = paths["resolv.conf"]
	s.dhclientConf = paths["dhclient.conf"]
	s.keaConf = paths["kea-dhcp4.conf"]
	s.unboundConf = paths["unbound.conf"]
	s.unboundApplied = paths["unbound-applied.conf"]

	ctx := context.Background()
	s.EnsureResolvConf(ctx)
	_, _ = s.Apply(ctx, netsvc.Config{}, nil, nil)

	for name, p := range paths {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s sumiu: %v", name, err)
			continue
		}
		if string(got) != sentinela {
			t.Errorf("%s foi ESCRITO em dry-run — o vazamento continua:\n%s", name, got)
		}
	}

	if len(exec.Writes) < 4 {
		t.Errorf("esperava as escritas de resolv.conf, dhclient.conf, kea e unbound; vieram %d: %v", len(exec.Writes), exec.Writes)
	}
	if len(exec.Writes) == 0 {
		t.Error("o executor de dry-run não registrou nenhuma escrita; o teste não exercitou o caminho de gravação")
	} else {
		t.Logf("escritas registradas (e não executadas): %v", exec.Writes)
	}
}

// dryRunUnboundEnabled é o DryRunExecutor real com uma única resposta trocada.
type dryRunUnboundEnabled struct {
	*firewall.DryRunExecutor
}

func (e *dryRunUnboundEnabled) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "systemctl" && len(args) >= 2 && args[0] == "is-enabled" {
		return "enabled\n", nil
	}
	return "", nil
}
