package firewallrules

// I-3 da revisão final da Fase C2, do lado de quem LÊ o banco.
//
// Reconcile lê os grupos e só então manda reconstruir as chains. Enquanto as
// duas metades não estavam sob o mesmo lock, uma passada que tivesse lido o
// banco ANTES de uma reversão podia escrever DEPOIS dela — devolvendo ao kernel
// exatamente o `jump` que a reversão tirou, com o pendente já apagado (o
// watchdog viu o Reconcile dele devolver nil) e o painel dizendo que reverteu.
//
// O teste prende uma passada no meio da reescrita, solta outra em cima dela e
// muda o banco enquanto a segunda espera. A pergunta que ele faz é a única que
// importa: a chain forward VIVA, no fim de tudo, é a do banco de agora ou a de
// um banco que já não existe?

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// holdExec grava os comandos (com mutex: há duas goroutines de verdade) e
// prende a PRIMEIRA passada no meio da reescrita da chain forward.
type holdExec struct {
	mu  sync.Mutex
	log []string

	holdOn  string
	held    chan struct{}
	release chan struct{}
	once    sync.Once
}

func (e *holdExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	line := cmd + " " + strings.Join(args, " ")
	e.mu.Lock()
	e.log = append(e.log, line)
	e.mu.Unlock()
	if strings.Contains(line, e.holdOn) {
		e.once.Do(func() {
			close(e.held)
			<-e.release
		})
	}
	return "", nil
}

func (e *holdExec) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return "table inet linkguard {\n}\n", nil
}

func (e *holdExec) IsDryRun() bool { return false }

func (e *holdExec) lines() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.log...)
}

// liveForward reconstrói a chain forward VIVA a partir dos comandos: o que
// vale é o que veio depois do último `flush chain … forward`.
func liveForward(lines []string) []string {
	prefix := "nft flush chain " + nftables.Family + " " + nftables.Table + " " + nftables.ForwardChain
	last := -1
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			last = i
		}
	}
	var out []string
	addPrefix := "nft add rule " + nftables.Family + " " + nftables.Table + " " + nftables.ForwardChain + " "
	for _, l := range lines[last+1:] {
		if strings.HasPrefix(l, addPrefix) {
			out = append(out, strings.TrimPrefix(l, addPrefix))
		}
	}
	return out
}

func TestAReconcileInFlightNeverAppliesADatabaseThatChangedUnderIt(t *testing.T) {
	db := newTestDB(t)
	exec := &holdExec{
		holdOn:  "flush chain " + nftables.Family + " " + nftables.Table + " " + nftables.ForwardChain,
		held:    make(chan struct{}),
		release: make(chan struct{}),
	}
	nft := nftables.NewService(exec)
	nft.SetConfPath(filepath.Join(t.TempDir(), "nftables.conf"))
	nft.SetInputChainSources(
		func() ([]nftables.StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, nil },
	)
	svc := NewService(db, nft)
	if err := svc.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("criar os grupos do sistema: %v", err)
	}

	doomed := storage.FirewallGroup{
		ID:          "gdoomed",
		Name:        "Sai no meio",
		ChainName:   nftables.GroupChainName("gdoomed"),
		Position:    9,
		Enabled:     true,
		Fallthrough: nftables.FallthroughContinue,
		Kind:        nftables.GroupKindAdmin,
	}
	if err := db.CreateFirewallGroup(&doomed); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := svc.Reconcile(context.Background()); err != nil {
			t.Errorf("primeira passada: %v", err)
		}
	}()

	select {
	case <-exec.held:
	case <-time.After(5 * time.Second):
		t.Fatal("a primeira passada nunca chegou a reescrever a chain forward")
	}

	// A segunda passada começa com a primeira presa. É a mutação de outro admin,
	// ou o boot: nenhuma das duas passa pela trava da janela de confirmação.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := svc.Reconcile(context.Background()); err != nil {
			t.Errorf("segunda passada: %v", err)
		}
	}()

	// Tempo de sobra para a segunda passada LER o banco, se ela puder ler antes
	// de ter a vez dela.
	time.Sleep(100 * time.Millisecond)

	// E agora o banco muda — é o que a reversão automática faz: restaura o estado
	// anterior, sem o grupo que a mudança tinha criado.
	if err := db.DeleteFirewallGroup(doomed.ID); err != nil {
		t.Fatalf("DeleteFirewallGroup: %v", err)
	}
	close(exec.release)
	wg.Wait()

	for _, expr := range liveForward(exec.lines()) {
		if strings.Contains(expr, doomed.ChainName) {
			t.Fatalf("a chain forward viva terminou com o jump de um grupo que já não está no banco (%s): uma passada que leu o banco antes da mudança escreveu depois dela.\nforward viva:\n%s",
				doomed.ChainName, strings.Join(liveForward(exec.lines()), "\n"))
		}
	}
}
