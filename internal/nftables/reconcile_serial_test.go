package nftables

// I-3 da revisão final da Fase C2 — duas reconciliações não podem se atropelar.
//
// `rebuildChain` é `flush chain` seguido de N × `add rule`: a chain fica VAZIA
// no meio do caminho, e nada disso é atômico no kernel. Enquanto ninguém
// serializava as passadas, duas delas podiam se intercalar — o caso caro é a
// reversão automática (que restaura o banco e reescreve as chains) contra uma
// mutação que a janela de confirmação deliberadamente NÃO trava, como o toggle
// de NTP: a segunda leu o estado antes da restauração e escreve depois dela,
// devolvendo ao kernel o `jump` que a reversão acabou de tirar. O watchdog, que
// viu o Reconcile dele devolver nil, já apagou o pendente — a regra perigosa
// fica viva sem janela, sem watchdog e com o painel dizendo que reverteu.
//
// O teste abaixo não tenta reproduzir a corrida por sorte: ele PRENDE uma
// passada no meio da reescrita e solta a outra em cima dela.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// passKey marca de qual passada é cada comando. É o que permite afirmar
// "nenhum comando da segunda saiu antes de a primeira terminar" sem depender
// do texto dos comandos, que as duas compartilham (as duas reescrevem a chain
// input, as duas emitem as regras do NTP).
type passKey struct{}

// serialExec registra os comandos com a etiqueta da passada e sabe PRENDER a
// primeira delas no meio da reescrita.
type serialExec struct {
	mu  sync.Mutex
	log []string

	holdOn  string        // o comando (substring) que prende a passada
	held    chan struct{} // fechado quando a passada foi presa
	release chan struct{} // fechado pelo teste para soltá-la
	once    sync.Once
}

func (e *serialExec) record(ctx context.Context, cmd string, args []string) {
	tag, _ := ctx.Value(passKey{}).(string)
	line := cmd + " " + strings.Join(args, " ")
	e.mu.Lock()
	e.log = append(e.log, tag+": "+line)
	e.mu.Unlock()
	if e.holdOn != "" && strings.Contains(line, e.holdOn) {
		e.once.Do(func() {
			close(e.held)
			<-e.release
		})
	}
}

func (e *serialExec) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	e.record(ctx, cmd, args)
	return "", nil
}

func (e *serialExec) ExecuteRead(ctx context.Context, cmd string, args ...string) (string, error) {
	e.record(ctx, cmd, args)
	return "", nil
}

func (e *serialExec) IsDryRun() bool { return false }

func (e *serialExec) lines() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.log...)
}

func TestAReconcileNeverInterleavesWithAnother(t *testing.T) {
	exec := &serialExec{
		holdOn:  "flush chain " + Family + " " + Table + " " + ForwardChain,
		held:    make(chan struct{}),
		release: make(chan struct{}),
	}
	svc := NewService(exec)
	svc.SetConfPath(t.TempDir() + "/nftables.conf")
	svc.SetInputChainSources(
		func() ([]StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return []string{"192.168.3.0/24"}, true, nil },
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.WithValue(context.Background(), passKey{}, "grupos")
		if err := svc.ReconcileGroups(ctx, []StoredGroup{{
			ID: "g1", Name: "Acesso", ChainName: "grp_aaaaaaaaaaaa", Enabled: true,
			CondSaddr: "192.168.3.0/24", Fallthrough: "continue", Scope: ScopeInput,
		}}); err != nil {
			t.Errorf("ReconcileGroups: %v", err)
		}
	}()

	select {
	case <-exec.held:
	case <-time.After(5 * time.Second):
		t.Fatal("a primeira passada nunca chegou a reescrever a chain forward")
	}

	// A segunda passada começa com a primeira PRESA no meio da reescrita. É o
	// toggle de NTP do outro admin, ou o boot reconciliando: nada disso é travado
	// pela janela de confirmação.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.WithValue(context.Background(), passKey{}, "ntp")
		if err := svc.ReconcileNTPInput(ctx, []string{"192.168.3.0/24"}, true); err != nil {
			t.Errorf("ReconcileNTPInput: %v", err)
		}
	}()

	// Tempo de sobra para a segunda passada emitir o que quer que ela emita antes
	// de a primeira terminar. Com o lock, ela não emite nada; sem ele, ela já
	// terminou a chain input inteira quando este prazo acaba.
	time.Sleep(100 * time.Millisecond)
	close(exec.release)
	wg.Wait()

	// A asserção: nenhum comando da segunda passada saiu antes do último da
	// primeira.
	lines := exec.lines()
	last := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "grupos: ") {
			last = i
		}
	}
	for i, l := range lines {
		if strings.HasPrefix(l, "ntp: ") && i < last {
			t.Fatalf("as duas reconciliações se intercalaram: o comando %q saiu no meio da reescrita da outra passada.\nsequência:\n%s",
				l, strings.Join(lines, "\n"))
		}
	}
}
