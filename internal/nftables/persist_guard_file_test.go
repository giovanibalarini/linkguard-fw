package nftables

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A metade que faltava da guarda da janela de confirmação (SetPersistGuard,
// I-1 da revisão final da Fase C2).
//
// persist_state_test.go já afirma que a guarda não vira FALHA em PersistState
// — isto é, o que o painel e o vigia contam ao operador. Nenhum teste afirmava
// o que a guarda existe para fazer: que o ARQUIVO DE BOOT não é escrito. Um
// Persist que gravasse o arquivo e só deixasse de registrar a tentativa
// passaria por toda a suíte anterior, e o efeito na máquina é o inteiro
// cenário do doc-comment de SetPersistGuard — o /etc/nftables.conf com a regra
// de escopo input ainda não confirmada, o nftables.service carregando esse
// arquivo antes de o LinkGuard subir, e o operador sem SSH e sem painel numa
// máquina remota depois de uma queda de energia dentro dos 90 segundos.
//
// Todos escrevem em t.TempDir() via SetConfPath: ver o TestMain deste pacote e
// o doc-comment do campo confPath para por que isso não é zelo excessivo.

// bootFileFixture grava o arquivo de boot uma vez, com a máquina saudável, e
// devolve o caminho, o conteúdo e o executor — o "antes" contra o qual as
// passadas bloqueadas são comparadas.
func bootFileFixture(t *testing.T) (*Service, *recordExec, string, []byte) {
	t.Helper()
	exec := &recordExec{tableOut: "table inet linkguard {\n\tchain input {\n\t\tct state related counter accept\n\t}\n}\n"}
	s := NewService(exec)
	path := filepath.Join(t.TempDir(), "nftables.conf")
	s.SetConfPath(path)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("pré-condição: a primeira gravação tinha que dar certo: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler o arquivo de boot recém-gravado: %v", err)
	}
	// mtime para trás, para que uma regravação com conteúdo IGUAL também
	// apareça: o que a guarda promete é não escrever, não escrever a mesma
	// coisa.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("ajustar o mtime do arquivo de boot: %v", err)
	}
	return s, exec, path, before
}

// TestPersistDoesNotRewriteTheBootFileWhileAChangeIsUnconfirmed: com a janela
// aberta, o arquivo de boot fica EXATAMENTE como estava — mesmo conteúdo,
// mesmo mtime — enquanto o ruleset vivo já é outro.
//
// É essa diferença que a Fase C2 quer: o kernel com a regra nova (para o
// operador poder testá-la) e o arquivo de boot com o firewall de antes dela
// (para a máquina voltar acessível se a energia cair no meio do teste).
func TestPersistDoesNotRewriteTheBootFileWhileAChangeIsUnconfirmed(t *testing.T) {
	s, exec, path, before := bootFileFixture(t)
	stBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat do arquivo de boot: %v", err)
	}

	// O ruleset vivo passa a ter a regra que pode trancar o operador.
	exec.tableOut = "table inet linkguard {\n\tchain input {\n\t\tct state related counter accept\n\t\ttcp dport 22 counter drop\n\t}\n}\n"
	s.SetPersistGuard(func() (bool, error) { return true, nil })

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("com a janela aberta o Persist devolve nil (não é falha, é a decisão de não gravar): %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler o arquivo de boot depois da passada bloqueada: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("o arquivo de boot foi REESCRITO com uma mudança aguardando confirmação.\nantes:\n%s\ndepois:\n%s", before, after)
	}
	if strings.Contains(string(after), "tcp dport 22 counter drop") {
		t.Errorf("a regra não confirmada chegou ao arquivo que o nftables.service carrega no boot:\n%s", after)
	}
	stAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat do arquivo de boot depois da passada bloqueada: %v", err)
	}
	if !stAfter.ModTime().Equal(stBefore.ModTime()) {
		t.Errorf("o arquivo foi regravado (mtime %v → %v) ainda que com o mesmo conteúdo: a guarda tem que parar ANTES da escrita, não gravar de novo por cima",
			stBefore.ModTime(), stAfter.ModTime())
	}
}

// TestPersistBlockedDoesNotEvenReadTheLiveRuleset amarra ONDE a guarda para:
// antes do `nft list table`, e não depois de já ter o dump na mão.
//
// Não é detalhe de implementação — é o que garante que a passada bloqueada não
// tem nenhum caminho para o arquivo. Com a guarda consultada só na hora da
// escrita, qualquer `return` novo no meio (ou um os.WriteFile acrescentado
// para um arquivo auxiliar) voltaria a levar o ruleset não confirmado para o
// disco sem que nenhum outro teste percebesse.
func TestPersistBlockedDoesNotEvenReadTheLiveRuleset(t *testing.T) {
	s, exec, _, _ := bootFileFixture(t)
	exec.calls = nil
	s.SetPersistGuard(func() (bool, error) { return true, nil })

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist com a janela aberta: %v", err)
	}
	for _, c := range exec.calls {
		if strings.Contains(c, "list table") {
			t.Errorf("a passada bloqueada não pode nem LER o ruleset vivo (%q): a guarda tem que parar antes de haver qualquer dump a caminho do arquivo de boot", c)
		}
	}
}

// TestPersistDoesNotCREATETheBootFileWhileAChangeIsUnconfirmed é o outro
// estado da máquina, e ele não é hipotético: o /etc/nftables.conf é conffile
// do pacote `nftables` e a validação em VM já mediu a máquina com ele AUSENTE
// (§10). Numa máquina assim, a janela aberta não pode ser a ocasião em que o
// arquivo nasce — nascer com a regra não confirmada dentro é o mesmo desastre,
// só que a partir do nada.
func TestPersistDoesNotCREATETheBootFileWhileAChangeIsUnconfirmed(t *testing.T) {
	exec := &recordExec{tableOut: "table inet linkguard {\n\tchain input {\n\t\ttcp dport 22 counter drop\n\t}\n}\n"}
	s := NewService(exec)
	path := filepath.Join(t.TempDir(), "nftables.conf")
	s.SetConfPath(path)
	s.SetPersistGuard(func() (bool, error) { return true, nil })

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist com a janela aberta: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		body, _ := os.ReadFile(path) //nolint:errcheck // só para a mensagem
		t.Errorf("o arquivo de boot foi CRIADO durante a janela de confirmação (stat: %v), com:\n%s", err, body)
	}
}

// TestPersistGuardErrorLeavesTheBootFileIntact: não conseguir PROVAR que a
// janela está fechada tem o mesmo efeito de ela estar aberta. Quem não sabe
// não grava — congelar no arquivo de boot uma regra possivelmente não
// confirmada por otimismo é exatamente o que a guarda existe para impedir.
func TestPersistGuardErrorLeavesTheBootFileIntact(t *testing.T) {
	s, exec, path, before := bootFileFixture(t)
	exec.tableOut = "table inet linkguard {\n\tchain input {\n\t\ttcp dport 22 counter drop\n\t}\n}\n"
	s.SetPersistGuard(func() (bool, error) { return false, errors.New("banco travado") })

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist com a guarda em erro devolve nil: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler o arquivo de boot: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("com a guarda em ERRO o arquivo de boot não pode mudar.\nantes:\n%s\ndepois:\n%s", before, after)
	}
}

// TestPersistWritesTheBootFileOnceTheWindowCloses fecha o par: a guarda
// PROTEGE, não congela para sempre. Fechada a janela (confirmada ou
// revertida), a passada seguinte grava o ruleset vivo — inclusive a regra que
// acabou de ser confirmada.
//
// Sem esta metade, uma guarda que respondesse "pendente" para sempre passaria
// nos testes acima e deixaria a máquina com um arquivo de boot eternamente
// desatualizado — falha silenciosa da mesma família, só que na direção
// oposta.
func TestPersistWritesTheBootFileOnceTheWindowCloses(t *testing.T) {
	s, exec, path, before := bootFileFixture(t)
	confirmed := "table inet linkguard {\n\tchain input {\n\t\tct state related counter accept\n\t\ttcp dport 2222 counter accept\n\t}\n}\n"
	exec.tableOut = confirmed

	pending := true
	s.SetPersistGuard(func() (bool, error) { return pending, nil })
	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist com a janela aberta: %v", err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != string(before) {
		t.Fatalf("pré-condição: com a janela aberta o arquivo tinha que continuar igual (err %v):\n%s", err, body)
	}

	pending = false
	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist com a janela fechada: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler o arquivo de boot: %v", err)
	}
	if !strings.Contains(string(after), "tcp dport 2222 counter accept") {
		t.Errorf("fechada a janela, o arquivo de boot tem que voltar a descrever o firewall vivo, veio:\n%s", after)
	}
}
