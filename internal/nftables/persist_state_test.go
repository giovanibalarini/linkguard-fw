package nftables

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A memória do Persist (§10 da validação em VM). Antes destes testes o
// resultado da gravação do arquivo de boot morria no `return err` de cada um
// dos cinco chamadores, que só o logavam em WARN — não havia NADA em memória
// para o apply status ou o vigia perguntarem, e por isso a falha era muda na
// tela enquanto as regras valiam no kernel e não sobreviveriam ao reboot.

// TestPersistStateStartsUnknown: antes da primeira gravação a resposta é
// "ainda não sei". Nunca "está tudo bem" — é essa distinção que impede o vigia
// de acender um item verde sobre um arquivo que ninguém tentou escrever.
func TestPersistStateStartsUnknown(t *testing.T) {
	s := NewService(&recordExec{})
	if st := s.PersistState(); st.Attempted {
		t.Errorf("um Service que nunca persistiu não pode dizer que tentou: %+v", st)
	}
}

// TestPersistStateRecordsSuccess: gravou, o estado diz que gravou.
func TestPersistStateRecordsSuccess(t *testing.T) {
	s := NewService(&recordExec{tableOut: "table inet linkguard {\n}\n"})
	s.SetConfPath(filepath.Join(t.TempDir(), "nftables.conf"))

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	st := s.PersistState()
	if !st.Attempted || !st.OK || st.Err != "" {
		t.Errorf("gravação bem-sucedida deveria virar {Attempted:true OK:true}, veio %+v", st)
	}
	if st.At == 0 {
		t.Error("a tentativa precisa carregar o instante em que aconteceu")
	}
}

// TestPersistStateRecordsWriteFailure é o caso medido na VM: /etc imutável,
// o arquivo de boot não existe e não pode ser criado. A gravação falha, as
// regras continuam valendo no kernel — e é isto que precisa sobrar em memória
// para o apply status e o vigia contarem ao operador.
func TestPersistStateRecordsWriteFailure(t *testing.T) {
	s := NewService(&recordExec{tableOut: "table inet linkguard {\n}\n"})
	// Um diretório que não existe reproduz o efeito do /etc imutável sem
	// precisar de root: o os.WriteFile falha e nada é gravado.
	s.SetConfPath(filepath.Join(t.TempDir(), "sem-esse-diretorio", "nftables.conf"))

	if err := s.Persist(context.Background()); err == nil {
		t.Fatal("Persist deveria devolver o erro da gravação")
	}
	st := s.PersistState()
	if !st.Attempted {
		t.Fatalf("a tentativa tem que ficar registrada: %+v", st)
	}
	if st.OK {
		t.Errorf("gravação que falhou não pode ficar como OK: %+v", st)
	}
	if st.Err == "" {
		t.Error("o motivo da falha tem que sobreviver — é ele que vai para a tela")
	}
}

// TestPersistStateRecordsListTableFailure: a recusa do `nft list table` tem a
// mesma consequência que a falha da gravação — o arquivo de boot fica com o
// conteúdo antigo (ou inexistente) enquanto o kernel tem outro.
func TestPersistStateRecordsListTableFailure(t *testing.T) {
	s := NewService(&recordExec{listTableErr: errors.New("nft: no such table")})
	s.SetConfPath(filepath.Join(t.TempDir(), "nftables.conf"))

	if err := s.Persist(context.Background()); err == nil {
		t.Fatal("Persist deveria propagar a recusa do nft")
	}
	if st := s.PersistState(); !st.Attempted || st.OK {
		t.Errorf("a recusa do nft é falha de persistência: %+v", st)
	}
}

// TestPersistStateClearsAfterRecovery: quando o arquivo volta a ser gravável,
// a próxima passada limpa o estado sozinha. É o que faz o item de saúde sumir
// sem ninguém precisar "resolver" nada à mão.
func TestPersistStateClearsAfterRecovery(t *testing.T) {
	dir := t.TempDir()
	s := NewService(&recordExec{tableOut: "table inet linkguard {\n}\n"})
	s.SetConfPath(filepath.Join(dir, "sem-esse-diretorio", "nftables.conf"))
	_ = s.Persist(context.Background())
	if st := s.PersistState(); st.OK {
		t.Fatalf("pré-condição: a primeira passada tinha que falhar, veio %+v", st)
	}

	s.SetConfPath(filepath.Join(dir, "nftables.conf"))
	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist depois da recuperação: %v", err)
	}
	st := s.PersistState()
	if !st.OK || st.Err != "" {
		t.Errorf("a gravação que deu certo tem que apagar a falha anterior: %+v", st)
	}
}

// TestPersistStateIgnoresDryRun: em dry-run nada neste binário toca no
// firewall, então não há nada a dizer sobre o arquivo de boot. Registrar uma
// tentativa aqui faria o vigia falar de um arquivo que ninguém ia escrever.
func TestPersistStateIgnoresDryRun(t *testing.T) {
	s := NewService(&recordExec{dryRun: true, tableOut: "table inet linkguard {\n}\n"})
	s.SetConfPath(filepath.Join(t.TempDir(), "nftables.conf"))

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist em dry-run: %v", err)
	}
	if st := s.PersistState(); st.Attempted {
		t.Errorf("dry-run não é tentativa de gravação: %+v", st)
	}
}

// TestPersistStateIgnoresTheConfirmationGuard é o teste que impede o falso
// positivo mais provável numa máquina SAUDÁVEL: toda mutação de escopo input
// abre a janela de 90 segundos, e durante ela o Persist decide — de propósito
// — não gravar. Se isso contasse como falha, o item de saúde acenderia
// vermelho em toda mudança correta de uma máquina que não tem problema nenhum,
// que é exatamente o alarme falso que este projeto acabou de corrigir em outro
// vigia.
func TestPersistStateIgnoresTheConfirmationGuard(t *testing.T) {
	dir := t.TempDir()
	s := NewService(&recordExec{tableOut: "table inet linkguard {\n}\n"})
	s.SetConfPath(filepath.Join(dir, "nftables.conf"))

	// Uma gravação boa antes, para provar que a guarda não DESFAZ o que já se
	// sabe — ela só não acrescenta nada.
	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist inicial: %v", err)
	}

	s.SetPersistGuard(func() (bool, error) { return true, nil })
	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist com a janela aberta deveria devolver nil: %v", err)
	}
	if st := s.PersistState(); !st.OK || st.Err != "" {
		t.Errorf("a janela de confirmação não é falha de persistência: %+v", st)
	}

	// E o mesmo para o erro da própria guarda: não gravar por não saber
	// também não é o arquivo de boot ter ficado para trás por falha de IO.
	s.SetPersistGuard(func() (bool, error) { return false, errors.New("banco travado") })
	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist com a guarda em erro deveria devolver nil: %v", err)
	}
	if st := s.PersistState(); !st.OK {
		t.Errorf("erro da guarda não é falha de gravação: %+v", st)
	}
}

// TestPersistPathIsWhatPersistWrites amarra o que o vigia vai stat'ar ao
// arquivo que o Persist realmente grava. Um caminho fixo do lado do vigia
// divergiria em silêncio de um Service redirecionado por SetConfPath.
func TestPersistPathIsWhatPersistWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nftables.conf")
	s := NewService(&recordExec{tableOut: "table inet linkguard {\n}\n"})
	s.SetConfPath(path)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if got := s.PersistPath(); got != path {
		t.Errorf("PersistPath = %q, queria %q", got, path)
	}
	if _, err := os.Stat(s.PersistPath()); err != nil {
		t.Errorf("PersistPath tem que apontar para o arquivo que o Persist gravou: %v", err)
	}
}
