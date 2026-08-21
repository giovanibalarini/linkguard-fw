package system

import (
	"context"
	"os"
	"reflect"
	"testing"
)

type execSS struct{ saida string }

func (e execSS) Execute(context.Context, string, ...string) (string, error) { return "", nil }
func (e execSS) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "ss" {
		return e.saida, nil
	}
	return "", nil
}
func (e execSS) IsDryRun() bool                              { return false }
func (e execSS) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestSSHPortsLeOndeOSshdEscuta(t *testing.T) {
	// Saída real de `ss -lntpH` numa caixa Debian 13 com sshd dual-stack.
	const saida = `LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=820,fd=6))
LISTEN 0      4096               *:9997            *:*    users:(("linkguard-fw",pid=193352,fd=11))
LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=820,fd=7))
`
	if got := SSHPorts(context.Background(), execSS{saida}); !reflect.DeepEqual(got, []int{22}) {
		t.Errorf("dual-stack na mesma porta devia dar [22], deu %v", got)
	}
}

func TestSSHPortsNaoInventaAPadrao(t *testing.T) {
	// A ASSERÇÃO QUE JUSTIFICA A FUNÇÃO. Numa caixa com `Port 2222`, devolver
	// 22 faria a liberação de gerência descartar exatamente a porta por onde o
	// admin entra — a regra que existe para não trancar ninguém trancando.
	const saida = `LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*    users:(("sshd",pid=820,fd=6))
LISTEN 0      128          0.0.0.0:2200      0.0.0.0:*    users:(("sshd",pid=820,fd=8))
`
	got := SSHPorts(context.Background(), execSS{saida})
	if !reflect.DeepEqual(got, []int{2200, 2222}) {
		t.Errorf("as duas portas do sshd deviam sair ordenadas, veio %v", got)
	}
	for _, p := range got {
		if p == 22 {
			t.Error("22 apareceu numa caixa que não usa 22")
		}
	}
}

func TestSSHPortsNaoChutaQuandoNaoSabe(t *testing.T) {
	// Vazio é "não sei", e quem chama decide. Chutar 22 aqui dentro
	// transformaria "não sei" em "é a padrão", que é a confusão que esta função
	// existe para desfazer — o padrão é aplicado uma camada acima, explícito.
	if got := SSHPorts(context.Background(), execSS{""}); len(got) != 0 {
		t.Errorf("sem saída do ss devia devolver vazio, veio %v", got)
	}
	semSSH := `LISTEN 0 4096 *:9997 *:* users:(("linkguard-fw",pid=1,fd=11))`
	if got := SSHPorts(context.Background(), execSS{semSSH}); len(got) != 0 {
		t.Errorf("sem sshd na lista devia devolver vazio, veio %v", got)
	}
}
