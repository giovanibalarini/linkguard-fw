package firewallrules_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// O apply_status e o arquivo de boot (§10 da validação em VM).
//
// A mentira que estes testes fecham: com /etc imutável, o apply CHEGAVA ao
// kernel (as regras valiam e filtravam), o Persist falhava, e o painel
// respondia `apply_status: {"ok": true}`. O operador clicava em aplicar e o
// produto dizia que tinha dado tudo certo, enquanto a máquina voltaria de um
// reboot com um firewall diferente do que a tela mostrava.

// TestApplyStatusStaysOKWhenTheBootFileIsWritten é O teste do falso positivo
// deste lado: numa máquina saudável — Persist grava, arquivo no lugar — o
// apply_status continua `ok: true` e sem campo nenhum sobre o boot. Um aviso
// falso aqui seria pior que o silêncio de antes.
func TestApplyStatusStaysOKWhenTheBootFileIsWritten(t *testing.T) {
	db := newTestDB(t)
	nft := nftables.NewService(&fakeExec{})
	svc := newTestService(t, db, nft)

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	st := svc.LastApplyStatus()
	if st == nil {
		t.Fatal("esperava um apply status gravado")
	}
	if !st.OK {
		t.Errorf("máquina saudável tem que continuar ok: %+v", st)
	}
	if st.BootPersistError != "" {
		t.Errorf("nada podia ser dito sobre o arquivo de boot numa máquina que o gravou: %+v", st)
	}
}

// TestApplyStatusReportsTheBootFileNotWritten reproduz o §10: o apply chega ao
// kernel (nenhum comando do nft falha) e só a gravação do arquivo de boot não
// acontece. O status não pode dizer `ok: true`, e o motivo tem que estar em
// BootPersistError — não em Error, que é o campo que a faixa vermelha do painel
// lê como "o apply falhou".
func TestApplyStatusReportsTheBootFileNotWritten(t *testing.T) {
	db := newTestDB(t)
	nft := nftables.NewService(&fakeExec{})
	svc := newTestService(t, db, nft)
	// newTestService aponta o Persist para um t.TempDir(); um subdiretório que
	// não existe reproduz, sem root, o efeito do /etc imutável: os comandos do
	// nft passam, o os.WriteFile é o único que falha.
	nft.SetConfPath(filepath.Join(t.TempDir(), "sem-esse-diretorio", "nftables.conf"))

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("a falha de persistência não pode virar erro do Reconcile — as regras entraram no kernel: %v", err)
	}

	st := svc.LastApplyStatus()
	if st == nil {
		t.Fatal("esperava um apply status gravado")
	}
	if st.OK {
		t.Errorf("apply_status não pode dizer ok com o arquivo de boot para trás: %+v", st)
	}
	if st.BootPersistError == "" {
		t.Errorf("o motivo tem que chegar à resposta, não só ao journal: %+v", st)
	}
	if st.Error != "" {
		t.Errorf("isto não é falha do apply: Error preenchido faz a tela mandar o operador desfazer um trabalho que funcionou: %+v", st)
	}
}

// TestApplyStatusForgetsTheBootFailureAfterItIsWritten: a condição é contínua e
// se resolve sozinha. Assim que uma gravação dá certo, a próxima passada volta
// a dizer ok — sem ninguém apagar nada à mão.
func TestApplyStatusForgetsTheBootFailureAfterItIsWritten(t *testing.T) {
	db := newTestDB(t)
	dir := t.TempDir()
	nft := nftables.NewService(&fakeExec{})
	svc := newTestService(t, db, nft)
	nft.SetConfPath(filepath.Join(dir, "sem-esse-diretorio", "nftables.conf"))

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if st := svc.LastApplyStatus(); st.OK || st.BootPersistError == "" {
		t.Fatalf("pré-condição: a primeira passada tinha que registrar a falha de boot, veio %+v", st)
	}

	nft.SetConfPath(filepath.Join(dir, "nftables.conf"))
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile depois da recuperação: %v", err)
	}
	st := svc.LastApplyStatus()
	if !st.OK || st.BootPersistError != "" {
		t.Errorf("a gravação que deu certo tem que limpar o aviso: %+v", st)
	}
}

// TestApplyStatusKeepsBothProblemsApart: uma passada pode carregar os dois
// problemas ao mesmo tempo. Os dois campos têm que aparecer, cada um no seu —
// o painel desenha duas faixas com duas ações diferentes, e fundir as
// mensagens perderia uma delas.
//
// A montagem: a primeira passada falha só na gravação do arquivo de boot (as
// regras entram no kernel); a segunda aborta na LEITURA do banco, antes de
// tocar no nft. O arquivo de boot continua para trás nessa segunda passada —
// nada o gravou —, e é por isso que ele tem que continuar sendo relatado
// mesmo num caminho que nem chegou a chamar o Persist.
func TestApplyStatusKeepsBothProblemsApart(t *testing.T) {
	db := newTestDB(t)
	nft := nftables.NewService(&fakeExec{})
	svc := newTestService(t, db, nft)
	nft.SetConfPath(filepath.Join(t.TempDir(), "sem-esse-diretorio", "nftables.conf"))

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if st := svc.LastApplyStatus(); st.BootPersistError == "" {
		t.Fatalf("pré-condição: a primeira passada tinha que registrar a falha de boot, veio %+v", st)
	}

	// Só a tabela lida vai embora — o banco continua de pé para o próprio
	// apply-status poder ser gravado (mesma escolha de
	// TestReconcileRecordsApplyStatusOnDBReadError).
	if _, err := db.Conn().Exec(`DROP TABLE firewall_groups`); err != nil {
		t.Fatalf("derrubar firewall_groups: %v", err)
	}
	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("esperava que o erro de leitura do banco abortasse o Reconcile")
	}

	st := svc.LastApplyStatus()
	if st == nil {
		t.Fatal("esperava um apply status gravado")
	}
	if st.OK {
		t.Errorf("com os dois problemas o status não pode ser ok: %+v", st)
	}
	if st.Error == "" {
		t.Errorf("o erro de leitura do banco tem que continuar em Error: %+v", st)
	}
	if st.BootPersistError == "" {
		t.Errorf("o arquivo de boot continua para trás e tem que continuar visível junto: %+v", st)
	}
}
