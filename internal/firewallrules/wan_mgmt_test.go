package firewallrules

import (
	"encoding/json"
	"testing"
)

// O fechamento das portas de gerência nas WANs (#119, fase 3b).
//
// É A ÚNICA MUTAÇÃO DO PRODUTO QUE PODE CORTAR O ACESSO DE QUEM A FEZ SEM QUE
// ELE PERCEBA NA HORA: quem fecha estando na LAN não sente nada — a sessão dele
// não passa pela regra — e descobre no dia em que precisar entrar de fora, que
// costuma ser o dia em que já não dá para entrar de dentro.
//
// A rede de segurança é a janela de 90 segundos, e ela só funciona se o valor
// estiver no snapshot. Os testes abaixo existem para isso, e nada mais.

func TestPadraoEhGerenciaAberta(t *testing.T) {
	svc := newTestService(t, newTestDB(t))
	fechada, err := svc.WANMgmtClosed()
	if err != nil {
		t.Fatalf("WANMgmtClosed: %v", err)
	}
	if fechada {
		// Toda máquina que recebeu a fase 1 roda assim, e é o estado que
		// impede a caixa de se trancar sozinha ao cadastrar um link.
		t.Error("máquina recém-instalada nasceu com a gerência fechada nas WANs")
	}
}

func TestSnapshotCarregaOFechamentoDaGerencia(t *testing.T) {
	// O TESTE QUE JUSTIFICA A ENTREGA. Sem o campo no snapshot, a janela de 90 s
	// arma, o prazo vence, e as portas continuam fechadas sem nada apontando
	// para elas — a reversão desfazendo tudo menos a mudança que ela existe
	// para desfazer.
	svc := newTestService(t, newTestDB(t))
	if err := svc.SetWANMgmtClosed(true); err != nil {
		t.Fatalf("SetWANMgmtClosed: %v", err)
	}

	blob, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("SnapshotState: %v", err)
	}
	var snap stateSnapshot
	if err := json.Unmarshal([]byte(blob), &snap); err != nil {
		t.Fatalf("o snapshot não é decodificável: %v", err)
	}
	if snap.WANMgmtClosed == nil {
		t.Fatal("o snapshot não guardou o fechamento da gerência: reverter a janela não o desfaria")
	}
	if !*snap.WANMgmtClosed {
		t.Error("guardou o valor errado")
	}
}

func TestSnapshotAntigoNaoTemOFechamento(t *testing.T) {
	// A propriedade que dispensa migração: linha de pendente gravada por uma
	// versão anterior não tem o campo, o Unmarshal deixa nil, e nil significa
	// "esta janela é anterior ao recurso" — reverter não mexe nele. Se o campo
	// deixar de ser ponteiro, um upgrade com janela aberta passa a REABRIR a
	// gerência de quem a fechou, sem ninguém ter pedido.
	var snap stateSnapshot
	if err := json.Unmarshal([]byte(`{"groups":[],"rules":[]}`), &snap); err != nil {
		t.Fatalf("snapshot antigo não decodifica: %v", err)
	}
	if snap.WANMgmtClosed != nil {
		t.Error("snapshot sem o campo virou um valor concreto")
	}
}

func TestGravaELeOFechamento(t *testing.T) {
	svc := newTestService(t, newTestDB(t))
	for _, quer := range []bool{true, false, true} {
		if err := svc.SetWANMgmtClosed(quer); err != nil {
			t.Fatalf("SetWANMgmtClosed(%v): %v", quer, err)
		}
		got, err := svc.WANMgmtClosed()
		if err != nil {
			t.Fatalf("WANMgmtClosed: %v", err)
		}
		if got != quer {
			t.Errorf("gravou %v e leu %v", quer, got)
		}
	}
}
