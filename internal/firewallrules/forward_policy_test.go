package firewallrules

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// A postura da chain forward, guardada e revertida como o resto (issue #92).

func TestForwardPolicyPadraoEhLiberar(t *testing.T) {
	svc := newTestService(t, newTestDB(t))
	p, err := svc.ForwardPolicy()
	if err != nil {
		t.Fatalf("ForwardPolicy: %v", err)
	}
	if p != nftables.PolicyAccept {
		t.Errorf("máquina recém-instalada nasceu com política %q; toda base instalada roda em accept", p)
	}
}

func TestForwardPolicyGravaELe(t *testing.T) {
	svc := newTestService(t, newTestDB(t))
	if err := svc.SetForwardPolicy(nftables.PolicyDrop); err != nil {
		t.Fatalf("SetForwardPolicy: %v", err)
	}
	p, err := svc.ForwardPolicy()
	if err != nil {
		t.Fatalf("ForwardPolicy: %v", err)
	}
	if p != nftables.PolicyDrop {
		t.Errorf("gravou drop e leu %q", p)
	}
}

// TestAsDuasPosturasSaoIndependentes é a razão de existirem duas chaves em vez
// de uma. "Bloquear o que atravessa, continuar entrando no painel pela LAN" é a
// combinação que o admin quer em quase todo caso real; uma chave só tiraria
// dele exatamente a escolha que ele veio fazer.
func TestAsDuasPosturasSaoIndependentes(t *testing.T) {
	svc := newTestService(t, newTestDB(t))
	if err := svc.SetForwardPolicy(nftables.PolicyDrop); err != nil {
		t.Fatalf("SetForwardPolicy: %v", err)
	}
	inp, err := svc.InputPolicy()
	if err != nil {
		t.Fatalf("InputPolicy: %v", err)
	}
	if inp != nftables.PolicyAccept {
		t.Errorf("bloquear a forward mudou a postura da input para %q: o admin se trancaria fora sem ter pedido", inp)
	}
}

func TestForwardPolicyInvalidaNoBancoNaoViraAccept(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)
	if err := db.SetSetting(ForwardPolicySettingKey, "reject"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if _, err := svc.ForwardPolicy(); err == nil {
		t.Fatal("valor estranho no banco foi resolvido em silêncio; um firewall não se abre sozinho por não entender a pergunta")
	}
}

// TestSnapshotCarregaAsDuasPosturas: a janela de 90 segundos reverte o que está
// no snapshot. Sem o campo, a mudança MAIS perigosa que o produto sabe fazer
// seria armada com janela e nunca desfeita — o pendente sumiria no prazo e a
// política restritiva continuaria de pé, sem nada apontando para ela.
func TestSnapshotCarregaAsDuasPosturas(t *testing.T) {
	svc := newTestService(t, newTestDB(t))
	if err := svc.SetForwardPolicy(nftables.PolicyDrop); err != nil {
		t.Fatalf("SetForwardPolicy: %v", err)
	}

	blob, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("SnapshotState: %v", err)
	}
	var snap stateSnapshot
	if err := json.Unmarshal([]byte(blob), &snap); err != nil {
		t.Fatalf("o snapshot não é decodificável: %v", err)
	}
	if snap.ForwardPolicy == nil {
		t.Fatal("o snapshot não guardou a postura da forward: reverter a janela não a desfaria")
	}
	if *snap.ForwardPolicy != nftables.PolicyDrop {
		t.Errorf("guardou %q, esperava drop", *snap.ForwardPolicy)
	}
	if snap.Policy == nil || *snap.Policy != nftables.PolicyAccept {
		t.Errorf("a postura da input se perdeu no mesmo snapshot: %v", snap.Policy)
	}
}

// TestSnapshotAntigoNaoTemPostura é a propriedade que dispensa migração.
//
// Uma linha de pendente gravada por uma versão anterior não tem os campos, e o
// Unmarshal deixa os ponteiros nil. Nil significa "esta janela é anterior à
// política" — reverter não mexe nas posturas, que é a resposta certa. Se os
// campos deixarem de ser ponteiro um dia, um upgrade com janela aberta passa a
// reverter a postura para `accept` sem ninguém ter pedido.
func TestSnapshotAntigoNaoTemPostura(t *testing.T) {
	var snap stateSnapshot
	if err := json.Unmarshal([]byte(`{"groups":[],"rules":[]}`), &snap); err != nil {
		t.Fatalf("Unmarshal do formato antigo: %v", err)
	}
	if snap.Policy != nil || snap.ForwardPolicy != nil {
		t.Errorf("um pendente gravado antes da política nasceu com postura: policy=%v forward=%v\n"+
			"Reverter passaria a impor `accept` a quem nunca escolheu nada.", snap.Policy, snap.ForwardPolicy)
	}
}

// TestReverterRestauraAPosturaDaForward é o fecho: gravar a postura e reverter
// tem de devolvê-la ao que era. Sem isto, a janela desarma a mudança mais
// perigosa do produto sem desfazê-la.
func TestReverterRestauraAPosturaDaForward(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newBootedService(t, db)

	ctx := context.Background()

	// A ordem é a obrigatória do confirmar-ou-reverte: o snapshot é do estado
	// ANTERIOR, a janela é armada antes de aplicar, e só então a postura muda.
	antes, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("SnapshotState: %v", err)
	}
	if err := svc.SetForwardPolicy(nftables.PolicyDrop); err != nil {
		t.Fatalf("SetForwardPolicy: %v", err)
	}
	if _, err := svc.openWindowWithSnapshot(antes, "admin", "bloquear o que atravessa"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	if err := svc.RevertPending(ctx, currentWindowID(t, svc)); err != nil {
		t.Fatalf("reverter: %v", err)
	}

	p, err := svc.ForwardPolicy()
	if err != nil {
		t.Fatalf("ForwardPolicy: %v", err)
	}
	if p != nftables.PolicyAccept {
		t.Errorf("a reversão deixou a postura em %q: o operador ficou com o bloqueio que o prazo devia ter desfeito", p)
	}
}
