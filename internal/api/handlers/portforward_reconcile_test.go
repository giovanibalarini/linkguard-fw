package handlers

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"os"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// execNulo aceita tudo e não faz nada. Este arquivo mede QUEM é chamado depois
// do apply, não o que o nft recebe — isso já é coberto em outro lugar.
type execNulo struct{}

func (execNulo) Execute(context.Context, string, ...string) (string, error)     { return "", nil }
func (execNulo) ExecuteRead(context.Context, string, ...string) (string, error) { return "", nil }
func (execNulo) IsDryRun() bool                                                 { return false }
func (execNulo) WriteFile(string, []byte, os.FileMode) error                    { return nil }

// Issue #82: o encaminhamento de porta escrevia só a chain de DNAT e nunca
// reconciliava as chains construídas a partir do banco.
//
// Hoje isso funciona por acidente: com a forward em `policy accept`, o pacote
// traduzido pelo DNAT passa por política. No dia em que a forward tiver política
// restritiva (#78), a liberação correspondente precisa existir na forward — e
// ela só aparece numa reconciliação.
//
// O defeito era invisível justamente porque o sintoma não existe enquanto a
// política é permissiva. Este teste o torna visível agora.

type reconciliadorEspiao struct {
	chamadas int
	erro     error
}

func (r *reconciliadorEspiao) Reconcile(context.Context) error {
	r.chamadas++
	return r.erro
}

func TestEncaminhamentoReconciliaDepoisDeAplicar(t *testing.T) {
	db := newPrereqTestDB(t)
	espiao := &reconciliadorEspiao{}
	h := NewPortForwardHandler(db, nftables.NewService(execNulo{})).WithReconciler(espiao)

	// apply() é o caminho por onde TODA mutação de encaminhamento passa —
	// criar, editar e apagar. Cobrir ele cobre as três.
	req := httptest.NewRequest("POST", "/api/firewall/portforward", strings.NewReader("{}"))
	if err := h.apply(req, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if espiao.chamadas != 1 {
		t.Errorf("Reconcile chamado %d vezes, esperava 1 — sem ele, a liberação da forward "+
			"não existe até uma reconciliação sem relação nenhuma acontecer", espiao.chamadas)
	}
}

// TestEncaminhamentoNaoFalhaQuandoAReconciliacaoFalha.
//
// O DNAT já está aplicado e salvo quando a reconciliação roda. Derrubar a
// operação inteira aqui deixaria o admin sem o recurso que ele acabou de
// configurar, por causa de um passo que a próxima mutação — ou o próximo boot —
// refaz sozinho.
func TestEncaminhamentoNaoFalhaQuandoAReconciliacaoFalha(t *testing.T) {
	db := newPrereqTestDB(t)
	espiao := &reconciliadorEspiao{erro: errors.New("nft recusou")}
	h := NewPortForwardHandler(db, nftables.NewService(execNulo{})).WithReconciler(espiao)

	req := httptest.NewRequest("POST", "/api/firewall/portforward", strings.NewReader("{}"))
	if err := h.apply(req, nil); err != nil {
		t.Errorf("a falha da reconciliação derrubou o encaminhamento: %v", err)
	}
	if espiao.chamadas != 1 {
		t.Error("nem tentou reconciliar")
	}
}

// TestEncaminhamentoSemReconciliadorNaoQuebra: o construtor sem reconciliador
// continua válido (os testes que só exercitam o DNAT o usam), e o caminho
// degrada com aviso em vez de panic.
func TestEncaminhamentoSemReconciliadorNaoQuebra(t *testing.T) {
	db := newPrereqTestDB(t)
	h := NewPortForwardHandler(db, nftables.NewService(execNulo{}))

	req := httptest.NewRequest("POST", "/api/firewall/portforward", strings.NewReader("{}"))
	if err := h.apply(req, nil); err != nil {
		t.Errorf("apply sem reconciliador devolveu erro: %v", err)
	}
}
