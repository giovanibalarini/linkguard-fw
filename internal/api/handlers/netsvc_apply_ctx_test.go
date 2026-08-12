package handlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
)

// ctxProbeProvider records what the apply actually got as a context.
type ctxProbeProvider struct {
	fakeNetsvcProvider
	sawCanceled bool
	hadDeadline bool
}

func (p *ctxProbeProvider) ReloadConfigs(ctx context.Context, _ netsvc.Config, _ []netsvc.Reservation, _ []string, _ string) (netsvc.ApplyResult, error) {
	p.sawCanceled = ctx.Err() != nil
	_, p.hadDeadline = ctx.Deadline()
	return netsvc.ApplyResult{}, nil
}

// O primeiro apply numa máquina pelada instala kea + unbound + dns-root-data.
// Se o admin fechar a aba (ou o axios desistir), o apt NÃO morre junto — a
// unidade transiente do systemd-run termina a transação. Cancelar o trabalho
// junto com o cliente fazia o LinkGuard registrar uma falha que não estava
// acontecendo, criar alerta crítico e queimar a única retentativa no lock do
// dpkg, enquanto o apt instalava com sucesso.
func TestApplyNaoMorreJuntoComOCliente(t *testing.T) {
	db := newPrereqTestDB(t)
	p := &ctxProbeProvider{}
	h := NewNetsvcHandler(db, p, nil)

	// Requisição cujo contexto já foi cancelado: é o que o net/http entrega
	// quando o cliente desiste.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/api/netsvc/apply", nil).WithContext(ctx)

	h.Apply(httptest.NewRecorder(), r)

	if p.sawCanceled {
		t.Error("o apply recebeu um contexto já cancelado: o trabalho morre junto com o cliente e o resultado registrado vira mentira")
	}
	if !p.hadDeadline {
		t.Error("o apply tem que ter um prazo próprio (applyBudget), senão um apt travado prende a goroutine para sempre")
	}
}
