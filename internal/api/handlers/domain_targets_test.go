package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/domainrouting"
	"github.com/giovanibalarini/linkguard-fw/internal/domtargets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type domainRuntimeStub struct {
	last []domtargets.Alvo
}

func (s *domainRuntimeStub) DefinirAlvos(alvos []domtargets.Alvo) {
	s.last = append([]domtargets.Alvo(nil), alvos...)
}

func (*domainRuntimeStub) Estado(context.Context) domtargets.Estado {
	return domtargets.Estado{Vivo: true, KernelLido: true}
}

func newDomainTargetsHandler(t *testing.T) (*DomainTargetsHandler, *domainrouting.Coordinator, *storage.DB) {
	t.Helper()
	db := newTestDB(t)
	if err := db.CreateFirewallGroup(&storage.FirewallGroup{
		ID: "system-blocklist", Name: "Bloqueios", Kind: "blocklist", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateLink(&storage.Link{
		ID: "wan-2", Name: "WAN 2", Interface: "wan2", Status: "online", Enabled: true, TableID: 200,
	}); err != nil {
		t.Fatal(err)
	}
	coordinator := domainrouting.New(db, &domainRuntimeStub{})
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	return NewDomainTargetsHandler(coordinator, db), coordinator, db
}

func domainRequest(method, path, body string, params ...string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if len(params) == 2 {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add(params[0], params[1])
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	}
	return req
}

func decodeDomainState(t *testing.T, recorder *httptest.ResponseRecorder) domainrouting.State {
	t.Helper()
	var state domainrouting.State
	if err := json.Unmarshal(recorder.Body.Bytes(), &state); err != nil {
		t.Fatalf("resposta não é State: %v (%s)", err, recorder.Body.String())
	}
	return state
}

func TestDomainTargetsHandlerCRUDKeepsPromotionExplicit(t *testing.T) {
	h, _, db := newDomainTargetsHandler(t)

	create := httptest.NewRecorder()
	h.Create(create, domainRequest(http.MethodPost, "/api/domain-targets",
		`{"domain":"Video.Example.com.","capability":"direcionar","link_id":"wan-2","note":"streaming"}`))
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", create.Code, create.Body.String())
	}
	created := decodeDomainState(t, create)
	if len(created.Targets) != 1 || created.Targets[0].Domain != "video.example.com" || created.Targets[0].Stage != storage.DomainStageEnsaio {
		t.Fatalf("criação não normalizou/nasceu em ensaio: %+v", created.Targets)
	}
	id := created.Targets[0].ID

	promote := httptest.NewRecorder()
	h.SetStage(promote, domainRequest(http.MethodPost, "/api/domain-targets/"+id+"/stage",
		`{"stage":"ativo"}`, "id", id))
	if promote.Code != http.StatusOK {
		t.Fatalf("promote = %d: %s", promote.Code, promote.Body.String())
	}
	if got := decodeDomainState(t, promote).Targets[0]; got.Stage != storage.DomainStageAtivo || got.EffectiveStage != storage.DomainStageAtivo {
		t.Fatalf("promoção explícita não ativou: %+v", got)
	}

	update := httptest.NewRecorder()
	h.Update(update, domainRequest(http.MethodPut, "/api/domain-targets/"+id,
		`{"domain":"media.example.com","capability":"direcionar","link_id":"wan-2","note":"editado"}`, "id", id))
	if update.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", update.Code, update.Body.String())
	}
	if got := decodeDomainState(t, update).Targets[0]; got.Stage != storage.DomainStageAtivo || got.Domain != "media.example.com" {
		t.Fatalf("edição promoveu/rebaixou por tabela: %+v", got)
	}

	list := httptest.NewRecorder()
	h.List(list, domainRequest(http.MethodGet, "/api/domain-targets", ""))
	if list.Code != http.StatusOK || len(decodeDomainState(t, list).Targets) != 1 {
		t.Fatalf("list = %d: %s", list.Code, list.Body.String())
	}

	remove := httptest.NewRecorder()
	h.Delete(remove, domainRequest(http.MethodDelete, "/api/domain-targets/"+id, "", "id", id))
	if remove.Code != http.StatusOK || len(decodeDomainState(t, remove).Targets) != 0 {
		t.Fatalf("delete = %d: %s", remove.Code, remove.Body.String())
	}

	logs, err := db.GetAuditLogs(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 4 {
		t.Fatalf("CRUD/promoção deveriam gerar 4 auditorias, vieram %d: %+v", len(logs), logs)
	}
}

func TestDomainTargetsHandlerRejectsUnknownTrailingAndInvalidPayloads(t *testing.T) {
	h, coordinator, _ := newDomainTargetsHandler(t)
	tests := []struct {
		name string
		body string
	}{
		{name: "stage hidden in create", body: `{"domain":"video.example.com","capability":"barrar","stage":"ativo"}`},
		{name: "trailing json", body: `{"domain":"video.example.com","capability":"barrar"} {}`},
		{name: "unknown capability", body: `{"domain":"video.example.com","capability":"redirecionar"}`},
		{name: "unknown link", body: `{"domain":"video.example.com","capability":"direcionar","link_id":"wan-missing"}`},
		{name: "control in note", body: "{\"domain\":\"video.example.com\",\"capability\":\"barrar\",\"note\":\"linha\\nnova\"}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.Create(w, domainRequest(http.MethodPost, "/api/domain-targets", tt.body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
		})
	}
	if len(coordinator.State(context.Background()).Targets) != 0 {
		t.Fatal("payload inválido alterou o banco/runtime")
	}

	badStage := httptest.NewRecorder()
	h.SetStage(badStage, domainRequest(http.MethodPost, "/api/domain-targets/id/stage", `{"stage":"talvez"}`, "id", "id"))
	if badStage.Code != http.StatusBadRequest {
		t.Fatalf("stage inválido = %d: %s", badStage.Code, badStage.Body.String())
	}
}

func TestDomainTargetsHandlerMapsConflictAndNotFound(t *testing.T) {
	h, _, _ := newDomainTargetsHandler(t)
	body := `{"domain":"video.example.com","capability":"barrar"}`
	first := httptest.NewRecorder()
	h.Create(first, domainRequest(http.MethodPost, "/api/domain-targets", body))
	if first.Code != http.StatusCreated {
		t.Fatal(first.Body.String())
	}

	duplicate := httptest.NewRecorder()
	h.Create(duplicate, domainRequest(http.MethodPost, "/api/domain-targets", body))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicado = %d: %s", duplicate.Code, duplicate.Body.String())
	}

	missing := httptest.NewRecorder()
	h.Delete(missing, domainRequest(http.MethodDelete, "/api/domain-targets/missing", "", "id", "missing"))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("ausente = %d: %s", missing.Code, missing.Body.String())
	}
}
