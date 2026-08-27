package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/domainrouting"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type domainTargetsCoordinator interface {
	State(context.Context) domainrouting.State
	Create(context.Context, domainrouting.Input) (domainrouting.State, error)
	Update(context.Context, string, domainrouting.Input) (domainrouting.State, error)
	SetStage(context.Context, string, string) (domainrouting.State, error)
	Delete(context.Context, string) (domainrouting.State, error)
}

// DomainTargetsHandler expõe intenção, decisão efetiva e estado do runtime. A
// promoção fica em uma rota própria para create/update nunca ativarem uma regra
// por presença acidental de um campo stage.
type DomainTargetsHandler struct {
	coordinator domainTargetsCoordinator
	db          *storage.DB
}

func NewDomainTargetsHandler(coordinator domainTargetsCoordinator, db *storage.DB) *DomainTargetsHandler {
	return &DomainTargetsHandler{coordinator: coordinator, db: db}
}

func (h *DomainTargetsHandler) List(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	writeJSON(w, http.StatusOK, h.coordinator.State(r.Context()))
}

func (h *DomainTargetsHandler) Create(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var input domainrouting.Input
	if err := decodeStrictJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "payload JSON inválido ou com campos desconhecidos")
		return
	}
	state, err := h.coordinator.Create(r.Context(), input)
	if err != nil {
		writeDomainTargetError(w, err)
		return
	}
	auditAction(h.db, r, "domain_target.create", "domain:"+input.Domain, input.Capability)
	writeJSON(w, http.StatusCreated, state)
}

func (h *DomainTargetsHandler) Update(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	id := chi.URLParam(r, "id")
	var input domainrouting.Input
	if err := decodeStrictJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "payload JSON inválido ou com campos desconhecidos")
		return
	}
	state, err := h.coordinator.Update(r.Context(), id, input)
	if err != nil {
		writeDomainTargetError(w, err)
		return
	}
	auditAction(h.db, r, "domain_target.update", "domain_target:"+id, input.Domain)
	writeJSON(w, http.StatusOK, state)
}

func (h *DomainTargetsHandler) SetStage(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		Stage string `json:"stage"`
	}
	if err := decodeStrictJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "payload JSON inválido ou com campos desconhecidos")
		return
	}
	state, err := h.coordinator.SetStage(r.Context(), id, body.Stage)
	if err != nil {
		writeDomainTargetError(w, err)
		return
	}
	auditAction(h.db, r, "domain_target.stage", "domain_target:"+id, body.Stage)
	writeJSON(w, http.StatusOK, state)
}

func (h *DomainTargetsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	id := chi.URLParam(r, "id")
	state, err := h.coordinator.Delete(r.Context(), id)
	if err != nil {
		writeDomainTargetError(w, err)
		return
	}
	auditAction(h.db, r, "domain_target.delete", "domain_target:"+id, "")
	writeJSON(w, http.StatusOK, state)
}

func (h *DomainTargetsHandler) available(w http.ResponseWriter) bool {
	if h.coordinator != nil {
		return true
	}
	writeError(w, http.StatusServiceUnavailable, "direcionamento por domínio indisponível")
	return false
}

func writeDomainTargetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domainrouting.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, domainrouting.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, domainrouting.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeInternalError(w, err)
	}
}

func decodeStrictJSON(r *http.Request, value any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("mais de um valor JSON")
		}
		return err
	}
	return nil
}
