package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/linkquota"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// QuotaHandler expõe a franquia (cota de dados) por link WAN — issue #126.
type QuotaHandler struct {
	svc *linkquota.Service
	db  *storage.DB
}

// NewQuotaHandler cria o handler.
func NewQuotaHandler(svc *linkquota.Service, db *storage.DB) *QuotaHandler {
	return &QuotaHandler{svc: svc, db: db}
}

// List devolve o estado de franquia e consumo de cada link.
func (h *QuotaHandler) List(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.Snapshot()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// Save grava a franquia de um link.
func (h *QuotaHandler) Save(w http.ResponseWriter, r *http.Request) {
	var q storage.LinkQuota
	if err := decodeJSON(r, &q); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	// O link vem da URL, não do corpo: com os dois, um corpo divergente
	// gravaria a franquia no link errado sem ninguém perceber.
	q.LinkID = chi.URLParam(r, "id")
	if err := h.svc.Save(q); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "update", "link_quota", q.LinkID)
	writeJSON(w, http.StatusOK, q)
}

// Delete remove a franquia de um link (o consumo medido continua).
func (h *QuotaHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.Delete(id); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "delete", "link_quota", id)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// History devolve os ciclos anteriores de um link.
func (h *QuotaHandler) History(w http.ResponseWriter, r *http.Request) {
	hist, err := h.svc.History(chi.URLParam(r, "id"), 12)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if hist == nil {
		hist = []storage.LinkUsage{}
	}
	writeJSON(w, http.StatusOK, hist)
}
