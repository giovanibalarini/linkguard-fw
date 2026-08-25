package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/hostquota"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// HostQuotaHandler expõe a cota de dados por aparelho da LAN — issue #126,
// metade "por host".
//
// As rotas ficam sob /api/hosts/quotas, e não sob /api/quotas, porque o
// assunto é aparelho: quem administra o inventário tem de conseguir declarar
// cota sem ganhar permissão de mexer nos links. Ver o registro em server.go.
type HostQuotaHandler struct {
	svc *hostquota.Service
	db  *storage.DB
}

// NewHostQuotaHandler cria o handler.
func NewHostQuotaHandler(svc *hostquota.Service, db *storage.DB) *HostQuotaHandler {
	return &HostQuotaHandler{svc: svc, db: db}
}

// List devolve o estado de cota e consumo de cada aparelho.
//
// Devolve TODO aparelho do inventário, com ou sem cota declarada: um aparelho
// ausente desta lista é um aparelho que ninguém consegue proteger, porque não
// há de onde clicar para declarar a cota dele.
func (h *HostQuotaHandler) List(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.Snapshot()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// Save grava a cota de um aparelho.
func (h *HostQuotaHandler) Save(w http.ResponseWriter, r *http.Request) {
	var q storage.HostQuota
	if err := decodeJSON(r, &q); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	// O aparelho vem da URL, não do corpo: com os dois, um corpo divergente
	// gravaria a cota no aparelho errado sem ninguém perceber.
	q.MAC = chi.URLParam(r, "mac")
	if err := h.svc.Save(q); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "update", "host_quota", q.MAC)
	writeJSON(w, http.StatusOK, q)
}

// Delete remove a cota de um aparelho (o consumo medido continua).
func (h *HostQuotaHandler) Delete(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	if err := h.svc.Delete(mac); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "delete", "host_quota", mac)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// History devolve os ciclos anteriores de um aparelho.
func (h *HostQuotaHandler) History(w http.ResponseWriter, r *http.Request) {
	hist, err := h.svc.History(chi.URLParam(r, "mac"), 12)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if hist == nil {
		hist = []storage.HostUsage{}
	}
	writeJSON(w, http.StatusOK, hist)
}
