package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// LinksHandler handles WAN link CRUD requests.
type LinksHandler struct {
	svc    *links.Service
	db     *storage.DB
	nftSvc *nftables.Service
}

// NewLinksHandler creates the handler. nftSvc is needed because changing a
// link's interface must also rebuild the firewall's NAT rule — before
// 2026-08-10 nothing did, so an edited link left the masquerade rule
// pointing at the previous interface.
func NewLinksHandler(svc *links.Service, db *storage.DB, nftSvc *nftables.Service) *LinksHandler {
	return &LinksHandler{svc: svc, db: db, nftSvc: nftSvc}
}

// reconcileNAT rebuilds the masquerade rule from the currently enabled WAN
// links. Best-effort: a failure here is logged (and surfaced by the
// firewall-nat health check) but never fails the link operation the admin
// just performed.
func (h *LinksHandler) reconcileNAT(ctx context.Context) {
	if h.nftSvc == nil {
		return
	}
	ls, err := h.db.GetLinks()
	if err != nil {
		slog.Warn("não foi possível carregar links para reconciliar a regra de NAT", "err", err)
		return
	}
	ifaces := make([]string, 0, len(ls))
	for _, l := range ls {
		if l.Enabled && l.Interface != "" {
			ifaces = append(ifaces, l.Interface)
		}
	}
	if err := h.nftSvc.ReconcileMasquerade(ctx, ifaces); err != nil {
		slog.Warn("não foi possível reconciliar a regra de NAT após mudança de link", "err", err)
	}
}

// List returns all links.
func (h *LinksHandler) List(w http.ResponseWriter, r *http.Request) {
	ls, err := h.svc.List()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if ls == nil {
		ls = []storage.Link{}
	}
	writeJSON(w, http.StatusOK, ls)
}

// Get returns a single link.
func (h *LinksHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	l, err := h.svc.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, l)
}

// Create inserts a new link.
func (h *LinksHandler) Create(w http.ResponseWriter, r *http.Request) {
	var l storage.Link
	if err := decodeJSON(r, &l); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.Create(&l); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.reconcileNAT(r.Context())
	writeJSON(w, http.StatusCreated, l)
}

// Update modifies an existing link.
func (h *LinksHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.svc.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	var updated storage.Link
	if err := decodeJSON(r, &updated); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt

	if err := h.svc.Update(&updated); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.reconcileNAT(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

// Delete removes a link.
func (h *LinksHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.svc.Get(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err := h.svc.Delete(id); err != nil {
		writeInternalError(w, err)
		return
	}
	h.reconcileNAT(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// AutoDetect discovers WAN interfaces from system routes and syncs them to DB.
func (h *LinksHandler) AutoDetect(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.DiscoverAndSyncWANLinks()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	h.reconcileNAT(r.Context())
	writeJSON(w, http.StatusOK, res)
}
