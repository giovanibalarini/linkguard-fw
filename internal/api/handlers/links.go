package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// LinksHandler handles WAN link CRUD requests.
type LinksHandler struct {
	svc *links.Service
	db  *storage.DB
}

// NewLinksHandler creates a LinksHandler.
func NewLinksHandler(svc *links.Service, db *storage.DB) *LinksHandler {
	return &LinksHandler{svc: svc, db: db}
}

// List returns all links.
func (h *LinksHandler) List(w http.ResponseWriter, r *http.Request) {
	ls, err := h.svc.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AutoDetect discovers WAN interfaces from system routes and syncs them to DB.
func (h *LinksHandler) AutoDetect(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.DiscoverAndSyncWANLinks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
