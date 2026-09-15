package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type hostGroupReconciler interface {
	Reconcile(context.Context) error
}

type HostGroupHandler struct {
	db  *storage.DB
	vpn hostGroupReconciler
}

func NewHostGroupHandler(db *storage.DB, vpn hostGroupReconciler) *HostGroupHandler {
	return &HostGroupHandler{db: db, vpn: vpn}
}

func (h *HostGroupHandler) List(w http.ResponseWriter, r *http.Request) {
	groups, err := h.db.ListHostGroups()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if groups == nil {
		groups = []storage.HostGroup{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (h *HostGroupHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "id é obrigatório")
		return
	}
	group, err := h.db.GetHostGroup(id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if group == nil {
		writeError(w, http.StatusNotFound, "grupo de hosts não encontrado")
		return
	}
	writeJSON(w, http.StatusOK, group)
}

type hostGroupBody struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Hosts       []string `json:"hosts"`
}

func (h *HostGroupHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body hostGroupBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	group := storage.HostGroup{
		ID:          strings.TrimSpace(body.ID),
		Name:        strings.TrimSpace(body.Name),
		Description: strings.TrimSpace(body.Description),
		Hosts:       body.Hosts,
	}
	if err := storage.ValidateHostGroup(group); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.db.CreateHostGroup(&group); err != nil {
		writeInternalError(w, err)
		return
	}
	if h.vpn != nil {
		_ = h.vpn.Reconcile(r.Context())
	}
	auditAction(h.db, r, "hostgroup.create", "hostgroup:"+group.ID, group.Name)
	writeJSON(w, http.StatusCreated, group)
}

func (h *HostGroupHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "id é obrigatório")
		return
	}
	var body hostGroupBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	group := storage.HostGroup{
		ID:          id,
		Name:        strings.TrimSpace(body.Name),
		Description: strings.TrimSpace(body.Description),
		Hosts:       body.Hosts,
	}
	if err := storage.ValidateHostGroup(group); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.db.UpdateHostGroup(&group); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.vpn != nil {
		_ = h.vpn.Reconcile(r.Context())
	}
	auditAction(h.db, r, "hostgroup.update", "hostgroup:"+id, group.Name)
	writeJSON(w, http.StatusOK, group)
}

func (h *HostGroupHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "id é obrigatório")
		return
	}
	if err := h.db.DeleteHostGroup(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.vpn != nil {
		_ = h.vpn.Reconcile(r.Context())
	}
	auditAction(h.db, r, "hostgroup.delete", "hostgroup:"+id, "")
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

