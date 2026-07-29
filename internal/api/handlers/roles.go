package handlers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// RolesHandler handles role management (RBAC). All routes require roles.manage.
type RolesHandler struct {
	db *storage.DB
}

// NewRolesHandler creates a RolesHandler.
func NewRolesHandler(db *storage.DB) *RolesHandler {
	return &RolesHandler{db: db}
}

// Catalog returns the in-code permission catalog used to build the role editor.
func (h *RolesHandler) Catalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, auth.Catalog)
}

// List returns all roles with their permissions.
func (h *RolesHandler) List(w http.ResponseWriter, r *http.Request) {
	roles, err := h.db.ListRoles()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if roles == nil {
		roles = []storage.Role{}
	}
	writeJSON(w, http.StatusOK, roles)
}

// Create adds a new (non-builtin) role.
func (h *RolesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if bad := invalidPermissions(body.Permissions); bad != "" {
		writeError(w, http.StatusBadRequest, "unknown permission: "+bad)
		return
	}

	role := &storage.Role{
		Name:        body.Name,
		Description: body.Description,
		Permissions: body.Permissions,
	}
	if err := h.db.CreateRole(role); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "role.create", "role:"+role.Name, strings.Join(body.Permissions, ","))
	writeJSON(w, http.StatusCreated, role)
}

// Update changes a role's name, description and permissions.
func (h *RolesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, err := h.db.GetRole(id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if role == nil {
		writeError(w, http.StatusNotFound, "role not found")
		return
	}

	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(body.Name) != "" {
		role.Name = strings.TrimSpace(body.Name)
	}
	role.Description = body.Description
	if bad := invalidPermissions(body.Permissions); bad != "" {
		writeError(w, http.StatusBadRequest, "unknown permission: "+bad)
		return
	}
	role.Permissions = body.Permissions

	if err := h.db.UpdateRole(role); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "role.update", "role:"+role.Name, strings.Join(body.Permissions, ","))
	writeJSON(w, http.StatusOK, role)
}

// Delete removes a role. Built-in roles and roles still assigned to users
// cannot be deleted.
func (h *RolesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, err := h.db.GetRole(id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if role == nil {
		writeError(w, http.StatusNotFound, "role not found")
		return
	}
	if role.Builtin {
		writeError(w, http.StatusBadRequest, "built-in roles cannot be deleted")
		return
	}
	n, err := h.db.CountUsersWithRole(id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if n > 0 {
		writeError(w, http.StatusBadRequest, "role is still assigned to users")
		return
	}
	if err := h.db.DeleteRole(id); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "role.delete", "role:"+role.Name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// invalidPermissions returns the first permission key that is not in the
// catalog, or "" if all are valid.
func invalidPermissions(perms []string) string {
	for _, p := range perms {
		if !auth.IsValidPermission(p) {
			return p
		}
	}
	return ""
}
