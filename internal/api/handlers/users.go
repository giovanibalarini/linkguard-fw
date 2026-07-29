package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// UsersHandler handles user management (RBAC). All routes require users.manage.
type UsersHandler struct {
	db *storage.DB
}

// NewUsersHandler creates a UsersHandler.
func NewUsersHandler(db *storage.DB) *UsersHandler {
	return &UsersHandler{db: db}
}

// List returns all users with their assigned role IDs (no password hashes).
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	users, err := h.db.ListUsers()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if users == nil {
		users = []storage.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

// Create adds a new user with a password and a set of roles.
func (h *UsersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		RoleIDs  []string `json:"role_ids"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	if len(body.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if existing, _ := h.db.GetUserByUsername(body.Username); existing != nil {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	if err := h.validateRoles(body.RoleIDs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Assigning roles at creation time is a permission GRANT — same escalation
	// as Update. users.manage alone (e.g. a helpdesk role scoped to account
	// creation) must not be enough to hand out any role, including one that
	// includes roles.manage/admin-equivalent permissions the actor may not even
	// hold. The requirement only kicks in when at least one role is actually
	// being granted; creating a role-less account (assign the role later) stays
	// a legitimate users.manage-only operation. Mirrors the blanket
	// roles.manage gate already enforced in Update.
	if len(body.RoleIDs) > 0 {
		claims := auth.ClaimsFromContext(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		perms, err := h.db.GetUserPermissions(claims.UserID)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		if !perms[string(auth.PermRolesManage)] {
			writeError(w, http.StatusForbidden, "atribuir papéis a um usuário exige a permissão roles.manage")
			return
		}
	}

	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	u := &storage.User{Username: body.Username}
	if err := h.db.CreateUser(u, hash, body.RoleIDs); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "user.create", "user:"+u.Username, "roles="+strings.Join(body.RoleIDs, ","))
	u.Password = ""
	writeJSON(w, http.StatusCreated, u)
}

// Update changes a user's roles and, optionally, resets their password.
func (h *UsersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.db.GetUserByID(id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	var body struct {
		Password *string   `json:"password"`
		RoleIDs  *[]string `json:"role_ids"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Changing role assignments is a permission GRANT — users.manage alone (e.g.
	// a helpdesk role scoped to password resets) must not be enough to hand out
	// any role, including one that includes roles.manage/admin-equivalent
	// permissions the actor may not even hold themselves. This is deliberately
	// a blanket roles.manage requirement, not a "target role can't exceed the
	// actor's own permissions" check — simpler, and matches the separation the
	// two permissions already imply.
	if body.RoleIDs != nil {
		claims := auth.ClaimsFromContext(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		perms, err := h.db.GetUserPermissions(claims.UserID)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		if !perms[string(auth.PermRolesManage)] {
			writeError(w, http.StatusForbidden, "alterar papéis de um usuário exige a permissão roles.manage")
			return
		}
	}

	if body.RoleIDs != nil {
		if err := h.validateRoles(*body.RoleIDs); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Guard against lockout: don't let the last admin-capable user lose it.
		if err := h.guardLastAdmin(id, *body.RoleIDs); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := h.db.SetUserRoles(id, *body.RoleIDs); err != nil {
			writeInternalError(w, err)
			return
		}
	}

	if body.Password != nil {
		if len(*body.Password) < 8 {
			writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		hash, err := auth.HashPassword(*body.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		if err := h.db.UpdateUserPassword(id, hash); err != nil {
			writeInternalError(w, err)
			return
		}
	}

	auditAction(h.db, r, "user.update", "user:"+user.Username, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// Delete removes a user. A user cannot delete themselves, and the last
// admin-capable user cannot be removed.
func (h *UsersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.db.GetUserByID(id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if c := auth.ClaimsFromContext(r.Context()); c != nil && c.UserID == id {
		writeError(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	// Removing this user must not leave the system with no admin.
	if err := h.guardLastAdmin(id, nil); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.db.DeleteUser(id); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "user.delete", "user:"+user.Username, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// validateRoles ensures every referenced role exists.
func (h *UsersHandler) validateRoles(roleIDs []string) error {
	for _, rid := range roleIDs {
		role, err := h.db.GetRole(rid)
		if err != nil {
			return err
		}
		if role == nil {
			return fmt.Errorf("role not found: %s", rid)
		}
	}
	return nil
}

// guardLastAdmin prevents an action that would leave no user holding the
// users.manage permission. newRoleIDs is the post-change role set for user id
// (nil when the user is being deleted entirely).
func (h *UsersHandler) guardLastAdmin(id string, newRoleIDs []string) error {
	users, err := h.db.ListUsers()
	if err != nil {
		return err
	}
	for _, u := range users {
		roleIDs := u.RoleIDs
		if u.ID == id {
			roleIDs = newRoleIDs // apply the pending change (nil = deleted)
		}
		if rolesGrant(h.db, roleIDs, auth.PermUsersManage) {
			return nil // at least one admin remains
		}
	}
	return errors.New("ao menos um usuário precisa manter a permissão 'Gerenciar usuários'")
}

// rolesGrant reports whether any of the given roles grants perm.
func rolesGrant(db *storage.DB, roleIDs []string, perm auth.Permission) bool {
	for _, rid := range roleIDs {
		role, err := db.GetRole(rid)
		if err != nil || role == nil {
			continue
		}
		for _, p := range role.Permissions {
			if p == string(perm) {
				return true
			}
		}
	}
	return false
}
