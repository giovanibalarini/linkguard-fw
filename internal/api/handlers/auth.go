package handlers

import (
"net/http"

"github.com/giovanibalarini/linkguard-fw/internal/auth"
"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// AuthHandler handles authentication requests.
type AuthHandler struct {
svc *auth.Service
db  *storage.DB
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(svc *auth.Service, db *storage.DB) *AuthHandler {
return &AuthHandler{svc: svc, db: db}
}

// Login authenticates a user and returns a JWT token.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
var body struct {
Username string `json:"username"`
Password string `json:"password"`
}
if err := decodeJSON(r, &body); err != nil {
writeError(w, http.StatusBadRequest, "invalid request body")
return
}
if body.Username == "" || body.Password == "" {
writeError(w, http.StatusBadRequest, "username and password are required")
return
}

token, user, err := h.svc.Login(body.Username, body.Password)
if err != nil {
writeError(w, http.StatusUnauthorized, "invalid credentials")
return
}

writeJSON(w, http.StatusOK, map[string]interface{}{
"token": token,
"user": map[string]string{
"id":       user.ID,
"username": user.Username,
"role":     user.Role,
},
})
}

// Me returns the authenticated user together with their effective permissions,
// so the frontend can show/hide features. Requires only authentication.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
claims := auth.ClaimsFromContext(r.Context())
if claims == nil {
writeError(w, http.StatusUnauthorized, "unauthorized")
return
}
perms, err := h.svc.EffectivePermissions(claims.UserID)
if err != nil {
writeError(w, http.StatusInternalServerError, err.Error())
return
}
roleIDs, _ := h.db.GetUserRoleIDs(claims.UserID)
writeJSON(w, http.StatusOK, map[string]interface{}{
"id":          claims.UserID,
"username":    claims.Username,
"role_ids":    roleIDs,
"permissions": perms,
})
}
