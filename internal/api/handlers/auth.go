package handlers

import (
"errors"
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

// Login authenticates a user (with optional 2FA code) and returns a JWT token.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
var body struct {
Username string `json:"username"`
Password string `json:"password"`
Code     string `json:"code"`
}
if err := decodeJSON(r, &body); err != nil {
writeError(w, http.StatusBadRequest, "invalid request body")
return
}
if body.Username == "" || body.Password == "" {
writeError(w, http.StatusBadRequest, "username and password are required")
return
}

token, user, err := h.svc.Login(body.Username, body.Password, body.Code)
if err != nil {
switch {
case errors.Is(err, auth.ErrTOTPRequired):
// Password OK; the client must now present a 2FA code.
writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
"error":         "two-factor code required",
"totp_required": true,
})
case errors.Is(err, auth.ErrLockedOut):
writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
"error":      "muitas tentativas. Tente novamente em alguns minutos.",
"locked_out": true,
})
default:
writeError(w, http.StatusUnauthorized, "invalid credentials")
}
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

// TwoFAStatus returns whether 2FA is enabled for the current user.
func (h *AuthHandler) TwoFAStatus(w http.ResponseWriter, r *http.Request) {
claims := auth.ClaimsFromContext(r.Context())
if claims == nil {
writeError(w, http.StatusUnauthorized, "unauthorized")
return
}
writeJSON(w, http.StatusOK, map[string]bool{"enabled": h.svc.TwoFAEnabled(claims.UserID)})
}

// TwoFASetup starts enrollment: returns the secret + otpauth URL to scan.
func (h *AuthHandler) TwoFASetup(w http.ResponseWriter, r *http.Request) {
claims := auth.ClaimsFromContext(r.Context())
if claims == nil {
writeError(w, http.StatusUnauthorized, "unauthorized")
return
}
secret, otpauth, err := h.svc.BeginTwoFASetup(claims.UserID, claims.Username)
if err != nil {
writeError(w, http.StatusInternalServerError, err.Error())
return
}
writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": otpauth})
}

// TwoFAActivate enables 2FA after verifying a code from the authenticator.
func (h *AuthHandler) TwoFAActivate(w http.ResponseWriter, r *http.Request) {
h.twoFAMutate(w, r, true)
}

// TwoFADisable turns 2FA off (requires a valid current code).
func (h *AuthHandler) TwoFADisable(w http.ResponseWriter, r *http.Request) {
h.twoFAMutate(w, r, false)
}

func (h *AuthHandler) twoFAMutate(w http.ResponseWriter, r *http.Request, activate bool) {
claims := auth.ClaimsFromContext(r.Context())
if claims == nil {
writeError(w, http.StatusUnauthorized, "unauthorized")
return
}
var body struct {
Code string `json:"code"`
}
if err := decodeJSON(r, &body); err != nil {
writeError(w, http.StatusBadRequest, "invalid request body")
return
}
var err error
if activate {
err = h.svc.ActivateTwoFA(claims.UserID, body.Code)
} else {
err = h.svc.DisableTwoFA(claims.UserID, body.Code)
}
if err != nil {
writeError(w, http.StatusBadRequest, err.Error())
return
}
auditAction(h.db, r, map[bool]string{true: "enable", false: "disable"}[activate], "2fa", claims.Username)
writeJSON(w, http.StatusOK, map[string]bool{"enabled": activate})
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
