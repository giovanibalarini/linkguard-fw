package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/wireguard"
)

const wireGuardApplyFailure = "a configuração foi salva, mas a reconciliação da VPN não terminou; tente aplicar novamente"

type wireGuardService interface {
	Overview(context.Context) (wireguard.Overview, error)
	UpdateConfig(context.Context, wireguard.Config) error
	Enroll(context.Context, string) (wireguard.Enrollment, error)
	Revoke(context.Context, string) error
	RecordIntegrationError(error)
}

type wireGuardReconciler interface {
	Reconcile(context.Context) error
}

type wireGuardInputReconciler interface {
	ReconcileInputProtection(context.Context) error
}

// WireGuardHandler keeps HTTP concerns at the boundary. Key generation,
// persistence, vault access and process execution remain in internal/wireguard.
type WireGuardHandler struct {
	db        *storage.DB
	svc       wireGuardService
	groups    wireGuardReconciler
	input     wireGuardInputReconciler
	reloadDNS func(context.Context) error
}

func NewWireGuardHandler(db *storage.DB, svc wireGuardService, groups wireGuardReconciler, input wireGuardInputReconciler) *WireGuardHandler {
	return &WireGuardHandler{db: db, svc: svc, groups: groups, input: input}
}

func (h *WireGuardHandler) SetDNSReload(reload func(context.Context) error) {
	h.reloadDNS = reload
}

func (h *WireGuardHandler) Get(w http.ResponseWriter, r *http.Request) {
	overview, err := h.svc.Overview(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (h *WireGuardHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var config wireguard.Config
	if err := decodeJSON(r, &config); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	config.Address = strings.TrimSpace(config.Address)
	config.EndpointHost = strings.TrimSpace(config.EndpointHost)
	config.EndpointLinkID = strings.TrimSpace(config.EndpointLinkID)
	if err := wireguard.ValidateConfig(config); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.svc.UpdateConfig(r.Context(), config); err != nil {
		auditAction(h.db, r, "vpn.config", "vpn", "reconciliação pendente")
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
	}
	if err := h.reconcileIntegrations(r.Context()); err != nil {
		h.svc.RecordIntegrationError(err)
		auditAction(h.db, r, "vpn.config", "vpn", "reconciliação pendente")
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
	}
	auditAction(h.db, r, "vpn.config", "vpn", "")
	writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
}

func (h *WireGuardHandler) EnrollSelf(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || strings.TrimSpace(claims.UserID) == "" {
		writeError(w, http.StatusUnauthorized, "autenticação necessária")
		return
	}
	result, err := h.svc.Enroll(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "não foi possível criar a identidade WireGuard")
		return
	}
	if result.ApplyError != "" {
		// The domain error can contain package/process details. This response
		// also carries private material, so keep every other field generic.
		result.ApplyError = wireGuardApplyFailure
	}
	if err := h.reconcileIntegrations(r.Context()); err != nil {
		h.svc.RecordIntegrationError(err)
		result.ApplyError = wireGuardApplyFailure
	}
	auditAction(h.db, r, "vpn.enroll", "vpn-user:"+claims.UserID, "")
	// This is the sole response that may contain the client private key and
	// QR data. No GET endpoint exists for recovering it later.
	writeJSON(w, http.StatusCreated, result)
}

func (h *WireGuardHandler) RevokeSelf(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || strings.TrimSpace(claims.UserID) == "" {
		writeError(w, http.StatusUnauthorized, "autenticação necessária")
		return
	}
	h.revoke(w, r, claims.UserID)
}

func (h *WireGuardHandler) RevokePeer(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "userID é obrigatório")
		return
	}
	h.revoke(w, r, userID)
}

func (h *WireGuardHandler) revoke(w http.ResponseWriter, r *http.Request, userID string) {
	serviceErr := h.svc.Revoke(r.Context(), userID)
	integrationErr := h.reconcileIntegrations(r.Context())
	if integrationErr != nil {
		h.svc.RecordIntegrationError(integrationErr)
	}
	auditAction(h.db, r, "vpn.revoke", "vpn-user:"+userID, "")
	if serviceErr != nil || integrationErr != nil {
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (h *WireGuardHandler) reconcileIntegrations(ctx context.Context) error {
	var failures []error
	if h.input != nil {
		failures = appendIfError(failures, h.input.ReconcileInputProtection(ctx))
	}
	if h.groups != nil {
		failures = appendIfError(failures, h.groups.Reconcile(ctx))
	}
	if h.reloadDNS != nil {
		failures = appendIfError(failures, h.reloadDNS(ctx))
	}
	return errors.Join(failures...)
}

func appendIfError(errs []error, err error) []error {
	if err != nil {
		return append(errs, err)
	}
	return errs
}
