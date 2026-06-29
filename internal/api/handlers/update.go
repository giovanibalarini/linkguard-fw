package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/updater"
)

// UpdateHandler checks for and installs new releases.
type UpdateHandler struct {
	db  *storage.DB
	svc *updater.Service
}

// NewUpdateHandler creates an UpdateHandler.
func NewUpdateHandler(db *storage.DB, svc *updater.Service) *UpdateHandler {
	return &UpdateHandler{db: db, svc: svc}
}

// Check reports whether a newer release is available.
func (h *UpdateHandler) Check(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Check(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// Apply installs the latest release. It responds immediately and performs the
// download + dpkg install in the background, because the package's postinst
// restarts this very service (which would otherwise cut the response).
func (h *UpdateHandler) Apply(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Check(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !res.UpdateAvailable {
		writeError(w, http.StatusBadRequest, "já está na versão mais recente")
		return
	}
	auditAction(h.db, r, "apply", "update", res.Latest)

	go func() {
		// Detached: survives the request and the impending restart.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		slog.Info("self-update starting", "to", res.Latest)
		if err := h.svc.Apply(ctx); err != nil {
			slog.Error("self-update failed", "err", err)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "updating",
		"to":      res.Latest,
		"message": "Atualizando para " + res.Latest + ". O serviço vai reiniciar; aguarde alguns segundos e recarregue a página.",
	})
}
