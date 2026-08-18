package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/updater"
)

const githubTokenKey = "github_update_token"

// UpdateHandler checks for and installs new releases.
type UpdateHandler struct {
	db  *storage.DB
	sec secrets.Secrets
	svc *updater.Service
	// alertSvc é como uma falha da atualização chega ao operador. Sem ele o
	// erro morre num slog e a tela fica dizendo "aguarde e recarregue" para
	// sempre (issue #101). Pode ser nil em teste.
	alertSvc *alerts.Service
}

// NewUpdateHandler creates an UpdateHandler.
func NewUpdateHandler(db *storage.DB, sec secrets.Secrets, svc *updater.Service, alertSvc *alerts.Service) *UpdateHandler {
	return &UpdateHandler{db: db, sec: sec, svc: svc, alertSvc: alertSvc}
}

// falhouAtualizar leva a falha para onde o operador olha.
//
// O canal é o de alertas, e não uma linha de log, porque a resposta do POST já
// saiu ("atualizando, aguarde e recarregue") e não existe mais caminho de volta
// pelo HTTP. Vale para qualquer causa: rede fora, GitHub com rate limit,
// checksum divergente — esta última é falha de INTEGRIDADE, a que mais precisa
// chegar à tela.
func (h *UpdateHandler) falhouAtualizar(para string, err error) {
	slog.Error("self-update failed", "err", err)
	if h.alertSvc == nil {
		return
	}
	if aerr := h.alertSvc.Create(
		alerts.TypeSelfUpdateFailed,
		alerts.SeverityWarning,
		"A atualização para "+para+" não concluiu",
		"O LinkGuard continua rodando na versão anterior, e nada foi alterado. Causa: "+err.Error(),
		"",
	); aerr != nil {
		slog.Error("não consegui registrar o alerta da falha de atualização", "err", aerr)
	}
}

// TokenStatus reports whether a GitHub token is configured (never returns it).
func (h *UpdateHandler) TokenStatus(w http.ResponseWriter, r *http.Request) {
	configured, _ := h.sec.Status(githubTokenKey)
	writeJSON(w, http.StatusOK, map[string]bool{"configured": configured})
}

// SetToken stores (or clears, if empty) the GitHub token used to reach the
// private repo's releases. Required because the repo is private — without it the
// GitHub API answers 404.
func (h *UpdateHandler) SetToken(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	tok := strings.TrimSpace(b.Token)
	if err := h.sec.Set(githubTokenKey, tok); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "update.token.set", "system", "")
	writeJSON(w, http.StatusOK, map[string]bool{"configured": tok != ""})
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
			h.falhouAtualizar(res.Latest, err)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "updating",
		"to":      res.Latest,
		"message": "Atualizando para " + res.Latest + ". O serviço vai reiniciar; aguarde alguns segundos e recarregue a página.",
	})
}
