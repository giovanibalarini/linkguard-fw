package handlers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const aiTokenSecretName = "ai_api_token"

// AIHandler exposes the AI layer's token, config, and report history.
type AIHandler struct {
	db     *storage.DB
	sec    secrets.Secrets
	client *ai.Client
}

func NewAIHandler(db *storage.DB, sec secrets.Secrets, client *ai.Client) *AIHandler {
	return &AIHandler{db: db, sec: sec, client: client}
}

type aiStatusResponse struct {
	Configured        bool    `json:"configured"`
	Hint              string  `json:"hint"`
	Enabled           bool    `json:"enabled"`
	Model             string  `json:"model"`
	Effort            string  `json:"effort"`
	MonthlyBudgetUSD  float64 `json:"monthly_budget_usd"`
	SpentThisMonthUSD float64 `json:"spent_this_month_usd"`
}

// Status reports configuration state — never the token itself.
func (h *AIHandler) Status(w http.ResponseWriter, r *http.Request) {
	configured, hint := h.sec.Status(aiTokenSecretName)
	cfg := ai.LoadConfig(h.db)
	writeJSON(w, http.StatusOK, aiStatusResponse{
		Configured: configured, Hint: hint,
		Enabled: cfg.Enabled, Model: cfg.Model, Effort: cfg.Effort,
		MonthlyBudgetUSD: cfg.MonthlyBudgetUSD, SpentThisMonthUSD: cfg.SpentThisMonthUSD,
	})
}

// SetToken stores the Claude API token. Write-only: this handler never
// returns the value it just stored, matching the updater's token pattern.
func (h *AIHandler) SetToken(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	tok := strings.TrimSpace(b.Token)
	if tok == "" {
		writeError(w, http.StatusBadRequest, "token vazio")
		return
	}
	if err := h.sec.Set(aiTokenSecretName, tok); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "ai.token.set", "system", "")
	writeJSON(w, http.StatusOK, map[string]bool{"configured": true})
}

// DeleteToken removes the token, effectively disabling the AI layer's calls
// (Analyze returns ErrTokenNotConfigured).
func (h *AIHandler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	if err := h.sec.Delete(aiTokenSecretName); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "ai.token.delete", "system", "")
	writeJSON(w, http.StatusOK, map[string]bool{"configured": false})
}

// TestToken makes one cheap request to verify the configured token works.
func (h *AIHandler) TestToken(w http.ResponseWriter, r *http.Request) {
	report, err := h.client.Analyze(r.Context(), ai.Evidence{Period: "connection-test"})
	if err != nil {
		writeError(w, http.StatusBadGateway, "falha ao conectar: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "sample_summary": report.Summary})
}

// SetConfig persists the non-secret AI configuration.
func (h *AIHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg ai.Config
	if err := decodeJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	// Preserve spend tracking fields the client should never set directly.
	existing := ai.LoadConfig(h.db)
	cfg.SpentThisMonthUSD = existing.SpentThisMonthUSD
	cfg.BudgetResetAt = existing.BudgetResetAt
	if err := ai.SaveConfig(h.db, cfg); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "ai.config.set", "system", "")
	writeJSON(w, http.StatusOK, ai.LoadConfig(h.db))
}

// ListReports returns recent AI reports.
func (h *AIHandler) ListReports(w http.ResponseWriter, r *http.Request) {
	reports, err := h.db.ListAIReports(50)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, reports)
}

// GetReport returns one report by ID.
func (h *AIHandler) GetReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	report, err := h.db.GetAIReport(id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if report == nil {
		writeError(w, http.StatusNotFound, "relatório não encontrado")
		return
	}
	writeJSON(w, http.StatusOK, report)
}
