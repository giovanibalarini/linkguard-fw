package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
)

// registerDomainTargetRoutes concentra caminho e permissão no mesmo ponto para
// o teste de RBAC exercitar exatamente a montagem usada em produção.
func registerDomainTargetRoutes(
	r chi.Router,
	require func(auth.Permission) func(http.Handler) http.Handler,
	h *handlers.DomainTargetsHandler,
) {
	r.With(require(auth.PermLinksRead)).Get("/api/domain-targets", h.List)
	r.With(require(auth.PermLinksWrite)).Post("/api/domain-targets", h.Create)
	r.With(require(auth.PermLinksWrite)).Put("/api/domain-targets/{id}", h.Update)
	r.With(require(auth.PermLinksWrite)).Delete("/api/domain-targets/{id}", h.Delete)
	r.With(require(auth.PermLinksWrite)).Post("/api/domain-targets/{id}/stage", h.SetStage)
}
