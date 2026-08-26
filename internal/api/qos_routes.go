package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
)

func registerQosRoutes(
	r chi.Router,
	require func(auth.Permission) func(http.Handler) http.Handler,
	h *handlers.QosHandler,
) {
	r.With(require(auth.PermLinksRead)).Get("/api/links/{id}/qos", h.Get)
	r.With(require(auth.PermLinksWrite)).Put("/api/links/{id}/qos", h.Update)
	r.With(require(auth.PermLinksWrite)).Post("/api/links/{id}/qos/test", h.Test)
}
