package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const claimsKey contextKey = "claims"

// Middleware returns an HTTP middleware that validates JWT tokens.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		claims, err := s.ValidateToken(token)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClaimsFromContext retrieves the JWT Claims from the request context.
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// ContextWithClaims returns a context carrying the given claims, for tests
// that call a handler directly without going through Middleware.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

// Require returns a middleware that allows the request only if the authenticated
// user holds the given permission. It must be chained after Middleware (which
// populates the claims). Effective permissions are resolved from the database on
// each request, so revoking a role takes effect immediately (no need to wait for
// the JWT to expire).
func (s *Service) Require(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			perms, err := s.db.GetUserPermissions(claims.UserID)
			if err != nil {
				http.Error(w, `{"error":"permission lookup failed"}`, http.StatusInternalServerError)
				return
			}
			if !perms[string(perm)] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// EffectivePermissions returns the permission keys granted to a user (the union
// across their roles). Used by /api/auth/me so the frontend can show/hide UI.
func (s *Service) EffectivePermissions(userID string) ([]string, error) {
	set, err := s.db.GetUserPermissions(userID)
	if err != nil {
		return nil, err
	}
	perms := make([]string, 0, len(set))
	for p := range set {
		perms = append(perms, p)
	}
	return perms, nil
}

func extractToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	// Check cookie
	cookie, err := r.Cookie("token")
	if err == nil {
		return cookie.Value
	}
	return ""
}
