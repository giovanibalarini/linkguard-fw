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
