package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/darmiel/talmi/internal/api/presenter"
)

// InjectRoleMiddleware is a middleware that reads the Talmi JWT token and injects user roles into the request context.
// You shoule use the RequireRoleMiddleware to enforce role-based access control on specific handlers.
// TODO(future): this is currently a simple middleware for admin role checking, used for a PoC.
// TODO(future): This should be replaced with a more flexible RBAC system in the future.
func InjectRoleMiddleware(signingKey []byte) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			tokenStr := strings.TrimPrefix(auth, "Bearer ")

			if tokenStr == "" {
				presenter.Error(w, r, "login required", http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return signingKey, nil
			})
			if err != nil || !token.Valid {
				presenter.Error(w, r, "invalid session token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				presenter.Error(w, r, "invalid claims", http.StatusUnauthorized)
				return
			}

			roles, ok := claims["roles"].([]any)
			if !ok {
				presenter.Error(w, r, "invalid claims", http.StatusUnauthorized)
				return
			}

			var rolesAsStr []string
			for _, roleAny := range roles {
				roleStr, ok := roleAny.(string)
				if !ok {
					continue
				}
				rolesAsStr = append(rolesAsStr, roleStr)
			}

			ctx := context.WithValue(r.Context(), "roles", rolesAsStr)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		})
	}
}

func RequireRoleMiddleware(requiredRole string) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rolesAny := r.Context().Value("roles")
			if rolesAny == nil {
				presenter.Error(w, r, "forbidden: missing roles", http.StatusForbidden)
				return
			}

			roles, ok := rolesAny.([]string)
			if !ok {
				presenter.Error(w, r, "forbidden: invalid roles", http.StatusForbidden)
				return
			}

			hasRole := false
			for _, role := range roles {
				if role == requiredRole {
					hasRole = true
					break
				}
			}

			if !hasRole {
				presenter.Error(w, r, "forbidden: insufficient role", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
