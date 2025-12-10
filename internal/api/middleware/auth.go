package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/darmiel/talmi/internal/api/presenter"
)

const adminRole = "admin"

// AdminAuth is a middleware that checks for admin privileges in the JWT token.
// TODO(future): this is currently a simple middleware for admin role checking, used for a PoC.
// TODO(future): This should be replaced with a more flexible RBAC system in the future.
func AdminAuth(signingKey []byte) func(handler http.Handler) http.Handler {
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

			hasPrivilege := false
			for _, roleAny := range roles {
				roleStr, ok := roleAny.(string)
				if !ok {
					continue
				}
				if roleStr == adminRole {
					hasPrivilege = true
					break
				}
			}
			if !hasPrivilege {
				presenter.Error(w, r, "insufficient privileges", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
			return
		})
	}
}
