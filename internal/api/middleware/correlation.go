package middleware

import (
	"net/http"

	"github.com/rs/xid"

	"github.com/darmiel/talmi/internal/correlation"
)

const CorrelationIDHeader = "X-Correlation-ID"

func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := xid.New().String()
		w.Header().Set(CorrelationIDHeader, id)
		next.ServeHTTP(w, r.WithContext(correlation.With(r.Context(), id)))
	})
}
