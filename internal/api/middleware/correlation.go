package middleware

import (
	"context"
	"net/http"

	"github.com/rs/xid"
)

const CorrelationIDHeader = "X-Correlation-ID"
const correlationIDKey = "correlation_id"

// CorrelationCtx retrieves the correlation ID from the context.
// TODO: move this to another package where it's more appropriate
func CorrelationCtx(ctx context.Context) string {
	id, ok := ctx.Value(correlationIDKey).(string)
	if !ok {
		return ""
	}
	return id
}

func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(CorrelationIDHeader)
		if id == "" {
			id = xid.New().String()
		}
		w.Header().Set(CorrelationIDHeader, id)

		ctx := context.WithValue(r.Context(), correlationIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
