package middleware

import (
	"net/http"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog/log"
)

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		reqID, _ := r.Context().Value(correlationIDKey).(string)

		// create a logger to wrap request info
		l := log.With().
			Str("correlation_id", reqID).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote", r.RemoteAddr).
			Logger()

		ctx := l.WithContext(r.Context())
		ww := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(ww, r.WithContext(ctx))

		// skip logging healthy / ready checks
		if r.URL.Path == "/healthz" && ww.statusCode < 400 {
			return
		}

		l.Info().
			Int("status", ww.statusCode).
			Dur("duration", time.Since(start)).
			Msg("request.handled")
	})
}

func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Ctx(r.Context()).Error().
					Interface("panic", err).
					Bytes("stack", debug.Stack()).
					Msg("panic.recovered")

				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error": "internal server error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
