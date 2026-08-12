package correlation

import "context"

type ctxKey struct{}

// With returns a context with the given correlation ID attached.
func With(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, ctxKey{}, correlationID)
}

// From returns the correlation ID from the context, or an empty string if not set.
func From(ctx context.Context) string {
	correlationID, _ := ctx.Value(ctxKey{}).(string)
	return correlationID
}

type sessionKey struct{}

// WithSession returns a context with the given session ID attached.
func WithSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionKey{}, sessionID)
}

// SessionFrom returns the session ID from the context, or an empty string if not set.
func SessionFrom(ctx context.Context) string {
	sessionID, _ := ctx.Value(sessionKey{}).(string)
	return sessionID
}
