package correlation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionContext(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	is.Empty(SessionFrom(context.Background()), "bare context has no session id")

	ctx := WithSession(context.Background(), "s1")
	is.Equal("s1", SessionFrom(ctx))

	// request id and session id are independent keys and do not collide
	ctx = With(ctx, "req1")
	is.Equal("s1", SessionFrom(ctx))
	is.Equal("req1", From(ctx))
}
