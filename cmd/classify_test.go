package cmd

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/pkg/client"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	t.Run("nil stays nil", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, classify(nil, ""))
	})

	t.Run("invalid session maps to auth with login hint", func(t *testing.T) {
		t.Parallel()
		var ee *cli.ExitError
		require.ErrorAs(t, classify(client.ErrInvalidSession, "c1"), &ee)
		assert.Equal(t, cli.CodeAuth, ee.Code)
		require.NotEmpty(t, ee.Hints)
		assert.Contains(t, ee.Hints[0], "session login")
		assert.Equal(t, "c1", ee.Correlation)
	})

	t.Run("network error becomes friendly but keeps the cause", func(t *testing.T) {
		t.Parallel()
		netErr := &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
		var ee *cli.ExitError
		require.ErrorAs(t, classify(fmt.Errorf("connection failed: %w", netErr), ""), &ee)
		assert.Contains(t, ee.Message, "reach the Talmi server")
		assert.NotEmpty(t, ee.Hints)
		require.NotNil(t, ee.Cause)
		assert.Contains(t, ee.Cause.Error(), "connection refused")
	})

	t.Run("api 403 maps to auth and keeps correlation", func(t *testing.T) {
		t.Parallel()
		apiErr := client.APIError{StatusCode: 403, Message: "forbidden", CorrelationID: "c2"}
		var ee *cli.ExitError
		require.ErrorAs(t, classify(apiErr, ""), &ee)
		assert.Equal(t, cli.CodeAuth, ee.Code)
		assert.Equal(t, "forbidden", ee.Message)
		assert.Equal(t, "c2", ee.Correlation)
	})

	t.Run("existing ExitError passes through", func(t *testing.T) {
		t.Parallel()
		orig := &cli.ExitError{Code: cli.CodeUsage, Message: "bad flag"}
		var ee *cli.ExitError
		require.ErrorAs(t, classify(orig, ""), &ee)
		assert.Same(t, orig, ee)
	})

	t.Run("unknown error falls back to generic", func(t *testing.T) {
		t.Parallel()
		var ee *cli.ExitError
		require.ErrorAs(t, classify(errors.New("boom"), ""), &ee)
		assert.Equal(t, cli.CodeGeneric, ee.Code)
		assert.Equal(t, "boom", ee.Message)
	})
}
