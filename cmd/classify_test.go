package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/url"
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

	t.Run("network error is friendly, names the host, keeps the cause", func(t *testing.T) {
		t.Parallel()
		urlErr := &url.Error{
			Op:  "Get",
			URL: "http://localhost:8080/v2/audit",
			Err: &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")},
		}
		var ee *cli.ExitError
		require.ErrorAs(t, classify(urlErr, ""), &ee)
		assert.Contains(t, ee.Message, "localhost:8080")
		assert.NotEmpty(t, ee.Hints)
		require.NotNil(t, ee.Cause)
	})

	t.Run("api 401 maps to auth", func(t *testing.T) {
		t.Parallel()
		var ee *cli.ExitError
		require.ErrorAs(t, classify(client.APIError{StatusCode: 401, Message: "no session"}, ""), &ee)
		assert.Equal(t, cli.CodeAuth, ee.Code)
	})

	t.Run("api 403 maps to denied with a rules hint and keeps correlation", func(t *testing.T) {
		t.Parallel()
		apiErr := client.APIError{StatusCode: 403, Message: "forbidden", CorrelationID: "c2"}
		var ee *cli.ExitError
		require.ErrorAs(t, classify(apiErr, ""), &ee)
		assert.Equal(t, cli.CodeDenied, ee.Code)
		assert.Equal(t, "forbidden", ee.Message)
		assert.Equal(t, "c2", ee.Correlation)
		require.NotEmpty(t, ee.Hints)
	})

	t.Run("api 5xx suggests a retry", func(t *testing.T) {
		t.Parallel()
		var ee *cli.ExitError
		require.ErrorAs(t, classify(client.APIError{StatusCode: 503, Message: "unavailable"}, ""), &ee)
		require.NotEmpty(t, ee.Hints)
		assert.Regexp(t, `(?i)(retry|try again)`, ee.Hints[0])
	})

	t.Run("existing ExitError passes through", func(t *testing.T) {
		t.Parallel()
		orig := &cli.ExitError{Code: cli.CodeUsage, Message: "bad flag"}
		var ee *cli.ExitError
		require.ErrorAs(t, classify(orig, ""), &ee)
		assert.Same(t, orig, ee)
	})

	t.Run("cobra usage error becomes CodeUsage", func(t *testing.T) {
		t.Parallel()
		var ee *cli.ExitError
		require.ErrorAs(t, classify(errors.New(`unknown flag: --nope`), ""), &ee)
		assert.Equal(t, cli.CodeUsage, ee.Code)
	})

	t.Run("unknown error falls back to generic", func(t *testing.T) {
		t.Parallel()
		var ee *cli.ExitError
		require.ErrorAs(t, classify(errors.New("boom"), ""), &ee)
		assert.Equal(t, cli.CodeGeneric, ee.Code)
		assert.Equal(t, "boom", ee.Message)
	})
}

func TestIsUsageError(t *testing.T) {
	t.Parallel()
	assert.True(t, isUsageError(errors.New(`unknown command "x" for "talmi"`)))
	assert.True(t, isUsageError(errors.New("accepts at most 1 arg(s), received 2")))
	assert.False(t, isUsageError(fmt.Errorf("some internal failure")))
}
