package configvet

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/providers/stub"
)

func TestLive(t *testing.T) {
	t.Parallel()

	t.Run("all covered - no live errors", func(t *testing.T) {
		t.Parallel()
		ps := []core.ResourceProvider{
			stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read")),
		}
		r := Live(context.Background(), LiveInput{Static: baseline(), Providers: ps})
		assert.Nil(t, findByCode(r, "CFG-CAPABILITY"))
		assert.Nil(t, findByCode(r, "CFG-COVERAGE"))
	})

	t.Run("capability failure is reported", func(t *testing.T) {
		t.Parallel()
		ps := []core.ResourceProvider{
			stub.New("gh", "ghes-corp", stub.WithCapabilitiesError(errors.New("401 unauthorized"))),
		}
		r := Live(context.Background(), LiveInput{Static: baseline(), Providers: ps})
		f := findByCode(r, "CFG-CAPABILITY")
		require.NotNil(t, f, "findings: %+v", r.Findings)
		assert.Equal(t, SeverityError, f.Severity)
	})

	t.Run("uncovered realm is reported", func(t *testing.T) {
		t.Parallel()
		// the only provider serves a different realm than the rule needs
		ps := []core.ResourceProvider{
			stub.New("x", "other", stub.WithResources("other:a/b"), stub.WithMaxActions("read")),
		}
		r := Live(context.Background(), LiveInput{Static: baseline(), Providers: ps})
		f := findByCode(r, "CFG-COVERAGE")
		require.NotNil(t, f, "findings: %+v", r.Findings)
		assert.Equal(t, SeverityError, f.Severity)
	})

	t.Run("Live is a superset of Static", func(t *testing.T) {
		t.Parallel()
		in := baseline()
		in.Sourced.Rules[0].Match.Issuer = "nope" // a static error
		r := Live(context.Background(), LiveInput{
			Static:    in,
			Providers: []core.ResourceProvider{stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))},
		})
		assert.NotNil(t, findByCode(r, "CFG-XREF-ISSUER"), "Live must include Static findings")
	})
}
