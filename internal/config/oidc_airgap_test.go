package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOIDCConfigJWKSValidation(t *testing.T) {
	t.Parallel()
	base := OIDCConfig{IssuerURL: "https://iss.example", ClientID: "aud"}

	t.Run("jwks alone is ok", func(t *testing.T) {
		t.Parallel()
		c := base
		c.JWKS = "raw:{}"
		assert.NoError(t, c.Validate())
	})
	t.Run("jwks_url alone is ok", func(t *testing.T) {
		t.Parallel()
		c := base
		c.JWKSURL = "https://mirror/jwks"
		assert.NoError(t, c.Validate())
	})
	t.Run("both is an error", func(t *testing.T) {
		t.Parallel()
		c := base
		c.JWKS = "raw:{}"
		c.JWKSURL = "https://mirror/jwks"
		assert.Error(t, c.Validate())
	})
	t.Run("neither is ok (discovery)", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, base.Validate())
	})
	t.Run("missing issuer_url still errors", func(t *testing.T) {
		t.Parallel()
		c := base
		c.IssuerURL = ""
		assert.Error(t, c.Validate())
	})
}
