package issuers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// SessionSigner signs and verifies Talmi admin session JWTs.
// The default signing algorithm is ES256, but HS256 is also supported.
type SessionSigner struct {
	method    jwt.SigningMethod
	signKey   any
	verifyKey any
}

func NewSessionSigner(algorithm string, key []byte) (*SessionSigner, error) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "", "ES256":
		priv, err := jwt.ParseECPrivateKeyFromPEM(key)
		if err != nil {
			return nil, fmt.Errorf("parsing ES256 private key: %w", err)
		}
		return &SessionSigner{
			method:    jwt.SigningMethodES256,
			signKey:   priv,
			verifyKey: &priv.PublicKey,
		}, nil
	case "HS256":
		if len(key) == 0 {
			return nil, fmt.Errorf("HS256 signing key is empty")
		}
		return &SessionSigner{
			method:    jwt.SigningMethodHS256,
			signKey:   key,
			verifyKey: key,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
}

// Sign issues a JWT with the given claims and signs it using the configured signing method and key.
func (s *SessionSigner) Sign(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(s.method, claims).SignedString(s.signKey)
}

func (s *SessionSigner) keyfunc(token *jwt.Token) (any, error) {
	if token.Method.Alg() != s.method.Alg() {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return s.verifyKey, nil
}

// NewEphemeralSigner generates a new ephemeral ES256 key pair and returns a SessionSigner that uses it.
func NewEphemeralSigner() (*SessionSigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral ES256 key: %w", err)
	}
	return &SessionSigner{
		method:    jwt.SigningMethodES256,
		signKey:   priv,
		verifyKey: &priv.PublicKey,
	}, nil
}
