package secret

import (
	"fmt"
	"os"
	"strings"
)

// Ref is a scheme-prefixed reference, e.g. file:/run/secrets/key.
type Ref string

type resolver func(value string) ([]byte, error)

var resolvers = map[string]resolver{
	"file": os.ReadFile,
	"env": func(value string) ([]byte, error) {
		val, ok := os.LookupEnv(value)
		if !ok {
			return nil, fmt.Errorf("environment variable %q not set", value)
		}
		return []byte(val), nil
	},
	"raw": func(value string) ([]byte, error) {
		return []byte(value), nil
	},
}

// Resolve returns the secret bytes referenced by ref.
func Resolve(ref Ref) ([]byte, error) {
	scheme, value, ok := strings.Cut(string(ref), ":")
	if !ok {
		return nil, fmt.Errorf("secret ref is missing a scheme (want file:/env:/raw:)")
	}
	res, ok := resolvers[scheme]
	if !ok {
		return nil, fmt.Errorf("secret ref has unknown scheme %q (want file:/env:/raw:)", scheme)
	}
	b, err := res(value)
	if err != nil {
		return nil, fmt.Errorf("resolving %s secret: %w", scheme, err)
	}
	return b, nil
}

// ResolveString is Resolve returning a string.
func ResolveString(ref Ref) (string, error) {
	b, err := Resolve(ref)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
