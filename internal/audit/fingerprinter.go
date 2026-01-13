package audit

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/darmiel/talmi/internal/core"
)

const (
	DefaultFingerprintType = "default"
	GitHubFingerprintType  = "github"
	TalmiFingerprintType   = "talmi_jwt"
	StubFingerprintType    = "stub"
)

var fingerprintRegistry = map[string]core.Fingerprinter{
	DefaultFingerprintType: func(_ string) string {
		return "(n/a)"
	},
}

func RegisterFingerprinter(providerType string, fn core.Fingerprinter) {
	fingerprintRegistry[providerType] = fn
}

func CalculateFingerprint(providerType, token string) string {
	fn, ok := fingerprintRegistry[providerType]
	if !ok {
		fn = fingerprintRegistry["default"]
	}
	return fn(token)
}

func RegisteredFingerprinterTypes() []string {
	types := make([]string, 0, len(fingerprintRegistry))
	for k := range fingerprintRegistry {
		types = append(types, k)
	}
	return types
}

func init() {
	RegisterFingerprinter(GitHubFingerprintType, calculateGitHubFingerprint)
	RegisterFingerprinter(TalmiFingerprintType, calculateGitHubFingerprint)
	RegisterFingerprinter(StubFingerprintType, calculateGitHubFingerprint)
}

func calculateGitHubFingerprint(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}
