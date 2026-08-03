package audit

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/darmiel/talmi/internal/core"
)

const (
	GitHubFingerprintType = "github"
	StubFingerprintType   = "stub"
)

var fingerprintRegistry = map[string]core.Fingerprinter{}

func RegisterFingerprinter(providerType string, fn core.Fingerprinter) {
	fingerprintRegistry[providerType] = fn
}

func CalculateFingerprint(providerType, token string) string {
	fn, ok := fingerprintRegistry[providerType]
	if !ok {
		return ""
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
	RegisterFingerprinter(StubFingerprintType, calculateStubFingerprint)
}

// calculateGitHubFingerprint calculates a fingerprint for a GitHub token using SHA-256 and base64 encoding.
func calculateGitHubFingerprint(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// calculateStubFingerprint is an alias for calculateGitHubFingerprint, used for testing purposes.
var calculateStubFingerprint = calculateGitHubFingerprint
