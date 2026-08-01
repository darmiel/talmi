package store

import (
	"crypto/sha256"
	"encoding/hex"
)

func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
