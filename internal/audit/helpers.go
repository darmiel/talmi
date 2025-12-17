package audit

import (
	"fmt"

	"github.com/darmiel/talmi/internal/buildinfo"
)

func CreateUserAgent(correlationID, principalID, provider string) string {
	return fmt.Sprintf("Talmi/%s (correlation_id=%s; principal=%s; provider=%s)",
		buildinfo.Version, correlationID, principalID, provider)
}
