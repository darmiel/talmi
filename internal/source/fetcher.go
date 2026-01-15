package source

import (
	"context"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/logging"
)

type Fetcher interface {
	Fetch(ctx context.Context, log logging.InternalLogger) ([]core.Rule, error)
}
