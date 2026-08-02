package source

import (
	"context"

	"github.com/darmiel/talmi/internal/config"
)

// Source loads the sourced config tree and the revision it represents.
// The revision is opque (e.g. local, or a git commit SHA) and is recorded it audit records for reproducibility.
type Source interface {
	Load(ctx context.Context) (sourced *config.SourcedConfig, revision string, err error)
}
