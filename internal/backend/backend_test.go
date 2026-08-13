package backend

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/darmiel/talmi/internal/config"
)

func TestSupportsAPIDiscovery(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	gh, ok := Lookup(config.KindGitHubApp)
	is.True(ok)
	is.True(gh.SupportsAPIDiscovery, "github-app discovers capabilities live")

	af, ok := Lookup(config.KindArtifactory)
	is.True(ok)
	is.False(af.SupportsAPIDiscovery, "artifactory capability is static")
}
