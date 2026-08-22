package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveNodeIDDefaultsToHostname(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	hostname, err := os.Hostname()
	must.NoError(err)

	is.Equal(hostname, ResolveNodeID(""), "an empty node id must default to the OS hostname")
}

func TestResolveNodeIDReturnsConfiguredValue(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	is.Equal("node-a", ResolveNodeID("node-a"), "a configured node id must be returned verbatim")
}
