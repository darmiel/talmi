package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClient embeds the TalmiClient facade so a test only overrides the methods
// it exercises; any unimplemented method panics if called.
type fakeClient struct{ TalmiClient }

func TestDepsNewClientReturnsInjected(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{}
	d := Deps{
		NewClient: func() (TalmiClient, error) { return fake, nil },
	}

	got, err := d.NewClient()
	require.NoError(t, err)
	gotFake, ok := got.(*fakeClient)
	require.True(t, ok)
	assert.Same(t, fake, gotFake)
}
