package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClient is defined in fake_test.go.

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
