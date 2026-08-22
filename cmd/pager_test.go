package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/cli"
)

func ttyDeps() (Deps, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return Deps{IO: cli.IOStreams{Out: &out, ErrOut: &errOut, IsTTY: true}}, &out, &errOut
}

func TestPageOutputWritesDirectlyWhenDisabled(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	d, out, _ := ttyDeps()
	must.NoError(pageOutput(d, true, "hello\n"))
	is.Equal("hello\n", out.String(), "disabled paging writes straight to Out even on a TTY")
}

func TestPageOutputWritesDirectlyWhenNotTTY(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	var out bytes.Buffer
	d := Deps{IO: cli.IOStreams{Out: &out, ErrOut: &bytes.Buffer{}, IsTTY: false}}
	must.NoError(pageOutput(d, false, "hello\n"))
	is.Equal("hello\n", out.String())
}

func TestPageOutputCatShortCircuits(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	t.Setenv("TALMI_PAGER", "cat")
	d, out, _ := ttyDeps()
	must.NoError(pageOutput(d, false, "hello\n"))
	is.Equal("hello\n", out.String(), "a 'cat' pager is written directly, not spawned")
}

func TestPageOutputPipesThroughPager(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	// "cat -" is not the special-cased "cat", so it exercises the exec path.
	t.Setenv("TALMI_PAGER", "cat -")
	d, out, _ := ttyDeps()
	must.NoError(pageOutput(d, false, "piped-content\n"))
	is.Equal("piped-content\n", out.String(), "content flows through the spawned pager to Out")
}

func TestPageOutputFallsBackWhenPagerMissing(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	t.Setenv("TALMI_PAGER", "talmi-no-such-pager-xyz")
	d, out, _ := ttyDeps()
	must.NoError(pageOutput(d, false, "safe\n"))
	is.Contains(out.String(), "safe", "a broken pager must not lose the output")
}
