package configvet

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleReport() Report {
	var r Report
	f := r.errorf("CFG-XREF-ISSUER", "rules", "rules[deploy].match.issuer",
		"rule %q references unknown issuer %q", "deploy", "githubb")
	f.Suggestions = []string{"github"}
	r.warnf("CFG-UNUSED-ISSUER", "issuers", "issuers[legacy]",
		"issuer %q is defined but never referenced", "legacy").Help = "remove it or reference it"
	return r
}

func TestRenderText(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	var buf bytes.Buffer
	RenderText(&buf, sampleReport(), false)
	out := buf.String()

	is.Contains(out, "error[CFG-XREF-ISSUER] rules[deploy].match.issuer")
	is.Contains(out, `references unknown issuer "githubb"`)
	is.Contains(out, "did you mean: github")
	is.Contains(out, "warn[CFG-UNUSED-ISSUER] issuers[legacy]")
	is.Contains(out, "help: remove it or reference it")
	is.Contains(out, "1 error(s), 1 warning(s)")
	// errors must be rendered before warnings
	is.Less(strings.Index(out, "CFG-XREF-ISSUER"), strings.Index(out, "CFG-UNUSED-ISSUER"))
}

func TestRenderTextClean(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	RenderText(&buf, Report{}, false)
	assert.Contains(t, buf.String(), "no issues found")
}

func TestRenderJSON(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	var buf bytes.Buffer
	require.NoError(t, RenderJSON(&buf, sampleReport()))

	var decoded struct {
		Findings []Finding `json:"findings"`
		Errors   int       `json:"errors"`
		Warnings int       `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	is.Equal(1, decoded.Errors)
	is.Equal(1, decoded.Warnings)
	require.Len(t, decoded.Findings, 2)
	is.Equal("CFG-XREF-ISSUER", decoded.Findings[0].Code)
	is.Equal([]string{"github"}, decoded.Findings[0].Suggestions)
}
