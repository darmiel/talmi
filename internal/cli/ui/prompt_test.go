package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfirm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "y", input: "y\n", want: true},
		{name: "yes", input: "yes\n", want: true},
		{name: "uppercase y", input: "Y\n", want: true},
		{name: "n", input: "n\n", want: false},
		{name: "empty defaults to no", input: "\n", want: false},
		{name: "garbage is no", input: "maybe\n", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			got, err := Confirm(strings.NewReader(tt.input), &out, "proceed?")
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Contains(t, out.String(), "proceed?")
		})
	}
}
