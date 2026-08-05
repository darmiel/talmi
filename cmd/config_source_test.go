package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateVetSourceFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		local   bool
		ref     string
		wantErr bool
	}{
		{name: "no flags", local: false, ref: "", wantErr: false},
		{name: "local only", local: true, ref: "", wantErr: false},
		{name: "ref only", local: false, ref: "main", wantErr: false},
		{name: "ref and local conflict", local: true, ref: "main", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateVetSourceFlags(tt.local, tt.ref)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
