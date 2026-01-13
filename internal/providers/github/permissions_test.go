package github

import (
	"reflect"
	"testing"
)

func TestDownscope(t *testing.T) {
	tests := []struct {
		name      string
		allowed   map[string]string
		requested map[string]string
		want      map[string]string
		wantErr   bool
	}{
		{
			name:      "Subset OK",
			allowed:   map[string]string{"contents": "write", "issues": "write"},
			requested: map[string]string{"contents": "read"},
			want:      map[string]string{"contents": "read"},
			wantErr:   false,
		},
		{
			name:      "Exceed Level",
			allowed:   map[string]string{"contents": "read"},
			requested: map[string]string{"contents": "write"},
			wantErr:   true,
		},
		{
			name:      "New Key Forbidden",
			allowed:   map[string]string{"contents": "write"},
			requested: map[string]string{"metadata": "read"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Downscope(tt.allowed, tt.requested)
			if (err != nil) != tt.wantErr {
				t.Errorf("Downscope() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Downscope() = %v, want %v", got, tt.want)
			}
		})
	}
}
