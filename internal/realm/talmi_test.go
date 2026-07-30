package realm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/darmiel/talmi/internal/core"
)

func TestTalmiCovers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		allows []core.Allow
		req    core.ResourceRequest
		want   bool
	}{
		{
			name:   "exact action on session covered",
			allows: []core.Allow{{Resources: []string{"talmi:session"}, Actions: []core.Action{"audit:read"}}},
			req:    core.ResourceRequest{Resource: "talmi:session", Actions: []core.Action{"audit:read"}},
			want:   true,
		},
		{
			name:   "different action not covered (no ordering)",
			allows: []core.Allow{{Resources: []string{"talmi:session"}, Actions: []core.Action{"audit:read"}}},
			req:    core.ResourceRequest{Resource: "talmi:session", Actions: []core.Action{"task:trigger"}},
			want:   false,
		},
		{
			name:   "role glob matches",
			allows: []core.Allow{{Resources: []string{"talmi:role/*"}, Actions: []core.Action{"task:trigger"}}},
			req:    core.ResourceRequest{Resource: "talmi:role/admin", Actions: []core.Action{"task:trigger"}},
			want:   true,
		},
		{
			name:   "cross-realm allow does not match",
			allows: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
			req:    core.ResourceRequest{Resource: "talmi:session", Actions: []core.Action{"audit:read"}},
			want:   false,
		},
	}
	tl := Talmi{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			got, reason := tl.Covers(tt.allows, tt.req)
			is.Equal(tt.want, got, "reason: %s", reason)
			if !got {
				is.NotEmpty(reason, "false result must carry a reason")
			}
		})
	}
}

func TestTalmiCompareLevel(t *testing.T) {
	tl := Talmi{}
	if got, err := tl.CompareLevel("audit:read", "audit:read"); err != nil || got != 0 {
		t.Errorf("CompareLevel(equal) = (%d,%v), want (0,nil)", got, err)
	}
	if _, err := tl.CompareLevel("audit:read", "task:trigger"); err == nil {
		t.Error("CompareLevel(unequal) expected error")
	}
}

func TestTalmiValidateResourcePattern(t *testing.T) {
	tl := Talmi{}
	tests := []struct {
		pattern string
		wantErr bool
	}{
		{"talmi:session", false},
		{"talmi:role/*", false},
		{"no-colon", true},
		{"talmi:", true},
	}
	for _, tt := range tests {
		if err := tl.ValidateResourcePattern(tt.pattern); (err != nil) != tt.wantErr {
			t.Errorf("ValidateResourcePattern(%q) err = %v, wantErr %v", tt.pattern, err, tt.wantErr)
		}
	}
}
