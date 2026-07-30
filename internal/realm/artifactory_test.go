package realm

import (
	"testing"

	"github.com/darmiel/talmi/internal/core"
)

func TestParseArtifactoryLevel(t *testing.T) {
	tests := []struct {
		in     string
		want   afLevel
		wantOK bool
	}{
		{"read", afRead, true},
		{"annotate", afAnnotate, true},
		{"write", afWrite, true},
		{"WRITE", afWrite, true},
		{"readwrite", afWrite, true},
		{"delete", afNone, false},
		{"", afNone, false},
	}
	for _, tt := range tests {
		got, ok := parseArtifactoryLevel(tt.in)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("parseAFLevel(%q) = (%d,%v), want (%d,%v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestArtifactoryCovers(t *testing.T) {
	tests := []struct {
		name   string
		allows []core.Allow
		req    core.ResourceRequest
		want   bool
	}{
		{
			name:   "read allow covers read",
			allows: []core.Allow{{Resources: []string{"artifactory:docker-*"}, Actions: []core.Action{"read"}}},
			req:    core.ResourceRequest{Resource: "artifactory:docker-prod", Actions: []core.Action{"read"}},
			want:   true,
		},
		{
			name:   "write allow covers annotate and read",
			allows: []core.Allow{{Resources: []string{"artifactory:docker-*"}, Actions: []core.Action{"write"}}},
			req: core.ResourceRequest{
				Resource: "artifactory:docker-prod",
				Actions:  []core.Action{"read", "annotate"},
			},
			want: true,
		},
		{
			name:   "read allow does not cover write",
			allows: []core.Allow{{Resources: []string{"artifactory:docker-*"}, Actions: []core.Action{"read"}}},
			req:    core.ResourceRequest{Resource: "artifactory:docker-prod", Actions: []core.Action{"write"}},
			want:   false,
		},
		{
			name:   "glob does not match different repo",
			allows: []core.Allow{{Resources: []string{"artifactory:docker-*"}, Actions: []core.Action{"read"}}},
			req:    core.ResourceRequest{Resource: "artifactory:npm-prod", Actions: []core.Action{"read"}},
			want:   false,
		},
		{
			name:   "cross-realm allow does not match",
			allows: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
			req:    core.ResourceRequest{Resource: "artifactory:docker-prod", Actions: []core.Action{"read"}},
			want:   false,
		},
	}
	af := Artifactory{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := af.Covers(tt.allows, tt.req)
			if got != tt.want {
				t.Errorf("Covers() = %v (reason %q), want %v", got, reason, tt.want)
			}
			if !got && reason == "" {
				t.Error("Covers() returned false with empty reason")
			}
		})
	}
}

func TestArtifactoryCompareLevel(t *testing.T) {
	af := Artifactory{}
	tests := []struct {
		a, b    core.Action
		want    int
		wantErr bool
	}{
		{"read", "annotate", -1, false},
		{"annotate", "write", -1, false},
		{"read", "write", -1, false},
		{"write", "read", 1, false},
		{"read", "read", 0, false},
		{"read", "delete", 0, true},
	}
	for _, tt := range tests {
		got, err := af.CompareLevel(tt.a, tt.b)
		if (err != nil) != tt.wantErr {
			t.Errorf("CompareLevel(%q,%q) err = %v, wantErr %v", tt.a, tt.b, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("CompareLevel(%q,%q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestArtifactoryValidateResourcePattern(t *testing.T) {
	af := Artifactory{}
	tests := []struct {
		pattern string
		wantErr bool
	}{
		{"artifactory:docker-*", false},
		{"artifactory:maven-releases", false},
		{"no-colon", true},
		{"artifactory:", true},
		{"artifactory:[", true},
	}
	for _, tt := range tests {
		if err := af.ValidateResourcePattern(tt.pattern); (err != nil) != tt.wantErr {
			t.Errorf("ValidateResourcePattern(%q) err = %v, wantErr %v", tt.pattern, err, tt.wantErr)
		}
	}
}
