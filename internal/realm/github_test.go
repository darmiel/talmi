package realm

import (
	"testing"

	"github.com/darmiel/talmi/internal/core"
)

func TestGitHubCovers(t *testing.T) {
	tests := []struct {
		name   string
		allows []core.Allow
		req    core.ResourceRequest
		want   bool
	}{
		{
			name:   "read allow covers read request",
			allows: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
			req:    core.ResourceRequest{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}},
			want:   true,
		},
		{
			name:   "read allow does not cover write request",
			allows: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
			req:    core.ResourceRequest{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:write"}},
			want:   false,
		},
		{
			name:   "write allow covers read request (write >= read)",
			allows: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:write"}}},
			req:    core.ResourceRequest{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}},
			want:   true,
		},
		{
			name: "glob service-* matches service-a",
			allows: []core.Allow{
				{
					Resources: []string{"ghes-corp:acme/service-*"},
					Actions:   []core.Action{"contents:write"},
				},
			},
			req: core.ResourceRequest{
				Resource: "ghes-corp:acme/service-a",
				Actions:  []core.Action{"contents:write"},
			},
			want: true,
		},
		{
			name: "glob service-* does not match lib",
			allows: []core.Allow{
				{
					Resources: []string{"ghes-corp:acme/service-*"},
					Actions:   []core.Action{"contents:write"},
				},
			},
			req:  core.ResourceRequest{Resource: "ghes-corp:acme/lib", Actions: []core.Action{"contents:write"}},
			want: false,
		},
		{
			name: "union of two allows covers a two-action request",
			allows: []core.Allow{
				{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}},
				{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"actions:write"}},
			},
			req: core.ResourceRequest{
				Resource: "ghes-corp:acme/x",
				Actions:  []core.Action{"contents:read", "actions:write"},
			},
			want: true,
		},
		{
			name: "first allow alone does not cover both actions",
			allows: []core.Allow{
				{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}},
			},
			req: core.ResourceRequest{
				Resource: "ghes-corp:acme/x",
				Actions:  []core.Action{"contents:read", "actions:write"},
			},
			want: false,
		},
		{
			name:   "cross-realm allow does not match",
			allows: []core.Allow{{Resources: []string{"artifactory:docker-*"}, Actions: []core.Action{"read"}}},
			req:    core.ResourceRequest{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}},
			want:   false,
		},
	}

	gh := GitHub{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := gh.Covers(tt.allows, tt.req)
			if got != tt.want {
				t.Errorf("Covers() = %v, want %v; reason: %s", got, tt.want, reason)
			}
			if !got && reason == "" {
				t.Errorf("Covers() returned false but reason is empty")
			}
		})
	}
}

func TestGitHubActionCovered(t *testing.T) {
	allows := []core.Allow{
		{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}},
		{Resources: []string{"ghes-corp:acme/service-*"}, Actions: []core.Action{"contents:write", "actions:write"}},
	}
	tests := []struct {
		name string
		res  core.Resource
		want core.Action
		ok   bool
	}{
		{"read via broad allow", "ghes-corp:acme/x", "contents:read", true},
		{"write via narrow allow", "ghes-corp:acme/service-a", "contents:write", true},
		{"read satisfied by write allow", "ghes-corp:acme/service-a", "contents:read", true},
		{"write denied on non-service repo", "ghes-corp:acme/lib", "contents:write", false},
		{"unknown requested action", "ghes-corp:acme/x", "contents:bogus", false},
		{"permission not granted anywhere", "ghes-corp:acme/x", "packages:read", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gitHubActionCovered(allows, tt.res, tt.want); got != tt.ok {
				t.Errorf("githubActionCovered(%q,%q) = %v, want %v", tt.res, tt.want, got, tt.ok)
			}
		})
	}
}

func TestParseGitHubLevel(t *testing.T) {
	tests := []struct {
		in     string
		want   ghLevel
		wantOK bool
	}{
		{"read", ghRead, true},
		{"readonly", ghRead, true},
		{"READ", ghRead, true}, // case-insensitive
		{"write", ghWrite, true},
		{"readwrite", ghWrite, true},
		{"admin", ghAdmin, true},
		{"bogus", ghNone, false},
		{"", ghNone, false},
	}
	for _, tt := range tests {
		got, ok := parseGitHubLevel(tt.in)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("parseGHLevel(%q) = (%d,%v), want (%d,%v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestParseGitHubAction(t *testing.T) {
	tests := []struct {
		in       core.Action
		wantPerm string
		wantLvl  ghLevel
		wantOK   bool
	}{
		{"contents:write", "contents", ghWrite, true},
		{"metadata:read", "metadata", ghRead, true},
		{"actions:admin", "actions", ghAdmin, true},
		{":read", "", ghNone, false},                  // empty permission
		{"contents", "", ghNone, false},               // no colon
		{"contents:", "contents", ghNone, false},      // empty level
		{"contents:bogus", "contents", ghNone, false}, // unknown level
		{"", "", ghNone, false},                       // empty
		{"a:b:c", "a", ghNone, false},                 // splits on first colon, "b:c" invalid level
	}
	for _, tt := range tests {
		p, l, ok := parseGitHubAction(tt.in)
		if p != tt.wantPerm || l != tt.wantLvl || ok != tt.wantOK {
			t.Errorf("parseGHAction(%q) = (%q,%d,%v), want (%q,%d,%v)",
				tt.in, p, l, ok, tt.wantPerm, tt.wantLvl, tt.wantOK)
		}
	}
}

func TestGitHubCompareLevel(t *testing.T) {
	gh := GitHub{}

	tests := []struct {
		a, b    core.Action
		want    int
		wantErr bool
	}{
		{"contents:read", "contents:write", -1, false},
		{"contents:write", "contents:read", 1, false},
		{"contents:read", "contents:read", 0, false},
		{"contents:read", "actions:read", 0, true},   // different permission
		{"contents:bogus", "contents:read", 0, true}, // unknown level
	}

	for _, tt := range tests {
		t.Run(string(tt.a)+" vs "+string(tt.b), func(t *testing.T) {
			got, err := gh.CompareLevel(tt.a, tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareLevel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && got != tt.want {
				t.Errorf("CompareLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGitHubValidateResourcePattern(t *testing.T) {
	gh := GitHub{}
	tests := []struct {
		pattern string
		wantErr bool
	}{
		{"ghes-corp:acme/service-*", false},
		{"ghes-corp:acme/repo", false},
		{"ghes-corp:*/*", false},
		{"no-colon", true},         // missing realm
		{"ghes-corp:", true},       // missing body
		{"ghes-corp:acme/[", true}, // invalid glob
	}
	for _, tt := range tests {
		err := gh.ValidateResourcePattern(tt.pattern)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateResourcePattern(%q) err = %v, wantErr %v", tt.pattern, err, tt.wantErr)
		}
	}
}
