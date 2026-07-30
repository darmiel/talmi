package realm

import (
	"testing"

	"github.com/darmiel/talmi/internal/core"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		res     core.Resource
		want    bool
	}{
		{"ghes-corp:acme/repo", "ghes-corp:acme/repo", true}, // exact
		{"ghes-corp:acme/*", "ghes-corp:acme/repo", true},    // single-level glob
		{"ghes-corp:acme/service-*", "ghes-corp:acme/service-a", true},
		{"ghes-corp:acme/service-*", "ghes-corp:acme/lib", false},
		{"ghes-corp:acme/*", "ghes-corp:acme/group/repo", false}, // * does not cross /
		{"ghes-corp:*/*", "ghes-corp:acme/repo", true},           // two-level glob
		{"artifactory:docker-*", "ghes-corp:acme/repo", false},   // cross-realm
		{"ghes-corp:acme/[", "ghes-corp:acme/x", false},          // invalid glob → false, no panic
		{"ghes-corp:acme/repo", "ghes-corp:acme/other", false},   // non-match
	}
	for _, tt := range tests {
		if got := matchPattern(tt.pattern, tt.res); got != tt.want {
			t.Errorf("matchPattern(%q,%q) = %v, want %v", tt.pattern, tt.res, got, tt.want)
		}
	}
}

func TestMatchAnyPattern(t *testing.T) {
	res := core.Resource("ghes-corp:acme/service-a")
	if !matchAnyPattern([]string{"ghes-corp:other/*", "ghes-corp:acme/service-*"}, res) {
		t.Error("expected match when one of several patterns matches")
	}
	if matchAnyPattern([]string{"ghes-corp:other/*", "ghes-corp:lib/*"}, res) {
		t.Error("expected no match when none of the patterns match")
	}
	if matchAnyPattern(nil, res) {
		t.Error("empty pattern list must not match")
	}
}

func TestValidGlob(t *testing.T) {
	if err := validGlob("ghes-corp:acme/service-*"); err != nil {
		t.Errorf("valid glob reported error: %v", err)
	}
	if err := validGlob("ghes-corp:acme/["); err == nil {
		t.Error("invalid glob did not report error")
	}
}
