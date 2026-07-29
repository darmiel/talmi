package realm

import (
	"testing"

	"github.com/darmiel/talmi/internal/core"
)

type fakeSemantics struct {
	kind string
}

func (f *fakeSemantics) Kind() string {
	return f.kind
}

func (f *fakeSemantics) Covers(allows []core.Allow, req core.ResourceRequest) (bool, string) {
	return false, "fake"
}

func (f *fakeSemantics) CompareLevel(a, b core.Action) (int, error) {
	return 0, nil
}

func (f *fakeSemantics) ValidateResourcePattern(pattern string) error {
	return nil
}

func TestRegistryGet(t *testing.T) {
	reg := NewRegistry()
	gh := fakeSemantics{kind: "github-app"}
	reg.Register("ghes-corp", &gh)
	reg.Register("github-com", &gh)

	if s, ok := reg.Get("ghes-corp"); !ok || s.Kind() != "github-app" {
		t.Errorf("Get(ghes-corp) = (%v, %v), want (github-app, true)", s, ok)
	}
	if _, ok := reg.Get("unknown"); ok {
		t.Errorf("Get(unknown) = (_, %v), want (_, false)", ok)
	}
}
