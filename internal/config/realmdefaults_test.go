package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRealmForType(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	for typ, want := range map[string]string{
		KindGitHubApp:   "github",
		KindArtifactory: "artifactory",
		"talmi":         "talmi",
	} {
		got, ok := DefaultRealmForType(typ)
		is.True(ok, "type %q should have a default", typ)
		is.Equal(want, got, "type %q", typ)
	}

	_, ok := DefaultRealmForType("mystery")
	is.False(ok, "unknown type has no default")
}

func TestNormalizeRealms(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	in := []RealmBlock{
		{Type: KindGitHubApp},                // omitted -> github
		{Realm: "corp", Type: KindGitHubApp}, // explicit -> untouched
		{Type: "mystery"},                    // no default -> left empty
	}

	out, defaulted := NormalizeRealms(in)

	must.Len(out, 3)
	is.Equal("github", out[0].Realm)
	is.Equal("corp", out[1].Realm)
	is.Equal("", out[2].Realm, "no-default type stays empty")

	is.Equal([]DefaultedRealm{{Type: KindGitHubApp, Name: "github"}}, defaulted)

	is.Equal("", in[0].Realm, "input slice must not be mutated")
}
