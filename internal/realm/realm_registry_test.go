package realm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSemanticsForAndKinds(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	for _, k := range Kinds() {
		sem, ok := SemanticsFor(k)
		is.Truef(ok, "SemanticsFor(%q) should be known", k)
		is.Equalf(k, sem.Kind(), "SemanticsFor(%q).Kind() mismatch", k)
	}

	_, ok := SemanticsFor("mystery")
	is.False(ok, "unknown kind must not resolve")

	is.ElementsMatch([]string{KindGitHub, KindArtifactory, KindTalmi}, Kinds())
}
