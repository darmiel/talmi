package engine

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

func managerFixture(t *testing.T) (*PolicyManager, core.Rule) {
	t.Helper()
	reg := realm.NewRegistry()
	reg.Register("ghes-corp", realm.GitHub{})
	rule := core.Rule{
		Name:  "read",
		Match: core.Match{Issuer: "cc", AllowEmptyCondition: true},
		Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
	}
	return NewManager([]core.Rule{rule}, reg), rule
}

func readReq() []core.ResourceRequest {
	return []core.ResourceRequest{{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}}}
}

func TestManagerReloadPreservesRealms(t *testing.T) {
	t.Parallel()
	m, rule := managerFixture(t)

	// initial engine authorizes
	require.True(t, m.GetEngine().Authorize(&core.Principal{Issuer: "cc"}, readReq()).Authorized)

	// reload — this is where the nil-realms bug used to panic
	require.NoError(t, m.Update([]core.Rule{rule}))

	dec := m.GetEngine().Authorize(&core.Principal{Issuer: "cc"}, readReq())
	assert.True(t, dec.Authorized, "reloaded engine must still resolve realms")
}

func TestManagerConcurrentUpdateAndAuthorize(t *testing.T) {
	t.Parallel()
	m, rule := managerFixture(t)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() { defer wg.Done(); _ = m.Update([]core.Rule{rule}) }()
		go func() {
			defer wg.Done()
			m.GetEngine().Authorize(&core.Principal{Issuer: "cc"}, readReq())
		}()
	}
	wg.Wait() // run with -race; must be clean
}
