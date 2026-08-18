package ratelimit

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/darmiel/talmi/internal/core"
)

func TestCostTableDefaultsAndOverride(t *testing.T) {
	t.Parallel()
	tbl := DefaultCosts()
	assert.Equal(t, 10, tbl.Cost(CategoryIssue, ClassAuthError))
	assert.Equal(t, 1, tbl.Cost(CategoryIssue, ClassSuccess))
	tbl = tbl.WithOverrides(map[Category]map[OutcomeClass]int{
		CategoryIssue: {ClassAuthError: 12},
	})
	assert.Equal(t, 12, tbl.Cost(CategoryIssue, ClassAuthError))
	assert.Equal(t, 1, tbl.Cost(CategoryIssue, ClassSuccess), "unspecified cells keep defaults")
}

func TestOutcomeClassMapping(t *testing.T) {
	t.Parallel()
	assert.Equal(t, ClassSuccess, ClassFromStatus(201))
	assert.Equal(t, ClassAuthError, ClassFromStatus(401))
	assert.Equal(t, ClassDenied, ClassFromStatus(403))
	assert.Equal(t, ClassClientError, ClassFromStatus(400))
	assert.Equal(t, ClassServerError, ClassFromStatus(500))
	assert.Equal(t, ClassDenied, ClassFromOutcome(core.OutcomeDenied))
	assert.Equal(t, ClassSuccess, ClassFromOutcome(core.OutcomeSuccess))
}
