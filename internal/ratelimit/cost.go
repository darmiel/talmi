package ratelimit

import (
	"net/http"

	"github.com/darmiel/talmi/internal/core"
)

// Category si the kind of operation being priced.
type Category string

const (
	CategoryIssue        Category = "issue"
	CategoryRevoke       Category = "revoke"
	CategoryExplain      Category = "explain"
	CategoryProviders    Category = "providers"
	CategoryResolve      Category = "resolve"
	CategoryAudit        Category = "audit"
	CategoryTaskTrigger  Category = "task_trigger"
	CategorySessionLogin Category = "session_login"
	CategoryWebhook      Category = "webhook"
	CategoryDefault      Category = ""
)

// OutcomeClass buckets a request outcome for pricing.
type OutcomeClass string

const (
	ClassSuccess     OutcomeClass = "success"
	ClassDenied      OutcomeClass = "denied"
	ClassAuthError   OutcomeClass = "auth_error"
	ClassClientError OutcomeClass = "client_error"
	ClassServerError OutcomeClass = "server_error"
)

// CostTable prices (category, class) pairs.
type CostTable struct {
	rows map[Category]map[OutcomeClass]int
}

func DefaultCosts() CostTable {
	return CostTable{
		rows: map[Category]map[OutcomeClass]int{
			CategoryIssue: {
				ClassSuccess:     1,
				ClassDenied:      4,
				ClassAuthError:   10,
				ClassClientError: 3,
				ClassServerError: 1,
			},
			CategoryRevoke: {
				ClassSuccess:     1,
				ClassDenied:      4,
				ClassAuthError:   10,
				ClassClientError: 3,
				ClassServerError: 1,
			},
			CategoryExplain: {
				ClassSuccess:     1,
				ClassDenied:      2,
				ClassAuthError:   8,
				ClassClientError: 2,
				ClassServerError: 1,
			},
			CategoryProviders: {
				ClassSuccess:     2,
				ClassDenied:      2,
				ClassAuthError:   8,
				ClassClientError: 2,
				ClassServerError: 1,
			},
			CategoryResolve: {
				ClassSuccess:     2,
				ClassDenied:      2,
				ClassAuthError:   8,
				ClassClientError: 2,
				ClassServerError: 1,
			},
			CategoryAudit: {
				ClassSuccess:     3,
				ClassDenied:      3,
				ClassAuthError:   8,
				ClassClientError: 2,
				ClassServerError: 1,
			},
			CategoryTaskTrigger: {
				ClassSuccess:     8,
				ClassDenied:      8,
				ClassAuthError:   8,
				ClassClientError: 4,
				ClassServerError: 1,
			},
			CategorySessionLogin: {
				ClassSuccess:     2,
				ClassDenied:      2,
				ClassAuthError:   10,
				ClassClientError: 3,
				ClassServerError: 1,
			},
			CategoryWebhook: {
				ClassSuccess:     1,
				ClassDenied:      1,
				ClassAuthError:   10,
				ClassClientError: 2,
				ClassServerError: 1,
			},
			CategoryDefault: {
				ClassSuccess:     2,
				ClassDenied:      3,
				ClassAuthError:   8,
				ClassClientError: 2,
				ClassServerError: 1,
			},
		},
	}
}

func (t CostTable) WithOverrides(overrides map[Category]map[OutcomeClass]int) CostTable {
	rows := make(map[Category]map[OutcomeClass]int, len(t.rows))
	for cat, cells := range t.rows {
		cp := make(map[OutcomeClass]int, len(cells))
		for cls, v := range cells {
			cp[cls] = v
		}
		rows[cat] = cp
	}
	for cat, cells := range overrides {
		if rows[cat] == nil {
			rows[cat] = make(map[OutcomeClass]int, len(cells))
		}
		for cls, v := range cells {
			rows[cat][cls] = v
		}
	}
	return CostTable{rows: rows}
}

func (t CostTable) Cost(cat Category, cls OutcomeClass) int {
	if cells, ok := t.rows[cat]; ok {
		if v, ok := cells[cls]; ok {
			return v
		}
	}
	if cells, ok := t.rows[CategoryDefault]; ok {
		if v, ok := cells[cls]; ok {
			return v
		}
	}
	return 1
}

// ClassFromStatus maps an HTTP status code to an OutcomeClass.
func ClassFromStatus(status int) OutcomeClass {
	switch {
	case status == http.StatusUnauthorized:
		return ClassAuthError
	case status == http.StatusForbidden:
		return ClassDenied
	case status >= 500:
		return ClassServerError
	case status >= 400:
		return ClassClientError
	default:
		return ClassSuccess
	}
}

// ClassFromOutcome maps a core.Outcome to an OutcomeClass.
func ClassFromOutcome(o core.Outcome) OutcomeClass {
	switch o {
	case core.OutcomeSuccess:
		return ClassSuccess
	case core.OutcomeDenied:
		return ClassDenied
	default:
		return ClassServerError
	}
}
