package core

// EvaluationTrace captures the detailed trace of an access evaluation.
type EvaluationTrace struct {
	// CorrelationID is the unique identifier for the evaluation request.
	CorrelationID string `yaml:"correlation_id" json:"correlation_id"`

	// Principal being evaluated.
	Principal *Principal `yaml:"principal" json:"principal"`

	// RuleResults contains the result of every rule evaluated.
	RuleResults []RuleResult `yaml:"rule_results" json:"rule_results"`

	// FinalDecision indicates whether access was granted or denied.
	FinalDecision bool `yaml:"final_decision" json:"final_decision"`

	// GrantedRule is the name of the rule that granted access, if any.
	GrantedRule string `yaml:"granted_rule,omitempty" json:"granted_rule,omitempty"`
}

// RuleResult captures why a specific rule matched or failed.
type RuleResult struct {
	RuleName         string            `yaml:"rule_name" json:"rule_name"`
	Description      string            `yaml:"description" json:"description"`
	Matched          bool              `yaml:"matched" json:"matched"`
	ConditionResults []ConditionResult `json:"condition_results,omitempty"`
}
