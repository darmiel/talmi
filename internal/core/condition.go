package core

import "fmt"

type ConditionResult struct {
	Matched bool

	// For leaves
	Expression string `json:"expression"` // e.g. "groups contains admin"
	Reason     string `json:"reason,omitempty"`

	// For branching
	Label    string // e.g. "AND"
	Children []ConditionResult
}

// Operator defines how to compare values.
type Operator string

const (
	OpEqual Operator = "equals"
	// OpContains means the attribute value contains the given substring or item.
	// for strings: "hello world" contains "world"
	// for lists: ["a", "b", "c"] contains "b"
	OpContains Operator = "contains"
	// OpIn means the attribute value is in the given list.
	// e.g., value "b" in ["a", "b", "c"]
	OpIn     Operator = "in"
	OpExists Operator = "exists"
)

func (op Operator) IsValid() bool {
	switch op {
	case OpEqual, OpContains, OpIn, OpExists:
		return true
	default:
		return false
	}
}

// Condition represents a single check against a Principal's attribute.
type Condition struct {
	// Logic operators
	All []Condition `json:"all,omitempty"`
	Any []Condition `json:"any,omitempty"`
	Not *Condition  `json:"not,omitempty"`

	// Leaf condition
	Key      string   `json:"key,omitempty"`
	Operator Operator `json:"operator,omitempty"`
	Value    any      `json:"value,omitempty"`
}

func (c *Condition) UnmarshalYAML(unmarshal func(any) error) error {
	var raw map[string]any
	if err := unmarshal(&raw); err != nil {
		// well it needs to be able to unmarshal into a map
		// otherwise the user entered something very weird
		return err
	}

	// isExplicit marks whether the condition is explicitly defined:
	//   { key: sub, operator: equals, value: "12345" }
	// or implicitly:
	//   { sub: "12345" }
	isExplicit := false
	for k := range raw {
		if k == "all" || k == "any" || k == "not" || k == "key" || k == "operator" || k == "value" {
			isExplicit = true
			break
		}
	}

	if isExplicit {
		// we can just unmarshal directly into our condition struct
		type plain Condition // hack to prevent recursion :)
		var p plain
		if err := unmarshal(&p); err != nil {
			return err
		}
		*c = Condition(p) // back to condition

		// implicit EQ operator if operator missing
		if c.Key != "" && c.Operator == "" {
			c.Operator = OpEqual
		}

		return nil // nice we successfully parsed an explicit condition!
	}

	// now the fun begins, because we want to support implicit conditions
	// /shorthands like { sub: "12345" } which means { key: "sub", operator: "equals", value: "12345" }
	var children []Condition

	for k, v := range raw {
		sub := Condition{Key: k}

		// is it an operator shorthand?
		if vMap, ok := v.(map[string]any); ok {
			foundOperator := false
			for opKey, opVal := range vMap {
				op := Operator(opKey)
				if op.IsValid() {
					sub.Operator = op
					sub.Value = opVal
					foundOperator = true
					break // only allow one operator per key (for now)
				}
			}
			// if no operator found, default to equals
			// like this: { sub: "1234" } -> { key: "sub", operator: "equals", value: "1234" }
			if !foundOperator {
				sub.Operator = OpEqual
				sub.Value = v
			}
		} else {
			// simple key: value equality :)
			// this is duplicate of the above case where no operator found
			// we ~~can~~ should probably refactor this later
			sub.Operator = OpEqual
			sub.Value = v
		}

		children = append(children, sub)
	}

	if len(children) == 1 {
		// if we have exactly one child, we can just use it directly
		*c = children[0]
	} else {
		// otherwise implicit AND
		c.All = children
	}

	return nil
}

func (c *Condition) Validate() error {
	if c == nil {
		return nil
	}

	// validate logic nodes
	hasAll := len(c.All) > 0
	hasAny := len(c.Any) > 0
	hasNot := c.Not != nil
	hasLeaf := c.Key != ""

	if hasAll {
		for _, sub := range c.All {
			if err := sub.Validate(); err != nil {
				return err
			}
		}
	}
	if hasAny {
		for _, sub := range c.Any {
			if err := sub.Validate(); err != nil {
				return err
			}
		}
	}
	if hasNot {
		if err := c.Not.Validate(); err != nil {
			return err
		}
	}
	if hasLeaf {
		if !c.Operator.IsValid() {
			return fmt.Errorf("invalid operator '%s' for key '%s'", c.Operator, c.Key)
		}
	}

	// make sure only one of the types is used
	count := 0
	if hasAll {
		count++
	}
	if hasAny {
		count++
	}
	if hasNot {
		count++
	}
	if hasLeaf {
		count++
	}
	if count > 1 {
		return fmt.Errorf("condition for key '%s' has multiple types set (all, any, not, leaf); only one is allowed", c.Key)
	} else if count == 0 {
		return fmt.Errorf("condition is missing required fields; must be one of (all, any, not, leaf)")
	} else {
		return nil
	}
}
