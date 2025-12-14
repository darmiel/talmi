package engine

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/darmiel/talmi/internal/core"
)

func evaluateCondition(cond core.Condition, attributes map[string]any) (bool, string) {
	val, exists := attributes[cond.Key]

	switch cond.Operator {
	case core.OpExists:
		if !exists {
			return false, fmt.Sprintf("attribute '%s' does not exist", cond.Key)
		}
		return true, ""

	case core.OpNotExists:
		if exists {
			return false, fmt.Sprintf("attribute '%s' exists", cond.Key)
		}
		return true, ""
	}

	if !exists {
		return false, fmt.Sprintf("attribute '%s' missing", cond.Key)
	}

	switch cond.Operator {
	case core.OpEqual:
		if !deepEqual(val, cond.Value) {
			return false, fmt.Sprintf("expected '%v' to equal '%v'", val, cond.Value)
		}
		return true, ""

	case core.OpNotEqual:
		if deepEqual(val, cond.Value) {
			return false, fmt.Sprintf("expected '%v' to not equal '%v'", val, cond.Value)
		}
		return true, ""

	case core.OpIn:
		// Check if Attribute Value (val) is inside the Config List (cond.Value)
		if !contains(cond.Value, val) {
			return false, fmt.Sprintf("value '%v' not in '%v'", val, cond.Value)
		}
		return true, ""

	case core.OpNotIn:
		if contains(cond.Value, val) {
			return false, fmt.Sprintf("value '%v' found in '%v'", val, cond.Value)
		}
		return true, ""
	}

	return false, fmt.Sprintf("unknown operator '%s' in condition", cond.Operator)
}

func deepEqual(a, b any) bool {
	return reflect.DeepEqual(a, b)
}

func contains(container, item any) bool {
	// handle string contains substring
	if str, ok := container.(string); ok {
		if subStr, ok := item.(string); ok {
			return strings.Contains(str, subStr)
		}
	}

	// handle slice/array contains
	v := reflect.ValueOf(container)
	if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
		for i := 0; i < v.Len(); i++ {
			if deepEqual(v.Index(i).Interface(), item) {
				return true
			}
		}
	}

	return false
}
