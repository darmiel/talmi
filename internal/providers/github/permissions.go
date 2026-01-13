package github

import (
	"fmt"
	"strings"
)

type PermissionLevel int

const (
	LevelNone PermissionLevel = iota
	LevelRead
	LevelWrite
	LevelAdmin // should not be used at all. 'write' is the highest allowed level
)

func parseLevel(s string) PermissionLevel {
	switch strings.ToLower(s) {
	case "read", "readonly":
		return LevelRead
	case "write", "readwrite":
		return LevelWrite
	case "admin":
		return LevelAdmin
	default:
		return LevelNone
	}
}

func Downscope(allowed, requested map[string]string) (map[string]string, error) {
	if len(requested) == 0 {
		return allowed, nil // no downscoping needed
	}

	final := make(map[string]string)
	for reqKey, reqValStr := range requested {
		allowedValStr, ok := allowed[reqKey]
		if !ok {
			return nil, fmt.Errorf("permission '%s' is not allowed by policy", reqKey)
		}

		// compare the levels
		reqLevel := parseLevel(reqValStr)
		allowedLevel := parseLevel(allowedValStr)

		// handle unknown strings (metadata: "true") - exact match required in that case
		if reqLevel == LevelNone && allowedLevel == LevelNone {
			if reqValStr != allowedValStr {
				return nil, fmt.Errorf("permission '%s' value mismatch: requested '%s', allowed '%s'",
					reqKey, reqValStr, allowedValStr)
			}
		} else {
			// handle known levels
			if reqLevel > allowedLevel {
				// cannot request a level higher than allowed
				return nil, fmt.Errorf("permission '%s' level too high: requested '%s', allowed '%s'",
					reqKey, reqValStr, allowedValStr)
			}
		}

		final[reqKey] = reqValStr
	}

	return final, nil
}
