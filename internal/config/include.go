package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/goccy/go-yaml"
)

// LoadSection reads every *.yaml file matched by the include patterns in baseDir, unmarshals them into a slice of T,
// and returns the concatenated result. The order is sorted by file path to ensure deterministic behavior.
func LoadSection[T any](baseDir string, patterns []string) ([]T, error) {
	var out []T
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(baseDir, pattern))
		if err != nil {
			return nil, fmt.Errorf("invalid include glob %q: %w", pattern, err)
		}
		slices.Sort(matches)

		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading %q: %w", path, err)
			}
			var items []T
			if err := yaml.Unmarshal(data, &items); err != nil {
				return nil, fmt.Errorf("parsing %q: %w", path, err)
			}
			out = append(out, items...)
		}
	}
	return out, nil
}
