package config

import "os"

// ResolveNodeID returns the node identity to use. If configured is empty, will return the hostname.
// If the hostname cannot be determined, will return "unknown".
func ResolveNodeID(configured string) string {
	if configured != "" {
		return configured
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}
	return "unknown"
}
