package ui

import (
	"fmt"
	"time"
)

// RelativeTime renders t relative to now for at-a-glance scanning: "just now",
// "Nm ago", "Nh ago", "Nd ago" up to a week, then a short absolute date. Future
// times (clock skew) render as "just now".
func RelativeTime(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours())/24)
	default:
		return t.Format("Jan 2")
	}
}
