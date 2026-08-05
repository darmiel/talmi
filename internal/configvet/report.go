package configvet

import "fmt"

type Severity int

const (
	SeverityError Severity = iota
	SeverityWarn
)

func (s *Severity) String() string {
	if s == nil {
		return ""
	}
	switch *s {
	case SeverityError:
		return "error"
	case SeverityWarn:
		return "warn"
	default:
		return "unknown"
	}
}

// MarshalJSON renders the severity as "error"/"warn" for readable JSON output.
func (s *Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON parses "error"/"warn" back into a Severity (lossless round-trip).
func (s *Severity) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case `"warn"`:
		*s = SeverityWarn
	case `"error"`:
		*s = SeverityError
	default:
		return fmt.Errorf("unknown severity %s", data)
	}
	return nil
}

// Position is a best-effort source location for a finding.
type Position struct {
	File   string `json:"file"`
	Line   int    `json:"line"`   // 0 if unknown
	Column int    `json:"column"` // 0 if unknown
}

// Finding carries as much context as possible so the CLI can render output (more or less) nicely.
type Finding struct {
	Severity    Severity   `json:"severity"`
	Code        string     `json:"code"`     // stable id
	Section     string     `json:"section"`  // issuers | realms | rules
	Location    string     `json:"location"` // path to the config block
	Pos         Position   `json:"pos"`
	Message     string     `json:"message"`
	Detail      string     `json:"detail,omitempty"`
	Value       string     `json:"value,omitempty"`
	Suggestions []string   `json:"suggestions,omitempty"`
	Related     []Position `json:"related,omitempty"`
	Help        string     `json:"help,omitempty"`
}

type Report struct {
	Findings []Finding
}

func (r *Report) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

func (r *Report) Errors() []Finding {
	return r.bySeverity(SeverityError)
}

func (r *Report) Warnings() []Finding {
	return r.bySeverity(SeverityWarn)
}

func (r *Report) bySeverity(sev Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

// add appends and returns a pointer for immediate chaining
func (r *Report) add(f Finding) *Finding {
	r.Findings = append(r.Findings, f)
	return &r.Findings[len(r.Findings)-1]
}

func (r *Report) errorf(code, section, location, format string, a ...any) *Finding {
	return r.add(Finding{
		Severity: SeverityError,
		Code:     code,
		Section:  section,
		Location: location,
		Message:  fmt.Sprintf(format, a...),
	})
}

func (r *Report) warnf(code, section, location, format string, a ...any) *Finding {
	return r.add(Finding{
		Severity: SeverityWarn,
		Code:     code,
		Section:  section,
		Location: location,
		Message:  fmt.Sprintf(format, a...),
	})
}
