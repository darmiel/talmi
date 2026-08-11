package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Confirm writes question to out and reads a yes/no answer from in.
// It defaults to no: only "y"/"yes" (case-insensitive) return true.
func Confirm(in io.Reader, out io.Writer, prompt string) (bool, error) {
	_, _ = fmt.Fprintf(out, "%s [y/N]: ", prompt)

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("reading confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
