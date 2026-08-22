package cmd

import (
	"io"
	"os"
	"os/exec"
	"strings"
)

// pageOutput writes content to the user.
//
// The pager is $TALMI_PAGER, then $PAGER, then "less". For less we default
// LESS=FR unless the user already set LESS.
func pageOutput(deps Deps, disable bool, content string) error {
	if disable || !deps.IO.IsTTY {
		_, err := io.WriteString(deps.IO.Out, content)
		return err
	}

	pager := firstNonEmpty(os.Getenv("TALMI_PAGER"), os.Getenv("PAGER"), "less")
	if pager == "cat" {
		_, err := io.WriteString(deps.IO.Out, content)
		return err
	}

	cmd := exec.Command("sh", "-c", pager)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = deps.IO.Out
	cmd.Stderr = deps.IO.ErrOut
	if _, ok := os.LookupEnv("LESS"); !ok {
		cmd.Env = append(os.Environ(), "LESS=FR")
	}

	if err := cmd.Run(); err != nil {
		// A missing or misbehaving pager must not lose the output.
		_, werr := io.WriteString(deps.IO.Out, content)
		return werr
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
