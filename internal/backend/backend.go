package backend

import (
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

type BuildInput struct {
	Spec config.ProviderSpec
}

type Backend struct {
	Type      string
	Semantics realm.Semantics
	Build     func(input BuildInput) (core.ResourceProvider, error)
}

func Lookup(kind string) (Backend, bool) {
	for _, b := range backends {
		if b.Type == kind {
			return b, true
		}
	}
	return Backend{}, false
}

func Types() []string {
	out := make([]string, 0, len(backends))
	for _, b := range backends {
		out = append(out, b.Type)
	}
	return out
}
