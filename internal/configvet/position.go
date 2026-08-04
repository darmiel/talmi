package configvet

import (
	"bytes"

	"github.com/goccy/go-yaml"
)

type Source struct {
	File string
	Data []byte
}

// resolve maps a goccy YAML path to a Position within src.
// On any failure it returns Position{File: src.File} with zero line/column.
func resolve(src Source, yamlPath string) Position {
	pos := Position{File: src.File}
	p, err := yaml.PathString(yamlPath)
	if err != nil {
		return pos
	}
	node, err := p.ReadNode(bytes.NewReader(src.Data))
	if err != nil || node == nil {
		return pos
	}
	tok := node.GetToken()
	if tok == nil || tok.Position == nil {
		return pos
	}
	pos.Line = tok.Position.Line
	pos.Column = tok.Position.Column
	return pos
}
