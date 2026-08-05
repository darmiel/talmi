package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/invopop/jsonschema"

	"github.com/darmiel/talmi/internal/core"
)

func GenerateSchema(target string) ([]byte, error) {
	var v any
	switch target {
	case "config":
		v = &Config{}
	case "issuers":
		v = &[]IssuerBlock{}
	case "realms":
		v = &[]RealmBlock{}
	case "rules":
		v = &[]core.Rule{}
	default:
		return nil, fmt.Errorf("unknown schema target %q (want config, issuers, realms, rules)", target)
	}
	s := reflector().Reflect(v)
	if target == "rules" {
		applyMatchConstraints(s)
	}
	return json.MarshalIndent(s, "", "  ")
}

// applyMatchConstraints tightens the reflected core.Match definition: Condition
// and Expr are mutually exclusive ("either/or, not both"), which cannot be
// expressed with plain struct tags.
func applyMatchConstraints(s *jsonschema.Schema) {
	if match, ok := s.Definitions["Match"]; ok {
		match.Not = &jsonschema.Schema{Required: []string{"condition", "expr"}}
	}
}

// schemaMapper overrides the reflected schema for types whose YAML shape differs
// from their Go representation.
func schemaMapper(t reflect.Type) *jsonschema.Schema {
	switch t {
	case reflect.TypeOf(time.Duration(0)):
		// Durations are written as Go duration strings (e.g. "8h", "5m",
		// "500ms"), not the underlying int64 nanoseconds.
		return &jsonschema.Schema{
			Type:        "string",
			Description: `Go duration string, e.g. "8h", "5m", "500ms".`,
		}
	case reflect.TypeOf(core.Condition{}):
		// Conditions are parsed dynamically and support key shorthands
		// (e.g. { teams: { contains: "..." } }), so accept any object.
		return &jsonschema.Schema{Type: "object"}
	}
	return nil
}

func reflector() *jsonschema.Reflector {
	return &jsonschema.Reflector{
		FieldNameTag:               "yaml",
		RequiredFromJSONSchemaTags: true,
		Mapper:                     schemaMapper,
	}
}

func expandedReflector() *jsonschema.Reflector {
	return &jsonschema.Reflector{
		FieldNameTag:               "yaml",
		RequiredFromJSONSchemaTags: true,
		DoNotReference:             true,
		ExpandedStruct:             true,
		Mapper:                     schemaMapper,
	}
}

func objectSchema() *jsonschema.Schema {
	s := &jsonschema.Schema{
		Type:                 "object",
		AdditionalProperties: jsonschema.FalseSchema,
	}
	s.Properties = jsonschema.NewProperties()
	return s
}

func capabilitySchema() *jsonschema.Schema {
	return expandedReflector().Reflect(&CapabilityBlock{})
}

func mergeProps(dst, src *jsonschema.Schema) {
	if src == nil {
		return
	}
	for p := src.Properties.Oldest(); p != nil; p = p.Next() {
		dst.Properties.Set(p.Key, p.Value)
	}
	dst.Required = append(dst.Required, src.Required...)
}

func (IssuerBlock) JSONSchemaExtend(base *jsonschema.Schema) {
	base.Properties, base.AdditionalProperties, base.Required = nil, nil, nil
	for _, typ := range IssuerTypes() {
		b := objectSchema()
		b.Properties.Set("name", &jsonschema.Schema{Type: "string"})
		b.Properties.Set("type", &jsonschema.Schema{Type: "string", Const: typ})
		b.Required = []string{"name", "type"}
		mergeProps(b, expandedReflector().Reflect(issuerConfigTypes[typ]()))
		base.OneOf = append(base.OneOf, b)
	}
}

func (RealmBlock) JSONSchemaExtend(base *jsonschema.Schema) {
	base.Properties, base.AdditionalProperties, base.Required = nil, nil, nil
	branch := func(typ string, instProto func() InstanceConfig) *jsonschema.Schema {
		b := objectSchema()
		b.Properties.Set("realm", &jsonschema.Schema{Type: "string"})
		b.Properties.Set("type", &jsonschema.Schema{Type: "string", Const: typ})
		b.Properties.Set("capability", capabilitySchema())
		b.Required = []string{"realm", "type"}

		inst := objectSchema()
		inst.Properties.Set("name", &jsonschema.Schema{Type: "string"})
		inst.Properties.Set("capability", capabilitySchema())
		inst.Required = []string{"name"}
		if instProto != nil {
			mergeProps(inst, expandedReflector().Reflect(instProto()))
		}
		b.Properties.Set("instances", &jsonschema.Schema{
			Type:  "array",
			Items: inst,
		})
		return b
	}
	for _, typ := range InstanceTypes() {
		t := typ
		base.OneOf = append(base.OneOf, branch(t, instanceConfigTypes[t]))
	}
	base.OneOf = append(base.OneOf, branch("talmi", nil))
}
