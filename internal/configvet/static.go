package configvet

import (
	"sort"
	"strings"

	"github.com/expr-lang/expr"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
	"github.com/darmiel/talmi/internal/secret"
)

// StaticInput is everything the offline pass needs.
type StaticInput struct {
	Config  *config.Config
	Sourced *config.SourcedConfig
	Realms  *realm.Registry
	Sources []Source
}

func Static(in StaticInput) Report {
	var r Report
	checkSigning(in, &r)
	checkStore(in, &r)
	checkAudit(in, &r)
	checkIssuers(in, &r)
	checkRealms(in, &r)
	checkRules(in, &r)
	checkAuth(in, &r)
	checkSecrets(in, &r)
	checkUnused(in, &r)
	return r
}

func checkSigning(in StaticInput, r *Report) {
	alg := in.Config.Signing.Algorithm
	if alg != "" && alg != "ES256" && alg != "HS256" {
		r.errorf("CFG-SIGNING", "signing", "signing.algorithm",
			"unsupported algorithm %q, must be one of ES256 or HS256", alg)
	}
}

func checkStore(in StaticInput, r *Report) {
	t := in.Config.Store.Type
	if t != "" && t != "memory" && t != "postgres" {
		r.errorf("CFG-STORE", "store", "store.type",
			"unsupported store type %q, must be one of memory or postgres", t)
	}
}

func checkAudit(in StaticInput, r *Report) {
	a := in.Config.Audit
	if !a.Enabled {
		return
	}
	if a.Type != "postgres" && a.Type != "memory" && a.Type != "noop" {
		r.errorf("CFG-AUDIT", "audit", "audit.type",
			"unsupported audit type %q, must be one of postgres, memory or noop", a.Type)
	}
}

func checkIssuers(in StaticInput, r *Report) {
	seen := make(map[string]struct{})
	for _, b := range in.Sourced.Issuers {
		loc := "issuers[" + b.Name + "]"
		if b.Name == "" {
			r.errorf("CFG-ISSUER-CONFIG", "issuers", "issuers", "issuer is missing a name")
			continue
		}
		if _, ok := seen[b.Name]; ok {
			r.errorf("CFG-ISSUER-DUP", "issuers", loc, "duplicate issuer name %q", b.Name)
			continue
		}
		seen[b.Name] = struct{}{}
		if _, err := config.DecodeIssuerConfig(b); err != nil {
			r.errorf("CFG-ISSUER-CONFIG", "issuers", loc, "%v", err)
		}
	}
}

func checkRealms(in StaticInput, r *Report) {
	instances := make(map[string]struct{})
	for _, rb := range in.Sourced.Realms {
		rloc := "realms[" + rb.Realm + "]"
		if _, ok := realm.SemanticsFor(rb.Type); !ok {
			r.errorf("CFG-REALM-TYPE", "realms", rloc,
				"unknown realm type %q (want one of %s)", rb.Type, strings.Join(realm.Kinds(), ", "))
		}
		for _, inst := range rb.Instances {
			iloc := rloc + ".instances[" + inst.Name + "]"
			if _, dup := instances[inst.Name]; dup {
				r.errorf("CFG-INSTANCE-DUP", "realms", iloc,
					"duplicate provider instance name %q", inst.Name)
			}
			instances[inst.Name] = struct{}{}
			if _, err := config.DecodeInstanceConfig(rb.Type, inst.Config); err != nil {
				r.errorf("CFG-INSTANCE-CONFIG", "realms", iloc, "%v", err)
			}
		}
	}
}

func checkRules(in StaticInput, r *Report) {
	issuers := issuerNameSet(in)
	issuerNames := sortedKeys(issuers)
	realmNames := realmNameList(in)

	if len(in.Sourced.Rules) == 0 {
		r.warnf("CFG-NO-RULES", "rules", "rules",
			"no rules are defined; every token request will be denied").
			Help = "add at least one rule granting resources to an issuer"
		return
	}

	seen := make(map[string]struct{})
	for _, rule := range in.Sourced.Rules {
		loc := "rules[" + rule.Name + "]"
		if rule.Name == "" {
			r.errorf("CFG-RULE-NAME", "rules", "rules", "rule is missing a name")
			continue
		}
		if _, ok := seen[rule.Name]; ok {
			r.errorf("CFG-RULE-DUP", "rules", loc, "duplicate rule name %q", rule.Name)
			continue
		}
		seen[rule.Name] = struct{}{}

		if rule.Match.Issuer == "" {
			r.errorf("CFG-RULE", "rules", loc+".match.issuer",
				"rule %q: missing match.issuer", rule.Name).
				Help = "set match.issuer to one of the defined issuers"
		} else if _, ok := issuers[rule.Match.Issuer]; !ok {
			r.errorf("CFG-XREF-ISSUER", "rules", loc+".match.issuer",
				"rule %q references unknown issuer %q", rule.Name, rule.Match.Issuer).
				Suggestions = Suggest(rule.Match.Issuer, issuerNames)
		}

		if len(rule.Allow) == 0 {
			r.errorf("CFG-RULE", "rules", loc, "rule %q: missing allow statements", rule.Name).
				Help = "a rule must grant at least one resource + action"
		}
		for _, allow := range rule.Allow {
			if len(allow.Resources) == 0 || len(allow.Actions) == 0 {
				r.errorf("CFG-RULE", "rules", loc+".allow",
					"rule %q: allow statement needs resources and actions", rule.Name)
			}

			// resolve the distinct realms this allow targets, then validate actions against each
			sems := make(map[string]realm.Semantics)
			for _, p := range allow.Resources {
				realmName, ok := core.Resource(p).Realm()
				if !ok {
					r.errorf("CFG-PATTERN", "rules", loc+".allow",
						"rule %q: pattern %q is missing a realm prefix (want realm:body)", rule.Name, p)
					continue
				}
				sem, ok := in.Realms.Get(realmName)
				if !ok {
					r.errorf("CFG-XREF-REALM", "rules", loc+".allow",
						"rule %q: pattern %q references unknown realm %q", rule.Name, p, realmName).
						Suggestions = Suggest(realmName, realmNames)
					continue
				}
				if err := sem.ValidateResourcePattern(p); err != nil {
					r.errorf("CFG-PATTERN", "rules", loc+".allow",
						"rule %q: pattern %q: %v", rule.Name, p, err)
				}
				sems[realmName] = sem
			}

			for realmName, sem := range sems {
				for _, act := range allow.Actions {
					if _, err := sem.CompareLevel(act, act); err != nil {
						r.errorf("CFG-ACTION", "rules", loc+".allow",
							"rule %q: action %q is not valid for realm %q (%s)",
							rule.Name, act, realmName, sem.Kind())
					}
				}
			}
		}

		checkMatch(rule, loc, r)
	}
}

func checkMatch(rule core.Rule, loc string, r *Report) {
	m := rule.Match
	switch {
	case m.Condition != nil && m.Expr != "":
		r.errorf("CFG-RULE", "rules", loc+".match",
			"rule %q: both match.condition and match.expr are set", rule.Name).
			Help = "provide either match.condition or match.expr, not both"
	case m.Condition == nil && m.Expr == "" && !m.AllowEmptyCondition:
		r.errorf("CFG-RULE", "rules", loc+".match",
			"rule %q: neither match.condition nor match.expr are set, and allow_empty is false", rule.Name).
			Help = "set match.condition/expr, or set allow_empty: true to match any principal from the issuer"
	}
	if m.Expr != "" {
		if _, err := expr.Compile(m.Expr, expr.AsBool()); err != nil {
			r.errorf("CFG-RULE", "rules", loc+".match.expr",
				"rule %q: compiling match.expr: %v", rule.Name, err)
		}
	}
	if m.Condition != nil {
		if err := m.Condition.Validate(); err != nil {
			r.errorf("CFG-RULE", "rules", loc+".match.condition",
				"rule %q: validating match.condition: %v", rule.Name, err)
		}
	}
}

func checkAuth(in StaticInput, r *Report) {
	auth := in.Config.Auth
	if auth == nil {
		return
	}
	byName := make(map[string]string) // name -> type
	names := make([]string, 0, len(in.Sourced.Issuers))
	for _, b := range in.Sourced.Issuers {
		byName[b.Name] = b.Type
		names = append(names, b.Name)
	}
	sort.Strings(names)

	requireIssuer := func(name, wantType, code, field string) {
		if name == "" {
			r.errorf(code, "auth", "auth."+field, "auth.%s is required", field)
			return
		}
		typ, ok := byName[name]
		if !ok {
			r.errorf(code, "auth", "auth."+field, "auth.%s references unknown issuer %q", field, name).
				Suggestions = Suggest(name, names)
			return
		}
		if typ != wantType {
			r.errorf(code, "auth", "auth."+field,
				"auth.%s %q must be a %s issuer, got %q", field, name, wantType, typ)
		}
	}
	requireIssuer(auth.LoginIssuer, "github-oauth", "CFG-AUTH-LOGIN", "login_issuer")
	requireIssuer(auth.SessionIssuer, "talmi-session", "CFG-AUTH-SESSION", "session_issuer")
}

func checkSecrets(in StaticInput, r *Report) {
	check := func(ref secret.Ref, section, location string) {
		if ref == "" {
			return
		}
		if _, err := secret.Resolve(ref); err != nil {
			r.errorf("CFG-SECRET", section, location, "cannot resolve secret %q: %v", ref, err)
		}
	}
	check(in.Config.Signing.Key, "signing", "signing.key")
	if in.Config.Store.Type == "postgres" {
		check(in.Config.Store.DSN, "store", "store.dsn")
	}
	if in.Config.Audit.Enabled && in.Config.Audit.Type == "postgres" {
		check(in.Config.Audit.DSN, "audit", "audit.dsn")
	}
	if src := in.Config.ConfigSource; src != nil && src.GitHub != nil {
		check(src.GitHub.PrivateKey, "source", "source.github.private_key")
		check(src.GitHub.WebhookSecret, "source", "source.github.webhook_secret")
	}
	for _, rb := range in.Sourced.Realms {
		for _, inst := range rb.Instances {
			cfg, err := config.DecodeInstanceConfig(rb.Type, inst.Config)
			if err != nil || cfg == nil {
				continue // already reported in checkRealms
			}
			iloc := "realms[" + rb.Realm + "].instances[" + inst.Name + "]"
			switch c := cfg.(type) {
			case *config.GitHubAppConfig:
				check(c.PrivateKey, "realms", iloc+".private_key")
			case *config.ArtifactoryConfig:
				check(c.AdminToken, "realms", iloc+".admin_token")
			}
		}
	}
}

func checkUnused(in StaticInput, r *Report) {
	refIssuers := make(map[string]struct{})
	refRealms := make(map[string]struct{})
	for _, rule := range in.Sourced.Rules {
		if rule.Match.Issuer != "" {
			refIssuers[rule.Match.Issuer] = struct{}{}
		}
		for _, allow := range rule.Allow {
			for _, p := range allow.Resources {
				if rn, ok := core.Resource(p).Realm(); ok {
					refRealms[rn] = struct{}{}
				}
			}
		}
	}
	if a := in.Config.Auth; a != nil {
		refIssuers[a.LoginIssuer] = struct{}{}
		refIssuers[a.SessionIssuer] = struct{}{}
	}

	for _, b := range in.Sourced.Issuers {
		if _, used := refIssuers[b.Name]; !used {
			r.warnf("CFG-UNUSED-ISSUER", "issuers", "issuers["+b.Name+"]",
				"issuer %q is defined but never referenced", b.Name).
				Help = "reference it from a rule's match.issuer or auth.*, or remove it"
		}
	}
	for _, rb := range in.Sourced.Realms {
		if _, used := refRealms[rb.Realm]; !used {
			r.warnf("CFG-UNUSED-REALM", "realms", "realms["+rb.Realm+"]",
				"realm %q is defined but never referenced", rb.Realm).
				Help = "reference it from a rule's allow pattern or remove it"
		}
	}
}

func issuerNameSet(in StaticInput) map[string]struct{} {
	set := make(map[string]struct{}, len(in.Sourced.Issuers))
	for _, b := range in.Sourced.Issuers {
		set[b.Name] = struct{}{}
	}
	return set
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func realmNameList(in StaticInput) []string {
	out := make([]string, 0, len(in.Sourced.Realms))
	for _, rb := range in.Sourced.Realms {
		out = append(out, rb.Realm)
	}
	return out
}
