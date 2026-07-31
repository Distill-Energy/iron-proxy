// Package allowlist implements a default-deny domain and CIDR allowlist transform.
package allowlist

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("allowlist", factory)
}

// Allowlist is a default-deny transform that checks request hosts, methods,
// paths, and optional GraphQL operation types against a set of rules.
type Allowlist struct {
	rules []rule
	warn  bool
}

type rule struct {
	http              hostmatch.Rule
	graphqlOperations map[graphqlOperation]bool // nil = no GraphQL restriction
}

type allowlistConfig struct {
	Domains []string              `yaml:"domains"`
	CIDRs   []string              `yaml:"cidrs"`
	Rules   []allowlistRuleConfig `yaml:"rules"`
	Warn    bool                  `yaml:"warn"`
}

type allowlistRuleConfig struct {
	Host              string   `yaml:"host,omitempty"`
	CIDR              string   `yaml:"cidr,omitempty"`
	Methods           []string `yaml:"methods,omitempty"`
	Paths             []string `yaml:"paths,omitempty"`
	GraphQLOperations []string `yaml:"graphql_operations,omitempty"`
}

func (c allowlistRuleConfig) hostmatchConfig() hostmatch.RuleConfig {
	return hostmatch.RuleConfig{
		Host:    c.Host,
		CIDR:    c.CIDR,
		Methods: c.Methods,
		Paths:   c.Paths,
	}
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c allowlistConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing allowlist config: %w", err)
	}
	return newFromConfig(c)
}

func newFromConfig(cfg allowlistConfig) (*Allowlist, error) {
	var rules []rule

	// Flat domains → rules with no method/path restrictions.
	for _, d := range cfg.Domains {
		m, err := hostmatch.New([]string{d}, nil)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule{http: hostmatch.Rule{Matcher: m}})
	}

	// Flat CIDRs → rules with no method/path restrictions.
	for _, c := range cfg.CIDRs {
		m, err := hostmatch.New(nil, []string{c})
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule{http: hostmatch.Rule{Matcher: m}})
	}

	// Explicit rules with optional method/path restrictions.
	hostmatchConfigs := make([]hostmatch.RuleConfig, len(cfg.Rules))
	for i, ruleConfig := range cfg.Rules {
		hostmatchConfigs[i] = ruleConfig.hostmatchConfig()
	}
	compiled, err := hostmatch.CompileRules(hostmatchConfigs, "allowlist")
	if err != nil {
		return nil, err
	}
	for i, httpRule := range compiled {
		operations, err := compileGraphQLOperations(cfg.Rules[i].GraphQLOperations, i)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule{http: httpRule, graphqlOperations: operations})
	}

	return &Allowlist{rules: rules, warn: cfg.Warn}, nil
}

// New creates an Allowlist from domain globs and CIDR strings.
// All methods and paths are allowed. This is the backwards-compatible constructor.
func New(domains []string, cidrs []string) (*Allowlist, error) {
	return newFromConfig(allowlistConfig{Domains: domains, CIDRs: cidrs})
}

func (a *Allowlist) Name() string { return "allowlist" }

func (a *Allowlist) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	host := hostmatch.StripPort(req.Host)
	var graphqlRules []*rule
	for i := range a.rules {
		rule := &a.rules[i]
		if !rule.http.Matches(host, req.Method, req.URL.Path) {
			continue
		}
		if rule.graphqlOperations == nil {
			return &transform.TransformResult{Action: transform.ActionContinue}, nil
		}
		graphqlRules = append(graphqlRules, rule)
	}

	if len(graphqlRules) > 0 {
		operation, classified, err := requestGraphQLOperation(req)
		if err != nil {
			return nil, err
		}
		if classified {
			for _, rule := range graphqlRules {
				if rule.allowsGraphQLOperation(operation) {
					return &transform.TransformResult{Action: transform.ActionContinue}, nil
				}
			}
		}
	}
	if a.warn {
		tctx.Annotate("action", "warn")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (a *Allowlist) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}
