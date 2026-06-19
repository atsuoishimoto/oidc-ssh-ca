package policy

import (
	"fmt"
	"strings"
)

// Identity is a verified caller identity. Claims hold the verified JWT
// claims; values used for matching and key ID expansion must be strings.
type Identity struct {
	Issuer    string
	Audiences []string
	Claims    map[string]any
}

// Decision is the result of evaluating a policy against an identity.
type Decision struct {
	Allowed bool
	Rule    *Rule
	// Reason is a stable machine-readable deny code for the audit log.
	// Empty when Allowed.
	Reason string
	// MatchedRules lists every matching rule name; more than one is a
	// deny (exactly-one-match).
	MatchedRules []string
}

// Deny reason codes.
const (
	ReasonPolicyDisabled = "policy_disabled"
	ReasonNoRuleMatched  = "no_rule_matched"
	ReasonMultipleRules  = "multiple_rules_matched"
)

// Evaluate matches the identity against the policy. Exactly one enabled
// rule must match; zero or multiple matches deny.
func (p *Policy) Evaluate(id *Identity) Decision {
	if p.Disabled {
		return Decision{Reason: ReasonPolicyDisabled}
	}

	var matched []*Rule
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.IsEnabled() {
			continue
		}
		if ruleMatches(r, id) {
			matched = append(matched, r)
		}
	}

	names := make([]string, len(matched))
	for i, r := range matched {
		names[i] = r.Name
	}

	switch len(matched) {
	case 0:
		return Decision{Reason: ReasonNoRuleMatched}
	case 1:
		return Decision{Allowed: true, Rule: matched[0], MatchedRules: names}
	default:
		return Decision{Reason: ReasonMultipleRules, MatchedRules: names}
	}
}

func ruleMatches(r *Rule, id *Identity) bool {
	m := r.Match.JWT
	if m == nil {
		return false
	}
	if m.Issuer != id.Issuer {
		return false
	}
	if !contains(id.Audiences, m.Audience) {
		return false
	}
	if m.Owner != "" || m.Repository != "" {
		repo, ok := id.Claims["repository"].(string)
		if !ok {
			return false
		}
		owner, name, found := strings.Cut(repo, "/")
		if !found {
			return false
		}
		if m.Owner != "" && m.Owner != owner {
			return false
		}
		if m.Repository != "" && m.Repository != name {
			return false
		}
	}
	for claim, want := range m.ClaimsExact {
		got, ok := id.Claims[claim].(string)
		// A referenced claim that is absent or non-string fails the
		// match: absence must not satisfy any condition.
		if !ok || got != want {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ExplainRule reports whether the rule matches and, if not, the first
// failing condition. Used by the `explain` subcommand.
func ExplainRule(r *Rule, id *Identity) (bool, string) {
	m := r.Match.JWT
	if m == nil {
		return false, "rule has no match.jwt"
	}
	if !r.IsEnabled() {
		return false, "rule is disabled (enabled: false)"
	}
	if m.Issuer != id.Issuer {
		return false, fmt.Sprintf("issuer mismatch: policy wants %q, token has %q", m.Issuer, id.Issuer)
	}
	if !contains(id.Audiences, m.Audience) {
		return false, fmt.Sprintf("audience mismatch: policy wants %q, token has %v", m.Audience, id.Audiences)
	}
	if m.Owner != "" || m.Repository != "" {
		raw, present := id.Claims["repository"]
		if !present {
			return false, "claim \"repository\" is not present in the token"
		}
		repo, ok := raw.(string)
		if !ok {
			return false, "claim \"repository\" is not a string"
		}
		owner, name, found := strings.Cut(repo, "/")
		if !found {
			return false, fmt.Sprintf("claim %q %q has no '/' to split into owner/repository", "repository", repo)
		}
		if m.Owner != "" && m.Owner != owner {
			return false, fmt.Sprintf("owner mismatch: policy wants %q, token has %q", m.Owner, owner)
		}
		if m.Repository != "" && m.Repository != name {
			return false, fmt.Sprintf("repository mismatch: policy wants %q, token has %q", m.Repository, name)
		}
	}
	for claim, want := range m.ClaimsExact {
		raw, present := id.Claims[claim]
		if !present {
			return false, fmt.Sprintf("claim %q is not present in the token", claim)
		}
		got, ok := raw.(string)
		if !ok {
			return false, fmt.Sprintf("claim %q is not a string", claim)
		}
		if got != want {
			return false, fmt.Sprintf("claim %q mismatch: policy wants %q, token has %q", claim, want, got)
		}
	}
	return true, ""
}
