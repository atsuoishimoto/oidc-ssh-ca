package policy

import (
	"strings"
	"testing"
)

const validPolicy = `
version: 1
disabled: false

defaults:
  valid_after_offset_seconds: -30
  max_valid_for_seconds: 900
  allowed_public_key_types:
    - "ssh-ed25519"

rules:
  - name: "prod-deploy"
    enabled: true
    match:
      jwt:
        issuer: "https://token.actions.githubusercontent.com"
        audience: "ssh-ca-prod"
        claims_exact:
          repository: "your-org/your-repo"
          ref: "refs/heads/main"
    certificate:
      principals: ["gha-prod-deploy"]
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
`

func TestParseValidPolicy(t *testing.T) {
	p, err := Parse([]byte(validPolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Rules) != 1 || p.Rules[0].Name != "prod-deploy" {
		t.Fatalf("unexpected rules: %+v", p.Rules)
	}
	if p.MaxValidForSeconds() != 900 || p.ValidAfterOffsetSeconds() != -30 {
		t.Fatalf("unexpected defaults")
	}
	if got := p.Issuers(); len(got) != 1 || got[0] != "https://token.actions.githubusercontent.com" {
		t.Fatalf("Issuers() = %v", got)
	}
}

func TestParseDefaultsApplied(t *testing.T) {
	minimal := `
version: 1
rules:
  - name: "r1"
    match:
      jwt:
        issuer: "https://example.com"
        audience: "aud"
    certificate:
      principals: ["p"]
      valid_for_seconds: 600
      key_id_template: "x:${sub}"
`
	p, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.MaxValidForSeconds() != DefaultMaxValidForSeconds {
		t.Errorf("MaxValidForSeconds = %d", p.MaxValidForSeconds())
	}
	if p.ValidAfterOffsetSeconds() != DefaultValidAfterOffsetSeconds {
		t.Errorf("ValidAfterOffsetSeconds = %d", p.ValidAfterOffsetSeconds())
	}
	if got := p.AllowedPublicKeyTypes(); len(got) != 1 || got[0] != "ssh-ed25519" {
		t.Errorf("AllowedPublicKeyTypes = %v", got)
	}
	if ext := p.ExtensionsFor(&p.Rules[0]); ext != (Extensions{}) {
		t.Errorf("extensions should default to all-disabled, got %+v", ext)
	}
	if !p.Rules[0].IsEnabled() {
		t.Errorf("rule without enabled flag must default to enabled")
	}
}

// withCertField appends a field to the rule's certificate block.
func withCertField(policyYAML, field string) string {
	const anchor = `      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"`
	return strings.Replace(policyYAML, anchor, anchor+"\n      "+field, 1)
}

func TestParseCertificateRestrictions(t *testing.T) {
	src := withCertField(validPolicy, `force_command: "/usr/local/bin/deploy.sh"`)
	src = withCertField(src, "source_address:\n        - \"192.0.2.0/24\"\n        - \"2001:db8::/32\"")
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := p.Rules[0].Certificate
	if c.ForceCommand != "/usr/local/bin/deploy.sh" {
		t.Errorf("ForceCommand = %q", c.ForceCommand)
	}
	if len(c.SourceAddress) != 2 || c.SourceAddress[0] != "192.0.2.0/24" {
		t.Errorf("SourceAddress = %v", c.SourceAddress)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(string) string
		contains string
	}{
		{"unknown field", func(s string) string {
			return s + "\nunknown_field: true\n"
		}, "field unknown_field not found"},
		{"aws match rejected", func(s string) string {
			return strings.Replace(s, "    match:\n", "    match:\n      aws:\n        account_id: \"123456789012\"\n", 1)
		}, "field aws not found"},
		{"bad version", func(s string) string {
			return strings.Replace(s, "version: 1", "version: 2", 1)
		}, "unsupported version"},
		{"ttl over max", func(s string) string {
			return strings.Replace(s, "valid_for_seconds: 600", "valid_for_seconds: 1200", 1)
		}, "exceeds"},
		{"empty principals", func(s string) string {
			return strings.Replace(s, `principals: ["gha-prod-deploy"]`, "principals: []", 1)
		}, "principals"},
		{"missing key_id_template", func(s string) string {
			return strings.Replace(s, `key_id_template: "gha:${repository}:${run_id}:${run_attempt}"`, "", 1)
		}, "key_id_template"},
		{"missing audience", func(s string) string {
			return strings.Replace(s, `audience: "ssh-ca-prod"`, "", 1)
		}, "audience"},
		{"unsupported key type", func(s string) string {
			return strings.Replace(s, `- "ssh-ed25519"`, `- "ssh-rsa"`, 1)
		}, "unsupported public key type"},
		{"malformed template", func(s string) string {
			return strings.Replace(s, "gha:${repository}", "gha:$repository", 1)
		}, "malformed variable"},
		{"duplicate rule names", func(s string) string {
			dup := strings.Replace(strings.SplitAfter(s, "rules:\n")[1], "ssh-ca-prod", "ssh-ca-other", 1)
			return s + "\n" + dup
		}, "duplicate rule name"},
		{"source_address not CIDR", func(s string) string {
			return withCertField(s, `source_address: ["192.0.2.10"]`)
		}, "CIDR"},
		{"force_command templating", func(s string) string {
			return withCertField(s, `force_command: "deploy ${repository}"`)
		}, "templating"},
		{"force_command control char", func(s string) string {
			return withCertField(s, "force_command: \"deploy\\tnow\"")
		}, "control character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.mutate(validPolicy)))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.contains)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error %q does not contain %q", err, tc.contains)
			}
		})
	}
}

func testIdentity() *Identity {
	return &Identity{
		Issuer:    "https://token.actions.githubusercontent.com",
		Audiences: []string{"ssh-ca-prod"},
		Claims: map[string]any{
			"repository":  "your-org/your-repo",
			"ref":         "refs/heads/main",
			"run_id":      "123456789",
			"run_attempt": "1",
		},
	}
}

func TestEvaluateSingleMatch(t *testing.T) {
	p, _ := Parse([]byte(validPolicy))
	d := p.Evaluate(testIdentity())
	if !d.Allowed || d.Rule.Name != "prod-deploy" {
		t.Fatalf("expected allow by prod-deploy, got %+v", d)
	}
}

func TestEvaluateDenies(t *testing.T) {
	t.Run("no match on claim mismatch", func(t *testing.T) {
		p, _ := Parse([]byte(validPolicy))
		id := testIdentity()
		id.Claims["ref"] = "refs/heads/feature"
		if d := p.Evaluate(id); d.Allowed || d.Reason != ReasonNoRuleMatched {
			t.Fatalf("expected no_rule_matched, got %+v", d)
		}
	})
	t.Run("missing claim denies", func(t *testing.T) {
		p, _ := Parse([]byte(validPolicy))
		id := testIdentity()
		delete(id.Claims, "ref")
		if d := p.Evaluate(id); d.Allowed {
			t.Fatalf("absent claim must not match")
		}
	})
	t.Run("audience mismatch denies", func(t *testing.T) {
		p, _ := Parse([]byte(validPolicy))
		id := testIdentity()
		id.Audiences = []string{"ssh-ca-staging"}
		if d := p.Evaluate(id); d.Allowed {
			t.Fatalf("audience mismatch must deny")
		}
	})
	t.Run("disabled policy denies", func(t *testing.T) {
		p, _ := Parse([]byte(strings.Replace(validPolicy, "disabled: false", "disabled: true", 1)))
		if d := p.Evaluate(testIdentity()); d.Allowed || d.Reason != ReasonPolicyDisabled {
			t.Fatalf("expected policy_disabled, got %+v", d)
		}
	})
	t.Run("disabled rule does not match", func(t *testing.T) {
		p, _ := Parse([]byte(strings.Replace(validPolicy, "enabled: true", "enabled: false", 1)))
		if d := p.Evaluate(testIdentity()); d.Allowed {
			t.Fatalf("disabled rule must not match")
		}
	})
	t.Run("multiple matches deny", func(t *testing.T) {
		second := strings.Replace(strings.SplitAfter(validPolicy, "rules:\n")[1], "prod-deploy", "prod-deploy-2", 1)
		p, err := Parse([]byte(validPolicy + "\n" + second))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		d := p.Evaluate(testIdentity())
		if d.Allowed || d.Reason != ReasonMultipleRules {
			t.Fatalf("expected multiple_rules_matched, got %+v", d)
		}
		if len(d.MatchedRules) != 2 {
			t.Fatalf("MatchedRules = %v", d.MatchedRules)
		}
	})
}

func TestExplainRule(t *testing.T) {
	p, _ := Parse([]byte(validPolicy))
	id := testIdentity()
	id.Claims["ref"] = "refs/heads/feature"
	ok, why := ExplainRule(&p.Rules[0], id)
	if ok || !strings.Contains(why, `claim "ref" mismatch`) {
		t.Fatalf("ok=%v why=%q", ok, why)
	}
}
