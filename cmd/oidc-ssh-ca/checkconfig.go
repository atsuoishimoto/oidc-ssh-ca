package main

import (
	"errors"
	"fmt"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
)

// knownGitHubClaims is the set of claims GitHub Actions OIDC tokens are
// known to carry. check-config warns (without failing) when a
// key_id_template references a claim outside this list.
var knownGitHubClaims = map[string]bool{
	"sub": true, "aud": true, "iss": true, "jti": true,
	"repository": true, "repository_owner": true, "repository_id": true,
	"repository_owner_id": true, "repository_visibility": true,
	"ref": true, "ref_type": true, "ref_protected": true, "sha": true,
	"workflow": true, "workflow_ref": true, "workflow_sha": true,
	"job_workflow_ref": true, "job_workflow_sha": true,
	"event_name": true, "environment": true,
	"actor": true, "actor_id": true,
	"run_id": true, "run_number": true, "run_attempt": true,
	"head_ref": true, "base_ref": true,
	"runner_environment": true, "enterprise": true,
}

func cmdCheckConfig(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: oidc-ssh-ca check-config policy.yaml")
	}
	pol, err := policy.Load(args[0])
	if err != nil {
		return err
	}

	var warnings []string
	for i := range pol.Rules {
		r := &pol.Rules[i]
		// Validation already ensured the template parses.
		vars, _ := policy.TemplateVars(r.Certificate.KeyIDTemplate)
		for _, v := range vars {
			if !knownGitHubClaims[v] {
				warnings = append(warnings, fmt.Sprintf(
					"rule %q: key_id_template references claim %q, which is not a known GitHub Actions claim", r.Name, v))
			}
		}
		if len(r.Match.JWT.ClaimsExact) == 0 {
			warnings = append(warnings, fmt.Sprintf(
				"rule %q: match has no claims_exact — any token from this issuer/audience will match", r.Name))
		}
	}

	fmt.Printf("policy OK: %d rule(s)\n", len(pol.Rules))
	fmt.Printf("  disabled: %v\n", pol.Disabled)
	fmt.Printf("  valid_after_offset_seconds: %d\n", pol.ValidAfterOffsetSeconds())
	fmt.Printf("  max_valid_for_seconds: %d\n", pol.MaxValidForSeconds())
	fmt.Printf("  allowed_public_key_types: %v\n", pol.AllowedPublicKeyTypes())
	for i := range pol.Rules {
		r := &pol.Rules[i]
		state := "enabled"
		if !r.IsEnabled() {
			state = "disabled"
		}
		extra := ""
		if r.Certificate.ForceCommand != "" {
			extra += fmt.Sprintf(" force_command=%q", r.Certificate.ForceCommand)
		}
		if len(r.Certificate.SourceAddress) > 0 {
			extra += fmt.Sprintf(" source_address=%v", r.Certificate.SourceAddress)
		}
		fmt.Printf("  rule %q (%s): principals=%v ttl=%ds%s\n",
			r.Name, state, r.Certificate.Principals, r.Certificate.ValidForSeconds, extra)
	}
	for _, w := range warnings {
		fmt.Println("warning:", w)
	}
	return nil
}
