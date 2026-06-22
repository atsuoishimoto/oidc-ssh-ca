package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
)

// cmdExplain evaluates a claim set against the policy and reports which
// rule matches, or why each rule does not. The claims file holds the
// decoded JWT payload (e.g. from `gh` or the workflow's oidc.jwt).
func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy.yaml (required)")
	claimsPath := fs.String("claims", "", "path to a JSON file with the JWT claims (required)")
	fs.Parse(args)
	if *policyPath == "" || *claimsPath == "" {
		return errors.New("usage: oidc-ssh-ca explain --policy policy.yaml --claims claims.json")
	}

	pol, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	id, err := loadIdentity(*claimsPath)
	if err != nil {
		return err
	}

	if pol.Disabled {
		fmt.Println("policy is disabled (disabled: true): all requests are denied")
		return nil
	}

	decision := pol.Evaluate(id)
	switch {
	case decision.Allowed:
		r := decision.Rule
		fmt.Printf("matched rule: %s\n", r.Name)
		fmt.Printf("principals: %v\n", r.Certificate.Principals)
		fmt.Printf("ttl: %ds\n", pol.ValidForSecondsFor(r))
		if r.Certificate.ForceCommand != "" {
			fmt.Printf("force_command: %s\n", r.Certificate.ForceCommand)
		}
		if sa := pol.SourceAddressFor(r); len(sa) > 0 {
			fmt.Printf("source_address: %v\n", sa)
		}
		keyID, err := policy.ExpandKeyID(pol.KeyIDTemplateFor(r), id.Claims)
		if err != nil {
			fmt.Printf("key_id: DENIED at issuance time: %v\n", err)
		} else {
			fmt.Printf("key_id: %s\n", keyID)
		}
	case decision.Reason == policy.ReasonMultipleRules:
		fmt.Printf("DENY: %d rules matched (exactly one is required): %v\n",
			len(decision.MatchedRules), decision.MatchedRules)
	default:
		fmt.Println("DENY: no rule matched")
		for i := range pol.Rules {
			r := &pol.Rules[i]
			ok, why := policy.ExplainRule(r, id)
			if !ok {
				fmt.Printf("  rule %q: %s\n", r.Name, why)
			}
		}
	}
	return nil
}

// loadIdentity builds an Identity from a claims JSON file. aud may be a
// string or an array of strings, as in a real JWT.
func loadIdentity(path string) (*policy.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	iss, _ := claims["iss"].(string)
	if iss == "" {
		return nil, errors.New("claims file has no iss claim")
	}
	var audiences []string
	switch aud := claims["aud"].(type) {
	case string:
		audiences = []string{aud}
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok {
				audiences = append(audiences, s)
			}
		}
	}
	return &policy.Identity{Issuer: iss, Audiences: audiences, Claims: claims}, nil
}
