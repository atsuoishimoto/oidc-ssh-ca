// Package policy implements parsing, validation, and rule matching for
// the oidc-ssh-ca policy file (policy.yaml).
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultValidAfterOffsetSeconds = -30
	DefaultMaxValidForSeconds      = 900
)

// supportedKeyTypes lists the public key types this build can accept.
var supportedKeyTypes = map[string]bool{
	"ssh-ed25519": true,
}

// Policy is the root of policy.yaml.
type Policy struct {
	Version  int      `yaml:"version"`
	Disabled bool     `yaml:"disabled"`
	Defaults Defaults `yaml:"defaults"`
	Rules    []Rule   `yaml:"rules"`
}

// Defaults holds policy-wide defaults applied to every rule.
type Defaults struct {
	ValidAfterOffsetSeconds *int        `yaml:"valid_after_offset_seconds"`
	MaxValidForSeconds      *int        `yaml:"max_valid_for_seconds"`
	AllowedPublicKeyTypes   []string    `yaml:"allowed_public_key_types"`
	Extensions              *Extensions `yaml:"extensions"`
}

// Extensions controls the OpenSSH certificate extensions. All default to
// false (disabled): a certificate grants nothing beyond authentication
// unless the policy explicitly enables it.
type Extensions struct {
	PermitPTY             bool `yaml:"permit_pty"`
	PermitPortForwarding  bool `yaml:"permit_port_forwarding"`
	PermitAgentForwarding bool `yaml:"permit_agent_forwarding"`
	PermitX11Forwarding   bool `yaml:"permit_x11_forwarding"`
	PermitUserRC          bool `yaml:"permit_user_rc"`
}

// Rule is a single issuance rule.
type Rule struct {
	Name        string      `yaml:"name"`
	Enabled     *bool       `yaml:"enabled"`
	Match       Match       `yaml:"match"`
	Certificate Certificate `yaml:"certificate"`
}

// IsEnabled reports whether the rule participates in matching.
// A rule without an explicit enabled flag is enabled.
func (r *Rule) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// Match describes the verified-identity conditions of a rule.
// Only JWT matching is supported in this version; an `aws:` key is
// rejected by strict decoding.
type Match struct {
	JWT *JWTMatch `yaml:"jwt"`
}

// JWTMatch matches verified JWT claims. All listed conditions must hold.
// A claim referenced in ClaimsExact that is absent from the token makes
// the match fail (deny).
//
// Owner and RepoName are the two halves of the GitHub Actions
// `repository` claim (`owner/repo`), split on the "/". Each is optional;
// an empty field is no constraint. When either is set, a token whose
// `repository` claim is absent or has no "/" fails the match.
type JWTMatch struct {
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	// Owner matches the portion of the `repository` claim before the "/"
	// (the org/user). Empty means no constraint.
	Owner string `yaml:"owner"`
	// RepoName matches the portion of the `repository` claim after the
	// "/" (the repo name). Empty means no constraint.
	RepoName    string            `yaml:"reponame"`
	ClaimsExact map[string]string `yaml:"claims_exact"`
}

// Certificate describes the certificate issued when the rule matches.
type Certificate struct {
	Principals      []string    `yaml:"principals"`
	ValidForSeconds int         `yaml:"valid_for_seconds"`
	KeyIDTemplate   string      `yaml:"key_id_template"`
	Extensions      *Extensions `yaml:"extensions"`
	// ForceCommand, when set, is embedded as the certificate's
	// force-command critical option: the target server runs only this
	// command regardless of what the client requests. It is used
	// verbatim — no ${claim} expansion — so it never carries
	// caller-controlled data.
	ForceCommand string `yaml:"force_command"`
	// SourceAddress, when set, is embedded as the source-address critical
	// option: a list of CIDR ranges the certificate may be used from.
	SourceAddress []string `yaml:"source_address"`
}

// ValidAfterOffsetSeconds returns the effective valid_after offset.
func (p *Policy) ValidAfterOffsetSeconds() int {
	if p.Defaults.ValidAfterOffsetSeconds != nil {
		return *p.Defaults.ValidAfterOffsetSeconds
	}
	return DefaultValidAfterOffsetSeconds
}

// MaxValidForSeconds returns the effective certificate TTL ceiling.
func (p *Policy) MaxValidForSeconds() int {
	if p.Defaults.MaxValidForSeconds != nil {
		return *p.Defaults.MaxValidForSeconds
	}
	return DefaultMaxValidForSeconds
}

// AllowedPublicKeyTypes returns the effective public key type allowlist.
func (p *Policy) AllowedPublicKeyTypes() []string {
	if len(p.Defaults.AllowedPublicKeyTypes) > 0 {
		return p.Defaults.AllowedPublicKeyTypes
	}
	return []string{"ssh-ed25519"}
}

// ExtensionsFor returns the effective extensions for a rule: the rule's
// own extensions if set, otherwise the policy defaults, otherwise all
// disabled.
func (p *Policy) ExtensionsFor(r *Rule) Extensions {
	if r.Certificate.Extensions != nil {
		return *r.Certificate.Extensions
	}
	if p.Defaults.Extensions != nil {
		return *p.Defaults.Extensions
	}
	return Extensions{}
}

// Issuers returns the deduplicated set of issuers referenced by enabled
// rules. The server pre-registers each with the JWT verifier.
func (p *Policy) Issuers() []string {
	seen := map[string]bool{}
	var out []string
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.IsEnabled() || r.Match.JWT == nil {
			continue
		}
		if iss := r.Match.JWT.Issuer; iss != "" && !seen[iss] {
			seen[iss] = true
			out = append(out, iss)
		}
	}
	return out
}

// Load reads, parses, and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

// Parse parses and validates policy YAML. Decoding is strict: unknown
// fields, type mismatches, and missing required fields are errors.
func Parse(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	// Reject trailing documents to avoid silently ignoring config.
	if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse policy: multiple YAML documents are not allowed")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

var ruleNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// principalRe constrains certificate principals. A principal becomes an
// OpenSSH certificate field and is matched against the target server's
// AuthorizedPrincipalsFile, so whitespace, commas, newlines, control
// characters, and unbounded length are rejected: a misconfigured policy
// must fail safe rather than emit a principal that confuses sshd.
var principalRe = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,128}$`)

// Validate checks semantic constraints beyond YAML decoding.
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d (expected 1)", p.Version)
	}
	if p.MaxValidForSeconds() <= 0 {
		return errors.New("policy: defaults.max_valid_for_seconds must be positive")
	}
	for _, kt := range p.AllowedPublicKeyTypes() {
		if !supportedKeyTypes[kt] {
			return fmt.Errorf("policy: unsupported public key type %q (supported: ssh-ed25519)", kt)
		}
	}
	if len(p.Rules) == 0 {
		return errors.New("policy: at least one rule is required")
	}

	names := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		where := fmt.Sprintf("rule %q", r.Name)
		if r.Name == "" {
			where = fmt.Sprintf("rule #%d", i+1)
			return fmt.Errorf("policy: %s: name is required", where)
		}
		if !ruleNameRe.MatchString(r.Name) {
			return fmt.Errorf("policy: %s: name contains invalid characters", where)
		}
		if names[r.Name] {
			return fmt.Errorf("policy: duplicate rule name %q", r.Name)
		}
		names[r.Name] = true

		m := r.Match.JWT
		if m == nil {
			return fmt.Errorf("policy: %s: match.jwt is required", where)
		}
		if m.Issuer == "" {
			return fmt.Errorf("policy: %s: match.jwt.issuer is required", where)
		}
		if m.Audience == "" {
			return fmt.Errorf("policy: %s: match.jwt.audience is required", where)
		}
		if strings.Contains(m.Owner, "/") {
			return fmt.Errorf("policy: %s: match.jwt.owner %q must not contain '/'", where, m.Owner)
		}
		if strings.Contains(m.RepoName, "/") {
			return fmt.Errorf("policy: %s: match.jwt.reponame %q must not contain '/'", where, m.RepoName)
		}
		for claim, v := range m.ClaimsExact {
			if claim == "" {
				return fmt.Errorf("policy: %s: claims_exact has an empty claim name", where)
			}
			if v == "" {
				return fmt.Errorf("policy: %s: claims_exact.%s has an empty value", where, claim)
			}
		}

		c := &r.Certificate
		if len(c.Principals) == 0 {
			return fmt.Errorf("policy: %s: certificate.principals must not be empty", where)
		}
		for _, principal := range c.Principals {
			if principal == "" {
				return fmt.Errorf("policy: %s: certificate.principals contains an empty principal", where)
			}
			if !principalRe.MatchString(principal) {
				return fmt.Errorf("policy: %s: certificate.principals %q contains characters outside [A-Za-z0-9._@:-] or exceeds 128 bytes", where, principal)
			}
		}
		if c.ValidForSeconds <= 0 {
			return fmt.Errorf("policy: %s: certificate.valid_for_seconds must be positive", where)
		}
		if c.ValidForSeconds > p.MaxValidForSeconds() {
			return fmt.Errorf("policy: %s: certificate.valid_for_seconds %d exceeds defaults.max_valid_for_seconds %d",
				where, c.ValidForSeconds, p.MaxValidForSeconds())
		}
		if c.KeyIDTemplate == "" {
			return fmt.Errorf("policy: %s: certificate.key_id_template is required", where)
		}
		if _, err := templateVars(c.KeyIDTemplate); err != nil {
			return fmt.Errorf("policy: %s: %w", where, err)
		}
		if err := validateForceCommand(c.ForceCommand); err != nil {
			return fmt.Errorf("policy: %s: %w", where, err)
		}
		if err := validateSourceAddress(c.SourceAddress); err != nil {
			return fmt.Errorf("policy: %s: %w", where, err)
		}
	}
	return nil
}

// validateForceCommand checks an optional force_command. It is used
// verbatim in the certificate, so claim templating is rejected (to avoid
// the illusion that ${claim} expands) and control characters are rejected
// (they would corrupt the certificate and audit log).
func validateForceCommand(cmd string) error {
	if cmd == "" {
		return nil
	}
	if strings.Contains(cmd, "${") {
		return errors.New("certificate.force_command does not support ${claim} templating; it is used verbatim")
	}
	for _, r := range cmd {
		if r < 0x20 || r == 0x7f {
			return errors.New("certificate.force_command contains a control character")
		}
	}
	return nil
}

// validateSourceAddress checks that every source_address entry is valid
// CIDR notation. Values are never silently rewritten, so a bare address
// without a mask (e.g. 192.0.2.10) is an error: write 192.0.2.10/32.
func validateSourceAddress(cidrs []string) error {
	for _, c := range cidrs {
		if c == "" {
			return errors.New("certificate.source_address contains an empty entry")
		}
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("certificate.source_address %q is not CIDR notation (e.g. 192.0.2.0/24 or 2001:db8::/32)", c)
		}
	}
	return nil
}
