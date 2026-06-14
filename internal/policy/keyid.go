package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxKeyIDLength is the byte-length limit of an expanded key ID.
const MaxKeyIDLength = 256

var (
	templateVarRe = regexp.MustCompile(`\$\{([^}]*)\}`)
	claimNameRe   = regexp.MustCompile(`^[a-z0-9_]+$`)
	// keyIDValueRe is the allowlist for expanded claim values. Anything
	// else (whitespace, quotes, control characters, ...) denies the
	// request: the Key ID appears verbatim in sshd logs, and audit
	// values must not be silently rewritten.
	keyIDValueRe = regexp.MustCompile(`^[A-Za-z0-9._/:@-]+$`)
	// keyIDLiteralRe is the allowlist for the literal portions of a
	// template (everything outside ${...}). It permits the empty string
	// so a template made entirely of variables is accepted, but rejects
	// newlines, control characters, and whitespace baked into the
	// template itself. A malformed literal would otherwise survive into
	// the Key ID even when every claim value is clean.
	keyIDLiteralRe = regexp.MustCompile(`^[A-Za-z0-9._/:@-]*$`)
)

// templateVars extracts the variable names referenced by a
// key_id_template, validating the template syntax.
func templateVars(tmpl string) ([]string, error) {
	if strings.Contains(tmpl, "$") {
		// Every "$" must start a well-formed "${name}".
		stripped := templateVarRe.ReplaceAllString(tmpl, "")
		if strings.Contains(stripped, "$") {
			return nil, fmt.Errorf("key_id_template: malformed variable reference (use ${claim_name})")
		}
	}
	var vars []string
	for _, m := range templateVarRe.FindAllStringSubmatch(tmpl, -1) {
		name := m[1]
		if !claimNameRe.MatchString(name) {
			return nil, fmt.Errorf("key_id_template: invalid claim name %q", name)
		}
		vars = append(vars, name)
	}
	// The literal text around the variables must itself stay within the
	// Key ID allowlist. Expanded claim values are checked at issuance,
	// but a template like "gha:${repo}\nspoofed: x" would otherwise inject
	// newlines or control characters into sshd logs and the audit trail.
	literals := templateVarRe.ReplaceAllString(tmpl, "")
	if !keyIDLiteralRe.MatchString(literals) {
		return nil, fmt.Errorf("key_id_template: literal text contains characters outside [A-Za-z0-9._/:@-]")
	}
	return vars, nil
}

// TemplateVars exposes templateVars for check-config.
func TemplateVars(tmpl string) ([]string, error) { return templateVars(tmpl) }

// ExpandKeyID expands a key_id_template with verified claims. It fails
// (deny) when a referenced claim is missing or not a string, when an
// expanded value contains characters outside the allowlist, or when the
// result exceeds MaxKeyIDLength bytes.
func ExpandKeyID(tmpl string, claims map[string]any) (string, error) {
	var expandErr error
	out := templateVarRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		if expandErr != nil {
			return ""
		}
		name := m[2 : len(m)-1] // strip ${ }
		raw, present := claims[name]
		if !present {
			expandErr = fmt.Errorf("key_id: claim %q is not present in the token", name)
			return ""
		}
		v, ok := raw.(string)
		if !ok {
			expandErr = fmt.Errorf("key_id: claim %q is not a string", name)
			return ""
		}
		if !keyIDValueRe.MatchString(v) {
			expandErr = fmt.Errorf("key_id: claim %q contains characters outside [A-Za-z0-9._/:@-]", name)
			return ""
		}
		return v
	})
	if expandErr != nil {
		return "", expandErr
	}
	if len(out) > MaxKeyIDLength {
		return "", fmt.Errorf("key_id: expanded key ID exceeds %d bytes", MaxKeyIDLength)
	}
	// Defense in depth: re-check the fully expanded result. Each claim
	// value and the template literals are validated independently above,
	// so this can only fail on a logic error, but the Key ID reaches sshd
	// logs verbatim and is not worth trusting to construction alone.
	if !keyIDValueRe.MatchString(out) {
		return "", fmt.Errorf("key_id: expanded key ID contains characters outside [A-Za-z0-9._/:@-]")
	}
	return out, nil
}
