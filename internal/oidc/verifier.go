// Package oidc verifies OIDC JWTs against the issuers referenced by the
// policy. Signature verification, discovery, and JWKS handling are
// delegated to github.com/coreos/go-oidc; this package fixes the
// operational rules: RS256 only, audience checked by policy matching,
// and a 60-second leeway on time-based claims.
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
)

// ClockSkewLeeway is applied when validating exp / nbf / iat.
const ClockSkewLeeway = 60 * time.Second

// discoveryRetryDelay is how long a failed OIDC discovery result is
// cached before another attempt is made. Without it, every request for
// an unreachable issuer would start a fresh outbound discovery attempt
// lasting up to the full client timeout.
const discoveryRetryDelay = 5 * time.Second

// Verifier verifies a bearer token and returns the verified identity.
type Verifier interface {
	Verify(ctx context.Context, rawToken string, allowedIssuers []string) (*policy.Identity, error)
}

// RemoteVerifier verifies tokens using OIDC discovery and remote JWKS.
// Discovered providers are cached per issuer; go-oidc caches JWKS keys
// in memory and refetches once when an unknown key ID appears. If a
// JWKS refresh fails, previously cached keys keep working; with no
// cached keys verification fails (deny).
//
// Discovery is serialized per issuer, never globally: a slow or
// unreachable issuer only delays requests for that issuer, and
// concurrent first requests for one issuer share a single fetch.
// Failed discovery is cached for discoveryRetryDelay so an unreachable
// issuer does not turn every request into an outbound attempt.
type RemoteVerifier struct {
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex // guards the map only, never held across I/O
	providers map[string]*providerEntry
}

// providerEntry holds the discovery state for one issuer. Its mutex
// serializes discovery for that issuer only.
type providerEntry struct {
	mu       sync.Mutex
	provider *gooidc.Provider // non-nil once discovery has succeeded
	err      error            // last failure, retried after discoveryRetryDelay
	failedAt time.Time
}

// NewRemoteVerifier returns a verifier with its own HTTP client.
func NewRemoteVerifier() *RemoteVerifier {
	return &RemoteVerifier{
		client:    &http.Client{Timeout: 10 * time.Second},
		now:       time.Now,
		providers: map[string]*providerEntry{},
	}
}

// Verify checks the token signature against the issuer's JWKS and
// validates time-based claims with leeway. The audience is NOT checked
// here: it is part of policy rule matching (exactly-one-match).
func (v *RemoteVerifier) Verify(ctx context.Context, rawToken string, allowedIssuers []string) (*policy.Identity, error) {
	issuer, err := unverifiedIssuer(rawToken)
	if err != nil {
		return nil, err
	}
	if !containsString(allowedIssuers, issuer) {
		return nil, fmt.Errorf("issuer %q is not referenced by any policy rule", issuer)
	}

	provider, err := v.provider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", issuer, err)
	}

	verifier := provider.Verifier(&gooidc.Config{
		// The audience requirement depends on which rule matches, so it
		// is enforced by policy.Evaluate, not here.
		SkipClientIDCheck: true,
		// exp / nbf / iat are checked below with ClockSkewLeeway.
		SkipExpiryCheck:      true,
		SupportedSigningAlgs: []string{gooidc.RS256},
	})
	token, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification: %w", err)
	}

	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	if err := checkTimeClaims(claims, v.now()); err != nil {
		return nil, err
	}

	return &policy.Identity{
		Issuer:    token.Issuer,
		Audiences: token.Audience,
		Claims:    claims,
	}, nil
}

func (v *RemoteVerifier) provider(ctx context.Context, issuer string) (*gooidc.Provider, error) {
	v.mu.Lock()
	e, ok := v.providers[issuer]
	if !ok {
		e = &providerEntry{}
		v.providers[issuer] = e
	}
	v.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.provider != nil {
		return e.provider, nil
	}
	if e.err != nil && v.now().Sub(e.failedAt) < discoveryRetryDelay {
		return nil, e.err
	}
	p, err := gooidc.NewProvider(gooidc.ClientContext(ctx, v.client), issuer)
	if err != nil {
		e.err = err
		e.failedAt = v.now()
		return nil, err
	}
	e.provider = p
	e.err = nil
	return p, nil
}

// checkTimeClaims validates exp (required), nbf, and iat with leeway.
func checkTimeClaims(claims map[string]any, now time.Time) error {
	exp, ok := numericClaim(claims, "exp")
	if !ok {
		return errors.New("token has no exp claim")
	}
	if now.After(exp.Add(ClockSkewLeeway)) {
		return errors.New("token is expired")
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok && now.Before(nbf.Add(-ClockSkewLeeway)) {
		return errors.New("token is not yet valid (nbf)")
	}
	if iat, ok := numericClaim(claims, "iat"); ok && now.Before(iat.Add(-ClockSkewLeeway)) {
		return errors.New("token issued in the future (iat)")
	}
	return nil
}

func numericClaim(claims map[string]any, name string) (time.Time, bool) {
	v, ok := claims[name].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(v), 0), true
}

// unverifiedIssuer extracts the iss claim without verifying the
// signature. It is used only to select which issuer's JWKS to verify
// against; the value is trusted only after verification succeeds.
func unverifiedIssuer(rawToken string) (string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return "", errors.New("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("token payload does not decode")
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Issuer == "" {
		return "", errors.New("token has no iss claim")
	}
	return c.Issuer, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
