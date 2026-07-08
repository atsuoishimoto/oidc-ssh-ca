// Package oidc verifies OIDC JWTs against the issuers referenced by the
// policy. Signature verification, discovery, and JWKS handling are
// delegated to github.com/coreos/go-oidc; this package fixes the
// operational rules: RS256 only, audience checked by policy matching,
// a 60-second leeway on time-based claims, and a 10-minute TTL on the
// cached JWKS.
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

// jwksTTL bounds how long a discovered provider — and therefore its
// cached JWKS — is trusted before discovery is re-run, so a signing key
// the IdP rotates out of its JWKS stops being accepted within this
// window instead of living for the whole process lifetime.
const jwksTTL = 10 * time.Minute

// Verifier verifies a bearer token and returns the verified identity.
type Verifier interface {
	Verify(ctx context.Context, rawToken string, allowedIssuers []string) (*policy.Identity, error)
}

// RemoteVerifier verifies tokens using OIDC discovery and remote JWKS.
// Discovered providers are cached per issuer for jwksTTL; once the TTL
// expires the provider is rebuilt, which re-runs discovery and fetches
// a fresh JWKS. Within the TTL go-oidc caches JWKS keys in memory and
// refetches once when an unknown key ID appears. If a refresh fails,
// the previously fetched keys keep working (stale, retried on the next
// request); with no cached keys verification fails (deny).
type RemoteVerifier struct {
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	providers map[string]cachedProvider
}

// cachedProvider is a discovered provider plus the time it was built,
// which bounds how long its JWKS cache is trusted.
type cachedProvider struct {
	provider  *gooidc.Provider
	fetchedAt time.Time
}

// NewRemoteVerifier returns a verifier with its own HTTP client.
func NewRemoteVerifier() *RemoteVerifier {
	return &RemoteVerifier{
		client:    &http.Client{Timeout: 10 * time.Second},
		now:       time.Now,
		providers: map[string]cachedProvider{},
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
	defer v.mu.Unlock()
	cached, ok := v.providers[issuer]
	if ok && v.now().Sub(cached.fetchedAt) < jwksTTL {
		return cached.provider, nil
	}
	p, err := gooidc.NewProvider(gooidc.ClientContext(ctx, v.client), issuer)
	if err != nil {
		if ok {
			// Fail safe: a failed refresh must not drop key material
			// that was fetched successfully before. The stale provider
			// keeps serving and the refresh is retried on the next
			// request; only a successful rebuild replaces it.
			return cached.provider, nil
		}
		return nil, err
	}
	v.providers[issuer] = cachedProvider{provider: p, fetchedAt: v.now()}
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
