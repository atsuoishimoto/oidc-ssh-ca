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
	"io"
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
// Discovered providers are cached per issuer for jwksTTL; once the TTL
// expires the provider is rebuilt, which re-runs discovery, and the
// rebuilt provider replaces the cached one only after its JWKS endpoint
// has served a parseable key set. Within the TTL go-oidc caches JWKS
// keys in memory and refetches once when an unknown key ID appears. If
// any part of a refresh fails, the previously fetched keys keep working
// (stale, retried after discoveryRetryDelay); with no cached keys
// verification fails (deny).
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
	mu        sync.Mutex
	provider  *gooidc.Provider // non-nil once discovery has succeeded
	fetchedAt time.Time        // when provider was built; bounds how long its JWKS is trusted
	err       error            // last failure, retried after discoveryRetryDelay
	failedAt  time.Time
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
	if e.provider != nil && v.now().Sub(e.fetchedAt) < jwksTTL {
		return e.provider, nil
	}
	if e.err != nil && v.now().Sub(e.failedAt) < discoveryRetryDelay {
		// A fetch failed moments ago; don't turn every request into an
		// outbound attempt. A stale provider, if any, keeps serving
		// until the retry delay has passed.
		if e.provider != nil {
			return e.provider, nil
		}
		return nil, e.err
	}
	p, err := v.discoverProvider(ctx, issuer)
	if err != nil {
		// A canceled or deadlined *request* context says nothing about
		// the issuer's health — don't poison the negative cache with it.
		if ctx.Err() == nil {
			e.err = err
			e.failedAt = v.now()
		}
		if e.provider != nil {
			// Fail safe: a failed refresh must not drop key material
			// that was fetched successfully before. The stale provider
			// keeps serving and the refresh is retried once the retry
			// delay has passed; only a successful rebuild replaces it.
			return e.provider, nil
		}
		return nil, err
	}
	e.provider = p
	e.fetchedAt = v.now()
	e.err = nil
	return p, nil
}

// jwksMaxResponseBytes caps how much of a JWKS response the pre-flight
// check reads.
const jwksMaxResponseBytes = 1 << 20

// discoverProvider runs OIDC discovery and then confirms the issuer's
// JWKS endpoint is serving a parseable key set. gooidc.NewProvider
// alone fetches only the discovery document — go-oidc fetches the JWKS
// lazily on first verification — so without this pre-flight a provider
// rebuilt during a partial IdP outage (discovery up, JWKS down) would
// replace working cached keys with a key set that cannot be fetched.
func (v *RemoteVerifier) discoverProvider(ctx context.Context, issuer string) (*gooidc.Provider, error) {
	p, err := gooidc.NewProvider(gooidc.ClientContext(ctx, v.client), issuer)
	if err != nil {
		return nil, err
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := p.Claims(&doc); err != nil {
		return nil, fmt.Errorf("decode discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return nil, errors.New("discovery document has no jwks_uri")
	}
	if err := v.checkJWKS(ctx, doc.JWKSURI); err != nil {
		return nil, fmt.Errorf("jwks pre-flight for %s: %w", doc.JWKSURI, err)
	}
	return p, nil
}

// checkJWKS fetches the JWKS URI and verifies the response looks like a
// key set. The keys go-oidc will trust are the ones from its own fetch,
// not this one; this only establishes that the endpoint is serving
// before the previously cached provider is discarded.
func (v *RemoteVerifier) checkJWKS(ctx context.Context, jwksURI string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("response is not a JWKS: %w", err)
	}
	if jwks.Keys == nil {
		return errors.New("response has no keys member")
	}
	return nil
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
