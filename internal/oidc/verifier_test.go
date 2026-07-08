package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// testIDP is a minimal OIDC identity provider whose published JWKS can
// be rotated and whose discovery endpoint can be made to fail, so tests
// can exercise the JWKS cache TTL and its fail-safe behavior.
type testIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	mu            sync.Mutex
	failDiscovery bool
	failJWKS      bool
	discoveryHits int
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()
	idp := &testIDP{}
	idp.rotateKey(t, "key-1")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		idp.discoveryHits++
		fail := idp.failDiscovery
		idp.mu.Unlock()
		if fail {
			http.Error(w, "discovery unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"issuer":                                idp.server.URL,
			"jwks_uri":                              idp.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		key, kid, fail := idp.key, idp.kid, idp.failJWKS
		idp.mu.Unlock()
		if fail {
			http.Error(w, "jwks unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// rotateKey replaces the published signing key, as an IdP does when it
// rotates a (possibly compromised) key out of its JWKS.
func (m *testIDP) rotateKey(t *testing.T, kid string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.key, m.kid = key, kid
}

func (m *testIDP) setFailDiscovery(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failDiscovery = fail
}

func (m *testIDP) setFailJWKS(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failJWKS = fail
}

func (m *testIDP) discoveryCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.discoveryHits
}

// mintToken signs the claims with the given key, which need not be the
// one the IdP currently publishes.
func mintToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) +
		"." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// fakeClockVerifier returns a verifier whose clock the test controls.
func fakeClockVerifier(start time.Time) (*RemoteVerifier, *time.Time) {
	now := start
	v := NewRemoteVerifier()
	v.now = func() time.Time { return now }
	return v, &now
}

func TestVerifyDeniesRemovedKeyAfterTTL(t *testing.T) {
	idp := newTestIDP(t)
	start := time.Now()
	v, clock := fakeClockVerifier(start)

	claims := map[string]any{
		"iss": idp.server.URL,
		"sub": "repo:example/example",
		"exp": float64(start.Add(time.Hour).Unix()),
		"iat": float64(start.Unix()),
	}
	oldKey, oldKid := idp.key, idp.kid
	token := mintToken(t, oldKey, oldKid, claims)
	allowed := []string{idp.server.URL}

	if _, err := v.Verify(context.Background(), token, allowed); err != nil {
		t.Fatalf("initial verification failed: %v", err)
	}

	// The IdP rotates the signing key out of its JWKS. Within the TTL
	// the cached key still verifies (the kid is known, so no refetch is
	// triggered) and discovery is not re-run.
	idp.rotateKey(t, "key-2")
	*clock = start.Add(jwksTTL - time.Minute)
	if _, err := v.Verify(context.Background(), token, allowed); err != nil {
		t.Fatalf("verification within TTL failed: %v", err)
	}
	if got := idp.discoveryCount(); got != 1 {
		t.Fatalf("discovery ran %d times within TTL, want 1", got)
	}

	// Once the TTL expires the JWKS is re-fetched and the removed key
	// must no longer verify tokens.
	*clock = start.Add(jwksTTL)
	if _, err := v.Verify(context.Background(), token, allowed); err == nil {
		t.Fatal("token signed with a rotated-out key verified after the TTL expired")
	}

	// The rotated-in key works against the refreshed JWKS.
	newToken := mintToken(t, idp.key, idp.kid, claims)
	if _, err := v.Verify(context.Background(), newToken, allowed); err != nil {
		t.Fatalf("verification with the new key failed: %v", err)
	}
}

func TestVerifyKeepsCachedKeysWhenRefreshFails(t *testing.T) {
	idp := newTestIDP(t)
	start := time.Now()
	v, clock := fakeClockVerifier(start)

	claims := map[string]any{
		"iss": idp.server.URL,
		"exp": float64(start.Add(time.Hour).Unix()),
	}
	token := mintToken(t, idp.key, idp.kid, claims)
	allowed := []string{idp.server.URL}

	if _, err := v.Verify(context.Background(), token, allowed); err != nil {
		t.Fatalf("initial verification failed: %v", err)
	}

	// The IdP becomes unreachable and the TTL expires: the refresh
	// fails, so the previously fetched keys must keep working.
	idp.setFailDiscovery(true)
	*clock = start.Add(jwksTTL + time.Minute)
	if _, err := v.Verify(context.Background(), token, allowed); err != nil {
		t.Fatalf("verification after failed refresh should use stale keys, got: %v", err)
	}

	// Once the IdP is reachable again the next request refreshes, and a
	// key rotated out in the meantime stops verifying.
	idp.setFailDiscovery(false)
	idp.rotateKey(t, "key-2")
	if _, err := v.Verify(context.Background(), token, allowed); err == nil {
		t.Fatal("token signed with a rotated-out key verified after a successful refresh")
	}
}

func TestVerifyKeepsCachedKeysWhenJWKSFetchFails(t *testing.T) {
	idp := newTestIDP(t)
	start := time.Now()
	v, clock := fakeClockVerifier(start)

	claims := map[string]any{
		"iss": idp.server.URL,
		"exp": float64(start.Add(time.Hour).Unix()),
	}
	token := mintToken(t, idp.key, idp.kid, claims)
	allowed := []string{idp.server.URL}

	if _, err := v.Verify(context.Background(), token, allowed); err != nil {
		t.Fatalf("initial verification failed: %v", err)
	}

	// Partial outage: discovery keeps answering but the JWKS endpoint
	// is down. Rebuilding the provider (discovery alone) would succeed,
	// but it must not replace the cached one — the previously fetched
	// keys have to keep working.
	idp.setFailJWKS(true)
	*clock = start.Add(jwksTTL + time.Minute)
	if _, err := v.Verify(context.Background(), token, allowed); err != nil {
		t.Fatalf("verification after failed JWKS refresh should use stale keys, got: %v", err)
	}

	// Once the JWKS endpoint recovers the next request refreshes, and a
	// key rotated out in the meantime stops verifying.
	idp.setFailJWKS(false)
	idp.rotateKey(t, "key-2")
	if _, err := v.Verify(context.Background(), token, allowed); err == nil {
		t.Fatal("token signed with a rotated-out key verified after a successful refresh")
	}
}

func TestVerifyDeniesWithoutCachedKeys(t *testing.T) {
	idp := newTestIDP(t)
	idp.setFailDiscovery(true)
	start := time.Now()
	v, _ := fakeClockVerifier(start)

	token := mintToken(t, idp.key, idp.kid, map[string]any{
		"iss": idp.server.URL,
		"exp": float64(start.Add(time.Hour).Unix()),
	})
	if _, err := v.Verify(context.Background(), token, []string{idp.server.URL}); err == nil {
		t.Fatal("verification succeeded with no JWKS ever fetched")
	}
}
