// Package e2e exercises the full certificate issuance flow against a
// local mock OIDC identity provider: real OIDC discovery, real JWKS
// fetch, and real RS256 signature verification, with no stubbed
// components.
package e2e

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockIDP is a minimal OIDC identity provider: one RSA signing key
// published through OIDC discovery and a JWKS endpoint, just enough
// for go-oidc to verify tokens minted by MintToken.
type mockIDP struct {
	Server *httptest.Server
	Key    *rsa.PrivateKey
	KeyID  string
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &mockIDP{Key: key, KeyID: "e2e-test-key"}

	// go-oidc requires the discovery document's issuer to equal the URL
	// it was given, which is only known once the server is listening, so
	// both handlers read Server.URL lazily.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                idp.Server.URL,
			"jwks_uri":                              idp.Server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": idp.KeyID,
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Server.Close)
	return idp
}

// Issuer returns the issuer URL to reference in policy and claims.
func (m *mockIDP) Issuer() string { return m.Server.URL }

// MintToken signs the claims with the IdP's published key.
func (m *mockIDP) MintToken(t *testing.T, claims map[string]any) string {
	return mintRS256(t, m.Key, m.KeyID, claims)
}

// mintRS256 builds an RS256 JWT by hand: the module has no JWT signing
// dependency, and the format is small enough to spell out. Standalone
// so tests can sign with a key the IdP does not publish.
func mintRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
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
