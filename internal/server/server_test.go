package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/audit"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/issuer"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
)

const testPolicy = `
version: 1
rules:
  - name: "prod-deploy"
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

// stubVerifier returns a fixed identity or error; the token string
// "good" selects the identity.
type stubVerifier struct {
	identity *policy.Identity
}

func (s *stubVerifier) Verify(_ context.Context, rawToken string, _ []string) (*policy.Identity, error) {
	if rawToken == "good" && s.identity != nil {
		return s.identity, nil
	}
	return nil, errors.New("token verification failed")
}

func goodIdentity() *policy.Identity {
	return &policy.Identity{
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

func newTestServer(t *testing.T, pol string, id *policy.Identity) (*Server, *bytes.Buffer) {
	t.Helper()
	p, err := policy.Parse([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	log := audit.NewWithHandler(slog.NewJSONHandler(&logBuf, nil))
	return New(p, issuer.NewMemorySigner(sshSigner), &stubVerifier{identity: id}, log), &logBuf
}

func clientKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func doSign(t *testing.T, srv *Server, token, publicKey string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"public_key": publicKey})
	req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestSignIssuesCertificate(t *testing.T) {
	srv, logBuf := newTestServer(t, testPolicy, goodIdentity())
	rec := doSign(t, srv, "good", clientKeyLine(t))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("response is not a key: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("response is not a certificate: %T", parsed)
	}
	if cert.KeyId != "gha:your-org/your-repo:123456789:1" {
		t.Errorf("KeyId = %q", cert.KeyId)
	}
	if cert.ValidBefore-cert.ValidAfter != 630 { // 600s TTL + 30s offset
		t.Errorf("validity window = %d", cert.ValidBefore-cert.ValidAfter)
	}
	if !strings.Contains(logBuf.String(), audit.EventIssued) {
		t.Errorf("issued event not logged: %s", logBuf.String())
	}
}

func TestSignDenials(t *testing.T) {
	keyLine := clientKeyLine(t)

	cases := []struct {
		name       string
		policy     string
		identity   *policy.Identity
		token      string
		publicKey  string
		wantStatus int
		wantReason string
	}{
		{
			name:     "disabled policy returns 503",
			policy:   strings.Replace(testPolicy, "version: 1", "version: 1\ndisabled: true", 1),
			identity: goodIdentity(), token: "good", publicKey: keyLine,
			wantStatus: http.StatusServiceUnavailable, wantReason: policy.ReasonPolicyDisabled,
		},
		{
			name: "missing token returns 401", policy: testPolicy,
			identity: goodIdentity(), token: "", publicKey: keyLine,
			wantStatus: http.StatusUnauthorized, wantReason: "missing_token",
		},
		{
			name: "bad token returns 401", policy: testPolicy,
			identity: goodIdentity(), token: "bad", publicKey: keyLine,
			wantStatus: http.StatusUnauthorized, wantReason: "token_invalid",
		},
		{
			name: "invalid public key returns 400", policy: testPolicy,
			identity: goodIdentity(), token: "good", publicKey: "garbage",
			wantStatus: http.StatusBadRequest, wantReason: "invalid_public_key",
		},
		{
			name: "no matching rule returns 403", policy: testPolicy,
			identity: func() *policy.Identity {
				id := goodIdentity()
				id.Claims["ref"] = "refs/heads/feature"
				return id
			}(), token: "good", publicKey: keyLine,
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonNoRuleMatched,
		},
		{
			name: "key_id injection returns 403", policy: testPolicy,
			identity: func() *policy.Identity {
				id := goodIdentity()
				id.Claims["run_id"] = "123\nforged"
				return id
			}(), token: "good", publicKey: keyLine,
			wantStatus: http.StatusForbidden, wantReason: "key_id_invalid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, logBuf := newTestServer(t, tc.policy, tc.identity)
			rec := doSign(t, srv, tc.token, tc.publicKey)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			// The response must be generic: no internal detail, only a
			// fixed message and request ID.
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("error body is not JSON: %v", err)
			}
			if resp["request_id"] == "" {
				t.Errorf("missing request_id")
			}
			if strings.Contains(resp["error"], tc.wantReason) {
				t.Errorf("error message leaks reason: %q", resp["error"])
			}
			if !strings.Contains(logBuf.String(), tc.wantReason) {
				t.Errorf("audit log missing reason %q: %s", tc.wantReason, logBuf.String())
			}
			if !strings.Contains(logBuf.String(), audit.EventDenied) {
				t.Errorf("denied event not logged")
			}
		})
	}
}

func TestSignRejectsExtraBodyFields(t *testing.T) {
	// principal smuggling via the request body must have no effect:
	// the body only carries public_key, everything else comes from
	// policy. Unknown fields are simply ignored by json.Unmarshal, so
	// verify the issued principal is the policy's one.
	srv, _ := newTestServer(t, testPolicy, goodIdentity())
	body := `{"public_key": "` + clientKeyLine(t) + `", "principal": "root", "ttl": 999999}`
	req := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	parsed, _, _, _, _ := ssh.ParseAuthorizedKey(rec.Body.Bytes())
	cert := parsed.(*ssh.Certificate)
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "gha-prod-deploy" {
		t.Fatalf("principals = %v", cert.ValidPrincipals)
	}
}

func TestSignMethodNotAllowed(t *testing.T) {
	srv, _ := newTestServer(t, testPolicy, goodIdentity())
	req := httptest.NewRequest(http.MethodGet, "/sign", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCAPublicKey(t *testing.T) {
	srv, logBuf := newTestServer(t, testPolicy, goodIdentity())

	req := httptest.NewRequest(http.MethodGet, "/ca-public-key", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type = %q", ct)
	}
	want := ssh.MarshalAuthorizedKey(srv.signer.PublicKey())
	if got := rec.Body.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("body = %q, want %q", got, want)
	}
	// Serving the public key must not write an audit event.
	if logBuf.Len() != 0 {
		t.Fatalf("unexpected audit output: %s", logBuf.String())
	}
}

func TestCAPublicKeyMethodNotAllowed(t *testing.T) {
	srv, _ := newTestServer(t, testPolicy, goodIdentity())
	req := httptest.NewRequest(http.MethodPost, "/ca-public-key", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSignOversizeBody(t *testing.T) {
	srv, _ := newTestServer(t, testPolicy, goodIdentity())
	big := strings.Repeat("x", MaxRequestBody+10)
	req := httptest.NewRequest(http.MethodPost, "/sign", io.NopCloser(strings.NewReader(big)))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestPolicyReloadSwap(t *testing.T) {
	srv, _ := newTestServer(t, testPolicy, goodIdentity())
	disabled, err := policy.Parse([]byte(strings.Replace(testPolicy, "version: 1", "version: 1\ndisabled: true", 1)))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetPolicy(disabled)
	rec := doSign(t, srv, "good", clientKeyLine(t))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status after disable = %d", rec.Code)
	}
}
