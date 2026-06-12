package lambda

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"golang.org/x/crypto/ssh"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/audit"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/issuer"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/server"
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
    certificate:
      principals: ["gha-prod-deploy"]
      valid_for_seconds: 600
      key_id_template: "gha:${repository}"
`

type stubVerifier struct{}

func (stubVerifier) Verify(_ context.Context, rawToken string, _ []string) (*policy.Identity, error) {
	if rawToken != "good" {
		return nil, errors.New("token verification failed")
	}
	return &policy.Identity{
		Issuer:    "https://token.actions.githubusercontent.com",
		Audiences: []string{"ssh-ca-prod"},
		Claims:    map[string]any{"repository": "your-org/your-repo"},
	}, nil
}

func newHandler(t *testing.T) func(context.Context, events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	t.Helper()
	p, err := policy.Parse([]byte(testPolicy))
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
	log := audit.NewWithHandler(slog.NewJSONHandler(&strings.Builder{}, nil))
	return Handler(server.New(p, issuer.NewMemorySigner(sshSigner), stubVerifier{}, log))
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

func newEvent(method, auth, body string, b64 bool) events.LambdaFunctionURLRequest {
	req := events.LambdaFunctionURLRequest{
		Body:            body,
		IsBase64Encoded: b64,
		Headers:         map[string]string{},
	}
	req.RequestContext.HTTP.Method = method
	if auth != "" {
		req.Headers["authorization"] = auth // Function URLs lowercase headers
	}
	return req
}

func signBody(t *testing.T) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"public_key": clientKeyLine(t)})
	return string(b)
}

func TestHandlerIssues(t *testing.T) {
	h := newHandler(t)
	resp, err := h(context.Background(), newEvent("POST", "Bearer good", signBody(t), false))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, resp.Body)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Body))
	if err != nil {
		t.Fatalf("response is not a key: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok || cert.KeyId != "gha:your-org/your-repo" {
		t.Fatalf("unexpected certificate: %+v", parsed)
	}
	if resp.Headers["X-Request-Id"] == "" {
		t.Error("missing X-Request-Id header")
	}
}

func TestHandlerBase64Body(t *testing.T) {
	h := newHandler(t)
	encoded := base64.StdEncoding.EncodeToString([]byte(signBody(t)))
	resp, err := h(context.Background(), newEvent("POST", "Bearer good", encoded, true))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, resp.Body)
	}
}

func TestHandlerDenials(t *testing.T) {
	h := newHandler(t)
	cases := []struct {
		name  string
		event events.LambdaFunctionURLRequest
		want  int
	}{
		{"missing token", newEvent("POST", "", signBody(t), false), http.StatusUnauthorized},
		{"bad token", newEvent("POST", "Bearer bad", signBody(t), false), http.StatusUnauthorized},
		{"wrong method", newEvent("GET", "Bearer good", "", false), http.StatusMethodNotAllowed},
		{"invalid base64", newEvent("POST", "Bearer good", "!!!not-base64!!!", true), http.StatusBadRequest},
		{"garbage body", newEvent("POST", "Bearer good", "garbage", false), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := h(context.Background(), tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, tc.want, resp.Body)
			}
			// Denials must stay generic in this transport too.
			var body map[string]string
			if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
				t.Fatalf("error body is not JSON: %v", err)
			}
			if body["request_id"] == "" {
				t.Error("missing request_id")
			}
		})
	}
}
