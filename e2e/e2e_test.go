package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/audit"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/issuer"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/oidc"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/server"
)

const (
	testPrincipal = "e2e-deploy"
	testKeyID     = "gha:test-org/test-repo:123456789:1"
)

const policyTemplate = `version: 1
rules:
  - name: "e2e-deploy"
    match:
      jwt:
        issuer: "%s"
        audience: "ssh-ca-e2e"
        claims_exact:
          repository: "test-org/test-repo"
          ref: "refs/heads/main"
    certificate:
      principals: ["e2e-deploy"]
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
`

// writeCAKey generates an ed25519 CA key in OpenSSH format with the
// 0600 permissions LoadCAKey requires, returning the path and the CA
// public key.
func writeCAKey(t *testing.T, dir string) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "e2e ca")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return path, sshPub
}

func writePolicy(t *testing.T, dir, issuerURL string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(policyTemplate, issuerURL)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// githubClaims returns a GitHub-Actions-shaped claim set that matches
// the test policy.
func githubClaims(issuerURL string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":         issuerURL,
		"aud":         "ssh-ca-e2e",
		"sub":         "repo:test-org/test-repo:ref:refs/heads/main",
		"repository":  "test-org/test-repo",
		"ref":         "refs/heads/main",
		"run_id":      "123456789",
		"run_attempt": "1",
		"iat":         now.Add(-30 * time.Second).Unix(),
		"exp":         now.Add(5 * time.Minute).Unix(),
	}
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

func postSign(t *testing.T, baseURL, token, publicKey string) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"public_key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/sign", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, respBody
}

// verifyCert checks the issued certificate the way a target server
// would: signed by the CA, valid now for the policy principal, with
// the policy-derived key ID, validity window, and (empty) extensions.
func verifyCert(t *testing.T, body []byte, caPub ssh.PublicKey) {
	t.Helper()
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		t.Fatalf("response is not a key: %v (body %q)", err, body)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("response is not a certificate: %T", parsed)
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPub.Marshal())
		},
	}
	if err := checker.CheckCert(testPrincipal, cert); err != nil {
		t.Fatalf("certificate does not verify against the CA: %v", err)
	}
	if cert.KeyId != testKeyID {
		t.Errorf("KeyId = %q, want %q", cert.KeyId, testKeyID)
	}
	if cert.ValidBefore-cert.ValidAfter != 630 { // 600s TTL + 30s offset
		t.Errorf("validity window = %d, want 630", cert.ValidBefore-cert.ValidAfter)
	}
	if len(cert.Permissions.Extensions) != 0 {
		t.Errorf("extensions = %v, want none (policy defaults)", cert.Permissions.Extensions)
	}
}

// syncBuffer guards a buffer written from server goroutines and read
// by the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestE2EInProcess wires the production components exactly as the
// serve command does — including the real OIDC verifier — and issues a
// certificate against a local mock IdP. Unlike the unit tests, nothing
// in the verification path is stubbed.
func TestE2EInProcess(t *testing.T) {
	idp := newMockIDP(t)
	dir := t.TempDir()
	caKeyPath, caPub := writeCAKey(t, dir)
	policyPath := writePolicy(t, dir, idp.Issuer())

	pol, err := policy.Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := issuer.LoadCAKey(caKeyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	logBuf := &syncBuffer{}
	log := audit.NewWithHandler(slog.NewJSONHandler(logBuf, nil))
	srv := server.New(pol, signer, oidc.NewRemoteVerifier(), log)
	ca := httptest.NewServer(srv.Handler())
	t.Cleanup(ca.Close)

	t.Run("issues certificate", func(t *testing.T) {
		token := idp.MintToken(t, githubClaims(idp.Issuer()))
		status, body := postSign(t, ca.URL, token, clientKeyLine(t))
		if status != http.StatusOK {
			t.Fatalf("status = %d, body = %s", status, body)
		}
		verifyCert(t, body, caPub)
		if !strings.Contains(logBuf.String(), audit.EventIssued) {
			t.Errorf("issued event not logged: %s", logBuf.String())
		}
	})

	// A key the IdP does not publish; signed with the published kid so
	// verification fails on the signature itself.
	rogueKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	denials := []struct {
		name       string
		token      func(t *testing.T) string
		wantStatus int
		wantReason string
	}{
		{
			name: "rejects token signed by unknown key",
			token: func(t *testing.T) string {
				return mintRS256(t, rogueKey, idp.KeyID, githubClaims(idp.Issuer()))
			},
			wantStatus: http.StatusUnauthorized, wantReason: "token_invalid",
		},
		{
			name: "rejects expired token",
			token: func(t *testing.T) string {
				claims := githubClaims(idp.Issuer())
				claims["iat"] = time.Now().Add(-10 * time.Minute).Unix()
				claims["exp"] = time.Now().Add(-5 * time.Minute).Unix()
				return idp.MintToken(t, claims)
			},
			wantStatus: http.StatusUnauthorized, wantReason: "token_invalid",
		},
		{
			name: "rejects unknown issuer",
			token: func(t *testing.T) string {
				claims := githubClaims("https://idp.invalid")
				return idp.MintToken(t, claims)
			},
			wantStatus: http.StatusUnauthorized, wantReason: "token_invalid",
		},
		{
			name: "rejects wrong audience",
			token: func(t *testing.T) string {
				claims := githubClaims(idp.Issuer())
				claims["aud"] = "some-other-service"
				return idp.MintToken(t, claims)
			},
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonNoRuleMatched,
		},
		{
			name: "rejects mismatched claim",
			token: func(t *testing.T) string {
				claims := githubClaims(idp.Issuer())
				claims["ref"] = "refs/heads/feature"
				return idp.MintToken(t, claims)
			},
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonNoRuleMatched,
		},
	}

	for _, tc := range denials {
		t.Run(tc.name, func(t *testing.T) {
			status, body := postSign(t, ca.URL, tc.token(t), clientKeyLine(t))
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", status, tc.wantStatus, body)
			}
			// The response must stay generic: a fixed message plus a
			// request ID, with the denial reason only in the audit log.
			var resp map[string]string
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("error body is not JSON: %v (body %q)", err, body)
			}
			if resp["request_id"] == "" {
				t.Errorf("missing request_id in %s", body)
			}
			if strings.Contains(resp["error"], tc.wantReason) {
				t.Errorf("error message leaks reason: %q", resp["error"])
			}
			if !strings.Contains(logBuf.String(), tc.wantReason) {
				t.Errorf("audit log missing reason %q", tc.wantReason)
			}
		})
	}
}

// TestE2EBinary builds the real binary and drives it over HTTP: serve
// issues a certificate for a mock-IdP token, and print-ca-pub provides
// the trust anchor that verifies it.
func TestE2EBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary e2e test in -short mode")
	}

	idp := newMockIDP(t)
	dir := t.TempDir()
	caKeyPath, _ := writeCAKey(t, dir)
	policyPath := writePolicy(t, dir, idp.Issuer())

	bin := filepath.Join(dir, "oidc-ssh-ca")
	build := exec.Command("go", "build", "-o", bin, "./cmd/oidc-ssh-ca")
	build.Dir = ".." // the test runs in e2e/; build from the repo root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// print-ca-pub is what operators distribute as TrustedUserCAKeys;
	// use its output as the trust anchor below.
	pubOut, err := exec.Command(bin, "print-ca-pub", "--ca-key-file", caKeyPath).Output()
	if err != nil {
		t.Fatalf("print-ca-pub: %v", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(pubOut)
	if err != nil {
		t.Fatalf("print-ca-pub output is not a key: %v (output %q)", err, pubOut)
	}

	addr := freeLoopbackAddr(t)
	serve := exec.Command(bin, "serve", "--config", policyPath, "--listen", addr, "--ca-key-file", caKeyPath)
	output := &syncBuffer{}
	serve.Stdout = output
	serve.Stderr = output
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		serve.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		serve.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			serve.Process.Kill()
			<-exited
		}
	})

	baseURL := "http://" + addr
	waitReady(t, baseURL+"/sign", exited, output)

	token := idp.MintToken(t, githubClaims(idp.Issuer()))
	status, body := postSign(t, baseURL, token, clientKeyLine(t))
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s\nserver output:\n%s", status, body, output.String())
	}
	verifyCert(t, body, caPub)
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// waitReady polls until the server answers HTTP (any status counts) or
// fails fast if the process exits first.
func waitReady(t *testing.T, url string, exited <-chan struct{}, output *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatalf("server exited before becoming ready; output:\n%s", output.String())
		default:
		}
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not become ready within 10s; output:\n%s", output.String())
}
