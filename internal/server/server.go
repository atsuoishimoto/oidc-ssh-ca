// Package server implements the signing flow behind POST /sign and the
// net/http transport that exposes it. On AWS Lambda the same HTTP server
// runs unchanged behind the Lambda Web Adapter, so there is no
// Lambda-specific transport.
//
// Error responses are deliberately generic — a fixed message plus a
// request ID. Denial reasons and internal details go only to the audit
// log, so callers cannot probe the policy by varying claims.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/audit"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/issuer"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/oidc"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
)

// MaxRequestBody bounds the /sign request body for every transport.
const MaxRequestBody = 16 * 1024

// Audit deny reason codes in addition to those defined by policy.
const (
	reasonBadRequest       = "bad_request"
	reasonInvalidPublicKey = "invalid_public_key"
	reasonMissingToken     = "missing_token"
	reasonTokenInvalid     = "token_invalid"
	reasonKeyIDInvalid     = "key_id_invalid"
	reasonSigningError     = "signing_error"
)

// auditedClaims are well-known GitHub Actions claims copied into audit
// events when present in the verified token.
var auditedClaims = []string{
	"sub", "repository", "ref", "environment", "event_name",
	"job_workflow_ref", "workflow", "actor", "run_id", "run_attempt",
}

// Response is the transport-agnostic outcome of a signing attempt. On
// success Body is the certificate (text/plain); on denial it is the
// generic JSON error. The audit event has already been written either
// way.
type Response struct {
	Status      int
	ContentType string
	Body        []byte
	RequestID   string
}

// Server holds the signing pipeline. The active policy is swapped
// atomically on SIGHUP reload.
type Server struct {
	signer   issuer.Signer
	verifier oidc.Verifier
	audit    *audit.Logger
	now      func() time.Time

	policy atomic.Pointer[policy.Policy]
}

// New creates a Server with the initial policy.
func New(p *policy.Policy, s issuer.Signer, v oidc.Verifier, a *audit.Logger) *Server {
	srv := &Server{signer: s, verifier: v, audit: a, now: time.Now}
	srv.policy.Store(p)
	return srv
}

// SetPolicy atomically replaces the active policy (SIGHUP reload).
func (s *Server) SetPolicy(p *policy.Policy) { s.policy.Store(p) }

// Policy returns the active policy.
func (s *Server) Policy() *policy.Policy { return s.policy.Load() }

// Sign runs the full pipeline for one request: validate the body and
// public key, verify the bearer token, match the policy
// (exactly-one-match), expand and sanitize the key ID, and sign. Every
// outcome — issued or denied — is audit-logged here, so transports only
// move bytes.
func (s *Server) Sign(ctx context.Context, method, authHeader string, body []byte) Response {
	requestID := newRequestID()

	if method != http.MethodPost {
		return s.deny(requestID, http.StatusMethodNotAllowed, reasonBadRequest, "method not allowed: "+method)
	}

	pol := s.policy.Load()
	if pol.Disabled {
		return s.deny(requestID, http.StatusServiceUnavailable, policy.ReasonPolicyDisabled, "policy is disabled")
	}

	// Parse and validate the request body. Only public_key is
	// accepted; principals, TTL, and extensions come from the policy.
	if len(body) > MaxRequestBody {
		return s.deny(requestID, http.StatusBadRequest, reasonBadRequest, "request body too large")
	}
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return s.deny(requestID, http.StatusBadRequest, reasonBadRequest, "request body is not valid JSON: "+err.Error())
	}
	pub, err := issuer.ValidatePublicKey(req.PublicKey, pol.AllowedPublicKeyTypes())
	if err != nil {
		return s.deny(requestID, http.StatusBadRequest, reasonInvalidPublicKey, err.Error())
	}
	fingerprint := ssh.FingerprintSHA256(pub)
	keyAttrs := []any{"public_key_fingerprint", fingerprint, "key_type", pub.Type()}

	// Verify the bearer token.
	rawToken, ok := bearerToken(authHeader)
	if !ok {
		return s.deny(requestID, http.StatusUnauthorized, reasonMissingToken, "missing or malformed Authorization header", keyAttrs...)
	}
	id, err := s.verifier.Verify(ctx, rawToken, pol.Issuers())
	if err != nil {
		return s.deny(requestID, http.StatusUnauthorized, reasonTokenInvalid, err.Error(), keyAttrs...)
	}
	claimAttrs := append(keyAttrs, identityAttrs(id)...)

	// Match policy rules: exactly one must match.
	decision := pol.Evaluate(id)
	if !decision.Allowed {
		status := http.StatusForbidden
		if decision.Reason == policy.ReasonPolicyDisabled {
			status = http.StatusServiceUnavailable
		}
		detail := decision.Reason
		if len(decision.MatchedRules) > 1 {
			detail = fmt.Sprintf("rules %v all matched", decision.MatchedRules)
		}
		return s.deny(requestID, status, decision.Reason, detail, claimAttrs...)
	}
	rule := decision.Rule

	keyID, err := policy.ExpandKeyID(rule.Certificate.KeyIDTemplate, id.Claims)
	if err != nil {
		return s.deny(requestID, http.StatusForbidden, reasonKeyIDInvalid, err.Error(), claimAttrs...)
	}

	now := s.now()
	certBytes, _, err := issuer.Issue(s.signer, &issuer.Request{
		PublicKey:     pub,
		KeyID:         keyID,
		Principals:    rule.Certificate.Principals,
		ValidAfter:    now.Add(time.Duration(pol.ValidAfterOffsetSeconds()) * time.Second),
		ValidBefore:   now.Add(time.Duration(rule.Certificate.ValidForSeconds) * time.Second),
		Extensions:    pol.ExtensionsFor(rule),
		ForceCommand:  rule.Certificate.ForceCommand,
		SourceAddress: rule.Certificate.SourceAddress,
	})
	if err != nil {
		return s.deny(requestID, http.StatusInternalServerError, reasonSigningError, err.Error(), claimAttrs...)
	}

	issuedAttrs := []any{
		"rule", rule.Name,
		"principals", rule.Certificate.Principals,
		"key_id", keyID,
		"valid_for_seconds", rule.Certificate.ValidForSeconds,
	}
	if rule.Certificate.ForceCommand != "" {
		issuedAttrs = append(issuedAttrs, "force_command", rule.Certificate.ForceCommand)
	}
	if len(rule.Certificate.SourceAddress) > 0 {
		issuedAttrs = append(issuedAttrs, "source_address", rule.Certificate.SourceAddress)
	}
	s.audit.Issued(requestID, append(issuedAttrs, claimAttrs...)...)

	return Response{
		Status:      http.StatusOK,
		ContentType: "text/plain; charset=utf-8",
		Body:        certBytes,
		RequestID:   requestID,
	}
}

// deny logs the real reason to the audit log and builds the generic
// response: fixed message + request ID only.
func (s *Server) deny(requestID string, status int, reason, detail string, attrs ...any) Response {
	s.audit.Denied(requestID, reason, detail, attrs...)

	body, _ := json.Marshal(map[string]string{
		"error":      "certificate request denied; contact your administrator with the request_id",
		"request_id": requestID,
	})
	return Response{
		Status:      status,
		ContentType: "application/json",
		Body:        append(body, '\n'),
		RequestID:   requestID,
	}
}

// Handler returns the net/http transport.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", s.handleSign)
	mux.HandleFunc("/ca-public-key", s.handleCAPub)
	return mux
}

// handleCAPub serves the CA public key in authorized_keys format. The CA
// public key is not a secret — it is distributed to every target server
// as TrustedUserCAKeys — so this endpoint is unauthenticated and reads no
// secret state. It is a plain data read, not an authorization decision,
// so it stays outside the audited Sign() pipeline.
func (s *Server) handleCAPub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(ssh.MarshalAuthorizedKey(s.signer.PublicKey()))
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	// Read at most one byte over the limit so Sign can distinguish
	// "too large" from a valid maximum-size body. A read error yields
	// a nil body, which fails JSON parsing and is denied as a bad
	// request.
	body, _ := io.ReadAll(io.LimitReader(r.Body, MaxRequestBody+1))

	resp := s.Sign(r.Context(), r.Method, r.Header.Get("Authorization"), body)

	w.Header().Set("Content-Type", resp.ContentType)
	w.Header().Set("X-Request-Id", resp.RequestID)
	w.WriteHeader(resp.Status)
	w.Write(resp.Body)
}

func bearerToken(authHeader string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) || len(authHeader) == len(prefix) {
		return "", false
	}
	return authHeader[len(prefix):], true
}

func identityAttrs(id *policy.Identity) []any {
	attrs := []any{"issuer", id.Issuer}
	for _, name := range auditedClaims {
		if v, ok := id.Claims[name].(string); ok {
			attrs = append(attrs, name, v)
		}
	}
	return attrs
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}
