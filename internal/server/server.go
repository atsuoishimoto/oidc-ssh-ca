// Package server implements the HTTP API: POST /sign.
//
// Error responses are deliberately generic — a fixed message plus a
// request ID. Denial reasons and internal details go only to the audit
// log, so callers cannot probe the policy by varying claims.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/audit"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/issuer"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/oidc"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
)

// maxRequestBody bounds the /sign request body.
const maxRequestBody = 16 * 1024

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

// Server handles /sign. The active policy is swapped atomically on
// SIGHUP reload.
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

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", s.handleSign)
	return mux
}

type signRequest struct {
	PublicKey string `json:"public_key"`
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()

	if r.Method != http.MethodPost {
		s.deny(w, requestID, http.StatusMethodNotAllowed, reasonBadRequest, "method not allowed: "+r.Method)
		return
	}

	pol := s.policy.Load()
	if pol.Disabled {
		s.deny(w, requestID, http.StatusServiceUnavailable, policy.ReasonPolicyDisabled, "policy is disabled")
		return
	}

	// Parse and validate the request body. Only public_key is
	// accepted; principals, TTL, and extensions come from the policy.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil || len(body) > maxRequestBody {
		s.deny(w, requestID, http.StatusBadRequest, reasonBadRequest, "request body unreadable or too large")
		return
	}
	var req signRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.deny(w, requestID, http.StatusBadRequest, reasonBadRequest, "request body is not valid JSON: "+err.Error())
		return
	}
	pub, err := issuer.ValidatePublicKey(req.PublicKey, pol.AllowedPublicKeyTypes())
	if err != nil {
		s.deny(w, requestID, http.StatusBadRequest, reasonInvalidPublicKey, err.Error())
		return
	}
	fingerprint := ssh.FingerprintSHA256(pub)
	keyAttrs := []any{"public_key_fingerprint", fingerprint, "key_type", pub.Type()}

	// Verify the bearer token.
	rawToken, ok := bearerToken(r)
	if !ok {
		s.deny(w, requestID, http.StatusUnauthorized, reasonMissingToken, "missing or malformed Authorization header", keyAttrs...)
		return
	}
	id, err := s.verifier.Verify(r.Context(), rawToken, pol.Issuers())
	if err != nil {
		s.deny(w, requestID, http.StatusUnauthorized, reasonTokenInvalid, err.Error(), keyAttrs...)
		return
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
		s.deny(w, requestID, status, decision.Reason, detail, claimAttrs...)
		return
	}
	rule := decision.Rule

	keyID, err := policy.ExpandKeyID(rule.Certificate.KeyIDTemplate, id.Claims)
	if err != nil {
		s.deny(w, requestID, http.StatusForbidden, reasonKeyIDInvalid, err.Error(), claimAttrs...)
		return
	}

	now := s.now()
	certBytes, _, err := issuer.Issue(s.signer, &issuer.Request{
		PublicKey:   pub,
		KeyID:       keyID,
		Principals:  rule.Certificate.Principals,
		ValidAfter:  now.Add(time.Duration(pol.ValidAfterOffsetSeconds()) * time.Second),
		ValidBefore: now.Add(time.Duration(rule.Certificate.ValidForSeconds) * time.Second),
		Extensions:  pol.ExtensionsFor(rule),
	})
	if err != nil {
		s.deny(w, requestID, http.StatusInternalServerError, reasonSigningError, err.Error(), claimAttrs...)
		return
	}

	s.audit.Issued(requestID, append([]any{
		"rule", rule.Name,
		"principals", rule.Certificate.Principals,
		"key_id", keyID,
		"valid_for_seconds", rule.Certificate.ValidForSeconds,
	}, claimAttrs...)...)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Request-Id", requestID)
	w.WriteHeader(http.StatusOK)
	w.Write(certBytes)
}

// deny logs the real reason to the audit log and sends a generic
// response: fixed message + request ID only.
func (s *Server) deny(w http.ResponseWriter, requestID string, status int, reason, detail string, attrs ...any) {
	s.audit.Denied(requestID, reason, detail, attrs...)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", requestID)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":      "certificate request denied; contact your administrator with the request_id",
		"request_id": requestID,
	})
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return "", false
	}
	return h[len(prefix):], true
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
