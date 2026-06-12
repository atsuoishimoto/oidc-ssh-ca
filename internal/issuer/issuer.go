// Package issuer signs OpenSSH user certificates entirely in memory.
// There are no temporary files, no subprocesses, and no external SSH
// tools anywhere in the signing path.
package issuer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
)

// Signer abstracts certificate signing so the CA key handling can be
// replaced (e.g. by a KMS-backed crypto.Signer) without touching the
// issuance logic.
type Signer interface {
	// SignCertificate signs cert in place.
	SignCertificate(cert *ssh.Certificate) error
	// PublicKey returns the CA public key.
	PublicKey() ssh.PublicKey
}

// memorySigner signs with an in-memory ssh.Signer (MVP implementation).
type memorySigner struct {
	signer ssh.Signer
}

// NewMemorySigner wraps an in-memory ssh.Signer.
func NewMemorySigner(s ssh.Signer) Signer {
	return &memorySigner{signer: s}
}

func (m *memorySigner) SignCertificate(cert *ssh.Certificate) error {
	return cert.SignCert(rand.Reader, m.signer)
}

func (m *memorySigner) PublicKey() ssh.PublicKey {
	return m.signer.PublicKey()
}

// Request describes one certificate to issue. All fields are derived
// from the matched policy rule and verified claims, never from the
// HTTP request body.
type Request struct {
	PublicKey   ssh.PublicKey
	KeyID       string
	Principals  []string
	ValidAfter  time.Time
	ValidBefore time.Time
	Extensions  policy.Extensions
}

// Issue builds and signs a user certificate, returning it in
// authorized_keys format (single line, trailing newline).
func Issue(s Signer, req *Request) ([]byte, *ssh.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("issue: %w", err)
	}

	cert := &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(req.ValidAfter.Unix()),
		ValidBefore:     uint64(req.ValidBefore.Unix()),
		Permissions: ssh.Permissions{
			Extensions: extensionMap(req.Extensions),
		},
	}
	if err := s.SignCertificate(cert); err != nil {
		return nil, nil, fmt.Errorf("issue: sign: %w", err)
	}
	return ssh.MarshalAuthorizedKey(cert), cert, nil
}

func extensionMap(e policy.Extensions) map[string]string {
	out := map[string]string{}
	if e.PermitPTY {
		out["permit-pty"] = ""
	}
	if e.PermitPortForwarding {
		out["permit-port-forwarding"] = ""
	}
	if e.PermitAgentForwarding {
		out["permit-agent-forwarding"] = ""
	}
	if e.PermitX11Forwarding {
		out["permit-X11-forwarding"] = ""
	}
	if e.PermitUserRC {
		out["permit-user-rc"] = ""
	}
	return out
}

func randomSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("generate serial: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
