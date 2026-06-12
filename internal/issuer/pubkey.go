package issuer

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// MaxPublicKeyBytes bounds the public_key request field. An ed25519
// public key line is ~100 bytes; this leaves room for comments without
// accepting arbitrarily large input.
const MaxPublicKeyBytes = 4096

// ValidatePublicKey parses and validates a client public key in
// authorized_keys format. The key is never trusted as-is: it must be a
// single non-empty line that parses with x/crypto/ssh, its type must be
// in the allowlist, and certificates are rejected.
func ValidatePublicKey(raw string, allowedTypes []string) (ssh.PublicKey, error) {
	trimmed := strings.TrimRight(raw, "\r\n")
	if trimmed == "" {
		return nil, errors.New("public_key is empty")
	}
	if len(trimmed) > MaxPublicKeyBytes {
		return nil, fmt.Errorf("public_key exceeds %d bytes", MaxPublicKeyBytes)
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return nil, errors.New("public_key must be a single line")
	}

	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, fmt.Errorf("public_key does not parse: %w", err)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("public_key has trailing data")
	}

	keyType := pub.Type()
	if strings.Contains(keyType, "-cert-") {
		return nil, errors.New("public_key is a certificate, expected a plain public key")
	}
	for _, t := range allowedTypes {
		if keyType == t {
			return pub, nil
		}
	}
	return nil, fmt.Errorf("public_key type %s is not allowed", keyType)
}
