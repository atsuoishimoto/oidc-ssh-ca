package issuer

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// Environment variables for the CA key source.
const (
	EnvKeyFile = "OIDC_SSH_CA_KEY_FILE"
	EnvKey     = "OIDC_SSH_CA_KEY"
)

// LoadCAKey resolves and parses the CA private key. Exactly one source
// must be set: the --ca-key-file flag, OIDC_SSH_CA_KEY_FILE, or
// OIDC_SSH_CA_KEY (the key material itself, for environments like
// Lambda where no file can be mounted). Zero or multiple sources is an
// error — there is no implicit precedence. The raw key bytes are not
// retained after parsing.
func LoadCAKey(flagPath string) (Signer, error) {
	type source struct {
		name string
		load func() ([]byte, error)
	}
	var sources []source

	if flagPath != "" {
		sources = append(sources, source{"--ca-key-file", func() ([]byte, error) {
			return readKeyFile(flagPath)
		}})
	}
	if p := os.Getenv(EnvKeyFile); p != "" {
		sources = append(sources, source{EnvKeyFile, func() ([]byte, error) {
			return readKeyFile(p)
		}})
	}
	if v := os.Getenv(EnvKey); v != "" {
		sources = append(sources, source{EnvKey, func() ([]byte, error) {
			return []byte(v), nil
		}})
	}

	switch len(sources) {
	case 0:
		return nil, fmt.Errorf("CA key not configured: set exactly one of --ca-key-file, %s, or %s", EnvKeyFile, EnvKey)
	case 1:
		// ok
	default:
		names := make([]string, len(sources))
		for i, s := range sources {
			names[i] = s.name
		}
		return nil, fmt.Errorf("CA key configured from multiple sources %v: set exactly one", names)
	}

	pem, err := sources[0].load()
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse CA key from %s: %w", sources[0].name, err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("CA key from %s has type %s: only ed25519 is supported", sources[0].name, signer.PublicKey().Type())
	}
	return NewMemorySigner(signer), nil
}

// readKeyFile reads a key file, refusing files readable by group or
// other (must be 0600 or stricter).
func readKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("CA key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("CA key file %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("CA key file %s has permissions %04o: must not be accessible by group/other (chmod 0600)", path, perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("CA key file: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("CA key file is empty")
	}
	return data, nil
}

// Fingerprint returns the SHA256 fingerprint of the CA public key. This
// is the only key-related value that may appear in logs.
func Fingerprint(s Signer) string {
	return ssh.FingerprintSHA256(s.PublicKey())
}
