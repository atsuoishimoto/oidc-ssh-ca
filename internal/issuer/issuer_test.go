package issuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
)

func newTestSigner(t *testing.T) (Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return NewMemorySigner(s), pub
}

func clientPublicKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func TestIssueRoundTrip(t *testing.T) {
	signer, _ := newTestSigner(t)
	clientPub, _ := clientPublicKey(t)

	now := time.Now()
	certBytes, cert, err := Issue(signer, &Request{
		PublicKey:   clientPub,
		KeyID:       "gha:org/repo:1:1",
		Principals:  []string{"gha-prod-deploy"},
		ValidAfter:  now.Add(-30 * time.Second),
		ValidBefore: now.Add(600 * time.Second),
		Extensions:  policy.Extensions{PermitPTY: true},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("issued certificate does not parse: %v", err)
	}
	got, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("not a certificate: %T", parsed)
	}
	if got.CertType != ssh.UserCert {
		t.Errorf("CertType = %d", got.CertType)
	}
	if got.KeyId != "gha:org/repo:1:1" {
		t.Errorf("KeyId = %q", got.KeyId)
	}
	if len(got.ValidPrincipals) != 1 || got.ValidPrincipals[0] != "gha-prod-deploy" {
		t.Errorf("ValidPrincipals = %v", got.ValidPrincipals)
	}
	if _, ok := got.Permissions.Extensions["permit-pty"]; !ok {
		t.Errorf("permit-pty missing: %v", got.Permissions.Extensions)
	}
	if len(got.Permissions.Extensions) != 1 {
		t.Errorf("unexpected extensions: %v", got.Permissions.Extensions)
	}
	if got.Serial == 0 && cert.Serial == 0 {
		t.Errorf("serial not set")
	}

	// The certificate must verify against the CA public key.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(signer.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("gha-prod-deploy", got); err != nil {
		t.Errorf("CheckCert: %v", err)
	}
}

func TestIssueCriticalOptions(t *testing.T) {
	signer, _ := newTestSigner(t)
	clientPub, _ := clientPublicKey(t)

	now := time.Now()
	certBytes, _, err := Issue(signer, &Request{
		PublicKey:     clientPub,
		KeyID:         "k",
		Principals:    []string{"gha-prod-deploy"},
		ValidAfter:    now.Add(-30 * time.Second),
		ValidBefore:   now.Add(600 * time.Second),
		ForceCommand:  "/usr/local/bin/deploy.sh",
		SourceAddress: []string{"192.0.2.0/24", "2001:db8::/32"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("issued certificate does not parse: %v", err)
	}
	got := parsed.(*ssh.Certificate)
	if cmd := got.Permissions.CriticalOptions["force-command"]; cmd != "/usr/local/bin/deploy.sh" {
		t.Errorf("force-command = %q", cmd)
	}
	if src := got.Permissions.CriticalOptions["source-address"]; src != "192.0.2.0/24,2001:db8::/32" {
		t.Errorf("source-address = %q", src)
	}

	// Without restrictions, no critical options are set.
	certBytes, _, err = Issue(signer, &Request{
		PublicKey:   clientPub,
		KeyID:       "k",
		Principals:  []string{"p"},
		ValidAfter:  now,
		ValidBefore: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, _, _, _, _ = ssh.ParseAuthorizedKey(certBytes)
	if opts := parsed.(*ssh.Certificate).Permissions.CriticalOptions; len(opts) != 0 {
		t.Errorf("expected no critical options, got %v", opts)
	}
}

func TestValidatePublicKey(t *testing.T) {
	_, line := clientPublicKey(t)
	allowed := []string{"ssh-ed25519"}

	if _, err := ValidatePublicKey(line, allowed); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := ValidatePublicKey(line+"\n", allowed); err != nil {
		t.Fatalf("trailing newline rejected: %v", err)
	}

	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"multi-line", line + "\n" + line},
		{"garbage", "not a key"},
		{"oversize", line + strings.Repeat(" x", MaxPublicKeyBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidatePublicKey(tc.key, allowed); err == nil {
				t.Fatal("expected error")
			}
		})
	}

	t.Run("type not in allowlist", func(t *testing.T) {
		if _, err := ValidatePublicKey(line, []string{"ssh-rsa"}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("certificate rejected", func(t *testing.T) {
		signer, _ := newTestSigner(t)
		clientPub, _ := clientPublicKey(t)
		certBytes, _, err := Issue(signer, &Request{
			PublicKey:   clientPub,
			KeyID:       "k",
			Principals:  []string{"p"},
			ValidAfter:  time.Now(),
			ValidBefore: time.Now().Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidatePublicKey(strings.TrimSpace(string(certBytes)), allowed); err == nil {
			t.Fatal("certificate must be rejected as a public key")
		}
	})
}

func writeTestCAKey(t *testing.T, perm os.FileMode) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca_key")
	data := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCAKey(t *testing.T) {
	t.Run("flag source", func(t *testing.T) {
		path := writeTestCAKey(t, 0o600)
		s, err := LoadCAKey(path, false)
		if err != nil {
			t.Fatalf("LoadCAKey: %v", err)
		}
		if !strings.HasPrefix(Fingerprint(s), "SHA256:") {
			t.Errorf("Fingerprint = %q", Fingerprint(s))
		}
	})

	t.Run("no source", func(t *testing.T) {
		if _, err := LoadCAKey("", false); err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("expected not-configured error, got %v", err)
		}
	})

	t.Run("multiple sources", func(t *testing.T) {
		path := writeTestCAKey(t, 0o600)
		t.Setenv(EnvKeyFile, path)
		if _, err := LoadCAKey(path, false); err == nil || !strings.Contains(err.Error(), "multiple sources") {
			t.Fatalf("expected multiple-sources error, got %v", err)
		}
	})

	t.Run("loose permissions", func(t *testing.T) {
		path := writeTestCAKey(t, 0o644)
		if _, err := LoadCAKey(path, false); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("expected permissions error, got %v", err)
		}
	})

	t.Run("loose permissions allowed when skip set", func(t *testing.T) {
		// Mirrors a systemd LoadCredential file (mode 0440): the perm
		// check must be bypassable, but only via the explicit flag.
		path := writeTestCAKey(t, 0o440)
		if _, err := LoadCAKey(path, true); err != nil {
			t.Fatalf("LoadCAKey with skip set rejected 0440: %v", err)
		}
	})

	t.Run("not a regular file", func(t *testing.T) {
		if _, err := LoadCAKey(t.TempDir(), false); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected not-a-regular-file error, got %v", err)
		}
	})

	t.Run("symlink to key file is followed", func(t *testing.T) {
		// Checks run on the opened descriptor, so a symlink resolves to
		// its target and the permission check applies to the target.
		path := writeTestCAKey(t, 0o600)
		link := filepath.Join(t.TempDir(), "ca_key_link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCAKey(link, false); err != nil {
			t.Fatalf("LoadCAKey via symlink: %v", err)
		}
	})

	t.Run("symlink to loose-permission key file is rejected", func(t *testing.T) {
		path := writeTestCAKey(t, 0o644)
		link := filepath.Join(t.TempDir(), "ca_key_link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCAKey(link, false); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("expected permissions error, got %v", err)
		}
	})

	t.Run("env key material", func(t *testing.T) {
		path := writeTestCAKey(t, 0o600)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(EnvKey, string(data))
		if _, err := LoadCAKey("", false); err != nil {
			t.Fatalf("LoadCAKey from env: %v", err)
		}
	})

	t.Run("garbage key", func(t *testing.T) {
		t.Setenv(EnvKey, "not a key")
		if _, err := LoadCAKey("", false); err == nil {
			t.Fatal("expected parse error")
		}
	})
}
