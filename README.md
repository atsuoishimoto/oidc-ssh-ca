# oidc-ssh-ca

A small SSH certificate authority that issues short-lived OpenSSH user
certificates to OIDC-authenticated callers — primarily GitHub Actions.

Instead of storing a long-term SSH private key in GitHub Secrets, a workflow
generates an ephemeral key pair on every run, proves its identity with the
GitHub OIDC token, and receives a certificate valid for a few minutes.
Servers trust only the CA public key; there are no `authorized_keys` to
distribute, rotate, or clean up after a leak.

```text
GitHub Actions
  │  GitHub OIDC JWT + ephemeral public key
  ▼
oidc-ssh-ca  POST /sign
  │  verify JWT → match policy.yaml → sign in memory
  ▼
short-lived OpenSSH user certificate
  │  ssh / ansible / rsync / scp
  ▼
target servers (trust only the CA public key)
```

This is not a replacement for Vault, OpenBao, or Teleport. It is a small,
single-binary certificate issuer for individuals and small teams who want
OIDC-based SSH without operating a secrets platform.

## Design guarantees

- **No subprocesses, no temporary files, no external SSH tools.** All key
  parsing and certificate signing happens in memory via
  `golang.org/x/crypto/ssh`. The CA private key is never written to disk.
- **The policy decides everything.** Principals, TTL, extensions, and the
  certificate key ID are derived from verified JWT claims and `policy.yaml`.
  The request body carries only the public key — a caller cannot request a
  principal or a longer TTL.
- **Deny by default, exactly one match.** A request is allowed only if
  exactly one enabled rule matches; zero or multiple matches deny.
- **Fail safe.** An invalid policy prevents startup; a failed reload keeps
  the previous policy; a JWKS outage without cached keys denies.
- **Generic errors.** Callers get a fixed message and a request ID. Denial
  reasons go only to the audit log, so the policy cannot be probed.

## Documentation

The full documentation lives in [`docs/`](docs/) (Sphinx):

- [Quickstart](docs/quickstart.md) — CA key, policy, server, sshd, and the
  GitHub Actions workflow, end to end
- [Choosing a deployment](docs/deployment/index.md) —
  [Cloud Run](docs/deployment/cloud-run.md) (recommended),
  [Docker Compose + Caddy](docs/deployment/docker-compose.md),
  [AWS Lambda via CLI](docs/deployment/lambda-cli.md) or
  [Terraform](docs/deployment/lambda-terraform.md), and
  [systemd](docs/deployment/systemd.md)
- Reference — [policy format](docs/policy.md), [the /sign API](docs/api.md),
  [commands](docs/commands.md), and
  [operations](docs/operations.md) (audit log, reload, emergency stop,
  key rotation)

To build the HTML docs locally:

```bash
pip install -r docs/requirements.txt
make -C docs html    # docs/_build/html/index.html
```

## Status

MVP plus native Lambda support. GitHub Actions OIDC (RS256) is the
supported identity source; only `ssh-ed25519` keys are accepted for both
the CA and client keys. AWS IAM identity matching, Terraform modules, and
an Ansible role are planned — see `.memo/memo.md` for the full design
document.

## License

[MIT](LICENSE)
