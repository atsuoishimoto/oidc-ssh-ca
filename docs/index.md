# oidc-ssh-ca

A small SSH certificate authority that issues short-lived OpenSSH user
certificates to OIDC-authenticated callers — primarily GitHub Actions.

Instead of storing a long-term SSH private key in GitHub Secrets, a workflow
generates an ephemeral key pair on every run, proves its identity with the
GitHub OIDC token, and receives a certificate valid for a few minutes.
Target servers trust only the CA public key; there are no `authorized_keys`
to distribute, rotate, or clean up after a leak.

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
single-binary tool that replaces long-lived SSH keys in GitHub Actions with
short-lived, OIDC-issued certificates.

## Design guarantees

- **No subprocesses, no temporary files, no external SSH tools.** All key
  parsing and certificate signing happens in memory via
  `golang.org/x/crypto/ssh`. The CA private key is never written to disk.
- **The policy decides everything.** Principals, TTL, extensions, and the
  certificate key ID are derived from verified JWT claims and `policy.yaml`.
  The request body carries only the public key — a caller cannot request a
  principal or a longer TTL.
- **Deny by default, exactly one match.** A request is allowed only if
  exactly one enabled rule matches. Zero matches deny; multiple matches deny
  (no first-match-wins surprises). A claim referenced by a rule but absent
  from the token denies.
- **Fail safe.** An invalid policy prevents startup; a failed reload keeps
  the previous policy; a JWKS outage without cached keys denies.
- **Generic errors.** Callers get a fixed message and a request ID. Denial
  reasons and details go only to the server's audit log, so the policy
  cannot be probed by varying claims.

```{toctree}
:maxdepth: 2
:caption: Getting started

quickstart
```

```{toctree}
:maxdepth: 2
:caption: Deployment

deployment/index
deployment/cloud-run
deployment/docker-compose
deployment/lambda-cli
deployment/lambda-terraform
deployment/systemd
```

```{toctree}
:maxdepth: 2
:caption: Target servers

target-servers
ansible
```

```{toctree}
:maxdepth: 2
:caption: Reference

policy
security-model
api
commands
operations
```

```{toctree}
:maxdepth: 2
:caption: Development

building
testing
```
