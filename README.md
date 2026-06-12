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
  exactly one enabled rule matches. Zero matches deny; multiple matches deny
  (no first-match-wins surprises). A claim referenced by a rule but absent
  from the token denies.
- **Fail safe.** An invalid policy prevents startup; a failed reload keeps
  the previous policy; a JWKS outage without cached keys denies.
- **Generic errors.** Callers get a fixed message and a request ID. Denial
  reasons and details go only to the server's audit log, so the policy
  cannot be probed by varying claims.

## Quickstart

### 1. Generate the CA key

```bash
ssh-keygen -t ed25519 -N "" -f ca_key -C "oidc-ssh-ca"
chmod 0600 ca_key
```

### 2. Write the policy

`policy.yaml`:

```yaml
version: 1
disabled: false

defaults:
  valid_after_offset_seconds: -30
  max_valid_for_seconds: 900
  allowed_public_key_types:
    - "ssh-ed25519"

rules:
  - name: "prod-deploy"
    enabled: true
    match:
      jwt:
        issuer: "https://token.actions.githubusercontent.com"
        audience: "ssh-ca-prod"
        claims_exact:
          repository: "your-org/your-repo"
          ref: "refs/heads/main"
          environment: "production"
          event_name: "push"
          job_workflow_ref: "your-org/your-repo/.github/workflows/deploy.yml@refs/heads/main"
    certificate:
      principals:
        - "gha-prod-deploy"
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
```

Validate it:

```bash
oidc-ssh-ca check-config policy.yaml
```

### 3. Run the server

```bash
oidc-ssh-ca serve --config policy.yaml --ca-key-file ./ca_key --listen :8080
```

The CA key source must be exactly one of `--ca-key-file`,
`OIDC_SSH_CA_KEY_FILE` (a path), or `OIDC_SSH_CA_KEY` (the key itself, for
environments without a filesystem, e.g. Lambda environment variables).
Configuring zero or multiple sources is a startup error. Key files must be
`0600` or stricter. At startup the server logs only the CA public key
fingerprint, never key material.

A systemd unit example is in
[`examples/systemd/oidc-ssh-ca.service`](examples/systemd/oidc-ssh-ca.service).

### 4. Trust the CA on target servers

```bash
oidc-ssh-ca print-ca-pub --ca-key-file ./ca_key > oidc-ssh-ca.pub
```

Install it on each server (see [`examples/sshd/`](examples/sshd/)):

```sshconfig
# /etc/ssh/sshd_config.d/oidc-ssh-ca.conf
TrustedUserCAKeys /etc/ssh/oidc-ssh-ca.pub

Match User deploy
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no
```

```text
# /etc/ssh/auth_principals/deploy
gha-prod-deploy
```

### 5. Use it from GitHub Actions

A complete workflow, including pinned `known_hosts` host-key verification,
is in [`examples/github-actions/deploy.yml`](examples/github-actions/deploy.yml).
The core steps:

```yaml
permissions:
  id-token: write

steps:
  - run: ssh-keygen -t ed25519 -N "" -f gha_key

  - run: |
      curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=ssh-ca-prod" \
        | jq -r .value > oidc.jwt

  - run: |
      jq -n --arg public_key "$(cat gha_key.pub)" '{public_key: $public_key}' \
        | curl -sS --fail "$OIDC_SSH_CA_URL/sign" \
            -H "Authorization: Bearer $(cat oidc.jwt)" \
            -H "Content-Type: application/json" \
            --data @- -o gha_key-cert.pub

  - run: |
      ssh -i gha_key \
        -o CertificateFile=gha_key-cert.pub \
        -o IdentitiesOnly=yes \
        -o UserKnownHostsFile=./.ssh/known_hosts \
        -o StrictHostKeyChecking=yes \
        deploy@example.com 'hostname && whoami'
```

Always pin host keys (`known_hosts` committed to the repository, or later a
host certificate): replacing user authentication with short-lived
certificates does not help if the connection itself is not verified.

## Commands

```text
oidc-ssh-ca serve --config policy.yaml [--listen :8080] [--ca-key-file PATH]
oidc-ssh-ca check-config policy.yaml
oidc-ssh-ca explain --policy policy.yaml --claims claims.json
oidc-ssh-ca print-ca-pub [--ca-key-file PATH]
```

`check-config` validates the policy and warns about templates referencing
unknown claims and overly broad rules. `explain` evaluates a claim set (a
decoded JWT payload as JSON) against the policy and reports which rule
matched — or, for each rule, the first condition that failed.

## Operations

### Audit log

Every decision emits one JSON line on stdout (`log/slog`):
`certificate_issued` with the rule, principals, key ID, and key fingerprint,
or `certificate_denied` with a stable reason code and detail. The key ID
embeds the repository / run ID, so an sshd log entry can be traced back to
the exact GitHub Actions run.

### Policy reload

`SIGHUP` reloads the policy file. If the new file is invalid, the server
keeps the current policy and logs an error — a broken reload neither stops
nor loosens issuance.

```bash
systemctl reload oidc-ssh-ca    # or: kill -HUP <pid>
```

### Emergency stop

To stop all issuance immediately:

1. Set `disabled: true` at the top of `policy.yaml` and reload (`SIGHUP`).
   The server answers `503` to every request.
2. Wait `max_valid_for_seconds` (default 900s / 15 minutes). After that, no
   valid certificate exists anywhere.
3. Only if the CA key itself may have leaked: remove the CA public key from
   `TrustedUserCAKeys` on the target servers and rotate the key.

### CA key rotation

`TrustedUserCAKeys` may list multiple keys, so rotation is zero-downtime:
add the new CA public key on the servers, swap the key on the CA and
restart, then remove the old public key after the old certificates' TTL has
passed.

## Status

MVP. GitHub Actions OIDC (RS256) is the supported identity source; only
`ssh-ed25519` keys are accepted for both the CA and client keys. AWS
IAM/Lambda support, Terraform modules, and an Ansible role are planned —
see `.memo/memo.md` for the full design document.

## License

[MIT](LICENSE)
