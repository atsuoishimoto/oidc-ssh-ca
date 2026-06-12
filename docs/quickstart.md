# Quickstart

This walks through a complete setup: a CA key, a policy, a running server,
a target server that trusts the CA, and a GitHub Actions workflow that
connects with a short-lived certificate.

## 1. Generate the CA key

```bash
ssh-keygen -t ed25519 -N "" -f ca_key -C "oidc-ssh-ca"
chmod 0600 ca_key
```

Only ed25519 keys are supported. The key file must be `0600` or stricter,
or the server refuses to start.

## 2. Write the policy

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

See the [policy reference](policy.md) for every field. What this policy
says:

- **`defaults`** — certificates are backdated 30 seconds
  (`valid_after_offset_seconds`) to tolerate clock skew on target servers,
  no rule may issue a certificate living longer than 900 seconds
  (`max_valid_for_seconds`), and only `ssh-ed25519` client keys are
  accepted. No `extensions` block means every extension is off: the
  certificate authenticates and nothing more (no PTY, no port forwarding
  — plain `ssh host 'command'`, rsync, and scp still work).
- **`match.jwt`** — the caller must present a token issued by GitHub
  Actions (`issuer`) for this CA's audience (`ssh-ca-prod`, the value the
  workflow requests with `&audience=...`). On top of that, all five
  `claims_exact` entries must match: the run is in `your-org/your-repo`,
  on branch `main`, triggered by a `push` (not a pull request), in a job
  that declares `environment: production`, executing exactly the
  `deploy.yml` workflow on `main` (`job_workflow_ref` — this pins the
  workflow *file*, so another workflow in the same repository cannot
  obtain this certificate). A claim that is absent from the token never
  matches, and a request matching zero rules — or more than one — is
  denied.
- **`certificate`** — the issued certificate carries the single principal
  `gha-prod-deploy` (which target servers map to a login user in step 4),
  lives for 600 seconds, and gets a key ID like
  `gha:your-org/your-repo:9000000000:1` built from verified claims — the
  string you will see in both the CA audit log and the target server's
  sshd log, tying the login to the exact run.

Validate it:

```bash
oidc-ssh-ca check-config policy.yaml
```

## 3. Run the server

Locally, for a first test:

```bash
oidc-ssh-ca serve --config policy.yaml --ca-key-file ./ca_key --listen :8080
```

At startup the server logs only the CA public key fingerprint, never key
material. For production, pick a deployment from
[Choosing a deployment](deployment/index.md) — [Cloud Run](deployment/cloud-run.md)
is the recommended default.

## 4. Trust the CA on target servers

Export the CA public key:

```bash
oidc-ssh-ca print-ca-pub --ca-key-file ./ca_key > oidc-ssh-ca.pub
```

Install it on each server (full examples in
[`examples/sshd/`](https://github.com/atsuoishimoto/oidc-ssh-ca/tree/main/examples/sshd)):

```text
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

A certificate logs in as user `deploy` only if one of its principals
appears in that user's `AuthorizedPrincipalsFile` — the principal list in
the policy and these files together decide who may go where.

## 5. Use it from GitHub Actions

A complete workflow, including pinned `known_hosts` host-key verification,
is in
[`examples/github-actions/deploy.yml`](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/examples/github-actions/deploy.yml).
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
