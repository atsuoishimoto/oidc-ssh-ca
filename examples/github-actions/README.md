# GitHub Actions example

A workflow that deploys over SSH using a short-lived certificate issued by
`oidc-ssh-ca`, replacing a long-lived SSH private key stored in GitHub Secrets.

## Contents

- **`deploy.yml`** — the workflow. It generates an ephemeral SSH key, fetches a
  GitHub OIDC token, exchanges it at `POST /sign` for a certificate, then uses
  the key + certificate to SSH into the target.
- **`known_hosts.example`** — template for the pinned host keys. Commit the real
  file to the repository as `.ssh/known_hosts`.

## Flow

1. The job requests `id-token: write` permission so it can mint an OIDC token.
2. `ssh-keygen` creates an ephemeral key pair in the runner.
3. The OIDC token is fetched with the `audience` matching the CA policy.
4. Only the **public key** is sent to `<OIDC_SSH_CA_URL>/sign` with the token in
   the `Authorization: Bearer` header; the CA returns a signed certificate.
5. `ssh` connects with `-i gha_key -o CertificateFile=gha_key-cert.pub`,
   verifying the server against the pinned `known_hosts`.

## Required setup

- **Repository/environment variable `OIDC_SSH_CA_URL`** — base URL of your
  deployed CA.
- **`.ssh/known_hosts`** committed to the repo — obtain it once over a trusted
  channel (`ssh-keyscan -t ed25519 example.com`). See `known_hosts.example`.
- A **policy rule** on the CA whose `match.jwt` accepts this workflow's claims
  (repository, ref, environment, event_name, job_workflow_ref) and whose
  `audience` matches the `audience` query parameter in the workflow
  (`ssh-ca-prod` here). See `examples/policy/github-oidc.yaml`.
- A **target server** trusting the CA public key. See `examples/sshd/`.

Adjust the `audience`, the `deploy@example.com` target, and the deploy command
to fit your setup.

See the
[quickstart](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/docs/quickstart.md)
for the end-to-end walkthrough.
