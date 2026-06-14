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

## Workflow-scoped SSH permissions

oidc-ssh-ca can issue SSH certificates with a forced command based on
GitHub Actions OIDC claims.

This means a workflow does not need general-purpose SSH access.

For example:

- `deploy-prod.yml` can only run `/usr/local/bin/deploy-prod`
- `restart-worker.yml` can only run `/usr/local/bin/restart-worker`
- `collect-logs.yml` can only run `/usr/local/bin/collect-logs`

Even if a certificate is leaked, it cannot be reused as a general SSH shell.
It is short-lived and restricted to the command encoded in the certificate.


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
