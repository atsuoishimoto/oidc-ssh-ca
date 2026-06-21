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
single-binary tool that replaces long-lived SSH keys in GitHub Actions with
short-lived, OIDC-issued certificates.

The value is not just fewer keys. For a team that deploys to production from
GitHub Actions, it makes a workflow's identity the unit of SSH authorization:
what each run may do is decided by verified OIDC claims against a reviewable
`policy.yaml`, every issued certificate is logged for audit, and key rotation
collapses onto the single CA key. See
[Why teams adopt oidc-ssh-ca](https://oidc-ssh-ca.readthedocs.io/en/latest/why-teams.html)
for the operational case.


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


## Building from source

`oidc-ssh-ca` is a single static Go binary with no cgo and no runtime
dependencies; building it needs only the Go toolchain (1.22 or newer):

```bash
go build -o oidc-ssh-ca ./cmd/oidc-ssh-ca   # build the binary
go test ./...                                # run the tests
```

Or install it straight onto your `PATH`:

```bash
go install github.com/atsuoishimoto/oidc-ssh-ca/cmd/oidc-ssh-ca@latest
```

A multi-stage `Dockerfile` builds a distroless image (`docker build -t
oidc-ssh-ca .`). See the
[build guide](https://oidc-ssh-ca.readthedocs.io/en/latest/building.html)
for cross-compilation, version stamping, and the container build.

## Documentation

The full documentation is at
**[oidc-ssh-ca.readthedocs.io](https://oidc-ssh-ca.readthedocs.io/)** —
start with the
**[Quickstart](https://oidc-ssh-ca.readthedocs.io/en/latest/quickstart.html)**.

- [Quickstart](https://oidc-ssh-ca.readthedocs.io/en/latest/quickstart.html) —
  CA key, policy, server, sshd, and the GitHub Actions workflow, end to end
- [Choosing a deployment](https://oidc-ssh-ca.readthedocs.io/en/latest/deployment/index.html) —
  [Cloud Run](https://oidc-ssh-ca.readthedocs.io/en/latest/deployment/cloud-run.html) (recommended),
  [Docker Compose + Caddy](https://oidc-ssh-ca.readthedocs.io/en/latest/deployment/docker-compose.html),
  [AWS Lambda via CLI](https://oidc-ssh-ca.readthedocs.io/en/latest/deployment/lambda-cli.html) or
  [Terraform](https://oidc-ssh-ca.readthedocs.io/en/latest/deployment/lambda-terraform.html), and
  [systemd](https://oidc-ssh-ca.readthedocs.io/en/latest/deployment/systemd.html)
- Reference —
  [policy format](https://oidc-ssh-ca.readthedocs.io/en/latest/policy.html),
  [the /sign API](https://oidc-ssh-ca.readthedocs.io/en/latest/api.html),
  [commands](https://oidc-ssh-ca.readthedocs.io/en/latest/commands.html), and
  [operations](https://oidc-ssh-ca.readthedocs.io/en/latest/operations.html)
  (audit log, reload, emergency stop, key rotation)
- [Testing](https://oidc-ssh-ca.readthedocs.io/en/latest/testing.html) —
  running the test suite, including the local end-to-end tests with a mock
  OIDC provider

The sources are in [`docs/`](docs/); to build locally:

```bash
pip install -r docs/requirements.txt
make -C docs html    # docs/_build/html/index.html
```

## Status

MVP plus AWS Lambda support (via the Lambda Web Adapter). GitHub Actions
OIDC (RS256) is the
supported identity source; only `ssh-ed25519` keys are accepted for both
the CA and client keys. An Ansible role for target servers is included
([`examples/ansible/`](examples/ansible/)). AWS IAM identity matching and Terraform modules
are planned — see `.memo/memo.md` for the full design document.

## Changelog

See the [release history](https://oidc-ssh-ca.readthedocs.io/en/latest/history.html).

## License

[MIT](LICENSE)
