# Release history

## 0.4.0 (2026-06-23)

### Added

- **Policy `defaults` for certificate fields.** The top-level `defaults`
  block now accepts `valid_for_seconds`, `key_id_template`, and
  `source_address`. A rule that omits `valid_for_seconds` or
  `key_id_template` inherits the default; setting either on the rule
  overrides it for that rule, and a rule `source_address` replaces the
  default entirely (matching `extensions` semantics). A rule that resolves
  to no `valid_for_seconds` or `key_id_template` through either source is a
  startup/reload error, and the `defaults` block itself is validated (TTL
  ceiling, template syntax, CIDR), so the fail-safe "policy decides
  everything" invariant is preserved. `check-config` and `explain` show the
  post-defaults values.
- **Published Docker image on ghcr.io.** A `workflow_dispatch` release
  workflow builds the distroless image from a release tag and pushes a
  multi-arch (amd64/arm64) image to
  `ghcr.io/atsuoishimoto/oidc-ssh-ca`, with SLSA build provenance and the
  release version baked in. The `:latest` tag is opt-in so re-running the
  workflow for an older tag cannot move it backwards.
- **Cloud Run deployment example.** `examples/cloud-run/` adds `deploy.sh`
  and `update-policy.sh` that store the CA key and policy in Secret Manager,
  create a least-privilege service account, deploy via Cloud Build, and roll
  a new revision to update the policy.
- **Ansible role account management.** `oidc_ssh_ca_users` entries accept
  two optional booleans (`create`, to create the login account, and `sudo`,
  to grant passwordless `NOPASSWD:ALL` sudo via a namespaced
  `/etc/sudoers.d` file validated with `visudo`). Accounts are only ever
  created, never removed; the sudoers file is removed when `sudo` is not
  requested.

### Changed

- **Container deployments use the prebuilt ghcr.io image.** Docker Compose
  and Cloud Run now deploy the published image instead of building locally.
  Because Cloud Run cannot pull from ghcr.io directly, the deploy script
  creates an Artifact Registry remote repository that proxies ghcr.io and
  deploys from the resulting `*-docker.pkg.dev` reference.
- **Ansible role relocated.** The role moved from `ansible/` to
  `examples/ansible/`, alongside the other deployment examples.
- **Dependencies.** Updated `github.com/coreos/go-oidc/v3` to 3.19.0 and
  bumped the pinned GitHub Actions (including major versions).

### Fixed

- **`check-config` over-warning.** The "any token will match" warning no
  longer fires for a rule narrowed only by `match.jwt.owner` or
  `match.jwt.reponame`; it warns only when none of `owner`, `reponame`, or
  `claims_exact` is set.


## 0.3.0 (2026-06-19)

### Added

- **`GET /ca-public-key` endpoint.** The server now serves the CA public key
  over HTTP, so a target server (or its configuration management) can fetch
  the key to populate `TrustedUserCAKeys` without copying it out of band.
- **`match.jwt.owner` and `match.jwt.reponame`.** A rule can now constrain
  the two halves of the GitHub Actions `repository` claim (`owner/repo`)
  independently: `owner` matches the part before the `/`, `reponame` the
  part after it. Either may be omitted to leave that half unconstrained — set
  only `owner` to allow any repo under an org, or only `reponame` to allow
  a given repo name under any owner. The generic `claims_exact` map is
  unchanged and can still pin the full `owner/repo` as a single exact string.
  Both fields reject a value containing `/` at startup, and a token whose
  `repository` claim is absent or has no `/` fails the match (deny by
  default).

### Changed

- **Dependencies and toolchain.** Adopted Renovate for automated dependency
  updates. Updated the Go toolchain to 1.26.4 (and the `golang` Docker tag to
  1.26), `github.com/coreos/go-oidc/v3` to 3.18.0, `golang.org/x/*` to 0.53.0,
  and the pinned GitHub Actions.


## 0.2.0  (2026-06-15)

- **Certificate restrictions in policy.** Rules can now emit `force_command`
  (the target runs only this command) and `source_address` (a CIDR allowlist
  of where the certificate may be used). Both are baked into the certificate
  by the CA, so they apply on every target server without per-host
  `AuthorizedPrincipalsFile` options.
- **Hardened validation.** Key ID templates and certificate principals are now
  checked against a strict allowlist at policy load time (and again at
  issuance), rejecting newlines, control characters, and unbounded values that
  could be injected into sshd logs or the audit trail.
- **Supply-chain hardening.** CI gained `govulncheck` and a CodeQL workflow,
  releases emit SLSA build provenance, and vulnerable dependencies were bumped.
- **Simpler Lambda support.** The Lambda-specific code was removed; the binary
  now runs the ordinary `serve` HTTP server behind the AWS Lambda Web Adapter.
