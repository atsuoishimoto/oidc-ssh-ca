# Release history

## 0.3.0 (2026-06-19)

### Added

- **`GET /ca-public-key` endpoint.** The server now serves the CA public key
  over HTTP, so a target server (or its configuration management) can fetch
  the key to populate `TrustedUserCAKeys` without copying it out of band.
- **`match.jwt.owner` and `match.jwt.repository`.** A rule can now constrain
  the two halves of the GitHub Actions `repository` claim (`owner/repo`)
  independently: `owner` matches the part before the `/`, `repository` the
  part after it. Either may be omitted to leave that half unconstrained — set
  only `owner` to allow any repo under an org, or only `repository` to allow
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
