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

Full diff: [`0.2.0...0.3.0`](https://github.com/atsuoishimoto/oidc-ssh-ca/compare/0.2.0...0.3.0)
