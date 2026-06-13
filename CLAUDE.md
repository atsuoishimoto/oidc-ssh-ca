# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language Policy

All code, comments, documentation, commit messages, and other project artifacts must be written in **English**. (The planning memo in `.memo/` is in Japanese, but everything produced for the project itself is English.)

## Project Status

The MVP (serve / check-config / explain / print-ca-pub, GitHub Actions OIDC only) is implemented. The complete design document (v4) is at `.memo/memo.md` (Japanese); it is the authoritative spec for anything not yet built.

## What This Project Is

`oidc-ssh-ca` is a lightweight SSH Certificate Authority written in **Go** that issues short-lived OpenSSH user certificates to identities authenticated via OIDC/JWT (primarily GitHub Actions OIDC) or AWS IAM. It targets reasonably mature teams and engineers who already run an OIDC identity provider and want to stop storing long-term SSH private keys in GitHub Secrets. It is deliberately small — not a replacement for Vault/Teleport.

Core flow: client generates an ephemeral SSH key → sends only the public key with an OIDC JWT to `POST /sign` → server validates the JWT, matches it against `policy.yaml` rules, and returns a signed short-lived certificate. Target servers trust only the CA public key (`TrustedUserCAKeys` + `AuthorizedPrincipalsFile`).

Positioning/audience wording lives in four places that must stay in sync: this file, `README.md`, `docs/index.md`, and `.memo/memo.md`. The agreed framing is "replacing long-lived SSH keys in GitHub Actions with short-lived, OIDC-issued certificates," aimed at reasonably mature teams/engineers who already run an OIDC provider — not "individuals and small teams." Do not reintroduce the small-team/small-scale framing.

## Non-Negotiable Design Invariants (from the spec)

- **No subprocess, no temp files, no external SSH tools.** All key parsing/signing uses `golang.org/x/crypto/ssh` in memory. The CA private key never touches disk; raw PEM bytes are not retained after parsing.
- **Policy decides everything.** `principal`, TTL, extensions, and key ID are determined solely by verified JWT claims + `policy.yaml`. The request body contains only `public_key` — never accept principal/TTL/extensions from the caller.
- **Deny by default, exactly-one-match.** 0 matching rules → deny; 2+ matching rules → deny (no first-match-wins). A claim referenced in policy but absent from the JWT → deny.
- **Fail safe.** Invalid policy at startup → refuse to start; invalid policy on SIGHUP reload → keep the old policy and log an error. JWKS fetch failure with no valid cache → deny. Top-level `disabled: true` → HTTP 503 (emergency stop).
- **Generic errors only.** Error responses contain a fixed generic message + request ID; details go only to the structured audit log (`log/slog`, JSON, events `certificate_issued` / `certificate_denied`).
- **Strict config parsing.** YAML with `KnownFields(true)` — unknown fields, type mismatches, and missing required fields are errors.
- **key_id_template sanitization.** Expanded claim values must match `[A-Za-z0-9._/:@-]`; any violation denies the request (no silent rewriting). Max key ID length 256 bytes.
- **CA key source is exactly one of** `--ca-key-file` / `OIDC_SSH_CA_KEY_FILE` / `OIDC_SSH_CA_KEY`; zero or multiple sources → startup failure. Key file permissions looser than 0600 → startup failure, unless the operator passes `--skip-key-permission-check` (the one documented escape hatch — for OS-isolated files that cannot carry 0600 bits, notably a systemd `LoadCredential` file under `/run/credentials`, exposed as mode 0440; `serve` logs a `Warn` when it is used). ed25519 only in MVP; only `ssh-ed25519` client public keys accepted (certificate keys rejected).
- **JWT verification** uses an established library (`lestrrat-go/jwx` or `coreos/go-oidc`), RS256 only, JWKS cached in memory (10 min TTL, one refetch on unknown `kid`), 60s clock-skew leeway.
- **`aws_session_name` must never be usable for authorization** (`match.aws.session_name` is a parse error); it may appear only in `key_id_template` for auditing.
- **Signing is abstracted behind a `Signer` interface** (in-memory `x/crypto/ssh` in MVP; KMS later via `crypto.Signer` + `ssh.NewSignerFromSigner`).

## Architecture

Single static binary with subcommands: `serve`, `lambda`, `check-config`, `explain`, `print-ca-pub` (spec also plans `sshd-config-example`).

```
cmd/oidc-ssh-ca/   # main + one file per subcommand
internal/policy/   # YAML parse / validate / rule matching / key_id expansion
internal/issuer/   # Signer abstraction + x/crypto/ssh implementation, CA key loading
internal/oidc/     # JWT verification, JWKS cache
internal/server/   # transport-agnostic Sign() pipeline + net/http transport
internal/lambda/   # AWS Lambda Function URL transport over server.Sign()
internal/audit/    # slog-based audit logging
examples/          # github-actions, policy, sshd, systemd
terraform/         # AWS deployment modules (planned, Phase 3)
ansible/           # oidc_ssh_ca_trust role for target servers (planned, Phase 2)
```

The signing pipeline (validate body/key → verify JWT → match policy → expand key ID → sign) lives in `server.(*Server).Sign()`, which is transport-agnostic and performs all audit logging. Transports (the net/http handler, the Lambda Function URL handler) only move bytes — add any new entry point the same way so the generic-error and audit guarantees stay in one place. In Lambda the binary is deployed as `bootstrap` (`provided.al2023`); `main()` auto-selects lambda mode when `AWS_LAMBDA_RUNTIME_API` is set. There is no policy reload in Lambda — the policy loads at cold start from the zip (`OIDC_SSH_CA_CONFIG`, default `policy.yaml`).

Deployment targets: binary + systemd (primary), AWS Lambda zip on `provided.al2023` (no container image needed), Docker distroless (convenience, planned).

## Build/Test Commands

```sh
go build ./...                       # build
go test ./...                        # all tests
go test -race ./...                  # what CI runs
go test ./internal/policy -run TestEvaluateDenies   # single test
go vet ./... && gofmt -l .           # lint (CI fails on unformatted files)
```

CI is `.github/workflows/ci.yml` (build, vet, test -race, gofmt check). Releases will use GoReleaser; the Dockerfile pattern is spec section 19.2 (multi-stage distroless, `CGO_ENABLED=0`).

## MVP Scope (spec section 23)

serve + check-config + explain + print-ca-pub; `/sign` endpoint; GitHub Actions OIDC verification; `policy.yaml` with `disabled`/`enabled` flags and SIGHUP reload; key_id sanitization; structured audit log; GoReleaser release; systemd/sshd/GitHub Actions examples. Explicitly out of MVP: browser login, human SSO, DB, approval flows, long-lived sessions, custom SSH server. AWS/Lambda features are Phase 3, not core.
