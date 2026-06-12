# Testing

```bash
go test ./...            # everything, including the local end-to-end tests
go test -race ./e2e -v   # end-to-end tests only
go test -short ./...     # skip the slow binary-based end-to-end test
```

The `e2e` package tests the whole issuance flow with nothing stubbed and
nothing external: each test starts a local mock OIDC identity provider
(an `httptest` server with a discovery document and a JWKS endpoint),
mints RS256 tokens against it, and requests a certificate through the
real verification pipeline — OIDC discovery, JWKS fetch, signature and
expiry checks, policy matching, and signing. The issued certificate is
verified against the CA public key the way a target server would.

`TestE2EInProcess` wires the production components in-process and also
covers the denial paths (wrong signing key, expired token, unknown
issuer, audience or claim mismatch). `TestE2EBinary` builds the actual
binary, runs `serve` against the mock provider, and uses the
`print-ca-pub` output as the trust anchor; it is skipped with `-short`.
Everything runs on loopback — no network access or external services
are required.
