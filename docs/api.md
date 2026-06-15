# The HTTP API

The server exposes two endpoints: `POST /sign`, which issues a
certificate, and `GET /ca-public-key`, which serves the CA public key.
The request and response format is identical across every deployment
(standalone HTTP, and Lambda behind the Lambda Web Adapter), so clients
never care where the CA runs.

## POST /sign

### Request

```text
POST /sign
Authorization: Bearer <OIDC JWT>
Content-Type: application/json

{"public_key": "ssh-ed25519 AAAA... comment"}
```

- The body carries **only** the public key (OpenSSH `authorized_keys`
  format, `ssh-ed25519` only; certificate keys are rejected). Principals,
  TTL, extensions, and the key ID are decided by the policy — there is no
  way to request them.
- The bearer token is the caller's identity. For GitHub Actions this is
  the workflow's OIDC token, requested with the audience your policy
  expects.
- The body is limited to 16 KiB.

### Success response

`200 OK` with `Content-Type: text/plain`; the body is the OpenSSH
certificate, ready to be written to `<key>-cert.pub`:

```text
ssh-ed25519-cert-v01@openssh.com AAAA...
```

### Error responses

Errors are deliberately generic — a fixed message plus a request ID, as
JSON. The real denial reason goes only to the server's audit log, so the
policy cannot be probed by varying claims; an operator correlates the
caller's `request_id` with the audit event.

```json
{"error": "certificate request denied; contact your administrator with the request_id",
 "request_id": "a1b2c3d4e5f60708"}
```

The request ID is also returned in the `X-Request-Id` response header.

| Status | Meaning |
|---|---|
| 400 | malformed body, body too large, or unacceptable public key |
| 401 | missing or invalid bearer token |
| 403 | policy denied (no rule, multiple rules, or key ID expansion failed) |
| 405 | method other than POST |
| 500 | signing error |
| 503 | the policy is disabled (emergency stop) |

The status code distinguishes only the broad class (the caller needs to
know whether to fix the request, fetch a new token, or call an operator);
everything finer-grained is audit-log-only.

## GET /ca-public-key

Returns the CA public key in OpenSSH `authorized_keys` format — the exact
bytes `print-ca-pub` emits — as `text/plain`:

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... 
```

The CA public key is not a secret: it is the value every target server
trusts as `TrustedUserCAKeys`. This endpoint is therefore
**unauthenticated** and exists purely as a convenience for provisioning —
fetch the key without copying the `print-ca-pub` output or running the
binary next to the private key:

```sh
curl -s https://ca.example.com/ca-public-key | sudo tee /etc/ssh/oidc-ssh-ca.pub
```

Only `GET` (and `HEAD`) are allowed; any other method returns `405`.
