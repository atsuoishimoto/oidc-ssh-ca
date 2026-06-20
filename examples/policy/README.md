# Policy examples

Example `policy.yaml` files for the CA. The policy is the only thing that
decides what a request gets: `principal`, TTL, extensions, and key ID are
determined solely by verified JWT claims plus the matching rule. The request
body carries only `public_key`.

## Contents

- **`github-oidc.yaml`** — issue certificates to a GitHub Actions deploy
  workflow authenticated via GitHub OIDC. Shows a single `prod-deploy` rule
  pinned to an issuer, audience, repository, branch, environment, event, and
  workflow file, with conservative defaults (no PTY/forwarding, short TTL).

## Usage

Edit the placeholders (`your-org`, `your-repo`, audience, principals) to match
your repository and target servers, then validate before deploying:

```sh
oidc-ssh-ca check-config github-oidc.yaml
```

To see what a given set of claims would resolve to without issuing a
certificate, use `oidc-ssh-ca explain`.

## Notes

- **Deny by default, exactly one match.** Zero matching rules deny; two or more
  matching rules also deny. A claim referenced by a rule but absent from the
  JWT denies.
- The `audience` in a rule must match the `audience` query parameter the client
  requests when fetching its OIDC token (see `examples/github-actions/`).
- `key_id_template` values are sanitized: expanded claims must match
  `[A-Za-z0-9._/:@-]`, or the request is denied.

See the [policy reference](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/docs/policy.md)
for the full schema and matching rules.
