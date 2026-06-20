# Command reference

`oidc-ssh-ca` is a single binary with subcommands:

```text
oidc-ssh-ca serve --config policy.yaml [--listen :8080] [--ca-key-file PATH]
oidc-ssh-ca check-config policy.yaml
oidc-ssh-ca explain --policy policy.yaml --claims claims.json
oidc-ssh-ca print-ca-pub [--ca-key-file PATH]
oidc-ssh-ca version
```

## Run without installing (Docker)

You don't have to build or install the binary to run a subcommand. The
released image
[`ghcr.io/atsuoishimoto/oidc-ssh-ca`](https://github.com/atsuoishimoto/oidc-ssh-ca/pkgs/container/oidc-ssh-ca)
has the binary as its entrypoint, so any subcommand and its arguments go
straight after the image name. Mount the directory holding your files and
reference them by their in-container path. For example, to lint a policy in
the current directory:

```bash
docker run -v "$(pwd)":/src ghcr.io/atsuoishimoto/oidc-ssh-ca \
  check-config /src/policy.yaml
```

This is handy in CI or for one-off checks. Pin a release tag (e.g.
`ghcr.io/atsuoishimoto/oidc-ssh-ca:0.1.0`) instead of the default `latest`
for reproducible runs.

## serve

Runs the HTTP server.

- `--config` (required) — path to the policy file. An invalid policy
  prevents startup.
- `--listen` — listen address, default `:8080`. The server speaks plain
  HTTP; terminate TLS in front of it (see the
  [deployment guides](deployment/index.md)).
- `--ca-key-file` — one of the three CA key sources (below).

`SIGHUP` reloads the policy; `SIGTERM`/`SIGINT` shut down gracefully.

On AWS Lambda the same `serve` server runs behind the
[Lambda Web Adapter](deployment/lambda-cli.md); there is no separate Lambda
mode. Policy reload is unavailable there — deploy a new zip to change the
policy.

## check-config

Validates a policy file: strict YAML decoding, semantic validation, plus
warnings for `key_id_template` variables that reference claims not pinned
by the rule and for overly broad rules. Exits non-zero on error, so it
slots into CI to lint policy changes before deployment.

## explain

Evaluates a claim set against the policy without running a server:

```bash
oidc-ssh-ca explain --policy policy.yaml --claims claims.json
```

`claims.json` is a decoded JWT payload. On a match it prints the rule,
principals, TTL, and the expanded key ID; otherwise it prints, for each
rule, the first condition that failed. Use it to answer "why was this
request denied?" from an audit event, or to dry-run a new rule.

## print-ca-pub

Prints the CA **public** key in `authorized_keys` format — the line that
goes into `TrustedUserCAKeys` on target servers. Reads the private key
from the same sources as `serve`.

## CA key sources

The CA private key is configured by **exactly one** of:

| Source | Use |
|---|---|
| `--ca-key-file PATH` | flag, for interactive use |
| `OIDC_SSH_CA_KEY_FILE` | a path, e.g. a systemd credential or a mounted secret |
| `OIDC_SSH_CA_KEY` | the key itself, for environments without a filesystem (Lambda, Cloud Run secrets-as-env) |

Zero or multiple configured sources is a startup error — the server never
guesses which key you meant. Key files must be `0600` or stricter. Only
ed25519 keys are accepted. The key is parsed in memory and the raw PEM is
not retained; logs only ever contain the public key fingerprint.
