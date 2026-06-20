# Docker Compose example

Self-hosted deployment of `oidc-ssh-ca` behind Caddy, which obtains and renews
a Let's Encrypt certificate automatically.

## Contents

- **`compose.yaml`** — two services: the CA (prebuilt distroless image from
  `ghcr.io`) and Caddy as the TLS-terminating reverse proxy.
- **`Caddyfile`** — minimal Caddy config; replace the domain with your own.

## Setup

Place these alongside `compose.yaml`:

- **`policy.yaml`** — your issuance policy (validate with `check-config`).
- **`ca_key`** — the CA private key, readable by the container's nonroot user:

  ```sh
  ssh-keygen -t ed25519 -N "" -f ca_key
  sudo chown 65532:65532 ca_key && sudo chmod 0600 ca_key
  ```

  (`65532` is the `nonroot` user of the distroless image.)

- **`Caddyfile`** — set your real domain. Ports 80 and 443 must be reachable
  for the ACME challenge.

## Run

```sh
docker compose up -d
```

Reload the policy after editing it (the image has no shell, so signal from the
host):

```sh
docker compose kill -s HUP oidc-ssh-ca
```

The CA key is supplied via `OIDC_SSH_CA_KEY_FILE` and the policy is mounted
read-only. Pin a release tag (e.g. `ghcr.io/atsuoishimoto/oidc-ssh-ca:0.1.0`)
in production rather than `latest`.

See
[Docker Compose deployment](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/docs/deployment/docker-compose.md).
