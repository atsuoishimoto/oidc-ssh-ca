# Docker Compose + Caddy

Self-hosting on a machine you already run: one `compose.yaml` starts the CA
behind [Caddy](https://caddyserver.com/), which obtains and renews the
Let's Encrypt certificate automatically — no certbot, no renewal cron, no
nginx configuration.

The complete example lives in
[`examples/docker-compose/`](https://github.com/atsuoishimoto/oidc-ssh-ca/tree/main/examples/docker-compose):
`compose.yaml` plus a two-line `Caddyfile`. The CA image is built from the
repository `Dockerfile` (distroless, binary only); the policy and CA key are
bind-mounted, never baked into the image.

## Prerequisites

- A DNS name pointing at the host (Caddy needs it for the certificate).
- Ports 80 and 443 reachable from the internet.
- Docker with the Compose plugin.

## Setup

In `examples/docker-compose/` (or a copy of it):

```bash
ssh-keygen -t ed25519 -N "" -f ca_key -C "oidc-ssh-ca"

# The container runs as the distroless "nonroot" user (uid 65532).
# The key must be 0600 and owned by that uid, or startup is refused.
sudo chown 65532:65532 ca_key
sudo chmod 0600 ca_key
```

Write `policy.yaml` (see the [policy reference](../policy.md)), and put
your domain in the `Caddyfile`:

```text
ca.example.com {
	reverse_proxy oidc-ssh-ca:8080
}
```

Start everything:

```bash
docker compose up -d
docker compose logs oidc-ssh-ca   # check the startup line / CA fingerprint
```

`https://ca.example.com` is now the `OIDC_SSH_CA_URL` for the GitHub Actions
workflow.

## Operations

**Reload the policy** — the distroless image has no shell, so signal the
container from the host:

```bash
docker compose kill -s HUP oidc-ssh-ca
```

An invalid file keeps the current policy running and logs an error.

**Emergency stop** — set `disabled: true` at the top of `policy.yaml` and
reload as above; the server answers `503` to every request. Or simply
`docker compose stop oidc-ssh-ca`.

**Audit logs** — JSON lines on stdout:

```bash
docker compose logs -f oidc-ssh-ca
```

For long-term retention, configure a Docker logging driver or ship the
container logs like any other service on the host.

## Compared to systemd

This trades the systemd unit's process isolation (`DynamicUser`,
`ProtectSystem`, `LoadCredential`) for container isolation and a much
shorter TLS story. If the host already runs Docker, Compose is less to
maintain; if it is a bare VPS where you'd have to install Docker first, the
[systemd deployment](systemd.md) has fewer layers.
