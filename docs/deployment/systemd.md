# systemd

For a bare-metal server or VPS without Docker. The binary has no runtime
dependencies; the deployment is three files and one unit. The example unit
in
[`examples/systemd/oidc-ssh-ca.service`](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/examples/systemd/oidc-ssh-ca.service)
applies the strongest process isolation of any deployment in these docs:
`DynamicUser`, `ProtectSystem=strict`, and the CA key passed as a systemd
credential visible only to the service.

## Install

The binary has no runtime dependencies, so the simplest way to obtain it is
the Go toolchain — `go install` builds it and drops it in `$(go env GOPATH)/bin`
(usually `~/go/bin`); move that onto a system path:

```bash
# The binary
go install github.com/atsuoishimoto/oidc-ssh-ca/cmd/oidc-ssh-ca@latest
sudo install -m 0755 "$(go env GOPATH)/bin/oidc-ssh-ca" /usr/local/bin/oidc-ssh-ca

# Configuration and key
mkdir -p /etc/oidc-ssh-ca
ssh-keygen -t ed25519 -N "" -f /etc/oidc-ssh-ca/ca_key -C "oidc-ssh-ca"
chmod 0600 /etc/oidc-ssh-ca/ca_key
# ... write /etc/oidc-ssh-ca/policy.yaml ...
oidc-ssh-ca check-config /etc/oidc-ssh-ca/policy.yaml

# The unit
cp examples/systemd/oidc-ssh-ca.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now oidc-ssh-ca
```

The key reaches the process via `LoadCredential` — it is exposed only to
this service under `%d/ca_key`, not to other processes of the same user.

systemd presents that credential file as mode `0440`, which the default
CA-key permission check (`0600` or stricter) would reject, so the unit
passes `--skip-key-permission-check`. The credential lives in the
service's private `/run/credentials` mount and is unreachable by other
users regardless of its mode bits; the flag disables the check for this
path only. Omit it elsewhere — without the flag the server refuses to
start on a CA key file readable by group or other.

## TLS

The server speaks plain HTTP on `:8080`; put any reverse proxy in front for
TLS. If nothing else on the host serves HTTPS yet, Caddy is the least
configuration:

```bash
apt install caddy   # or your distro's package
```

`/etc/caddy/Caddyfile`:

```text
ca.example.com {
	reverse_proxy localhost:8080
}
```

Caddy obtains and renews the certificate automatically. If you already run
nginx or another proxy, a standard `proxy_pass http://127.0.0.1:8080;`
virtual host works the same way.

If the TLS setup is the part you want to avoid, the
[Docker Compose deployment](docker-compose.md) bundles Caddy, and
[Cloud Run](cloud-run.md) removes the host entirely.

## Operations

**Reload the policy** (an invalid file keeps the current policy running):

```bash
systemctl reload oidc-ssh-ca
```

**Emergency stop** — set `disabled: true` at the top of `policy.yaml` and
reload; the server answers `503` to every request. Or
`systemctl stop oidc-ssh-ca`.

**Audit logs** — JSON lines on stdout, captured by journald:

```bash
journalctl -u oidc-ssh-ca -f
```
