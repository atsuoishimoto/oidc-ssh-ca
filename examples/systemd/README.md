# systemd example

Run the CA as a hardened systemd service on a Linux host. This is the primary
deployment target.

## Contents

- **`oidc-ssh-ca.service`** — a unit that runs `serve`, reloads the policy on
  `systemctl reload`, and applies a strict sandbox (`DynamicUser`,
  `ProtectSystem=strict`, dropped capabilities, etc.).

## Install

```sh
install -m 0755 oidc-ssh-ca /usr/local/bin/oidc-ssh-ca
install -D -m 0644 policy.yaml /etc/oidc-ssh-ca/policy.yaml
install -D -m 0600 ca_key /etc/oidc-ssh-ca/ca_key       # owned by root
cp oidc-ssh-ca.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now oidc-ssh-ca
```

Reload the policy after editing it (validate first with `check-config`):

```sh
systemctl reload oidc-ssh-ca
```

## Key handling

The CA key is delivered with `LoadCredential`, so it is exposed only to this
service under `%d/ca_key` (passed via `OIDC_SSH_CA_KEY_FILE`). systemd exposes
that file as mode `0440`, which the default permission check (0600 or stricter)
rejects — so the unit passes `--skip-key-permission-check`. This is safe
*because* the credential lives in the service's private `/run/credentials`
mount and is unreachable by other users regardless of the mode bits. Do not
add this flag for keys outside that mount.

You normally want TLS in front of the service (e.g. a reverse proxy);
`/sign` authenticates callers by verifying their OIDC token, not by network
position.

See
[systemd deployment](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/docs/deployment/systemd.md).
