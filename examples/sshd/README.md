# Target server (sshd) example

Configuration for servers that accept `oidc-ssh-ca` certificates. Target
servers trust **only the CA public key** — they hold no per-user keys and need
no inbound connection to the CA.

## Contents

- **`sshd_config.example`** — drop-in for `/etc/ssh/sshd_config.d/`. Sets
  `TrustedUserCAKeys` and, for the `deploy` user, an `AuthorizedPrincipalsFile`.
- **`auth_principals.example`** — list of certificate principals allowed to log
  in as a given user, one per line.

## Setup

1. Put the CA public key on the server:

   ```sh
   oidc-ssh-ca print-ca-pub > /etc/ssh/oidc-ssh-ca.pub
   ```

2. Install the sshd drop-in:

   ```sh
   cp sshd_config.example /etc/ssh/sshd_config.d/oidc-ssh-ca.conf
   ```

3. Install the principals file for each login user, e.g. for `deploy`:

   ```sh
   install -D auth_principals.example /etc/ssh/auth_principals/deploy
   ```

   The principals listed here must match `certificate.principals` in the CA's
   `policy.yaml`.

4. Validate and reload:

   ```sh
   sshd -t && systemctl reload ssh
   ```

The principals file is what binds a certificate to a Unix account: a
certificate is accepted as user `deploy` only if one of its principals appears
in `/etc/ssh/auth_principals/deploy`.

See
[target servers](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/docs/target-servers.md)
for details.
