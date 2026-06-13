# Configuring target servers

A target server is any host that GitHub Actions (or another OIDC caller)
logs into with a certificate issued by the CA. Configuring it means two
things, both on the SSH server side only:

1. **Trust the CA** — tell sshd that user certificates signed by the CA
   public key are valid (`TrustedUserCAKeys`).
2. **Authorize principals per user** — decide, for each login account,
   which certificate principals may use it
   (`AuthorizedPrincipalsFile`).

Nothing about `oidc-ssh-ca` itself runs here — the server only needs its
own `sshd` and a copy of the CA *public* key. This page does it by hand on
a single host; to apply the same configuration to a fleet, the bundled
Ansible role automates every step below — see
[Configuring target servers with Ansible](ansible.md).

## How certificate login works

A normal key-based login checks the client's public key against
`authorized_keys`. A certificate login is different: sshd checks that the
certificate is **signed by a trusted CA** and that the certificate carries
a **principal that the target account allows**. There is no per-user public
key to distribute, rotate, or clean up — only the CA public key, the same
on every host.

So a login as user `deploy` succeeds when both hold:

- the certificate is signed by a CA listed in `TrustedUserCAKeys`, and
- one of the certificate's principals appears in `deploy`'s
  `AuthorizedPrincipalsFile`.

The principals come from `certificate.principals` in the CA's
[policy](policy.md); the per-user file on the server is the other half of
the decision. The login account itself must already exist — none of this
creates Unix users.

## 1. Install the CA public key

Export the CA public key (never the private key) and copy it to each
server:

```bash
oidc-ssh-ca print-ca-pub --ca-key-file ./ca_key > oidc-ssh-ca.pub
```

Install it at `/etc/ssh/oidc-ssh-ca.pub`. It is not secret, but it must not
be writable by anyone but root — sshd trusts whatever it contains.

```bash
sudo install -o root -g root -m 0644 oidc-ssh-ca.pub /etc/ssh/oidc-ssh-ca.pub
```

## 2. Authorize principals for each login user

For every account a certificate may log into, list the allowed principals,
one per line:

```text
# /etc/ssh/auth_principals/deploy
gha-prod-deploy
```

These must match `certificate.principals` in the policy. In the
[quickstart](quickstart.md) policy the `prod-deploy` rule issues the single
principal `gha-prod-deploy`, so a certificate from that rule may log in as
`deploy` and nowhere else.

## 3. Configure sshd

Drop a fragment into `/etc/ssh/sshd_config.d/` (a full example is in
[`examples/sshd/`](https://github.com/atsuoishimoto/oidc-ssh-ca/tree/main/examples/sshd)):

```text
# /etc/ssh/sshd_config.d/oidc-ssh-ca.conf
TrustedUserCAKeys /etc/ssh/oidc-ssh-ca.pub

Match User deploy
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no
```

`TrustedUserCAKeys` is global — it makes the CA trusted for the whole host.
The per-user `Match User` block points at the principals file from step 2
(`%u` expands to the login user) and, for those accounts, turns off
password and keyboard-interactive logins so the certificate is the only way
in. That hardening affects only the listed users; other accounts are left
as they were — disable password auth globally yourself if that is your
policy.

This fragment only takes effect if `sshd_config` includes the drop-in
directory, which is the default on current Debian, Ubuntu, RHEL, and
Fedora:

```text
Include /etc/ssh/sshd_config.d/*.conf
```

If your `sshd_config` lacks that line, either add it or place the
configuration directly in `sshd_config`.

## 4. Validate and reload

Always check the configuration before reloading — a syntax error that
reaches a restart can lock you out:

```bash
sudo sshd -t          # exits non-zero and prints the offending line on error
sudo systemctl reload ssh    # `sshd` on RHEL/Fedora; reload, not restart
```

`reload` re-reads the configuration without dropping existing connections,
so an open session stays available as a fallback while you confirm a fresh
login works.

## 5. Test the login

From a machine that has a freshly issued certificate (or reproduce one with
the [quickstart](quickstart.md) flow), confirm the certificate logs in and
that the key ID shows up in the server's sshd log — it embeds the
repository and run ID, tying the login back to the exact CI run:

```bash
ssh -i gha_key -o CertificateFile=gha_key-cert.pub -o IdentitiesOnly=yes \
    deploy@example.com 'whoami'
```

```bash
sudo journalctl -u ssh | grep 'Accepted publickey'
# ... Accepted publickey for deploy ...: ED25519-CERT ID gha:your-org/your-repo:9000000000:1 (serial 0) CA ...
```

Always pin host keys on the client side (`known_hosts`, or a host
certificate) — short-lived user certificates do not help if the connection
itself is not verified.

## CA key rotation

`TrustedUserCAKeys` may list more than one key (or the file may hold
several lines), so rotation is zero-downtime: trust both the old and new CA
public keys during the transition, then drop the old one once its
certificates have expired. The full procedure is in
[Operations → CA key rotation](operations.md#ca-key-rotation).

## Doing this across many servers

Repeating these steps by hand does not scale and is easy to get subtly
wrong (a missing `sshd -t`, an inconsistent principals file). The
[`oidc_ssh_ca_trust` Ansible role](ansible.md) performs exactly steps 1–4
above — idempotently, validating with `sshd -t` both before and after, and
reloading only when something changed.
