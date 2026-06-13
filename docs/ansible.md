# Configuring target servers with Ansible

The `oidc_ssh_ca_trust` role, in
[`ansible/roles/oidc_ssh_ca_trust`](https://github.com/atsuoishimoto/oidc-ssh-ca/tree/main/ansible/roles/oidc_ssh_ca_trust),
automates the manual setup in
[Configuring target servers](target-servers.md): making target servers
trust the CA. It touches only the SSH server side — it does not deploy or
configure `oidc-ssh-ca` itself (for that, see
[Choosing a deployment](deployment/index.md)).

On each host the role:

1. installs the CA public key at `/etc/ssh/oidc-ssh-ca.pub`;
2. creates `/etc/ssh/auth_principals/<user>` for every entry in
   `oidc_ssh_ca_users`, listing the certificate principals allowed to
   log in as that user;
3. installs `/etc/ssh/sshd_config.d/oidc-ssh-ca.conf` with
   `TrustedUserCAKeys` and a `Match User` block per user;
4. validates the configuration with `sshd -t` (the fragment when it is
   written, and the full configuration again before reloading — a broken
   config never takes effect);
5. reloads sshd, only if something changed.

## Requirements

- Ansible 2.12 or newer; `become` (root) on the target hosts.
- An sshd whose `/etc/ssh/sshd_config` contains
  `Include /etc/ssh/sshd_config.d/*.conf` (the default on current
  Debian, Ubuntu, RHEL, and Fedora). The role fails with a clear error
  if the include is missing; set `oidc_ssh_ca_verify_include: false`
  if you include the fragment some other way.
- The CA public key, exported with:

  ```bash
  oidc-ssh-ca print-ca-pub --ca-key-file ./ca_key > oidc-ssh-ca.pub
  ```

## Usage

Point Ansible at the role (for example with
`ANSIBLE_ROLES_PATH=path/to/oidc-ssh-ca/ansible/roles`, a
`roles_path` entry in `ansible.cfg`, or by copying the role into your
own repository), then:

```yaml
- name: Trust the oidc-ssh-ca certificate authority
  hosts: app_servers
  become: true
  roles:
    - role: oidc_ssh_ca_trust
      oidc_ssh_ca_public_key: "{{ lookup('file', './oidc-ssh-ca.pub') }}"
      oidc_ssh_ca_users:
        - user: deploy
          principals:
            - gha-prod-deploy
        - user: staging
          principals:
            - gha-staging-deploy
```

```bash
ansible-playbook -i inventory.ini site.yml
```

A runnable copy of this playbook is at
[`ansible/playbook.example.yml`](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/ansible/playbook.example.yml).

The principals must match `certificate.principals` in the CA's
[policy](policy.md): a certificate logs in as `deploy` only if one of
its principals appears in `/etc/ssh/auth_principals/deploy`. The login
users themselves must already exist; the role does not create accounts.

With the example above, the role writes:

```text
# /etc/ssh/sshd_config.d/oidc-ssh-ca.conf
TrustedUserCAKeys /etc/ssh/oidc-ssh-ca.pub

Match User deploy
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no

Match User staging
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no
```

```text
# /etc/ssh/auth_principals/deploy
gha-prod-deploy
```

## Variables

| Variable | Default | Purpose |
|---|---|---|
| `oidc_ssh_ca_public_key` | — (required) | CA public key in OpenSSH format (`ssh-ed25519 AAAA...`) |
| `oidc_ssh_ca_users` | — (required) | List of `{user, principals}` mappings |
| `oidc_ssh_ca_public_key_path` | `/etc/ssh/oidc-ssh-ca.pub` | Where the CA key is installed |
| `oidc_ssh_ca_principals_dir` | `/etc/ssh/auth_principals` | Directory for per-user principals files |
| `oidc_ssh_ca_sshd_config_path` | `/etc/ssh/sshd_config.d/oidc-ssh-ca.conf` | Managed sshd fragment |
| `oidc_ssh_ca_disable_password_auth` | `true` | Add `PasswordAuthentication no` and `KbdInteractiveAuthentication no` to each `Match User` block |
| `oidc_ssh_ca_verify_include` | `true` | Fail if `sshd_config` does not include `sshd_config.d` |
| `oidc_ssh_ca_sshd_binary` | `/usr/sbin/sshd` | Binary used for `sshd -t` validation |
| `oidc_ssh_ca_sshd_service` | `ssh` on Debian/Ubuntu, else `sshd` | Service reloaded after changes |

## Notes

- The role is idempotent: rerunning it without changes reports no
  changes and does not reload sshd.
- `oidc_ssh_ca_disable_password_auth` only affects the listed users.
  Password logins for other accounts are untouched — disable them
  globally yourself if that is your policy.
- Removing a user from `oidc_ssh_ca_users` removes their `Match` block,
  which is what sshd consults; the now-unreferenced principals file is
  left behind and is inert. Delete it manually if you want a tidy
  `/etc/ssh/auth_principals`.
- [CA key rotation](operations.md) works through this role too:
  `TrustedUserCAKeys` may list several keys, so set
  `oidc_ssh_ca_public_key` to both public keys (one per line) during
  the transition, then rerun with only the new key once the old
  certificates have expired.
