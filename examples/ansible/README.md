# Ansible role: oidc_ssh_ca_trust

Configures target servers to trust an `oidc-ssh-ca` certificate
authority. The role installs the CA public key, creates per-user
`AuthorizedPrincipalsFile` entries, drops an `sshd_config.d` fragment,
validates the result with `sshd -t`, and reloads sshd. It can also
create the login accounts and grant them passwordless sudo when an entry
sets `create: true` or `sudo: true`.

Quick start:

```bash
oidc-ssh-ca print-ca-pub --ca-key-file ./ca_key > oidc-ssh-ca.pub
ansible-playbook -i inventory.ini playbook.example.yml
```

See [`playbook.example.yml`](playbook.example.yml) for a complete
playbook, and the full documentation (variables, behavior, manual
alternative) at
<https://oidc-ssh-ca.readthedocs.io/en/latest/ansible.html> (source:
[`docs/ansible.md`](../../docs/ansible.md)).
