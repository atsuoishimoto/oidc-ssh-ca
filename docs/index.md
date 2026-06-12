# oidc-ssh-ca

A small SSH certificate authority that issues short-lived OpenSSH user
certificates to OIDC-authenticated callers — primarily GitHub Actions.

Instead of storing a long-term SSH private key in GitHub Secrets, a workflow
generates an ephemeral key pair on every run, proves its identity with the
GitHub OIDC token, and receives a certificate valid for a few minutes.
Target servers trust only the CA public key; there are no `authorized_keys`
to distribute, rotate, or clean up after a leak.

```text
GitHub Actions
  │  GitHub OIDC JWT + ephemeral public key
  ▼
oidc-ssh-ca  POST /sign
  │  verify JWT → match policy.yaml → sign in memory
  ▼
short-lived OpenSSH user certificate
  │  ssh / ansible / rsync / scp
  ▼
target servers (trust only the CA public key)
```

For the policy format, the GitHub Actions workflow, and sshd configuration,
see the [README](https://github.com/atsuoishimoto/oidc-ssh-ca#readme). This
documentation focuses on deploying and operating the CA itself.

```{toctree}
:maxdepth: 2
:caption: Deployment

deployment/index
deployment/cloud-run
deployment/docker-compose
deployment/lambda-cli
deployment/lambda-terraform
deployment/systemd
```
