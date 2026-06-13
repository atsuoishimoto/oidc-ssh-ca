# Choosing a deployment

`oidc-ssh-ca` is a single static binary with no runtime dependencies, so it
runs almost anywhere. The workload is tiny — a few `POST /sign` requests per
CI run — which makes scale-to-zero platforms a natural fit: you pay nothing
while idle and get a public HTTPS endpoint without managing certificates.

| Deployment | Best for | TLS | Cost while idle | Policy reload |
|---|---|---|---|---|
| [Cloud Run](cloud-run.md) | Most users; no infrastructure to manage | automatic | none (scale to zero) | new revision |
| [Docker Compose + Caddy](docker-compose.md) | An existing Docker host / VPS | automatic (Caddy) | the host you already run | `SIGHUP` |
| [AWS Lambda (CLI)](lambda-cli.md) | AWS users who want minimal moving parts | Function URL | none (scale to zero) | redeploy zip |
| [AWS Lambda (Terraform)](lambda-terraform.md) | AWS users who already use Terraform | Function URL | none (scale to zero) | redeploy zip |
| [systemd](systemd.md) | Bare metal / VPS without Docker | bring your own proxy | the host you already run | `systemctl reload` |

**Recommendation:** if you have no strong platform preference, use
[Cloud Run](cloud-run.md). It needs no AWS-specific knowledge, no state files,
and no reverse proxy; deployment is one `gcloud` command and the service costs
nothing between CI runs.

Whatever the platform, the security model is the same:

- The CA private key is the crown jewel. Choosing a deployment is mostly
  choosing where the key lives: a secret manager (Cloud Run, Lambda), a
  `0600` file (Compose, systemd), or — later — a KMS key that never leaves
  the HSM.
- The `/sign` endpoint can be public: callers are authenticated by verifying
  their OIDC token against the policy, not by network position. Still, cap the
  service to a single instance (`--max-instances 1` on Cloud Run,
  `reserved_concurrent_executions = 1` on Lambda) to bound the cost of
  unauthenticated traffic.
- Audit logs are JSON lines on stdout. Every platform below captures them
  (CloudWatch Logs, Cloud Logging, `docker logs`, journald).
