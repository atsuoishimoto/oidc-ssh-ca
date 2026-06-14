# Security model

This page explains what changes when you replace a long-lived SSH key in
GitHub Secrets with short-lived, OIDC-issued certificates: which risks go
away, which new ones you take on, when the trade is worth it, and how to
deploy so the new design is actually safer than the old one.

It is written against the GitHub Actions deploy use case (the supported
identity source), but the reasoning applies to any OIDC caller.

## What this changes (and what it doesn't)

The baseline is the common pattern: a long-lived SSH private key stored in
GitHub Secrets, injected into the runner, and used with `ssh -i`. That key
is a *standing secret* — it is valuable for as long as it exists, and a
copy of it is enough to log in until every target server is reconfigured.

`oidc-ssh-ca` replaces the standing secret with a *runtime* credential.
Each run generates an ephemeral key pair, proves its identity with the
GitHub OIDC token, and receives a certificate valid for a few minutes. The
core shift is **what leaks and for how long**, not whether a compromised
run can reach your servers.

Point by point, *stored key* versus *oidc-ssh-ca*:

- **Secret stored at GitHub** — a long-lived SSH private key, versus none
  (an OIDC token is fetched per run).
- **Material on the runner** — the long-lived private key, versus an
  ephemeral key, the OIDC JWT, and a short-lived certificate.
- **Lifetime if leaked** — valid until rotated everywhere, versus the
  token / certificate TTL (minutes) — except a leaked CA key, which is
  severe.
- **Authorization granularity** — whichever workflow can read the secret,
  versus claim matching on `repository`, `ref`, `environment`,
  `event_name`, `job_workflow_ref`, and so on.
- **Target-server management** — distribute and rotate `authorized_keys`,
  versus trust the CA public key and manage principals.
- **Availability** — no CA needed, versus issuance fails if the CA is
  unreachable.
- **Worst-case leak** — one deploy key's blast radius, versus CA-key
  compromise affecting every server that trusts it.

## What you stop trusting

The biggest win is that there is no longer a long-lived SSH private key
sitting in GitHub. The exposures that come with a standing secret simply
disappear:

- A leaked secret (mis-scoped repository access, a departed employee, a
  backup or log that captured it, an accidental `echo`) is no longer a
  permanent key — at most it is a credential that expires in minutes.
- The *time-based blast radius* of any leak shrinks from "until we rotate
  and reconfigure every server" to the certificate TTL. The example policy
  issues 600-second certificates with a 900-second ceiling
  (`defaults.max_valid_for_seconds`), so after an emergency stop you wait
  out the ceiling and no valid certificate exists anywhere — there is
  nothing to revoke (see [Operations](operations.md)).
- Authorization is no longer "anything that can read the secret." A rule
  can pin `repository`, `ref`, `environment`, `event_name`, and
  `job_workflow_ref`, so a different workflow in the same repository, a
  different branch, or a manual run cannot obtain a certificate. The
  caller sends only its public key; it cannot ask for a different
  principal, a longer TTL, or extra extensions.

## What you start trusting

In exchange, the CA server and the **CA private key become new critical
assets** — the "king's key." Anyone who holds the CA private key can mint
certificates for every server that trusts it. The risk has moved from
"an SSH key in GitHub Secrets" to "the CA and its key," and that asset
must be protected accordingly:

- Restrict who and what can reach the `/sign` endpoint and the host
  running the CA.
- Treat suspected CA-key compromise as a fleet-wide event: remove the CA
  public key from `TrustedUserCAKeys` on every target server and rotate
  the key (see CA key rotation in [Operations](operations.md)).
- Keep the key off disk and out of version control. The signer keeps the
  parsed key in memory only; supply it through exactly one of
  `--ca-key-file`, `OIDC_SSH_CA_KEY_FILE`, or `OIDC_SSH_CA_KEY`, with file
  permissions no looser than `0600`.

You also take on an **availability dependency**. With a stored secret a
deploy needs only GitHub and the target server. With `oidc-ssh-ca` every
deploy first calls the CA, so an outage of the CA, its network, JWKS
fetching, or policy loading stops deploys. The tool fails safe — it
refuses to start on an invalid policy, keeps the old policy on a failed
reload, and denies when JWKS is unavailable with no cache — which is the
right default, but it fails *closed*: the failure mode is "deploy
denied," not "deploy with stale trust."

## What this does not protect against

Short-lived certificates change the lifetime of credentials, not who can
obtain them during a legitimate run. Be explicit about the limits:

- **A compromised runner or build step.** If an attacker controls the job
  while it runs — a malicious dependency, a poisoned step, an injected
  script — they can fetch the OIDC token, request a certificate, and SSH,
  exactly as they could read a stored secret. OIDC proves *which workflow
  run* is calling; it does not prove the code in that run is benign.
  Against this threat `oidc-ssh-ca` offers no advantage over a stored
  secret; its value is bounded to reducing the standing secret and the
  blast radius over time.
- **The OIDC token is a bearer token.** Anyone holding a valid GitHub
  OIDC JWT can present their own public key to `/sign` and receive a
  certificate while the token is valid. Handle the JWT with the same care
  as a secret; do not log it, print it, or pass it where it can be
  captured.
- **Host-key verification is still your job.** A short-lived client
  certificate does nothing for the *server's* identity. Without host-key
  pinning the connection remains open to a machine-in-the-middle. Pin
  `known_hosts` and use `StrictHostKeyChecking=yes`, as the
  [Quickstart](quickstart.md) workflow does.

## When this is worth it

`oidc-ssh-ca` pays off as the following become true; if few of them hold,
a stored deploy key with least privilege may be the simpler, equally safe
choice:

- You SSH to **multiple servers**, so distributing and rotating
  `authorized_keys` is real work.
- You want **different SSH access per branch, environment, or workflow**.
- You need to **trace which GitHub Actions run** logged into a server.
- You do not want a long-lived private key in GitHub Secrets, and you
  want a leak to expire in minutes.

Conversely, weigh the costs honestly. For a **single target server with
one rarely-changing deploy key**, introducing a CA means standing up an
internet-reachable service and protecting a key whose compromise is
worse than the secret it replaced — often a net increase in attack
surface. And because this is a small, young, single-binary tool sitting
on your authentication path (not a Vault/Teleport replacement), running it
in production means pinning versions, reading the code you depend on, and
giving the CA an availability target you are willing to own.

## Hardening checklist

If you do adopt it, these are the points whose absence turns the migration
into a new incident source:

- **Write narrow policies.** Matching only `repository` lets any branch,
  workflow, manual run, or event in that repository obtain a certificate.
  For production, also pin `ref`, `environment`, `event_name`, and
  `job_workflow_ref` (and validate the `audience`). Use `check-config` and
  `explain` to confirm a token matches exactly one rule.
- **Grant nothing by default.** Leave the certificate extensions
  (`permit_pty`, `permit_port_forwarding`, ...) off unless a use case
  needs them; the example policy ships them disabled.
- **Protect the CA key.** Single source, `0600` or stricter, never on
  disk in a runner or in version control. Have the rotation runbook ready
  before you need it.
- **Constrain what a certificate can do, not just who gets one.** A rule
  can set `certificate.force_command` (the target runs only that command,
  so a leaked certificate cannot open a shell) and
  `certificate.source_address` (a CIDR allowlist of where the certificate
  may be used). Both are baked into the certificate by the CA, so they
  apply on every target without per-host configuration. GitHub-hosted
  runners use broad IP ranges, so `source_address` helps mainly with
  self-hosted runners. See the
  [policy reference](policy.md#certificateforce_command).
- **Plan for CA availability.** A deploy now depends on the CA being
  reachable; size and monitor it like the production dependency it is.
- **Watch the audit log.** Alert on `certificate_denied` spikes and on
  `policy_disabled`, and use the key ID (repository / run ID) to tie an
  sshd login on a target server back to the exact run. See
  [Operations](operations.md).
