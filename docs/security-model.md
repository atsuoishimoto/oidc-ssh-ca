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

That dependency is cheap to make redundant, because the CA is
**stateless**. It keeps no database and no session state: the policy is
read from a file, the JWKS is cached in memory and refetched on demand,
and each `/sign` request is decided entirely from the request plus that
in-memory state. Nothing has to be shared or synchronized between
instances, so you can run as many as you like — N replicas behind a load
balancer, or a serverless target such as AWS Lambda (which the tool
supports via the Lambda Web Adapter; see
[Deployment](deployment/index.md)) that scales out on its own and has no
host to keep running. Availability becomes a deployment choice rather than
a single point of failure: the same property that makes the CA a sensitive
asset — it only signs, it never stores — is what makes it easy to make
highly available.

## One key to guard, not many

Stepping back, the migration changes the *shape* of the key-protection
problem more than its total size. The stored-key world disperses risk: a
fleet accumulates many long-lived private keys — one per repository,
per environment, per "we needed access that one time" — scattered across
GitHub Secrets, CI variables, and developer laptops. `oidc-ssh-ca`
concentrates it into a single CA private key. Neither is strictly safer;
they fail in opposite ways, and it is worth being clear about the trade.

**Many scattered keys** spread the blast radius — a single leak only
exposes what that one key authorizes — but they are hard to *govern*. They
are easy to copy and slow to notice missing, no one can confidently
enumerate where every copy lives, and rotation means tracking down and
replacing each one, so in practice they are rarely rotated and quietly
accumulate. The aggregate attack surface is large, diffuse, and
under-monitored: many small, neglected secrets, each an independent way in.

**One central CA key** inverts both sides. The blast radius is the worst
case in the project — whoever holds it can mint certificates for every
server that trusts the CA, so its compromise is a fleet-wide event. But
there is exactly one asset to reason about, and that makes strong
protection tractable: you can spend real effort on a single key — keep it
in memory only, put it behind a KMS/HSM via the `Signer` interface,
restrict the one host that can reach it, and rotate it with one runbook
instead of an inventory hunt. Every certificate it signs is also recorded
in the audit log, so issuance is observable in a way that copies of a
static key never are.

The honest summary: the stored-key model gives you *many easy problems you
will tend to neglect*; the CA model gives you *one hard problem you can
actually solve*. The CA is worth it when you would rather concentrate risk
into a single, well-defended, observable, rotatable key than disperse it
across secrets you cannot fully account for — and when you are prepared to
defend that one key accordingly. The earlier sections on protecting the CA
key and on availability are how you pay for that concentration.

## What this does not protect against

Short-lived certificates change the lifetime of credentials, not who can
obtain them during a legitimate run. Be explicit about the limits:

- **A compromised runner or build step.** If an attacker controls the job
  while it runs — a malicious dependency, a poisoned step, an injected
  script — they can fetch the OIDC token, request a certificate, and SSH,
  exactly as they could read a stored secret. OIDC proves *which workflow
  run* is calling; it does not prove the code in that run is benign. What
  `oidc-ssh-ca` can still do is **limit what that certificate is able to
  do**: with `certificate.force_command` the certificate runs only your
  deploy script, never an interactive shell or an arbitrary command, and
  with `certificate.source_address` it is usable only from your runner's
  network. A stored SSH key, by contrast, is full access wherever it is
  authorized. So the right framing is not "no protection" but "the
  credential expires in minutes *and* is scoped to a single action" —
  see [force-command below](#use-force-command-to-cap-the-blast-radius).
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

## Use force-command to cap the blast radius

The single biggest reason to prefer certificates over a stored key is not
that they expire — it is that the CA decides, per rule, **what the holder
may do with one**. A stored SSH key authorizes a login; from there the
holder runs whatever the account allows. A certificate issued with
`certificate.force_command` runs exactly one command and nothing else.

This changes the worst case in concrete ways:

- **A leaked or misused certificate cannot pivot.** With
  `force_command: "/usr/local/bin/deploy.sh"` there is no interactive
  shell, no `cat ~/.ssh/id_rsa`, no `curl | sh` — the only thing the
  certificate can do is run your deploy script. Whatever the attacker
  asks for, sshd runs the forced command instead.
- **It narrows even the unpreventable case.** A compromised runner can
  still obtain a certificate (above), but `force_command` bounds that
  certificate to one action, and `source_address` bounds it to one
  network — turning "an attacker has SSH for a few minutes" into "an
  attacker can run the deploy script, from our runners, for a few
  minutes." A stored key offers neither bound.
- **It is enforced at the CA, on the certificate itself.** You do not
  have to trust that every target server's `AuthorizedPrincipalsFile`
  carries the right `command=`/`from=` options; the restriction travels
  with the certificate and applies on every host that trusts the CA. One
  policy rule, enforced everywhere.
- **It costs nothing operationally.** `force-command` and
  `source-address` are standard OpenSSH critical options understood by
  every server, so there is no compatibility risk and no per-host setup.

The pattern that gets the most out of this CA, then, is *narrow rule +
short TTL + `force_command`*: a certificate that only the right workflow
can obtain, that dies in minutes, and that can do exactly one thing while
it lives. See the [policy reference](policy.md#certificateforce_command)
for the fields.

## Scope certificates with purpose-specific principals

`force-command` bounds *what* a certificate can do; principals bound *where* it
can go — and that boundary is easy to leave wider than intended. `TrustedUserCAKeys`
is host-global: once a server trusts the CA (see
[Configuring target servers](target-servers.md)), **every** certificate the CA
issues becomes a candidate to log in there. The only remaining gate is whether
one of the certificate's principals appears in that account's
`AuthorizedPrincipalsFile`. The principal name, not the workflow's intent, is
what separates "may log in here" from "may not."

That has a consequence worth stating plainly: a certificate minted for
"workflow A, deploying to server A" is equally usable on server B if server B
authorizes the same principal. If two unrelated workflows share a principal
(both issue `gha-deploy`), or every server authorizes one broad principal, then
any certificate from any of those workflows can log into any of those servers.
The short TTL bounds *how long* such a certificate works, not *where* — so a
leaked or misdirected certificate reaches further than the workflow ever
intended.

The fix is to make the principal carry the intent. Give each purpose its own
principal in the [policy](policy.md#certificateprincipals), and list on each
server only the principals that server legitimately serves.

In the policy, one rule per target:

```yaml
rules:
  - name: "app-a-deploy"
    match:
      jwt:
        issuer: "https://token.actions.githubusercontent.com"
        audience: "ssh-ca-prod"
        owner: "your-org"
        reponame: "app-a"
        claims_exact:
          ref: "refs/heads/main"
    certificate:
      principals:
        - "gha-app-a"        # only server A authorizes this
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"

  - name: "app-b-deploy"
    match:
      jwt:
        issuer: "https://token.actions.githubusercontent.com"
        audience: "ssh-ca-prod"
        owner: "your-org"
        reponame: "app-b"
        claims_exact:
          ref: "refs/heads/main"
    certificate:
      principals:
        - "gha-app-b"        # only server B authorizes this
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
```

On each server, the `AuthorizedPrincipalsFile` for the login account lists only
its own principal:

```text
# server A — /etc/ssh/auth_principals/deploy
gha-app-a

# server B — /etc/ssh/auth_principals/deploy
gha-app-b
```

Now a certificate carrying `gha-app-a` is rejected by server B, because that
name does not appear in any of server B's principal files — the same per-account
check shown in
[Configuring target servers](target-servers.md#2-authorize-principals-for-each-login-user),
applied as a boundary *between* servers. Combined with the previous section, the
two controls layer cleanly: principals decide which servers a certificate can
reach, and `force_command` decides what it may do once it gets there.

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
- **Constrain what a certificate can do, not just who gets one.** Set
  `certificate.force_command` so a certificate runs only your deploy
  script, and `certificate.source_address` to bound where it works. This
  is the highest-leverage control here — see
  [Use force-command to cap the blast radius](#use-force-command-to-cap-the-blast-radius).
- **Plan for CA availability.** A deploy now depends on the CA being
  reachable; size and monitor it like the production dependency it is.
- **Watch the audit log.** Alert on `certificate_denied` spikes and on
  `policy_disabled`, and use the key ID (repository / run ID) to tie an
  sshd login on a target server back to the exact run. See
  [Operations](operations.md).
