# Why teams adopt oidc-ssh-ca

The useful question is not "how many servers do we have." A single server is
enough. The question is whether a team keeps accepting **long-lived SSH private
keys in CI/CD**. For a team that runs production deploys from GitHub Actions,
that is the real decision, and it is where `oidc-ssh-ca` earns its place.

The headline value is not "fewer keys." It is that a workflow's *identity*
becomes the unit of SSH authorization, and the permission boundaries that used
to be implicit become something a team can review, audit, and rotate in one
place.

## How the deploy-key model decays in a team

The common setup is simple: a long-lived SSH private key in GitHub Secrets,
injected into the runner, used with `ssh -i`. For one person and one workflow it
is a reasonable choice.

In a team it tends to spread:

```text
DEPLOY_KEY_PROD
DEPLOY_KEY_STAGING
MIGRATION_KEY
RESTART_KEY
deploy keys across several repositories
environment secrets
a secret left behind in an old workflow
a secret nobody is sure is still in use
```

The deeper problem is not that the permissions are "simple." It is that they are
**broad and hard to see**. Anything that can read `DEPLOY_KEY_PROD` effectively
has that SSH access, and from the server every such workflow arrives as the same
key. The boundaries you actually care about —

```text
only the main-branch deploy workflow
only after a production environment approval
migrations only from the migration workflow
restarts only from the restart workflow
never anything triggered by a pull request
```

— are spread implicitly across GitHub Secrets scope, workflow YAML, branch and
environment protection, `authorized_keys`, sudoers, and runbooks. They are never
reviewed in one place because there is no one place.

## What changes operationally

With `oidc-ssh-ca`, GitHub Actions holds no long-lived SSH key. Each run fetches
a GitHub OIDC token, generates an ephemeral key pair, and asks the CA for a
short-lived certificate; the CA checks the run's claims against `policy.yaml`
and signs only if exactly one rule matches.

That shifts day-to-day operations in concrete ways:

- **Identity is the unit of authorization.** Issuance is decided by verified
  claims — `repository`, `ref`, `workflow`, `environment`, `event_name`,
  `job_workflow_ref`, and so on — not by who can read a secret.
- **Permission changes become reviewable policy diffs.** This is not new toil.
  The boundaries were always open; now they are written down in one file and
  changed through review, instead of living implicitly across six systems.
- **Issuance is auditable.** Every decision is a structured
  `certificate_issued` / `certificate_denied` log line, and the certificate key
  ID can embed claims such as the repository, workflow, and run ID — so you can
  answer "which run reached this server" after the fact.
- **Rotation collapses onto the CA key.** Instead of rotating N scattered deploy
  keys (and discovering what breaks), there is one CA key to rotate; target
  servers trust only the CA public key, so there are no `authorized_keys` to
  redistribute.
- **A leaked certificate is not a general shell.** Combined with a forced
  command and a short TTL, a workflow can be limited to exactly one operation
  (for example `deploy-prod.yml` may only run `/usr/local/bin/deploy-prod`), so
  even a leaked certificate cannot be reused as an interactive login.

The net effect: instead of distributing a secret and trying to contain who and
what can use it through surrounding rules, you authorize a workflow's identity
and issue exactly the SSH permission it needs, for a few minutes, on the spot.

## Centralization is the value, and the cloud makes it practical

For a team, the win is moving from

```text
scattered GitHub Secrets and deploy keys
```

to

```text
one CA + one policy + one issuance log
```

This is a deliberate trade: management gets simpler, but the CA key and policy
now matter a great deal. That trade is much easier to make well on managed cloud
infrastructure than on a self-hosted CA VPS. Running the CA on Cloud Run or AWS
Lambda makes **availability easier to secure** — the deploy path now depends on
the CA, and managed platforms absorb most of that operational burden — while
KMS / Secret Manager make the **CA key easier to keep confidential**. With a KMS
backend the CA key is never exportable: the service signs without ever holding
the raw key (the signing path is built behind a `Signer` abstraction precisely
so this is possible). Seen this way, `oidc-ssh-ca` is less "run a CA server" and
more "manage a CA policy and a CA secret on infrastructure you already operate."

## What you take on

Centralization has a cost, and it is worth stating plainly:

- The CA becomes a dependency on the deploy path; if it is unreachable,
  issuance fails.
- The CA key and the quality of the policy now determine overall safety.
  Concentrating into one key removes the accidental blast-radius isolation that
  scattered keys gave you, so that one key has to be guarded accordingly.
- A workflow that is itself compromised but still presents a valid identity will
  still receive a valid certificate; short TTLs and forced commands shrink the
  damage but do not remove this.

These are trade-offs, not dealbreakers, and they are mitigated by the design
choices above. See the [Security model](security-model.md) for the full risk
trade-off — which risks go away, which you take on, and how to deploy so the new
design is actually safer than the old one.

## Bottom line

For a team running production SSH deploys from GitHub Actions, `oidc-ssh-ca` is a
legitimate way out of keeping long-lived SSH keys in CI — not merely an
alternative to deploy keys. The value is operational as much as it is security:
SSH permissions managed as policy, issuance you can audit, rotation reduced to
one key, and per-workflow access expressed without breeding secrets.

It is clearly better than the deploy-key model only once you design the whole
picture together: CA-key protection, a strict policy, short TTLs, forced
commands, issuance logs, and GitHub environment protection. With those in place,
the team gains both a safer and a more manageable way to operate CI/CD SSH
access.
