# Policy reference

`policy.yaml` is the single source of authorization decisions. Principals,
TTL, extensions, and the certificate key ID are derived from verified JWT
claims and this file — the request body carries only a public key, so a
caller can never ask for a principal or a longer TTL.

Parsing is strict: unknown fields, type mismatches, missing required
fields, and multiple YAML documents in one file are all errors. An invalid
policy prevents startup; an invalid policy on reload keeps the previous
policy running. Validate with `oidc-ssh-ca check-config policy.yaml`.

## File structure

```yaml
version: 1          # required
disabled: false     # optional
defaults:           # optional
  valid_after_offset_seconds: -30
  max_valid_for_seconds: 900
  allowed_public_key_types: ["ssh-ed25519"]
  extensions:
    permit_pty: false
    permit_port_forwarding: false
    permit_agent_forwarding: false
    permit_x11_forwarding: false
    permit_user_rc: false
rules:              # required, at least one
  - name: "prod-deploy"
    enabled: true
    match:
      jwt:
        issuer: "https://token.actions.githubusercontent.com"
        audience: "ssh-ca-prod"
        claims_exact:
          repository: "your-org/your-repo"
    certificate:
      principals: ["gha-prod-deploy"]
      valid_for_seconds: 600
      key_id_template: "gha:${repository}:${run_id}"
      extensions:
        permit_pty: true
```

## Top-level fields

### `version`

Required, integer. Must be `1`. Any other value is a validation error, so
a future format change can never be misread by an old binary.

### `disabled`

Optional, boolean, default `false`. When `true`, every request is denied
with HTTP 503 while the server stays up — this is the emergency stop:
flip it, reload (`SIGHUP`), and issuance halts immediately (see
[Operations](operations.md)). Existing certificates remain valid until
their TTL expires, which is bounded by `max_valid_for_seconds`.

### `defaults`

Optional mapping of policy-wide settings, described below.

### `rules`

Required list with at least one entry. An empty or missing `rules` is a
validation error: a policy that can never issue anything is more likely a
mistake than an intent (use `disabled: true` to stop issuance
deliberately).

## `defaults`

### `defaults.valid_after_offset_seconds`

Optional, integer, default `-30`. Offset in seconds applied to the
certificate's `valid after` timestamp relative to signing time. The
negative default backdates certificates by 30 seconds so that a target
server whose clock runs slightly behind the CA does not reject a
freshly issued certificate as "not yet valid".

### `defaults.max_valid_for_seconds`

Optional, integer, default `900` (15 minutes). Must be positive. A
ceiling for every rule's `valid_for_seconds`: a rule exceeding it is a
validation error, so one glance at `defaults` bounds the lifetime of any
certificate this CA can produce.

It also bounds the emergency-stop window: after disabling the policy,
every outstanding certificate is dead within this many seconds — there is
no revocation list to manage.

### `defaults.allowed_public_key_types`

Optional, list of strings, default `["ssh-ed25519"]`. The client public
key types the CA accepts in `/sign` requests. `ssh-ed25519` is the only
type this version supports — listing anything else is a validation error.
Certificate keys (`*-cert-v01@openssh.com`) are always rejected: the CA
signs raw public keys, never other certificates.

### `defaults.extensions`

Optional mapping. The OpenSSH certificate extensions applied to issued
certificates when a rule does not define its own `extensions` block.
Every flag defaults to `false`: **a certificate grants nothing beyond
authentication unless the policy explicitly enables it.**

| Field | OpenSSH extension | When `true` |
|---|---|---|
| `permit_pty` | `permit-pty` | the session may allocate a PTY (interactive shell). Not needed for plain `ssh host 'command'`, rsync, or scp |
| `permit_port_forwarding` | `permit-port-forwarding` | the session may forward TCP ports (`-L`/`-R`) |
| `permit_agent_forwarding` | `permit-agent-forwarding` | the session may forward an SSH agent (`-A`) |
| `permit_x11_forwarding` | `permit-X11-forwarding` | the session may forward X11 |
| `permit_user_rc` | `permit-user-rc` | sshd executes `~/.ssh/rc` on login |

All five fields are optional and independent; an omitted field is `false`.

## `rules` entries

### `name`

Required, string, matching `[A-Za-z0-9._-]+`, unique across the file. The
rule's identifier in audit events, `check-config` warnings, and `explain`
output. Renaming a rule changes how its decisions are reported, so prefer
stable names.

### `enabled`

Optional, boolean, default `true`. When `false`, the rule stays in the
file but never participates in matching — useful for staging a new rule
before turning it on, or disabling one without losing it.

### `match`

Required. The conditions on the caller's verified identity. The only
supported key in this version is `jwt`; an `aws:` key is a parse error
(AWS identity matching is planned).

### `match.jwt.issuer`

Required, string. Exact match against the verified token's `iss` claim.
For GitHub Actions this is `https://token.actions.githubusercontent.com`.
The server pre-registers every issuer referenced by an enabled rule with
the JWT verifier (OIDC discovery + JWKS); a token from an issuer no rule
references fails verification before matching even starts.

### `match.jwt.audience`

Required, string. The token's `aud` claim must contain this value. The
audience is what the GitHub Actions workflow requests
(`...&audience=ssh-ca-prod`); giving each CA (or each environment) its own
audience keeps a token requested for one from ever matching rules meant
for another.

### `match.jwt.owner` and `match.jwt.repository`

Optional strings. Both are halves of the GitHub Actions `repository` claim
(`owner/repo`), split on the `/`: `owner` matches the part before the slash
(the org/user), `repository` matches the part after it (the repo name). Each
is independent — set both to pin an exact repo, or only one to leave the other
unconstrained (e.g. `owner: "your-org"` alone allows any repo under the org).
An omitted field is no constraint.

```yaml
jwt:
  owner: "your-org"        # any repo under your-org
  repository: "your-repo"  # any owner's repo literally named your-repo
```

Neither value may contain `/` (a startup validation error). When either is
set, a token whose `repository` claim is absent or has no `/` fails the match.
If you prefer to pin the full `owner/repo` as a single exact string, use
`claims_exact: { repository: "your-org/your-repo" }` instead.

### `match.jwt.claims_exact`

Optional mapping of claim name → expected string value. Every listed
claim must be present in the token and equal the expected value — string
equality, no globs, no regexes. A claim listed here but **absent from the
token denies**; absence never matches anything. Empty claim names and
empty expected values are validation errors.

Which claims exist depends on the issuer. Useful GitHub Actions claims:

| Claim | Pins |
|---|---|
| `repository` | `owner/repo` the workflow runs in |
| `ref` | the git ref, e.g. `refs/heads/main` |
| `event_name` | the trigger, e.g. `push` (excludes `pull_request` from forks) |
| `environment` | the job's `environment:`; **only present when the job declares one** |
| `workflow` | the workflow name |
| `job_workflow_ref` | the exact workflow file and ref; with reusable workflows, the *called* workflow |
| `actor` | the user who triggered the run |

`sub`, `run_id`, and `run_attempt` also exist; `run_id`/`run_attempt`
change on every run, so they belong in `key_id_template`, not here.

#### Pinning the branch

Pin the git ref a run is allowed to come from with the `ref` claim. It is
the full ref, not a short name:

```yaml
claims_exact:
  ref: "refs/heads/main"        # the main branch
  # ref: "refs/tags/v1.2.3"     # a specific tag
  # ref: "refs/heads/release/*" is NOT supported — values are exact, no globs
```

`ref` is matched by exact string equality, so `main`, `refs/head/main`, or
a glob will never match. To restrict to release tags in general (rather
than one exact tag), pin `event_name: "push"` together with a tag-only
trigger in the workflow, or use `job_workflow_ref` below.

#### Pinning the workflow file

Prefer `job_workflow_ref` over `workflow`. `workflow` is the workflow's
display name (its `name:`), which silently breaks the moment the workflow
is renamed; `job_workflow_ref` pins the workflow **file** and its ref:

```yaml
claims_exact:
  job_workflow_ref: "your-org/your-repo/.github/workflows/deploy.yml@refs/heads/main"
```

The value is `owner/repo/path/to/workflow.yml@ref`. Because it ends with
`@<ref>`, it pins the branch (or tag) as well — so a rule that sets
`job_workflow_ref` usually does not also need `ref`. Notes:

- The `@<ref>` is the ref the *workflow file* is read from. For a `push`
  or `workflow_dispatch` run this equals the run's own ref (e.g.
  `@refs/heads/main`); pinning a different branch denies.
- With **reusable workflows**, `job_workflow_ref` is the *called*
  workflow's file and ref — pin the reusable workflow that actually does
  the signing request, not the caller.
- The value is matched exactly, including the `.github/workflows/` path
  and the `@<ref>` suffix. No globs.

A rule combining both — only `deploy.yml`, only on `main`, only on a real
push:

```yaml
match:
  jwt:
    issuer: "https://token.actions.githubusercontent.com"
    audience: "ssh-ca-prod"
    claims_exact:
      repository: "your-org/your-repo"
      event_name: "push"
      job_workflow_ref: "your-org/your-repo/.github/workflows/deploy.yml@refs/heads/main"
```

### `certificate`

Required. What is issued when this rule is the single match.

### `certificate.principals`

Required, non-empty list of non-empty strings. The principals embedded in
the certificate. A target server's sshd maps them to login users via
`AuthorizedPrincipalsFile` — the certificate logs in as user X only if one
of these principals appears in X's principals file. Use task-shaped names
(`gha-prod-deploy`), not user names: the mapping to users is the target
server's decision.

### `certificate.valid_for_seconds`

Required, integer. The certificate TTL, measured from signing time. Must
be positive and at most `defaults.max_valid_for_seconds`. Size it to the
job that uses it: a deploy that takes 2 minutes does not need a 15-minute
certificate.

### `certificate.key_id_template`

Required, string. Template for the certificate's key ID, expanded from
verified claims. The key ID appears in the CA audit log and verbatim in
the target server's sshd log — it is the thread that ties an SSH login
back to the exact CI run that requested it. See
[key_id_template expansion](#key_id_template-expansion) below.

### `certificate.extensions`

Optional. Same fields as `defaults.extensions`. When present it
**replaces** the defaults block entirely (no per-flag merging): the
effective extensions are the rule's block if set, otherwise the defaults
block, otherwise everything off.

### `certificate.force_command`

Optional, string. When set, it is embedded as the certificate's
`force-command` critical option: the target server ignores whatever
command the client asks for and runs **only this one**. Use it to bind a
deploy certificate to a single script (`/usr/local/bin/deploy.sh`) so a
leaked certificate cannot be used for an interactive shell or an arbitrary
command.

### `certificate.source_address`

Optional, list of strings. When set, it is embedded as the
`source-address` critical option: the certificate is only accepted when
the client connects from one of these CIDR ranges. Each entry must be
**CIDR notation** — a bare address is an error, so write `192.0.2.10/32`,
not `192.0.2.10`. Both IPv4 and IPv6 are accepted
(`192.0.2.0/24`, `2001:db8::/32`).

```yaml
certificate:
  principals: ["gha-prod-deploy"]
  valid_for_seconds: 600
  key_id_template: "gha:${repository}:${run_id}"
  force_command: "/usr/local/bin/deploy.sh"
  source_address:
    - "192.0.2.0/24"
```

GitHub-hosted runners use broad, changing IP ranges, so `source_address`
is mainly useful with self-hosted runners or a fixed NAT egress.
`force-command` and `source-address` are standard OpenSSH critical
options understood by every server, so enabling them does not risk an
"unknown critical option" rejection.

## Matching semantics

- **Deny by default.** A request is allowed only if a rule matches.
- **Exactly one match.** Zero matching rules deny (`no_rule_matched`);
  two or more matching rules also deny (`multiple_rules_matched`). There
  is no first-match-wins, so rule order can never silently change what a
  rule means — overlapping rules are surfaced as denials instead of one
  shadowing the other.
- All conditions inside one rule are ANDed: issuer, audience, and every
  `claims_exact` entry must hold.
- If two workflows need certificates, write two rules, and keep them
  disjoint via their audiences or claims.

## key_id_template expansion

```yaml
key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
```

- `${claim_name}` expands to the named claim's value. Claim names must
  match `[a-z0-9_]+`. A `$` that does not start a well-formed `${...}` is
  a validation error.
- Expansion happens after the rule matched, with verified claims only.
- A referenced claim that is missing from the token, or whose value is
  not a string, **denies the request** (`key_id_invalid`).
- Expanded values must match `[A-Za-z0-9._/:@-]`. Anything else —
  whitespace, quotes, control characters — denies. Values are never
  silently rewritten: an audit value that cannot be logged faithfully is
  not logged at all.
- The expanded key ID is limited to 256 bytes.

## Validating and debugging

`check-config` validates a policy file and warns about templates
referencing claims the rule does not pin and about overly broad rules:

```bash
oidc-ssh-ca check-config policy.yaml
```

`explain` evaluates a claim set (a decoded JWT payload as JSON) against
the policy and reports which rule matched — or, for each rule, the first
condition that failed — plus the expanded key ID:

```bash
oidc-ssh-ca explain --policy policy.yaml --claims claims.json
```

Neither command needs the CA key, so both run anywhere — including CI, to
lint policy changes before deploying them.

## Complete example

A fully commented policy is in
[`examples/policy/github-oidc.yaml`](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/examples/policy/github-oidc.yaml).
