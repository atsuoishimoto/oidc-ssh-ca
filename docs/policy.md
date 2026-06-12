# Policy reference

`policy.yaml` is the single source of authorization decisions. Principals,
TTL, extensions, and the certificate key ID are derived from verified JWT
claims and this file — the request body carries only a public key, so a
caller can never ask for a principal or a longer TTL.

Parsing is strict: unknown fields, type mismatches, missing required
fields, and multiple YAML documents in one file are all errors. An invalid
policy prevents startup; an invalid policy on reload keeps the previous
policy running.

## Top level

```yaml
version: 1        # required; must be 1
disabled: false   # optional; true denies every request with HTTP 503
defaults: { }     # optional; see below
rules: [ ]        # required; at least one rule
```

`disabled: true` is the emergency stop: flip it and reload, and the server
answers `503` to everything while staying up (see
[Operations](operations.md)).

## defaults

Policy-wide settings applied to every rule.

```yaml
defaults:
  valid_after_offset_seconds: -30    # default -30
  max_valid_for_seconds: 900         # default 900; must be positive
  allowed_public_key_types:          # default ["ssh-ed25519"]
    - "ssh-ed25519"
  extensions:                        # default: all false
    permit_pty: false
    permit_port_forwarding: false
    permit_agent_forwarding: false
    permit_x11_forwarding: false
    permit_user_rc: false
```

- `valid_after_offset_seconds` — backdates the certificate's `valid after`
  to tolerate clock skew between the CA and target servers.
- `max_valid_for_seconds` — a ceiling: a rule whose `valid_for_seconds`
  exceeds it is a validation error. It also bounds the emergency-stop
  window — after a stop, every outstanding certificate is dead within this
  many seconds.
- `allowed_public_key_types` — only `ssh-ed25519` is supported in this
  version; certificate keys are rejected.
- `extensions` — OpenSSH certificate extensions. Everything defaults to
  **off**: a certificate grants nothing beyond authentication unless the
  policy enables it. A rule can override the whole block (see below).

## rules

```yaml
rules:
  - name: "prod-deploy"        # required; [A-Za-z0-9._-]+, unique
    enabled: true              # optional; default true
    match:
      jwt:                     # required
        issuer: "https://token.actions.githubusercontent.com"   # required
        audience: "ssh-ca-prod"                                 # required
        claims_exact:          # optional; string equality per claim
          repository: "your-org/your-repo"
          ref: "refs/heads/main"
    certificate:
      principals:              # required; non-empty
        - "gha-prod-deploy"
      valid_for_seconds: 600   # required; > 0 and <= max_valid_for_seconds
      key_id_template: "gha:${repository}:${run_id}"   # required
      extensions:              # optional; replaces defaults.extensions
        permit_pty: true
```

`enabled: false` keeps a rule in the file but takes it out of matching —
useful for staging a rule before turning it on, or disabling one without
deleting it.

### Matching semantics

- **Deny by default.** A request is allowed only if a rule matches.
- **Exactly one match.** Zero matching rules deny; two or more matching
  rules also deny (`multiple_rules_matched`) — there is no
  first-match-wins, so rule order can never silently change what a rule
  means.
- All conditions inside one rule are ANDed: issuer, audience, and every
  `claims_exact` entry must hold.
- A claim listed in `claims_exact` but **absent from the token denies** —
  absence never matches anything.
- Comparison is exact string equality. There are no globs or regexes; if
  two workflows need certificates, write two rules (with audiences or
  claims that keep them disjoint).

Which claims are available depends on the issuer. For GitHub Actions, the
useful ones include `repository`, `ref`, `environment`, `event_name`,
`workflow`, `job_workflow_ref`, `actor`, `run_id`, and `run_attempt`; note
that `environment` is only present when the job declares `environment:`,
and `job_workflow_ref` pins the *called* workflow when reusable workflows
are involved.

### key_id_template

The key ID appears in the certificate, in the CA's audit log, and verbatim
in the target server's sshd log — it is the thread that ties an SSH login
back to the exact CI run that requested it.

```yaml
key_id_template: "gha:${repository}:${run_id}:${run_attempt}"
```

- `${claim_name}` expands to the claim's value; claim names must match
  `[a-z0-9_]+`. A stray `$` that is not part of `${...}` is a parse error.
- Expanded values must match `[A-Za-z0-9._/:@-]` — anything else
  (whitespace, quotes, control characters) **denies the request**. Values
  are never silently rewritten: an audit value that cannot be logged
  faithfully is not logged at all.
- A referenced claim that is missing or not a string denies.
- The expanded key ID is limited to 256 bytes.

## Validating and debugging

`check-config` validates a policy file and warns about templates
referencing unknown claims and overly broad rules:

```bash
oidc-ssh-ca check-config policy.yaml
```

`explain` evaluates a claim set (a decoded JWT payload as JSON) against the
policy and reports which rule matched — or, for each rule, the first
condition that failed — plus the expanded key ID:

```bash
oidc-ssh-ca explain --policy policy.yaml --claims claims.json
```

Neither command needs the CA key, so both run anywhere — including CI, to
lint policy changes before deploying them.

## Complete example

A fully commented policy is in
[`examples/policy/github-oidc.yaml`](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/examples/policy/github-oidc.yaml).
