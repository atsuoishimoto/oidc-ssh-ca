## Design guarantees

- **No subprocesses, no temporary files, no external SSH tools.** All key
  parsing and certificate signing happens in memory via
  `golang.org/x/crypto/ssh`. The CA private key is never written to disk.
- **The policy decides everything.** Principals, TTL, extensions, and the
  certificate key ID are derived from verified JWT claims and `policy.yaml`.
  The request body carries only the public key — a caller cannot request a
  principal or a longer TTL.
- **Deny by default, exactly one match.** A request is allowed only if
  exactly one enabled rule matches. Zero matches deny; multiple matches deny
  (no first-match-wins surprises). A claim referenced by a rule but absent
  from the token denies.
- **Fail safe.** An invalid policy prevents startup; a failed reload keeps
  the previous policy; a JWKS outage without cached keys denies.
- **Generic errors.** Callers get a fixed message and a request ID. Denial
  reasons and details go only to the server's audit log, so the policy
  cannot be probed by varying claims.