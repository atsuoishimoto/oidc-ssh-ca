# Operations

## Audit log

Every decision emits one JSON line on stdout (`log/slog`):

- `certificate_issued` — the matched rule, principals, key ID, TTL, the
  client key fingerprint, and well-known identity claims (`repository`,
  `ref`, `run_id`, ...).
- `certificate_denied` — a stable machine-readable `reason` code plus a
  human-readable detail, with the same identity attributes when the token
  was verified.

Both carry the `request_id` returned to the caller, so a support request
("my deploy was denied, request_id …") maps to exactly one audit event.
The key ID embeds the repository / run ID, so an sshd log entry on a
target server can be traced back to the exact GitHub Actions run.

Deny reason codes:

| Reason | Meaning |
|---|---|
| `bad_request` | malformed body, body too large, or wrong method |
| `invalid_public_key` | key unparsable, wrong type, or a certificate |
| `missing_token` | no usable `Authorization: Bearer` header |
| `token_invalid` | JWT verification failed (signature, issuer, expiry, ...) |
| `no_rule_matched` | deny by default: nothing matched |
| `multiple_rules_matched` | exactly-one-match violated; the detail lists the rules |
| `key_id_invalid` | key ID expansion failed (missing claim, bad characters, too long) |
| `policy_disabled` | emergency stop is active |
| `signing_error` | internal signing failure |

Where the log ends up: journald (systemd), `docker compose logs`
(Compose), CloudWatch Logs (Lambda), Cloud Logging (Cloud Run).

## Policy reload

`SIGHUP` reloads the policy file. If the new file is invalid, the server
keeps the current policy and logs an error — a broken reload neither stops
nor loosens issuance.

```bash
systemctl reload oidc-ssh-ca                  # systemd
docker compose kill -s HUP oidc-ssh-ca        # docker compose
kill -HUP <pid>                               # anywhere else
```

Lambda and Cloud Run have no reload; deploying a new zip / revision is the
equivalent, with the same fail-safe (a bad policy fails the new instance,
the old one keeps serving).

## Emergency stop

To stop all issuance immediately:

1. Set `disabled: true` at the top of `policy.yaml` and reload. The server
   answers `503` to every request while staying up. (Platform shortcuts:
   reserved concurrency 0 on Lambda; removing the `allUsers` invoker
   binding on Cloud Run.)
2. Wait out `defaults.max_valid_for_seconds` (default 900 s / 15 minutes).
   After that, no valid certificate exists anywhere — there is nothing to
   revoke.
3. Only if the CA key itself may have leaked: remove the CA public key
   from `TrustedUserCAKeys` on the target servers and rotate the key.

## CA key rotation

`TrustedUserCAKeys` may list multiple keys, so rotation is zero-downtime:

1. Generate the new CA key; append its public key to the target servers'
   `TrustedUserCAKeys` file (both keys are now trusted).
2. Swap the key on the CA and restart.
3. After the old certificates' TTL has passed, remove the old public key
   from the servers.
