# Google Cloud Run

The recommended deployment for most users. Cloud Run provides a public HTTPS
endpoint, scales to zero between CI runs (typically staying within the free
tier), and stores the CA key in Secret Manager. There are no state files or
load balancers to manage.

The container image is built from the repository
[`Dockerfile`](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/Dockerfile)
and contains only the binary. The policy and the CA key are both delivered
through Secret Manager: the key as an environment variable, the policy as a
mounted file.

The steps below are also packaged as runnable scripts in
[`examples/cloud-run/`](https://github.com/atsuoishimoto/oidc-ssh-ca/tree/main/examples/cloud-run)
(`deploy.sh`, `update-policy.sh`). They follow this same flow — read them once,
then prefer them so a deploy is a single command. Run them from the repository
root with `ca_key` and `policy.yaml` in the working directory.

## 1. Create the CA key and policy

```bash
ssh-keygen -t ed25519 -N "" -f ca_key -C "oidc-ssh-ca"
```

Write your `policy.yaml` (see the [policy reference](../policy.md)) and
validate it:

```bash
oidc-ssh-ca check-config policy.yaml
```

## 2. Store both in Secret Manager

The policy is not confidential, but Secret Manager is the simplest way to
deliver a runtime file to Cloud Run, and it gives policy changes a versioned
history for free.

```bash
gcloud secrets create oidc-ssh-ca-key --data-file=ca_key
gcloud secrets create oidc-ssh-ca-policy --data-file=policy.yaml
```

Create a dedicated service account so the CA runs with no permissions beyond
reading its own two secrets:

```bash
gcloud iam service-accounts create oidc-ssh-ca

PROJECT_ID=$(gcloud config get-value project)
for s in oidc-ssh-ca-key oidc-ssh-ca-policy; do
  gcloud secrets add-iam-policy-binding "$s" \
    --member="serviceAccount:oidc-ssh-ca@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role=roles/secretmanager.secretAccessor
done
```

## 3. Deploy

From the repository root (Cloud Build uses the `Dockerfile` automatically):

```bash
gcloud run deploy oidc-ssh-ca \
  --source . \
  --region asia-northeast1 \
  --service-account "oidc-ssh-ca@${PROJECT_ID}.iam.gserviceaccount.com" \
  --allow-unauthenticated \
  --set-secrets "OIDC_SSH_CA_KEY=oidc-ssh-ca-key:latest,/etc/oidc-ssh-ca/policy.yaml=oidc-ssh-ca-policy:latest" \
  --max-instances 1
```

Or run the bundled script, which performs everything above (secrets, service
account, IAM, deploy) and is safe to re-run:

```bash
./examples/cloud-run/deploy.sh   # SERVICE / REGION overridable via env vars
```

Notes:

- `--allow-unauthenticated` is intentional: `/sign` authenticates callers by
  verifying their OIDC token, the same model as running the server on any
  public host. `--max-instances 1` bounds the cost of unauthenticated
  traffic — a single instance serves up to 80 concurrent requests by default,
  far more than this workload needs.
- The server listens on `:8080` by default, which matches Cloud Run's default
  container port.
- The command prints the service URL — that is the `OIDC_SSH_CA_URL` for the
  GitHub Actions workflow.

Check the startup log (the CA logs its public key fingerprint, the policy
path, and the rule count — never key material):

```bash
gcloud run services logs read oidc-ssh-ca --region asia-northeast1 --limit 20
```

## Updating the policy

Add a new secret version, then roll a new revision (secret versions are
resolved when a revision starts, so a deploy is required either way):

```bash
gcloud secrets versions add oidc-ssh-ca-policy --data-file=policy.yaml
gcloud run deploy oidc-ssh-ca --source . --region asia-northeast1
```

Or use the bundled script (it also runs `check-config` first if the binary is
on `PATH`):

```bash
./examples/cloud-run/update-policy.sh
```

There is no `SIGHUP` reload on Cloud Run; revisions are the reload mechanism.
An invalid policy fails the new revision's startup and Cloud Run keeps
routing to the previous revision — the same fail-safe behavior as the
standalone server, enforced by the platform.

## Emergency stop

The fastest stop is removing public access (immediate, no rebuild):

```bash
gcloud run services remove-iam-policy-binding oidc-ssh-ca \
  --region asia-northeast1 \
  --member=allUsers --role=roles/run.invoker
```

Then follow the standard procedure: wait out `max_valid_for_seconds`, and
rotate the CA key only if the key itself may have leaked. To stop issuance
but keep the endpoint answering (HTTP 503), set `disabled: true` in the
policy and deploy a new revision.
