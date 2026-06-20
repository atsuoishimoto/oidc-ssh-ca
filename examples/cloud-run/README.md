# Google Cloud Run example

Deploy `oidc-ssh-ca` to Cloud Run from the published `ghcr.io` image. The
scripts automate the steps in the
[Cloud Run deployment guide](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/docs/deployment/cloud-run.md).

## Contents

- **`deploy.sh`** — first-time deploy: stores the CA key and policy in Secret
  Manager, creates a least-privilege service account, sets up an Artifact
  Registry remote repository that proxies `ghcr.io` (Cloud Run cannot pull from
  `ghcr.io` directly), and deploys the service.
- **`update-policy.sh`** — ship an updated policy by adding a new secret version
  and rolling a new revision (there is no SIGHUP reload on Cloud Run; revisions
  are the reload mechanism).

## Prerequisites

- The `gcloud` CLI, authenticated, with a project selected
  (`gcloud config set project PROJECT_ID`).
- Two files in the working directory:
  - **`ca_key`** — `ssh-keygen -t ed25519 -N "" -f ca_key`
  - **`policy.yaml`** — validated with `oidc-ssh-ca check-config policy.yaml`

## Usage

```sh
./deploy.sh                 # first deploy; prints the service URL
./update-policy.sh          # after editing policy.yaml
```

Override defaults via environment variables, e.g.:

```sh
SERVICE=oidc-ssh-ca REGION=asia-northeast1 IMAGE_TAG=0.1.0 ./deploy.sh
```

Available overrides: `SERVICE`, `REGION`, `KEY_SECRET`, `POLICY_SECRET`,
`SERVICE_ACCOUNT`, `GHCR_REPO`, `IMAGE_TAG`, `PROJECT_ID`. Pin `IMAGE_TAG` to a
release tag in production.

## Notes

- The service is deployed `--allow-unauthenticated` on purpose: `/sign`
  authenticates callers by verifying their OIDC token, not by network position.
  `--max-instances 1` bounds the cost of unauthenticated traffic.
- The CA key is injected as the `OIDC_SSH_CA_KEY` environment variable; the
  policy is mounted as a file. The service account can read only its own two
  secrets.
- An invalid policy makes the new revision fail to start, and Cloud Run keeps
  routing to the previous revision — the same fail-safe behavior as the
  standalone server.

The service URL printed by `deploy.sh` is the `OIDC_SSH_CA_URL` for the GitHub
Actions workflow (`examples/github-actions/`).
