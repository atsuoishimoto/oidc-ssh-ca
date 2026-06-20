#!/bin/sh
# Update the issuance policy on Cloud Run.
#
# Secret versions are resolved when a revision starts, so a new policy needs a
# new secret version plus a new revision. This adds the version and rolls a
# revision from the same image. If the new policy is invalid the revision fails
# to start and Cloud Run keeps routing to the previous revision — the same
# fail-safe behavior as the standalone server, enforced by the platform.
#
# There is no SIGHUP reload on Cloud Run; revisions are the reload mechanism.
#
# Run with the updated policy.yaml in the working directory. Override
# SERVICE / REGION / POLICY_SECRET / IMAGE_TAG as for deploy.sh.
set -eu

SERVICE="${SERVICE:-oidc-ssh-ca}"
REGION="${REGION:-asia-northeast1}"
POLICY_SECRET="${POLICY_SECRET:-oidc-ssh-ca-policy}"
GHCR_REPO="${GHCR_REPO:-ghcr}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
if [ -z "$PROJECT_ID" ]; then
  echo "error: no project set (gcloud config set project PROJECT_ID)" >&2
  exit 1
fi
if [ ! -f policy.yaml ]; then
  echo "error: policy.yaml not found in the current directory" >&2
  exit 1
fi

IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${GHCR_REPO}/atsuoishimoto/oidc-ssh-ca:${IMAGE_TAG}"

# Validate locally before shipping, if the binary is on PATH.
if command -v oidc-ssh-ca >/dev/null 2>&1; then
  oidc-ssh-ca check-config policy.yaml
fi

gcloud secrets versions add "$POLICY_SECRET" --data-file=policy.yaml
gcloud run deploy "$SERVICE" --image "$IMAGE" --region "$REGION"
