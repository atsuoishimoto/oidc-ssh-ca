#!/bin/sh
# Deploy oidc-ssh-ca to Google Cloud Run.
#
# This automates the steps in docs/deployment/cloud-run.md: it stores the CA
# key and policy in Secret Manager, creates a least-privilege service account,
# and deploys the service. The container image is built from the repository
# Dockerfile by Cloud Build (`--source`), so run this from the repository root.
#
# Expects two files in the working directory:
#   ca_key       the CA private key (ssh-keygen -t ed25519 -N "" -f ca_key)
#   policy.yaml  your issuance policy (validate first: check-config policy.yaml)
#
# Override any of these before running:
#   SERVICE=oidc-ssh-ca REGION=asia-northeast1 ./examples/cloud-run/deploy.sh
set -eu

SERVICE="${SERVICE:-oidc-ssh-ca}"
REGION="${REGION:-asia-northeast1}"
KEY_SECRET="${KEY_SECRET:-oidc-ssh-ca-key}"
POLICY_SECRET="${POLICY_SECRET:-oidc-ssh-ca-policy}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-oidc-ssh-ca}"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
if [ -z "$PROJECT_ID" ]; then
  echo "error: no project set (gcloud config set project PROJECT_ID)" >&2
  exit 1
fi
for f in ca_key policy.yaml; do
  if [ ! -f "$f" ]; then
    echo "error: $f not found in the current directory" >&2
    exit 1
  fi
done

SA_EMAIL="${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com"

# 1. Store the CA key and policy in Secret Manager. Both commands create the
#    secret on first run and add a new version on later runs, so this script is
#    safe to re-run to ship an updated key or policy.
echo "Storing secrets..."
create_or_update_secret() {
  secret="$1"; file="$2"
  if gcloud secrets describe "$secret" >/dev/null 2>&1; then
    gcloud secrets versions add "$secret" --data-file="$file"
  else
    gcloud secrets create "$secret" --data-file="$file"
  fi
}
create_or_update_secret "$KEY_SECRET" ca_key
create_or_update_secret "$POLICY_SECRET" policy.yaml

# 2. Create a dedicated service account that can read only its own two secrets.
echo "Configuring service account ${SA_EMAIL}..."
if ! gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$SERVICE_ACCOUNT" \
    --display-name="oidc-ssh-ca"
fi
for s in "$KEY_SECRET" "$POLICY_SECRET"; do
  gcloud secrets add-iam-policy-binding "$s" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role=roles/secretmanager.secretAccessor >/dev/null
done

# 3. Deploy. The CA key arrives as the OIDC_SSH_CA_KEY environment variable;
#    the policy is mounted as a file the binary reads with --config (the image
#    default). --allow-unauthenticated is intentional: /sign authenticates
#    callers by verifying their OIDC token, not by network position.
#    --max-instances 1 bounds the cost of unauthenticated traffic.
echo "Deploying ${SERVICE} to ${REGION}..."
gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --service-account "$SA_EMAIL" \
  --allow-unauthenticated \
  --set-secrets "OIDC_SSH_CA_KEY=${KEY_SECRET}:latest,/etc/oidc-ssh-ca/policy.yaml=${POLICY_SECRET}:latest" \
  --max-instances 1

echo
echo "Done. The service URL printed above is the OIDC_SSH_CA_URL for the"
echo "GitHub Actions workflow. Check the startup log with:"
echo "  gcloud run services logs read ${SERVICE} --region ${REGION} --limit 20"
