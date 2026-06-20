# AWS Lambda example

Run `oidc-ssh-ca` on AWS Lambda (`provided.al2023`) behind the
[AWS Lambda Web Adapter](https://github.com/awslabs/aws-lambda-web-adapter)
(LWA). There is **no Lambda-specific code** in the binary: it runs the ordinary
`serve` HTTP server, and LWA converts each Function URL event into a
`POST /sign` request.

## Contents

- **`run.sh`** — the function handler. With `AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap`,
  the LWA layer runs this script at start; it launches `serve` listening on the
  port LWA expects (`8080` by default, overridable with `AWS_LWA_PORT`).

## How it fits together

- **Handler:** set the function handler to `run.sh`.
- **Layer:** attach the LWA layer and set
  `AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap`.
- **CA key:** supplied via the `OIDC_SSH_CA_KEY` environment variable.
- **Policy:** shipped inside the zip as `policy.yaml` and loaded at cold start.
  There is no SIGHUP reload on Lambda — redeploy to change the policy.

## Packaging

Build a static binary, then zip it with `run.sh` and `policy.yaml`:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -ldflags="-s -w" \
  -o oidc-ssh-ca ./cmd/oidc-ssh-ca
cp examples/lambda/run.sh .
zip lambda.zip oidc-ssh-ca run.sh policy.yaml
```

`run.sh` must keep its executable bit inside the zip.

Two guides cover the full deployment, including the function URL, layer, and IAM:

- [Lambda via CLI](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/docs/deployment/lambda-cli.md)
- [Lambda via Terraform](https://github.com/atsuoishimoto/oidc-ssh-ca/blob/main/docs/deployment/lambda-terraform.md)
