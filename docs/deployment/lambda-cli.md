# AWS Lambda with the AWS CLI

For AWS users who want the smallest possible footprint: three resources
(an IAM role, a function, a Function URL), created with plain `aws` commands.
There is no state file, no S3 staging bucket (zips under 50 MB upload
directly), and nothing to host while idle.

The binary handles Lambda Function URL events natively — no HTTP server, no
container image, no adapter layer. Deployed as `bootstrap` on
`provided.al2023`, it detects the Lambda runtime and serves events directly;
the request and response format is identical to the standalone server, so
the GitHub Actions workflow is unchanged.

If you prefer declarative infrastructure, the same setup is available as
[Terraform](lambda-terraform.md).

## 1. Build the zip

The zip contains the binary and the policy. The policy is loaded once at
cold start (`OIDC_SSH_CA_CONFIG` overrides the path; the default is
`policy.yaml` in the zip).

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -ldflags="-s -w" -tags lambda.norpc \
  -o bootstrap ./cmd/oidc-ssh-ca
zip lambda.zip bootstrap policy.yaml
```

## 2. Create the execution role

CloudWatch Logs is the only permission the function needs:

```bash
aws iam create-role --role-name oidc-ssh-ca-lambda \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy --role-name oidc-ssh-ca-lambda \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

## 3. Create the function

The CA key goes into the `OIDC_SSH_CA_KEY` environment variable (Lambda
environment variables are encrypted at rest). The key is multi-line, so
build the `--environment` JSON with `jq` instead of inlining it. If the role
was created seconds ago, IAM propagation may make this fail once — retry.

```bash
aws lambda create-function \
  --function-name oidc-ssh-ca \
  --runtime provided.al2023 \
  --architectures arm64 \
  --handler bootstrap \
  --role "$(aws iam get-role --role-name oidc-ssh-ca-lambda --query Role.Arn --output text)" \
  --zip-file fileb://lambda.zip \
  --timeout 10 \
  --memory-size 128 \
  --environment "$(jq -n --rawfile key ca_key '{Variables: {OIDC_SSH_CA_KEY: $key}}')"
```

No reserved concurrency is needed to bound cost: each `/sign` invocation is
tiny (128 MB, milliseconds) and OIDC verification rejects unauthorized callers
fast, so the function scales on the account's default concurrency pool. The
CloudWatch invocation alarm below is enough to notice abuse of the public URL.
(`reserved-concurrent-executions 0` is still the fastest emergency stop — see
[Operations](#operations).)

## 4. Create the Function URL

Public invocation is intentional: `/sign` authenticates callers by verifying
their OIDC token, the same model as running the server on a public host.

```bash
aws lambda create-function-url-config \
  --function-name oidc-ssh-ca \
  --auth-type NONE

aws lambda add-permission \
  --function-name oidc-ssh-ca \
  --statement-id allow-public-function-url \
  --action lambda:InvokeFunctionUrl \
  --principal "*" \
  --function-url-auth-type NONE
```

The first command prints the `FunctionUrl` — that is the `OIDC_SSH_CA_URL`
for the GitHub Actions workflow.

## Operations

**Update the binary or the policy** — rebuild the zip and redeploy (there is
no `SIGHUP` reload in Lambda; the zip is the unit of change):

```bash
zip lambda.zip bootstrap policy.yaml
aws lambda update-function-code --function-name oidc-ssh-ca \
  --zip-file fileb://lambda.zip
```

**Emergency stop** — immediate, no redeploy:

```bash
aws lambda put-function-concurrency \
  --function-name oidc-ssh-ca \
  --reserved-concurrent-executions 0
```

**Audit logs** go to CloudWatch Logs
(`/aws/lambda/oidc-ssh-ca`). Set a CloudWatch alarm on invocation count to
notice unexpected traffic against the public URL.

**Tear down**:

```bash
aws lambda delete-function --function-name oidc-ssh-ca
aws iam detach-role-policy --role-name oidc-ssh-ca-lambda \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam delete-role --role-name oidc-ssh-ca-lambda
```
