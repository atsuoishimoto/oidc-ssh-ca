# AWS Lambda with the AWS CLI

For AWS users who want the smallest possible footprint: three resources
(an IAM role, a function, a Function URL), created with plain `aws` commands.
There is no state file, no S3 staging bucket (zips under 50 MB upload
directly), and nothing to host while idle.

There is no Lambda-specific code in the binary: on Lambda it runs the same
ordinary HTTP server as everywhere else, behind the AWS-provided
[Lambda Web Adapter](https://github.com/awslabs/aws-lambda-web-adapter) (LWA)
layer, which converts each Function URL event into a `POST /sign` request. No
container image is needed. The request and response format is identical to the
standalone server, so the GitHub Actions workflow is unchanged.

If you prefer declarative infrastructure, the same setup is available as
[Terraform](lambda-terraform.md).

## 1. Build the zip

The zip contains the binary, the `run.sh` startup script (the LWA handler), and
the policy. The policy is loaded once at cold start from `policy.yaml` in the
zip. `run.sh` is in the repository at `examples/lambda/run.sh`.

The `linux/arm64` binary comes from the prebuilt
[`ghcr.io/atsuoishimoto/oidc-ssh-ca`](https://github.com/atsuoishimoto/oidc-ssh-ca/pkgs/container/oidc-ssh-ca)
image — no Go toolchain or cross-compilation needed (pin a release tag instead
of `latest` in production). `docker cp` pulls the binary straight out of the
image; the container is never started:

```bash
docker create --platform linux/arm64 --name oidc-ssh-ca-extract \
  ghcr.io/atsuoishimoto/oidc-ssh-ca:latest
docker cp oidc-ssh-ca-extract:/oidc-ssh-ca ./oidc-ssh-ca
docker rm oidc-ssh-ca-extract

cp examples/lambda/run.sh .
zip lambda.zip oidc-ssh-ca run.sh policy.yaml
```

`run.sh` must keep its executable bit inside the zip (creating the zip on
Windows is a known way to lose it).

If you have a Go toolchain and prefer to build from source instead, see
[Building](../building.md#cross-compile) for the cross-compile command.

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

The function uses the LWA layer: its handler is `run.sh`, and
`AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap` tells the runtime to start through the
adapter. Pick the layer ARN for your architecture and region from the
[LWA releases](https://github.com/awslabs/aws-lambda-web-adapter#lambda-functions-powered-by-aws-lambda-web-adapter)
(`LambdaAdapterLayerArm64` for `arm64`); the version below may be newer by the
time you deploy.

The CA key goes into the `OIDC_SSH_CA_KEY` environment variable (Lambda
environment variables are encrypted at rest). The key is multi-line, so
build the `--environment` JSON with `jq` instead of inlining it. If the role
was created seconds ago, IAM propagation may make this fail once — retry.

```bash
LWA_LAYER="arn:aws:lambda:${AWS_REGION}:753240598075:layer:LambdaAdapterLayerArm64:28"

aws lambda create-function \
  --function-name oidc-ssh-ca \
  --runtime provided.al2023 \
  --architectures arm64 \
  --handler run.sh \
  --layers "$LWA_LAYER" \
  --role "$(aws iam get-role --role-name oidc-ssh-ca-lambda --query Role.Arn --output text)" \
  --zip-file fileb://lambda.zip \
  --timeout 10 \
  --memory-size 128 \
  --environment "$(jq -n --rawfile key ca_key \
    '{Variables: {OIDC_SSH_CA_KEY: $key, AWS_LAMBDA_EXEC_WRAPPER: "/opt/bootstrap"}}')"

# Cap the function at a single instance.
aws lambda put-function-concurrency \
  --function-name oidc-ssh-ca \
  --reserved-concurrent-executions 1
```

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
zip lambda.zip oidc-ssh-ca run.sh policy.yaml
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
