# AWS Lambda with Terraform

The same three resources as the [CLI deployment](lambda-cli.md) — execution
role, function, Function URL — expressed as a single `main.tf`. Use this if
you already run Terraform; if not, the CLI version has fewer concepts to
learn for an identical result.

```{warning}
The CA private key is passed to the function as an environment variable,
and Terraform records resource attributes in its state: **`terraform.tfstate`
contains the CA private key in plaintext.** Treat the state file exactly
like the key itself. At this scale, local state in a private directory is
fine — there is no need to set up a remote backend just for this — but do
not commit it, and if you do use a remote backend, make sure it is private
and encrypted.
```

## 1. Build the zip

Same as the [CLI deployment](lambda-cli.md#1-build-the-zip) — Terraform deploys
the artifact, it does not build it. The `linux/arm64` binary is pulled from the
prebuilt
[`ghcr.io/atsuoishimoto/oidc-ssh-ca`](https://github.com/atsuoishimoto/oidc-ssh-ca/pkgs/container/oidc-ssh-ca)
image (pin a release tag instead of `latest` in production):

```bash
docker create --platform linux/arm64 --name oidc-ssh-ca-extract \
  ghcr.io/atsuoishimoto/oidc-ssh-ca:latest
docker cp oidc-ssh-ca-extract:/oidc-ssh-ca ./oidc-ssh-ca
docker rm oidc-ssh-ca-extract

cp examples/lambda/run.sh .
zip lambda.zip oidc-ssh-ca run.sh policy.yaml
```

The function runs the ordinary HTTP server behind the AWS-provided
[Lambda Web Adapter](https://github.com/awslabs/aws-lambda-web-adapter) layer
(set as `layers` below), which converts Function URL events into `POST /sign`
requests. `run.sh` (the handler) is at `examples/lambda/run.sh`.

## 2. main.tf

Place `lambda.zip` and the `ca_key` file next to this configuration:

```hcl
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-1"
}

resource "aws_iam_role" "lambda" {
  name = "oidc-ssh-ca-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# CloudWatch Logs is the only permission the function needs.
resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "ca" {
  function_name = "oidc-ssh-ca"
  role          = aws_iam_role.lambda.arn

  runtime       = "provided.al2023"
  architectures = ["arm64"]
  handler       = "run.sh"

  # AWS Lambda Web Adapter. Pick the ARN for your architecture and region;
  # the version may be newer when you deploy. See
  # https://github.com/awslabs/aws-lambda-web-adapter
  layers = ["arn:aws:lambda:ap-northeast-1:753240598075:layer:LambdaAdapterLayerArm64:28"]

  filename         = "${path.module}/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda.zip")

  timeout     = 10
  memory_size = 128

  # Cap the function at a single instance.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      # Lambda environment variables are encrypted at rest.
      OIDC_SSH_CA_KEY = file("${path.module}/ca_key")
      # Start the binary through the Lambda Web Adapter.
      AWS_LAMBDA_EXEC_WRAPPER = "/opt/bootstrap"
    }
  }
}

# Public invocation is intentional: /sign authenticates callers by
# verifying their OIDC token, the same model as running the server
# on a public host.
resource "aws_lambda_function_url" "ca" {
  function_name      = aws_lambda_function.ca.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "public_url" {
  statement_id           = "allow-public-function-url"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.ca.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

output "function_url" {
  description = "OIDC_SSH_CA_URL for the GitHub Actions workflow"
  value       = aws_lambda_function_url.ca.function_url
}
```

## 3. Apply

```bash
terraform init
terraform apply
```

The `function_url` output is the `OIDC_SSH_CA_URL` for the GitHub Actions
workflow.

## Operations

**Update the binary or the policy** — rebuild the zip and apply;
`source_code_hash` makes Terraform pick up the change:

```bash
zip lambda.zip oidc-ssh-ca run.sh policy.yaml
terraform apply
```

**Emergency stop** — for speed, bypass Terraform and use the CLI directly,
then reconcile:

```bash
aws lambda put-function-concurrency \
  --function-name oidc-ssh-ca \
  --reserved-concurrent-executions 0
```

Afterwards set `reserved_concurrent_executions = 0` in the
`aws_lambda_function` resource so the next `terraform apply` does not silently
re-enable issuance.

**Tear down**:

```bash
terraform destroy
```

**Audit logs** go to CloudWatch Logs (`/aws/lambda/oidc-ssh-ca`), the same
as the CLI deployment.
