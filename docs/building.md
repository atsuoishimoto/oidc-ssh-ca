# Building

`oidc-ssh-ca` is a single static Go binary with no cgo and no runtime
dependencies. Building it needs only the Go toolchain.

## Prerequisites

- Go 1.22 or newer (the module targets `go 1.22.2`).

## Build the binary

From the repository root:

```bash
go build -o oidc-ssh-ca ./cmd/oidc-ssh-ca
```

This produces an `oidc-ssh-ca` binary in the current directory. To install
it onto your `PATH` instead:

```bash
go install github.com/atsuoishimoto/oidc-ssh-ca/cmd/oidc-ssh-ca@latest
```

The binary embeds a version string (printed by `oidc-ssh-ca version`) that
defaults to `dev`. Release builds set it through the linker; to stamp a
local build with, for example, the current git description:

```bash
go build -trimpath \
  -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty)" \
  -o oidc-ssh-ca ./cmd/oidc-ssh-ca
```

`-trimpath` and `-ldflags="-s -w"` are what release and container builds
use to produce a smaller, reproducible binary; they are optional for local
development.

## Cross-compile

Go cross-compiles without a C toolchain because the build uses no cgo. Set
`GOOS`/`GOARCH` for the target:

```bash
GOOS=linux GOARCH=arm64 go build -o oidc-ssh-ca ./cmd/oidc-ssh-ca
```

The same command, with `CGO_ENABLED=0`, produces the `bootstrap` binary for
the AWS Lambda `provided.al2023` runtime — see
[Deploy to AWS Lambda with the CLI](deployment/lambda-cli.md).

## Build the container image

The repository ships a multi-stage `Dockerfile` that compiles the binary
and copies it into a distroless base image. It contains only the binary —
the CA private key and `policy.yaml` are mounted or passed as secrets at
runtime, never baked in:

```bash
docker build -t oidc-ssh-ca .
```

## Verify the build

```bash
go vet ./...
go test ./...
./oidc-ssh-ca version
```

See [Testing](testing.md) for the full test suite, including the
end-to-end tests with a mock OIDC provider.

## Build the documentation

These docs are built with [Sphinx](https://www.sphinx-doc.org/) and
[MyST](https://myst-parser.readthedocs.io/) from the Markdown sources in
`docs/`:

```bash
pip install -r docs/requirements.txt
make -C docs html
```

The rendered site is written to `docs/_build/html/index.html`.
