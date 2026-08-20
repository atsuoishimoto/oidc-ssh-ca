# Multi-stage build producing a minimal distroless image (spec 19.2).
#
# The image contains only the binary. The CA private key and policy.yaml
# are never baked in — mount them or pass them as secrets at runtime.

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION is optional; the release workflow passes the release tag so the
# version is baked into the binary (matching the released binaries).
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /oidc-ssh-ca ./cmd/oidc-ssh-ca

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /oidc-ssh-ca /oidc-ssh-ca
ENTRYPOINT ["/oidc-ssh-ca"]
CMD ["serve", "--config", "/etc/oidc-ssh-ca/policy.yaml"]
