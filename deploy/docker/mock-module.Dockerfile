# syntax=docker/dockerfile:1
# Hardened multi-architecture image for the mock module.
# Distroless, non-root base without a shell, supporting a read-only root filesystem.

FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/J466Y/WhiteTower/internal/version.version=${VERSION}" \
      -o /out/mock-module ./cmd/whitetower

FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.title="White Tower Mock Module" \
      org.opencontainers.image.description="Mock reference module for White Tower conformance and demo testing" \
      org.opencontainers.image.url="https://github.com/J466Y/WhiteTower" \
      org.opencontainers.image.source="https://github.com/J466Y/WhiteTower" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="White Tower"

COPY --from=builder /out/mock-module /usr/local/bin/mock-module
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mock-module"]
