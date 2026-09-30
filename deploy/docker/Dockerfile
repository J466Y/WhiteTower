# syntax=docker/dockerfile:1
# Builds the core from source, with the console embedded. Used by the Docker
# Compose setups and the end-to-end tests. Releases use goreleaser.Dockerfile.

FROM node:22-alpine AS console
WORKDIR /src/web
RUN npm install --global pnpm@12.6.0
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM golang:1.27-alpine AS core
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=console /src/internal/webui/dist ./internal/webui/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -tags embedui -trimpath \
      -ldflags "-s -w -X github.com/J466Y/WhiteTower/internal/version.version=${VERSION}" \
      -o /out/whitetower ./cmd/whitetower

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=core /out/whitetower /usr/local/bin/whitetower
USER nonroot:nonroot
# The three listeners on every interface; certificates come from the
# configuration (docs/reference/configuration.md).
ENV WT_LISTENERS_CONSOLE_ADDRESS=:8443 \
    WT_LISTENERS_MACHINE_ADDRESS=:9443 \
    WT_LISTENERS_OPERATIONS_ADDRESS=:9090
EXPOSE 8443 9443 9090
ENTRYPOINT ["/usr/local/bin/whitetower"]
CMD ["serve"]
