# Release image, built by GoReleaser from the binary it already compiled
# (see .goreleaser.yaml). For builds from source, use deploy/docker/Dockerfile.
FROM gcr.io/distroless/static-debian13:nonroot

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/whitetower /usr/local/bin/whitetower

USER nonroot:nonroot
ENV WT_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/whitetower"]
