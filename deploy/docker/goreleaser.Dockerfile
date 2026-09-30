# Release image, built by GoReleaser from the binary it already compiled
# (see .goreleaser.yaml). For builds from source, use deploy/docker/Dockerfile.
FROM gcr.io/distroless/static-debian13:nonroot

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/whitetower /usr/local/bin/whitetower

USER nonroot:nonroot
# The three listeners on every interface; certificates come from the
# configuration (docs/reference/configuration.md).
ENV WT_LISTENERS_CONSOLE_ADDRESS=:8443 \
    WT_LISTENERS_MACHINE_ADDRESS=:9443 \
    WT_LISTENERS_OPERATIONS_ADDRESS=:9090
EXPOSE 8443 9443 9090
ENTRYPOINT ["/usr/local/bin/whitetower"]
CMD ["serve"]
