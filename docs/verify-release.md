# Verifying a release

Every White Tower release is built by the release workflow on GitHub Actions, which signs it with Sigstore keyless signing (cosign), publishes SBOMs, and attests its build provenance. Verify an artifact before you deploy it, especially in air-gapped environments where it will be trusted for a long time.

The examples use version `v0.1.0`; replace it with the version you downloaded.

## 1. Checksums and their signature

Download the archives, `checksums.txt` and `checksums.txt.sigstore.json` from the release page. Then:

```sh
# The signature proves that checksums.txt was produced by the project's release workflow.
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/J466Y/WhiteTower/\.github/workflows/release\.yml@refs/tags/v'

# The checksums prove that your downloads are the files that were signed.
sha256sum --ignore-missing --check checksums.txt
```

The Sigstore bundle contains the proof of inclusion in the public transparency log. On a machine without Internet access, add `--offline` and point cosign to a Sigstore trusted root file copied from a connected machine (`--trusted-root`).

## 2. Container images

```sh
cosign verify ghcr.io/j466y/whitetower:0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/J466Y/WhiteTower/\.github/workflows/release\.yml@refs/tags/v'
```

To install air-gapped, copy the verified image into your private registry by digest, never by tag.

## 3. Build provenance

The release workflow attests how every archive was built (SLSA provenance). With the GitHub CLI:

```sh
gh attestation verify whitetower_0.1.0_linux_amd64.tar.gz --repo J466Y/WhiteTower
```

## 4. SBOMs

Each archive has an SPDX (`.spdx.json`) and a CycloneDX (`.cdx.json`) SBOM, both covered by `checksums.txt`. Feed them to your vulnerability scanner, for example `grype sbom:whitetower_0.1.0_linux_amd64.tar.gz.spdx.json`.
