# P1-13: Security hardening and release v0.1.0

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | M |
| **Depends on** | All feature plans (P1-01 to P1-12) |
| **Unblocks** | P1-14 |
| **Requirements** | NFR-07, NFR-11, NFR-12, NFR-13, NFR-21 |
| **Decisions** | All |

## Goal

The first release, v0.1.0, is secure enough to govern real agents in a pilot: every high-rated threat mitigated or knowingly accepted, the ASVS level 2 baseline met, scale targets verified under load, and every artifact signed with its SBOM and provenance.

## Scope

**In:** threat model refresh, the ASVS checklist, security testing, hardening review, key management review, load and soak tests, supply-chain verification, external review, the release itself.

**Out:** new features. Findings are fixed in the plan that owns the code; this plan tracks them.

## Deliverables

- Threat model v0.2 (`docs/security/threat-model.md`).
- The completed ASVS 5.0 level 2 checklist, with evidence.
- Security test, load test and soak test reports.
- Release v0.1.0: images, binaries, chart, offline bundle and adapter wheel, all signed.

## Steps

### 1. Threat model refresh

Compare the implementation with threat model v0.1: new trust boundaries, mitigations actually built, residual risks. Publish v0.2.

**Done when:** reviewed by the security reviewer.

### 2. ASVS 5.0 level 2

Walk the checklist for the console and the API, fix gaps in the owning plans, and record the evidence per requirement.

**Done when:** every applicable requirement has evidence or an accepted exception.

### 3. Security testing

- The full security test catalog of P0-04.
- Dynamic scans in CI against the Compose stack: OWASP ZAP baseline, plus an API scan driven by the OpenAPI document.
- The complete permission matrix tests.
- Longer fuzzing campaigns on the assertion, CloudEvents, manifest and bundle parsers.
- `govulncheck`, OSV-Scanner and an image scan (Trivy or Grype).
- A secret scan of the full history.

**Done when:** there is no open critical or high finding.

### 4. Hardening review

Review, and fix in the owning plans:

- security headers and CSP, rate limits, request size limits, TLS configuration, cookie flags;
- error messages that leak nothing, and logs without secrets;
- database privileges of the runtime role, and the container and Kubernetes security context;
- secure defaults: development-only switches cannot be enabled in the production image.

**Done when:** the review checklist is complete.

### 5. Key management review

Rehearse the generation, storage and rotation of the three keys, and write the compromise procedures:

- **token key:** rotate, and outstanding tokens expire within minutes;
- **bundle key:** rotate, rebuild every bundle, and roll the new trust root out to enforcement points through the overlap period;
- **checkpoint key:** rotate; old checkpoints stay verifiable with the old public key.

**Done when:** each rotation was rehearsed in the Kubernetes test environment.

### 6. Scale and soak

- **Load test** of the full stack at MVP scale for one hour: 1,000 agents, 500 enforcement points, 200 audit events per second, 50 console users (NFR-07, NFR-11).
- **Soak test** for 24 hours, watching memory and sealing lag.

**Done when:** the reports are published and the targets are met.

### 7. Supply chain (NFR-13)

- Verify that the release pipeline produces SBOMs, signatures and provenance, with SLSA Build Level 3 as the target (GitHub's reusable workflows).
- Check dependency licenses (ADR-0008).
- Reach an OpenSSF Scorecard of 7 or more, and apply for the OpenSSF Best Practices "passing" badge.

**Done when:** a third party can verify every artifact with the documented commands.

### 8. External review

Ask for a review or penetration test of the core by the community, the pilot organization or a volunteer. Fix what it finds, or record the accepted risks.

**Done when:** the review is done, or its absence is recorded as a known limitation of v0.1.0.

### 9. Release v0.1.0

The release checklist:

- documentation complete, changelog, known limitations;
- a dry run of the private vulnerability reporting process;
- tag, then publish images, binaries, chart, offline bundle and adapter wheel;
- announcement.

**Done when:** v0.1.0 is published, and its artifacts verify.

## Acceptance criteria

- No open critical or high finding from any source.
- The ASVS level 2 checklist is complete with evidence.
- The load and soak results meet NFR-07 and NFR-11.
- Every v0.1.0 artifact is signed and verifiable, with SBOMs and provenance.
- Threat model v0.2 is published.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| No external reviewer available | Record it as a known limitation, and schedule a review for v0.2 |
| Hardening findings arrive late and delay the pilot | Run the dynamic scans and the permission tests continuously from P1-03 onward, not only here |

## Notes for implementers

- Most of this plan should confirm work already done. If it discovers a lot, the definition of done was not applied in earlier plans.
- Track findings as issues labeled `security`, linked to the owning plan.
