# P1-13: Security hardening and release v0.1.0

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | M |
| **Depends on** | All feature plans (P1-01 to P1-12, P1-15 and P1-16) |
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
- Release v0.1.0: images (core, mock module, demo agent and network quarantine module), binaries, Helm charts, offline bundle and enforcement point wheel, all signed.

## Steps

### 1. Threat model refresh

Compare the implementation with the latest threat model, v0.1.6 today: new trust boundaries, mitigations actually built, residual risks. Publish v0.2.

Since version 0.1.1, the threat model includes RFC-0002: tooling reports and blocks across TB-2, what agents report shown to people across TB-1, the agent's MCP servers and model providers across the new TB-10 (flows F16 and F17), actor TA-11, assumption A-7, threats T-74 to T-82, attack tree AT-10, DC-9, DC-10 and R-15.

Version 0.1.3 adds threat T-83 and design change DC-11 (plan P1-17).

**Done when:** reviewed by the security reviewer.

### 2. ASVS 5.0 level 2

Walk the checklist for the console and the API, fix gaps in the owning plans, and record the evidence per requirement.

**Done when:** every applicable requirement has evidence or an accepted exception.

### 3. Security testing

- The full [security test catalog](../../security/security-tests.md) of P0-04, with RFC-0002's ST-75 to ST-83 and P1-17's ST-84 and ST-85.
- Dynamic scans in CI against the Compose stack: OWASP ZAP baseline, plus an API scan driven by the OpenAPI document.
- The complete permission matrix tests.
- Longer fuzzing campaigns on the assertion, CloudEvents, manifest and bundle parsers, and on what RFC-0002 parses: tooling reports and definitions (validation, the hashes the core recomputes, and the core's redaction, CAT-10), the bundle's catalog file, the usage-rule compiler and its check at submission, and the argument transforms (T-78).
- `govulncheck`, OSV-Scanner and an image scan (Trivy or Grype).
- A secret scan of the full history.

**Done when:** there is no open critical or high finding.

### 4. Hardening review

Review, and fix in the owning plans:

- security headers and CSP, rate limits, request size limits, TLS configuration, cookie flags;
- the limits of tooling reports and definitions (counts and sizes, at most one report per instance and agent every 10 seconds, and DC-10's bound on an agent's entries waiting for review) and of blocks (at most 500 active);
- error messages that leak nothing, and logs without secrets, including those a tooling report could carry (CAT-10);
- the core never fetches a reported URL, and the console never turns one into a link;
- database privileges of the runtime role, and the container and Kubernetes security context;
- secure defaults: development-only switches cannot be enabled in the production image.

**Done when:** the review checklist is complete.

### 5. Key management review

Rehearse the generation, storage and rotation of the three keys, and write the compromise procedures:

- **token key:** rotate, and outstanding tokens expire within minutes;
- **bundle key:** keep a next key configured on every enforcement point in advance; to rotate, sign with it, rebuild every bundle, then remove the old key from every configuration, with no overlap, since for a compromised key an overlap keeps the thief's key trusted (contracts, sections 7.3 and 12);
- **checkpoint key:** rotate; old checkpoints stay verifiable with the old public key.

**Done when:** each rotation was rehearsed in the Kubernetes test environment.

### 6. Scale and soak

- **Load test** of the full stack at MVP scale for one hour: 1,000 agents, 500 enforcement points, 200 audit events per second, 50 console users (NFR-07, NFR-11). Every agent's tooling is reported and enabled, the mock enforcement points of P1-07 repeat their reports at the rate limit, and 500 blocks are active. During the hour, the approval of a new definition of a tool that every agent uses rebuilds every bundle, while a fleet halt still meets NFR-03 (T-80).
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

- documentation complete, changelog, known limitations, including those of RFC-0002:
  - usage rules judge arguments as written, so symbolic links, defaults that servers apply and forms that no transform normalizes escape them (R-15), and they hold no state until Phase 2;
  - what model providers do with the tools they run (T-79, A-7);
  - secrets passed to local MCP servers as positional arguments, which redaction cannot recognize (T-76);
  - the declared tooling of agents at C0 and C1, which nothing enforces;
- a dry run of the private vulnerability reporting process;
- tag, then publish images, binaries, Helm charts, offline bundle and enforcement point wheel;
- announcement.

**Done when:** v0.1.0 is published, and its artifacts verify.

## Acceptance criteria

- No open critical or high finding from any source.
- The ASVS level 2 checklist is complete with evidence.
- The load and soak results meet NFR-07 and NFR-11, with the catalog workload of step 6.
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
