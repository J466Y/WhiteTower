# Governance

White Tower is an open-source project with maintainer-led governance, an RFC process for changes to the module contracts, and the medium-term goal of being hosted by a software foundation (see the [project charter](Project%20Declaration.pdf)).

## Roles

| Role | Who | Responsibilities |
| --- | --- | --- |
| Contributor | Anyone who opens an issue or a pull request | Follow the [contribution guide](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md) |
| Reviewer | Contributors trusted to review an area (listed in `.github/CODEOWNERS`) | Review pull requests in their area; their approval counts towards merging |
| Maintainer | Listed below | Merge pull requests, decide ADRs and RFCs, run releases, handle security reports, enforce the code of conduct |

### Maintainers

| Maintainer | Areas |
| --- | --- |
| [@J466Y](https://github.com/J466Y) | Everything (founder) |

### Becoming a maintainer

A contributor with a sustained record of good contributions and reviews can be nominated by a maintainer. The nomination is accepted by lazy consensus of the maintainers after one week. Maintainers who are inactive for six months are moved to an emeritus list, and can come back the same way.

## Decision making

- **Everyday changes** are decided in pull requests: one maintainer approval merges a change, once CI is green.
- **Architecture decisions** are recorded as [ADRs](docs/adr/README.md). A maintainer accepts or rejects them after discussion in their pull request.
- **Module contract changes** need an **RFC** (see below).
- **Disagreements** that discussion cannot settle are decided by a simple majority of maintainers. The decision and its reasoning are written down in the pull request, the ADR or the RFC.

## RFC process

Changes to the module contracts (`api/proto`, `api/events`, `api/manifest`) affect every module author, so they follow a stricter path.

1. Copy [the template](docs/rfcs/0000-template.md) to `docs/rfcs/NNNN-short-title.md` and open a pull request labeled `rfc`.
2. Announce it where the community follows the project.
3. **The review period lasts at least two weeks.**
4. **Every RFC has a security section**, and the threat model is updated if the RFC changes a trust boundary.
5. **Acceptance needs two maintainer approvals.** While the project has a single maintainer, it needs that maintainer plus one external reviewer.
6. The accepted RFC is merged, and the contract changes land afterwards in their own pull requests, checked by the breaking-change tools in CI.

## Security

Vulnerability reports are handled by the maintainers following [SECURITY.md](SECURITY.md). The threat model (`docs/security/`) is reviewed at every phase gate, whenever a trust boundary changes, and in the security section of every RFC.

## Repository settings

These settings are part of the project's security posture. Maintainers keep them enabled:

- **Rulesets:** the files in [`.github/rulesets/`](.github/rulesets/README.md) are the source of truth, imported into GitHub (Settings → Rules → Rulesets). They protect `main` (pull requests only; every CI and CodeQL check green; squash merges and linear history; signed commits; no force pushes) and the release tags. Required reviews are 0 while there is a single maintainer, because GitHub does not let authors approve their own pull requests; they become 1 when a second maintainer joins.
- **Code owners:** the review rules of `.github/CODEOWNERS`; contract changes follow the RFC rules above.
- **Secret scanning** with push protection.
- **Private vulnerability reporting.**
- **Dependency graph and security alerts.**
- **Workflow permissions:** read-only by default; GitHub Actions may not approve pull requests.

## Working without shortcuts

Rules only protect the project if nobody works around them, maintainers included.

1. **Every change reaches `main` through a pull request**, including documentation and one-line fixes.
2. **A red check is fixed, never silenced.** Do not add `continue-on-error`, skip or delete tests, lower thresholds (vulnerability severity, lint rules, coverage), make a required check optional, or rename a job to escape it. A `//nolint` or `biome-ignore` needs a comment explaining why, and the reviewer's agreement.
3. **Changes that weaken a control go in their own pull request, with the reason written down.** This covers workflows, rulesets, linter configuration, license and vulnerability policies, and `CODEOWNERS`. Never bundle them with the code they would let through.
4. **Self-review is still review.** While there is a single maintainer, the author walks through the pull request checklist, reads the whole diff on GitHub, and merges only once every check is green.
5. **Secrets stay out, even when blocked.** If push protection stops a push because of a secret, remove the secret and rotate it; never choose to allow it.
6. **Dependency updates follow the same rules.** Renovate pull requests merge only with green checks, and major updates are reviewed like code.
7. **Release tags come only from `main`, after green checks,** and only a repository administrator can create them.
8. **Emergencies are recorded.** If a ruleset must be relaxed, for example because a GitHub outage blocks a critical security fix, the maintainer opens an issue labeled `ruleset-exception` that explains why, relaxes the smallest rule for the shortest time, restores it by re-importing the file from `.github/rulesets/`, and links the ruleset history entry in the issue.
9. **The rulesets in GitHub match the files.** Every change to `.github/rulesets/` is re-imported once merged. At every phase gate, a maintainer exports the live rulesets and compares them with the files.

## Changes to this document

Changes to this document follow the RFC review rules: two weeks of review and two maintainer approvals (or one maintainer and one external reviewer while there is a single maintainer).
