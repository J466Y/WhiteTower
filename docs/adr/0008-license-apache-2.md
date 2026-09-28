# ADR-0008: Apache-2.0 license and DCO for contributions

- **Status:** Proposed
- **Date:** 2026-09-28
- **Related:** CON-01; plan P0-01

## Context

The charter proposes Apache 2.0 (permissive, with a patent grant), maintainer-led governance and a medium-term goal of hosting the project in a foundation. The repository already contains the Apache-2.0 `LICENSE`, but the README still says the license is "to be decided before the first code release".

## Decision

- White Tower code and documentation are licensed under **Apache-2.0**.
- Contributions are accepted under the **Developer Certificate of Origin** (every commit signed off with `git commit -s`), without a CLA. This is the practice of the Linux Foundation and the CNCF, the likely foundations.
- A `NOTICE` file is added, and the README's License section is updated to say Apache-2.0.
- Dependencies shipped in White Tower artifacts must have licenses compatible with Apache-2.0. CI checks them: permissive licenses (MIT, BSD, ISC, Apache-2.0) are allowed, weak copyleft (MPL-2.0) needs review, and strong copyleft or source-available licenses (GPL, AGPL, SSPL, BUSL) are not allowed.

## Consequences

- Organizations and vendors can adopt White Tower and build commercial modules without legal friction, which is essential for an ecosystem of interchangeable modules.
- The patent grant protects users and contributors.
- A future move to a foundation does not require relicensing or collecting CLAs.
- Anyone, including competitors, can fork the project. Accepted; the charter mitigates the risk of acquisition with the permissive license and a preference for foundation-hosted projects.

## Alternatives considered

- **AGPL or another copyleft license.** Protects against closed forks, but deters enterprise adoption and commercial modules, which the charter relies on.
- **A CLA instead of the DCO.** Allows relicensing later, but adds contributor friction and is disliked in foundation-hosted projects.
