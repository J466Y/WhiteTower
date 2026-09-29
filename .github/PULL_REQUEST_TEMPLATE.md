## What and why

<!-- What does this change do, and why? Link the issue it resolves. -->

**Plan step and requirements:** <!-- for example: P1-04 step 5, INV-04 -->

## Checklist

- [ ] Commits are signed off (`git commit -s`) and follow Conventional Commits.
- [ ] Tests cover the change, including negative cases for authorization and input validation.
- [ ] Contract changes (OpenAPI, protobuf, event schemas) come first, and `task gen` output is committed.
- [ ] Every state change writes its audit events, and new flows expose metrics (from Phase 1).
- [ ] No secrets in code, logs or test data; the permission matrix and its tests are updated if access rules changed.
- [ ] Documentation is updated (user, administrator, API, configuration reference, runbooks).
- [ ] Console strings are translated (English and Spanish), if the console changed.
- [ ] New runtime dependencies are justified below, and their licenses are compatible with Apache-2.0.

## New dependencies

<!-- Delete if none. For each: what it does, why it is needed, how well it is maintained. -->
