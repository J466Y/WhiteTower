# Repository rulesets

These JSON files are the source of truth for the repository's protection rules. GitHub does not read them automatically: a maintainer imports them (**Settings → Rules → Rulesets → New ruleset → Import a ruleset**) and re-imports them after every change. Changes to these files follow the RFC review rules of [GOVERNANCE.md](../../GOVERNANCE.md#changes-to-this-document).

| File | Applies to | What it enforces | Who can bypass |
| --- | --- | --- | --- |
| [`main.json`](main.json) | The default branch | Changes only through pull requests, squash merges and linear history; every CI and CodeQL check green, with the branch up to date; conversations resolved; no high or critical code scanning alerts; signed commits; no force pushes or deletion | Nobody |
| [`release-tags-immutable.json`](release-tags-immutable.json) | Tags `v*` | Release tags cannot be deleted or moved | Nobody |
| [`release-tags-creation.json`](release-tags-creation.json) | Tags `v*` | Only repository administrators can create release tags, which trigger the release workflow | Repository administrators |

## Notes

- **Required reviews are set to 0** while the project has a single maintainer, because GitHub does not let authors approve their own pull requests. When a second maintainer joins, set `required_approving_review_count` to 1 and `require_code_owner_review` to `true`, then re-import.
- **Required checks are job names** of `.github/workflows/ci.yml` and `codeql.yml` (`integration_id` 15368 is GitHub Actions). Renaming a job without updating `main.json` blocks every pull request, which is the intended safety net: update both in the same pull request.
- **Signed commits** are satisfied by squash merges, which GitHub signs. Commits on feature branches do not need to be signed.
- **`bypass_actors` is empty on purpose.** An administrator can still edit or disable a ruleset in an emergency, but GitHub records every change in the ruleset history. The procedure is in [GOVERNANCE.md](../../GOVERNANCE.md#working-without-shortcuts).
