# P1-11: CLI (`wtctl`)

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | M |
| **Depends on** | P1-03 (login); then the API of each feature plan |
| **Unblocks** | P1-13, P1-14 |
| **Requirements** | API-04, AUD-04, KIL-05, KIL-08 |
| **Decisions** | ADR-0001, ADR-0009 |

## Goal

A command-line tool for operators, owners and auditors that covers the day-to-day tasks, scripts well, and keeps the kill switch reachable when the console is not. It is also the tool auditors use to verify evidence independently.

## Scope

**In:** login, profiles, agents, credentials, policies, halts, audit (query, export, verification), modules, documentation and packaging.

**Out:** anything the public API does not offer (the CLI is a pure API client), except local key generation and offline audit verification.

## Deliverables

- `cmd/wtctl`, built on the generated Go client.
- A generated command reference in the documentation.
- Signed builds for Linux, macOS and Windows (through the P0-01 release pipeline).

## Steps

### 1. Skeleton

- Built with `cobra` on the generated client.
- Profiles in a configuration file (`~/.config/whitetower/config.yaml`).
- Output as table, JSON or YAML.
- Flags for the server and custom certificate authorities.
- Shell completion and `version`.

**Done when:** `wtctl version` and `wtctl --help` work on the three operating systems.

### 2. Login

- `wtctl login` uses the authorization code flow with PKCE and a loopback redirect at the IdP, then exchanges the ID token at White Tower (P1-03, step 7).
- The resulting token is stored in the operating system's keychain, falling back to a file readable only by the user.
- `wtctl login --token` accepts a personal access token.
- `logout` and `whoami`.

**Done when:** login works against the development Keycloak on Linux, macOS and Windows.

### 3. Agents

- `list`, `get`, `create -f`, `update`.
- Lifecycle transitions (`submit`, `validate`, `activate`, `suspend`, `reinstate`, `retire`).
- Ownership, use cases and reviews.
- `import` (Could).

**Done when:** the onboarding path can be scripted end to end.

### 4. Credentials

- `wtctl agent key generate` creates the key pair locally and never uploads the private key.
- `key add`, `list`, `revoke` and `rotate`.

**Done when:** an agent can be given a credential in two commands.

### 5. Policies

`apply -f` (creates a version), `validate`, `diff`, `submit`, `approve`, `reject`, and `effective --agent`.

**Done when:** policy-as-code workflows work from a CI pipeline using a service account token.

### 6. Halts

- `wtctl halt agent <id> --reason`.
- `wtctl halt fleet --reason [--selector]`, which asks for explicit confirmation unless `--yes` is given.
- `wtctl halt status <id> --watch`, with live propagation.
- `wtctl halt release request` and `approve`.
- Works with a break-glass session (KIL-08).

**Done when:** with the console down, an operator halts an agent and the fleet and watches the confirmations.

### 7. Audit

- `audit query` and `audit export` (JSON Lines).
- `audit verify`: online through the API, or offline against an export.
- `audit prove --event` and `audit consistency --checkpoint <file>`.

All are built on `pkg/auditverify` (P1-02).

**Done when:** `wtctl audit verify` detects every manipulation of the P1-02 tamper suite, and a consistency check against a checkpoint saved from the SIEM passes on an untouched log.

### 8. Modules

`module register -f manifest.yaml`, `approve`, `list` and `instances`.

**Done when:** an operator registers and approves the mock module from the CLI.

### 9. Documentation

Generate the command reference from `cobra`, and add task-oriented examples: onboarding, policy as code, halting, verifying evidence, break-glass.

**Done when:** the reference is published with the documentation and the examples run in CI.

### 10. Packaging

Build through GoReleaser (P0-01): signed binaries for Linux, macOS and Windows on amd64 and arm64. Package managers (Homebrew, Scoop, winget) come later.

**Done when:** the binaries of a snapshot release verify with cosign.

## Acceptance criteria

- End-to-end tests cover the main flows using a personal access token in CI; interactive login is tested manually on the three operating systems.
- `wtctl audit verify` detects the P1-02 tamper suite.
- Halting through the CLI works while the console is down, and with a break-glass session while the IdP is down.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Loopback redirects are blocked on some corporate machines | Personal access tokens as fallback; the device authorization grant is a later option |
| The CLI drifts from the API | Generated client, and end-to-end tests in the same CI as the API |

## Notes for implementers

- Keep commands thin: argument parsing, one API call, output. Logic belongs in the API.
- Make every destructive command ask for confirmation, with `--yes` for scripts.
- Exit codes must be meaningful for scripts: 0 success, 1 error, 2 usage error, 3 not permitted.
