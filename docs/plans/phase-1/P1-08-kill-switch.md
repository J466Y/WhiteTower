# P1-08: Kill switch

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | L |
| **Depends on** | P1-04, P1-05, P1-07 |
| **Unblocks** | P1-09, P1-10.5, P1-15 (end-to-end tests), P1-14 |
| **Requirements** | KIL-01 to KIL-10, NFR-03 to NFR-05 |
| **Decisions** | ADR-0005, ADR-0010 |

## Goal

Anyone with the right role can stop one agent, a selection of agents or the whole fleet from the console, the API or the CLI, in seconds and without asking permission. The system shows which instances confirmed the stop and how long it took, keeps stopped agents from getting credentials, and makes sure that bringing anything back takes two people.

## Scope

**In:** halt domain and API, fleet and selector halts, propagation tracking, release workflow, lease policy, break-glass integration, drills, fault-injection tests, performance validation, runbooks.

**Out:** the watch transport (P1-07); what the enforcement point does inside the agent (P1-09); the network quarantine module (P1-15); the console screens (P1-10.5); stopping workloads (Phase 2 harness module).

## Deliverables

- `internal/killswitch` with its OpenAPI operations.
- Propagation metrics and alerts.
- The fault-injection test suite.
- Runbooks: halting, unconfirmed halts, releasing.

## Steps

### 1. API first

- `POST /api/v1/halts`: target (agent, fleet or selector), agent ID or selector, reason, optional `drill` flag, and an idempotency key so retries never create two halts.
- `GET /api/v1/halts`: active halts and history.
- `GET /api/v1/halts/{id}`: status per instance.
- Release requests and their approvals.

Permissions follow the matrix: halting an agent is open to steering, advisory, its owner and operators; halting the fleet to steering and operators.

**Done when:** the operations are merged and agreed with P1-10.5 and P1-11.

### 2. Halt domain

In one transaction:

- create the halt record;
- set the run state to halted for the targets;
- for an agent halt, move the agent to `suspended` with the halt as reason (KIL-06);
- write the audit event and bump the governance state version.

After commit, notify the other replicas. Token issuance is blocked at once, because the gate of P1-05 reads the run state.

**Done when:** after a successful response, the halt is visible on every replica and the agent's next token request fails (test).

### 3. Fleet and selector halts

- A fleet halt is one fleet state record. It covers every agent, including agents registered or connecting later, and **does not change lifecycle states** (KIL-06).
- A selector halt (Should) stores its selector (environment, label, risk tier) and applies it to current and future agents.
- An agent stays halted while any halt covering it is active.

**Done when:** an agent registered after a fleet halt starts halted, and releasing one of two overlapping halts leaves the agent halted.

### 4. Propagation tracking

- **Expected instances:** those connected, or holding a valid lease, for the targeted agents when the halt is issued, plus any that connect afterwards. They include the network quarantine module of each cluster where a targeted agent has pods (P1-15).
- **Acknowledgements** report each layer with its timestamp: gate closed, in-flight action interrupted, process terminated, network quarantined (with the number of workloads covered).
- **Halt status:** propagating, then confirmed (every expected instance acknowledged), partially confirmed, or unconfirmed after a timeout (10 seconds by default), which fires an alert.
- **Metrics:** `whitetower_halt_propagation_seconds` (issued to acknowledged), `whitetower_halt_effect_seconds` (issued to in-flight interruption or termination) and `whitetower_halt_quarantine_seconds` (issued to network quarantine applied).
- An instance that keeps sending action events after acknowledging a halt is flagged as suspect (threat model: an enforcement point that lies).

**Done when:** the status and the metrics are correct in tests with mock instances that acknowledge, delay, stay silent and lie, including a mock quarantine module.

### 5. Release workflow

- A release request, with a reason, is made by an authorized person; an owner may request the release of their own agent's halt.
- A **different** authorized person approves it (KIL-05), following the permission matrix: steering, advisory or an operator for an agent halt; steering or an operator for a fleet halt.
- On approval, the run state returns to running if no other halt covers the agent.
- For an agent halt, the agent **stays suspended**: reinstating it is a separate lifecycle transition (P1-04), so a release never puts an agent back into service on its own.

**Done when:** releasing with one person is impossible (tests), and the lifecycle state is unchanged by a release.

### 6. Lease policy

- Lease TTL per risk tier comes from the settings, with defaults from P0-05; renewals are sent every third of the TTL (P1-07).
- The core cannot see an enforcement point's clock, so it treats an instance as **lost** once its stream has been disconnected longer than the TTL. The console shows it as "failed closed (lost contact)".

**Done when:** the lease watchdog job marks lost instances, and they are counted in the halt status.

### 7. Break-glass (Should)

The break-glass session of P1-03 can call the halt endpoints and nothing else. The console's minimal break-glass page (P1-10.5) and the CLI both use it.

**Done when:** with the IdP stopped, a break-glass session halts an agent and the fleet (end-to-end test).

### 8. Drills (Should)

- A drill is a halt with `drill=true` on an agent that its owner marked as eligible.
- It is released automatically once confirmed, or after a maximum duration. The release is a system action, without the two-person rule, and is audited.
- Timings are recorded. A drill confirmed within the targets gives the agent coverage C3 (INV-08).
- Drills can be scheduled.

**Done when:** a drill on a mock agent runs, is released and updates coverage.

### 9. Fault injection and end-to-end tests

- A core replica crashes during a halt: the enforcement points reconnect and still see it halted.
- Database failover during a halt.
- Network partition between an enforcement point and the core: it halts within the TTL plus a tolerance.
- Duplicate, late and forged acknowledgements; forged ones are rejected.
- An enforcement point restarts while halted and starts halted (KIL-07).

**Done when:** every scenario runs in CI with the mock module, and those needing real infrastructure run in the P1-12 environment.

### 10. Performance validation

With 500 mock instances, halt one agent and the whole fleet repeatedly. Measure against NFR-03 to NFR-05 and publish the results, which feed P1-13 and the pilot.

**Done when:** the report is in `docs/performance/`.

### 11. Runbooks

- How to halt an agent or the fleet.
- What to do when a halt stays unconfirmed: check the network quarantine layer (P1-15); otherwise kill the process or pod manually, revoke credentials and isolate the network by hand.
- How to release, and then how to reinstate.

**Done when:** the runbooks are reviewed by an operator and rehearsed once.

## Acceptance criteria

- Halts of one agent and of the fleet reach 500 mock instances within the NFR-03 target, with confirmed status per instance.
- In the partition test, the mock instance halts within its TTL plus tolerance.
- A release needs two distinct authorized people, and leaves an agent-halted agent suspended.
- A fleet halt covers agents registered after it was issued.
- Every step is audited, and the runbooks are reviewed.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Enforcement points acknowledge but do not stop | Layered acknowledgements; suspicious activity flagged; token issuance stopped; network quarantine on Kubernetes (P1-15); stopping workloads in Phase 2 |
| Accidental fleet halt | Strong confirmation in the console and CLI (reason plus an explicit confirmation), fast two-person release, and drills that build familiarity |
| Halt storms (many halts issued in a short time) | Idempotency keys; coalesced state changes in the governance state hub |

## Notes for implementers

- Never make halting depend on anything slower than one database transaction: no synchronous calls to modules, and no approval.
- Keep the halt path free of optional dependencies (SMTP, webhooks): notifications happen after commit and may fail without affecting the halt.
- The halt, the suspension and the state version bump must be in one transaction; test it with a failure injected between them.
- Spike S2 measured this path with 1,000 enforcement points: a fleet halt was delivered with p99 ≤ 310 ms and acknowledged with p95 0.63 s. Most of the difference is 1,000 acknowledgements written in a burst: write them in batches ([report](../../spikes/S2-watch-streams.md)).
