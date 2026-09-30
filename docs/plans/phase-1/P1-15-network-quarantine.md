# P1-15: Kubernetes network quarantine module

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | M (about 2 weeks) |
| **Depends on** | P0-03 (the `runtime-control` capability), P1-05 (module identity), P1-07 (module API); P1-08 only for the final end-to-end halt tests |
| **Unblocks** | P1-12.2 (offline bundle and compatibility matrix), P1-13, P1-14 |
| **Requirements** | KIL-10, KIL-03, KIL-07, NFR-01, NFR-23; assumption ASM-05 |
| **Decisions** | ADR-0005, ADR-0011 |

## Goal

When an agent running on Kubernetes is halted, its pods lose network access within seconds, whatever the agent's code does, and get it back when the halt is released. The halt acknowledgement says so, per agent, with the number of pods covered. This is the MVP's only halt layer that works even if the agent is compromised or not instrumented (architecture, section 6.2).

## Scope

**In:** a Go controller deployed once per cluster, deny rule templates for Cilium (the reference), Calico, Antrea and AdminNetworkPolicy, reconciliation, acknowledgements and events, protection of the quarantine against tampering, the image and Helm chart, end-to-end tests on kind with Cilium, measurements, a runbook.

**Out:** stopping, scaling down or restarting workloads (Phase 2 harness module); agents on Docker hosts or virtual machines (a documented manual procedure only); finding agent pods that carry no agent label (Phase 3 discovery); the halt domain and its status (P1-08).

## Deliverables

- `modules/k8s-quarantine/`: the controller, its manifest and tests.
- The deny rule templates, one per supported CNI.
- The container image and the `deploy/helm/whitetower-quarantine/` chart.
- An end-to-end test on kind with Cilium, and a weekly job for the other templates.
- A measurement report in `docs/performance/` and a runbook.

## Steps

### 1. Contract and manifest

- The module declares the `runtime-control` capability of P0-03, the acknowledgement layer `network_quarantined`, and the events `whitetower.quarantine.applied.v1` and `whitetower.quarantine.lifted.v1`.
- An operator registers and approves the module (P1-07), then binds it to **all agents** (`module_agent_bindings` with scope `all`), so agents created later are covered without a new binding.
- Each instance reports as the agents it serves only those with pods in its cluster. P1-08 therefore expects its acknowledgement exactly for the agents it can isolate.

**Done when:** the manifest validates against the P0-03 schema, and the binding to all agents works through the API.

### 2. Controller skeleton

- Go, with `client-go` informers (or `controller-runtime`), two replicas and leader election.
- Authenticates to the core with its module identity (P1-05) and uses the Go module API client (`pkg/moduleapi`): `RegisterInstance`, `Watch`, `Acknowledge`, `Publish`.
- Lease timer on the monotonic clock and jittered reconnection, as for any module.

**Done when:** the controller connects to a real core, receives the snapshot of all agents and survives a core restart.

### 3. Deny rules per CNI

One cluster-wide rule per halted agent, named deterministically (`whitetower-quarantine-<agent-id>`), selecting pods by the label `whitetower.io/agent-id` (the prefix follows the domain decision of open question Q6). A fleet halt uses one rule selecting every pod that carries the label.

Each rule denies all ingress and egress, with two exceptions:

- egress to the core's machine listener, so the in-process enforcement point can still acknowledge, deliver its buffered evidence and learn of the release;
- traffic from the node for health probes, so a quarantined pod is not restarted.

| CNI | Rule | How the exception for the core is expressed |
| --- | --- | --- |
| Cilium (reference) | `CiliumClusterwideNetworkPolicy` with `ingressDeny` and `egressDeny` | Deny rules always win over allow rules in Cilium, so the core is left out of the denied destinations |
| Calico | `GlobalNetworkPolicy` with a low `order`, evaluated first | An `Allow` rule for the core, then `Deny` |
| Antrea | `ClusterNetworkPolicy` in the `emergency` tier | An `Allow` rule for the core, then `Drop` |
| AdminNetworkPolicy | Priority 0 (an alpha Kubernetes API; best effort) | An `Allow` rule for the core, then `Deny` |

**No DNS during a quarantine** ([threat model](../../security/threat-model.md), DC-7): DNS can carry data out, and the halt path does not need it, because the enforcement point reconnects to the core's last resolved addresses (P1-09). On a CNI with DNS-aware rules, such as Cilium, an option allows lookups of the core's name only.

**Done when:** each template isolates a test pod except for the core and node probes, on a cluster running that CNI.

### 4. Reconciliation

- Compute the desired rules from the governance state: agents covered by an agent or selector halt, and the fleet state.
- Create and delete rules to match, idempotently; on startup, adopt the rules that already exist.
- **Never lift a quarantine without fresh state from the core.** While disconnected, or after its lease expires, the controller keeps every existing rule and raises an alert; it applies no new rule until it reconnects, because it no longer knows the state. An option, off by default, quarantines every covered agent when the lease expires, for sites that prefer isolation to availability.
- Watch pods to count, per agent, the pods each rule covers.

**Done when:** unit tests cover halts, releases, overlapping halts, a fleet halt, a controller restart and a lost connection.

### 5. Acknowledgements, events and coverage

- Acknowledge each halt, per agent, with the layer `network_quarantined`, the time the rule was accepted by the API server and the number of pods covered (P1-08 stores them in `halt_acks`).
- Report honestly: the acknowledgement says the rule is in place, not that every connection is gone; the measurements of step 8 give the time to effective isolation.
- Publish `quarantine.applied` and `quarantine.lifted` events.
- Report per agent the pods found, so the console can show agents that run in the cluster without the label, or with no pods at all.

**Done when:** a halt on a mock core shows the quarantine layer with the right pod count, and the events validate against the catalog.

### 6. Protecting the quarantine

- **RBAC:** the controller may manage only its rule kind and read pods; it has no access to workloads or Secrets.
- **Admission policies** (`ValidatingAdmissionPolicy`, shipped with the chart and enabled by default): only the controller's service account may change or delete the quarantine rules, nobody may change the `whitetower.io/agent-id` label of a running pod, and no pod carrying that label may use the host's network, which deny rules cannot reach (DC-5).
- **Documentation:** agents' service accounts must not be able to patch pods or network rules.

**Done when:** tests show that a user with broad namespace rights cannot remove a quarantine, relabel a quarantined pod, or run a labeled pod on the host's network.

### 7. Image and Helm chart

- A distroless, non-root image, multi-architecture, like the core's (P1-12).
- A chart with the CNI choice, the core's URL and trust settings, the credentials Secret, the core exception (a CIDR, or a selector when the core runs in the same cluster), two replicas, a pod disruption budget and the admission policies.

**Done when:** `helm install` on kind with Cilium passes a smoke test.

### 8. End-to-end tests and measurements

On kind with Cilium, with the core, the Python enforcement point (P1-09) or the mock module, and an echo server outside the agent's namespace:

- halting an agent cuts its pods' traffic to the echo server, while the enforcement point still reaches the core;
- a pod started after the halt is isolated from its start;
- releasing the halt restores traffic;
- a fleet halt isolates every labeled pod;
- restarting the controller, or cutting it off from the core, never lifts a quarantine;
- whether a connection opened before the halt survives it; if it does on the reference CNI, the risk and its mitigation are recorded (see risks).

Measure the time from halt issued to effective isolation (p50, p95, p99, max) against NFR-23. The Calico, Antrea and AdminNetworkPolicy templates run in a weekly job.

**Done when:** the tests run in CI and the report is in `docs/performance/`.

### 9. Runbook and documentation

- Installation per CNI, and how to verify that the rule kind is enforced.
- What the console shows when the CNI cannot deny, and how to proceed.
- Investigating a quarantined pod, and lifting a quarantine by releasing the halt (never by deleting the rule by hand).
- A manual isolation procedure for agents on Docker hosts.

**Done when:** an operator from the pilot organization reviews the runbook.

## Acceptance criteria

- On kind with Cilium, a halted agent's pods lose all traffic except to the core and from node probes within NFR-23, including pods started after the halt, and regain it on release (end-to-end test).
- The halt acknowledgement shows the `network_quarantined` layer with the pods covered (test against the core).
- A controller restart or a lost connection to the core never lifts a quarantine (test).
- The controller cannot touch workloads, and users cannot remove a quarantine or relabel a quarantined pod (tests).
- The templates for Calico, Antrea and AdminNetworkPolicy pass their weekly job, or their limits are documented.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-15-network-quarantine) pass: ST-69 to ST-73.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Connections opened before the quarantine survive it on some CNIs | Measured in step 8; the in-process gate still denies governed calls; residual risk recorded in the threat model; if needed, the enforcement point closes its connections on halt |
| The cluster's CNI does not enforce deny rules (ASM-05) | Detected at installation; the console shows the layer as unavailable; documented in the runbook |
| Pods run without the agent label | Pods found per agent shown in the console; optional admission policy requiring the label in namespaces marked for agents |
| Quarantine blocks what the enforcement point needs | Exception for the core by design; no DNS, so the enforcement point reuses the core's resolved addresses (step 3) |
| A lost connection to the core leaves new halts without network enforcement | Alert on disconnection; the in-process gate and token issuance still apply; optional quarantine on lease expiry |
| AdminNetworkPolicy is still an alpha API | Cilium is the reference; the AdminNetworkPolicy template is best effort |

## Notes for implementers

- Never modify workloads: the controller only creates and deletes its own rules, which keeps it safe to run with narrow rights.
- One rule per halted agent, with a deterministic name, keeps reconciliation simple and the evidence readable.
- Selecting pods by the agent label, not by pod name, is what closes the race with pods started after the halt.
