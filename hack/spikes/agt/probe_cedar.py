"""Spike S1, probe 1: Cedar evaluation inside the agent process (cedarpy).

Questions (plan P0-05, S1 and S4):
  1. Does one Cedar policy set holding the global and the agent-specific
     policies give White Tower's combination semantics (deny overrides,
     default deny)?
  2. What does a decision cost with 1, 10 and 100 policies, parsing the
     policy text on every call versus once?
  3. What does AGT's PolicyEvaluator add when White Tower plugs in as an
     external backend?
  4. Can policies be validated against a schema before approval?

Run: .venv/Scripts/python probe_cedar.py   (Windows)   or   .venv/bin/python probe_cedar.py
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

import cedarpy
from agent_os.policies.evaluator import PolicyEvaluator

SCHEMA = """
namespace WhiteTower {
  entity Agent;
  entity Tool;
  action "tool.invoke" appliesTo {
    principal: Agent,
    resource: Tool,
    context: { environment: String, risk_tier: String, recipient_domain?: String }
  };
}
"""

GLOBAL_POLICIES = """
@id("global-no-external-email")
forbid (
  principal,
  action == WhiteTower::Action::"tool.invoke",
  resource == WhiteTower::Tool::"send_email"
) when { context has recipient_domain && context.recipient_domain != "example.org" };
"""

# Sets of entities are allowed in conditions, not in the policy scope.
AGENT_POLICIES = """
@id("invoice-triage-tools")
permit (
  principal == WhiteTower::Agent::"invoice-triage",
  action == WhiteTower::Action::"tool.invoke",
  resource
) when { resource in [WhiteTower::Tool::"read_invoice", WhiteTower::Tool::"send_email"] };
"""


def request(agent: str, tool: str, **context: str) -> dict:
    return {
        "principal": f'WhiteTower::Agent::"{agent}"',
        "action": 'WhiteTower::Action::"tool.invoke"',
        "resource": f'WhiteTower::Tool::"{tool}"',
        "context": {"environment": "production", "risk_tier": "high", **context},
    }


def decide(policies: str | cedarpy.PolicySet, req: dict) -> str:
    result = cedarpy.is_authorized(req, policies, [])
    return "allow" if result.decision == cedarpy.Decision.Allow else "deny"


def check_semantics() -> None:
    print("== 1. Combination semantics (one policy set = global + agent-specific)")
    policies = GLOBAL_POLICIES + AGENT_POLICIES
    cases = [
        ("agent permit only", request("invoice-triage", "read_invoice"), "allow"),
        ("agent permit, internal email", request("invoice-triage", "send_email", recipient_domain="example.org"), "allow"),
        ("global forbid overrides agent permit", request("invoice-triage", "send_email", recipient_domain="evil.test"), "deny"),
        ("no applicable permit: default deny", request("invoice-triage", "delete_database"), "deny"),
        ("other agent: default deny", request("unknown-agent", "read_invoice"), "deny"),
    ]
    for name, req, want in cases:
        got = decide(policies, req)
        print(f"   {'OK ' if got == want else 'BAD'} {name:40s} -> {got} (want {want})")


def check_validation() -> None:
    print("== 4. Schema validation before approval")
    ok = cedarpy.validate_policies(GLOBAL_POLICIES + AGENT_POLICIES, SCHEMA)
    print(f"   valid policies: passes={ok.validation_passed}")
    broken = AGENT_POLICIES.replace('"tool.invoke"', '"tool.invok"')
    bad = cedarpy.validate_policies(broken, SCHEMA)
    first_error = bad.errors[0] if bad.errors else None
    print(f"   typo in action: passes={bad.validation_passed}; first error: {first_error}")


def generated_policies(n: int) -> str:
    rules = [
        f'@id("agent-tool-{i}")\npermit (principal == WhiteTower::Agent::"invoice-triage", '
        f'action == WhiteTower::Action::"tool.invoke", resource == WhiteTower::Tool::"tool_{i}");'
        for i in range(n - 1)
    ]
    return GLOBAL_POLICIES + "\n".join(rules)


@dataclass
class Stats:
    p50: float
    p99: float


def measure(fn, iterations: int = 2000) -> Stats:
    for _ in range(50):
        fn()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - start) / 1e6)
    samples.sort()
    return Stats(p50=statistics.median(samples), p99=samples[int(len(samples) * 0.99) - 1])


class WhiteTowerCedarBackend:
    """What the adapter would register in AGT: a backend over a pre-parsed policy set."""

    name = "whitetower-cedar"

    def __init__(self, policies: str) -> None:
        self._policies = cedarpy.PolicySet.from_str(policies)

    def evaluate(self, context: dict):
        from agent_os.policies.backends import BackendDecision

        req = request(context["agent_id"], context["tool_name"])
        allowed = decide(self._policies, req) == "allow"
        return BackendDecision(allowed=allowed, action="allow" if allowed else "deny",
                               reason="White Tower bundle", backend=self.name)


def check_latency() -> None:
    print("== 2. Latency per decision (ms, p50 / p99, 2,000 decisions)")
    req = request("invoice-triage", "tool_0")
    for n in (1, 10, 100):
        text = generated_policies(n)
        parsed = cedarpy.PolicySet.from_str(text)
        per_call = measure(lambda: decide(text, req))
        once = measure(lambda: decide(parsed, req))
        print(f"   {n:3d} policies: parsed per call {per_call.p50:.3f} / {per_call.p99:.3f}"
              f" | parsed once {once.p50:.3f} / {once.p99:.3f}")

    print("== 3. Through AGT's PolicyEvaluator with a White Tower backend (10 policies, parsed once)")
    evaluator = PolicyEvaluator()
    evaluator.add_backend(WhiteTowerCedarBackend(generated_policies(10)))
    context = {"agent_id": "invoice-triage", "tool_name": "tool_0"}
    via_agt = measure(lambda: evaluator.evaluate(context))
    decision = evaluator.evaluate(context)
    print(f"   p50 / p99: {via_agt.p50:.3f} / {via_agt.p99:.3f}  (decision: {decision.action})")


if __name__ == "__main__":
    check_semantics()
    check_validation()
    check_latency()
