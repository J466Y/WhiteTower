"""Checks the conformance vectors with Python: cedarpy for Cedar, cryptography for Ed25519.

The Go tests in test/conformance check the same vectors with cedar-go. Passing
both shows the decision profile does not depend on one Cedar implementation,
and gives the Python enforcement point (plan P1-09) a reference to start from.

Run from the repository root with a Python that has cedarpy and cryptography:
    python test/conformance/python/check_vectors.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

import cedarpy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VECTORS = Path(__file__).resolve().parent.parent / "vectors"
CEDAR_SCHEMA = Path(__file__).resolve().parents[3] / "api" / "policy" / "whitetower.cedarschema"

ACTION_RESOURCE = {
    "agent.start": "agent", "input.receive": "agent", "output.emit": "agent", "agent.stop": "agent",
    "model.invoke": "model", "model.result": "model", "tool.invoke": "tool", "tool.result": "tool",
}
RESOURCE_TYPES = {
    "agent": "Agent", "tool": "Tool", "model": "Model", "mcp_server": "McpServer",
    "dataset": "Dataset", "skill": "Skill", "url": "Url",
}


class InvalidRequest(Exception):
    pass


def uid(entity_type: str, entity_id: str) -> dict:
    return {"type": f"WhiteTower::{entity_type}", "id": entity_id}


def to_cedar(req: dict) -> tuple[dict, list]:
    """Maps an AuthZEN request of the profile to a cedarpy request and entities (section 6.4)."""
    action, resource, subject, ctx = req["action"]["name"], req["resource"], req["subject"], req["context"]
    want = ACTION_RESOURCE.get(action)
    if want is None or resource["type"] != want or not resource.get("id"):
        raise InvalidRequest(action)
    props = subject["properties"]
    principal = {
        "uid": uid("Agent", subject["id"]),
        "attrs": {k: props[k] for k in ("slug", "kind", "risk_tier", "environment", "data_categories", "owner")},
        "parents": [],
        "tags": dict(props.get("labels", {})),
    }
    entities = [principal]
    rprops = resource.get("properties", {})
    if resource["type"] == "agent":
        if resource["id"] != subject["id"]:
            raise InvalidRequest("an agent action must concern the requesting agent")
    else:
        attrs = {}
        if resource["type"] == "tool":
            if rprops.get("kind") not in ("function", "mcp", "http", "other"):
                raise InvalidRequest("tool kind")
            attrs["kind"] = rprops["kind"]
            if "server" in rprops:
                attrs["server"] = rprops["server"]
        elif resource["type"] == "model" and "provider" in rprops:
            attrs["provider"] = rprops["provider"]
        entities.append({"uid": uid(RESOURCE_TYPES[resource["type"]], resource["id"]), "attrs": attrs, "parents": []})
    context = {"time": {"__extn": {"fn": "datetime", "arg": ctx["time"]}}}
    for key in ("task_id", "trace_id", "on_behalf_of"):
        if key in ctx:
            context[key] = ctx[key]
    if "args" in ctx:
        if want != "tool":
            raise InvalidRequest("args on a non-tool action")
        context["args"] = ctx["args"]
    request = {
        "principal": f'WhiteTower::Agent::"{subject["id"]}"',
        "action": f'WhiteTower::Action::"{action}"',
        "resource": f'WhiteTower::{RESOURCE_TYPES[resource["type"]]}::"{resource["id"]}"',
        "context": context,
    }
    return request, entities


class Engine:
    """One bundle's policies for one agent, with the combining algorithm wt-deny-overrides-v1."""

    def __init__(self, agent_id: str, policies: list[dict]):
        self.agent_id = agent_id
        self.owner_of: list[str] = []
        texts = []
        for p in policies:
            count = len(cedarpy.PolicySet.from_str(p["text"]))  # raises if it does not parse
            self.owner_of += [p["id"]] * count
            texts.append(p["text"])
        self.policies = cedarpy.PolicySet.from_str("\n".join(texts))

    def owners(self, policy_ids) -> list[str]:
        return sorted({self.owner_of[int(pid.removeprefix("policy"))] for pid in policy_ids})

    def evaluate(self, req: dict) -> dict:
        if req["subject"]["type"] != "agent" or req["subject"]["id"] != self.agent_id:
            return deny("error.unknown_agent")
        try:
            request, entities = to_cedar(req)
        except InvalidRequest:
            return deny("error.invalid_request")
        result = cedarpy.is_authorized(request, self.policies, entities)
        diag = result.diagnostics
        # cedarpy reports errors as text, for example
        # "error while evaluating policy `policy1`: ...".
        errors = [m.group(1) for e in (diag.errors if diag else []) for m in [ERROR_POLICY.search(e)] if m]
        if diag and len(errors) != len(diag.errors):
            return deny("error.evaluation")
        reasons = list(diag.reasons) if diag else []
        if errors or result.decision not in (cedarpy.Decision.Allow, cedarpy.Decision.Deny):
            return {"decision": False, "reason": "error.evaluation", "policies": self.owners(errors)}
        if result.decision == cedarpy.Decision.Allow:
            return {"decision": True, "reason": "policy.permit", "policies": self.owners(reasons)}
        if reasons:
            return {"decision": False, "reason": "policy.forbid", "policies": self.owners(reasons)}
        return deny("policy.no_permit")


def deny(reason: str) -> dict:
    return {"decision": False, "reason": reason, "policies": []}


def gate_reason(state: dict) -> str:
    """The gate of section 5.4, in the contract's order."""
    if not state["state_received"]:
        return "gate.no_state"
    if not state["lease_valid"]:
        return "gate.lease_expired"
    if state["agent_halted"]:
        return "gate.halted"
    if state["fleet_halted"]:
        return "gate.fleet_halted"
    if state["lifecycle_state"] not in ("validated", "ready", "active"):
        return "gate.lifecycle"
    if not state["bundle_active"]:
        return "gate.no_bundle"
    if state["evidence_buffer_full"]:
        return "gate.evidence_full"
    return ""


def b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


ERROR_POLICY = re.compile(r"policy `(policy\d+)`")
POLICY_PATH = re.compile(r"^policies/(global|agent)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(cedar|rego)$")


class Rejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def verify_bundle(case_dir: Path, trusted: dict[str, Ed25519PublicKey], case: dict) -> dict:
    """The verification steps V1 to V6 of section 7.4."""
    files = {p.relative_to(case_dir).as_posix(): p.read_bytes() for p in case_dir.rglob("*") if p.is_file()}
    manifest = files.pop("manifest.json")
    signature = files.pop("manifest.jws", b"").decode()
    files.pop("case.json")
    ref = case["ref"]
    size = len(manifest) + sum(len(c) for c in files.values())
    if ref["size_bytes"] > 2 << 20 or size > 2 << 20 or len(files) > 1000:
        raise Rejected("oversized")
    parts = signature.split(".")
    if len(parts) != 3 or parts[1] != "":
        raise Rejected("signature")
    header = json.loads(b64url(parts[0]))
    if set(header) != {"alg", "kid", "typ"} or header["alg"] != "EdDSA" or header["typ"] != "whitetower-bundle+jws":
        raise Rejected("signature")
    key = trusted.get(header["kid"])
    if key is None:
        raise Rejected("unknown_key")
    signing_input = (parts[0] + "." + base64.urlsafe_b64encode(manifest).decode().rstrip("=")).encode()
    try:
        key.verify(b64url(parts[2]), signing_input)
    except InvalidSignature:
        raise Rejected("signature") from None
    digest = hashlib.sha256(manifest).hexdigest()
    if digest != ref["manifest_sha256"]:
        raise Rejected("manifest_mismatch")
    m = json.loads(manifest)
    if m["format"] != "whitetower.bundle.v1" or m["combining_algorithm"] != "wt-deny-overrides-v1" or m["language"] != "cedar":
        raise Rejected("unsupported")
    if m["agent_id"] != case["agent_id"] or m["version"] != ref["version"]:
        raise Rejected("invalid_manifest")
    listed = {}
    for p in m["policies"]:
        if not POLICY_PATH.match(p["path"]) or not p["path"].endswith("." + m["language"]) \
                or not p["path"].startswith(f"policies/{p['scope']}/") or p["path"] in listed:
            raise Rejected("invalid_manifest")
        listed[p["path"]] = p["sha256"]
    if "cedar_schema" in m:
        listed[m["cedar_schema"]["path"]] = m["cedar_schema"]["sha256"]
    for path in sorted(listed):
        if path not in files:
            raise Rejected("missing_file")
        if hashlib.sha256(files[path]).hexdigest() != listed[path]:
            raise Rejected("file_hash")
    if set(files) - set(listed):
        raise Rejected("extra_file")
    if m["version"] < case["active_version"] or (
            m["version"] == case["active_version"] and digest != case.get("active_manifest_sha256")):
        raise Rejected("older_version")
    try:
        Engine(m["agent_id"], [{"id": p["id"], "text": files[p["path"]].decode()} for p in m["policies"]])
    except Exception:  # noqa: BLE001 - any parse failure rejects the bundle
        raise Rejected("parse_error") from None
    return {"outcome": "activated"}


def main() -> int:
    failures = 0

    def check(name: str, got: dict, want: dict) -> None:
        nonlocal failures
        if got != want:
            failures += 1
            print(f"FAIL {name}: got {got}, want {want}")

    combination = json.loads((VECTORS / "combination.json").read_text(encoding="utf-8"))
    schema = CEDAR_SCHEMA.read_text(encoding="utf-8").replace("type ToolArgs = {};", combination["tool_args_extension"], 1)
    for case in combination["cases"]:
        for p in case["policies"]:
            passes = cedarpy.validate_policies(p["text"], schema).validation_passed
            if passes != p["valid"]:
                failures += 1
                print(f"FAIL {case['id']}: policy {p['id']} validation {passes}, want {p['valid']}")
        engine = Engine(combination["agent_id"], case["policies"])
        check(case["id"], engine.evaluate(case["request"]), case["expected"])

    fail_closed = json.loads((VECTORS / "fail-closed.json").read_text(encoding="utf-8"))
    engine = Engine(fail_closed["agent_id"], fail_closed["policies"])
    for case in fail_closed["cases"]:
        reason = gate_reason(case["state"])
        check(case["id"], deny(reason) if reason else engine.evaluate(fail_closed["request"]), case["expected"])

    keys = json.loads((VECTORS / "bundles" / "keys.json").read_text(encoding="utf-8"))
    trusted = {k["kid"]: Ed25519PublicKey.from_public_bytes(b64url(k["x"])) for k in keys["trusted"]}
    bundle_cases = sorted(p for p in (VECTORS / "bundles").iterdir() if p.is_dir())
    for case_dir in bundle_cases:
        case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        try:
            got = verify_bundle(case_dir, trusted, case)
        except Rejected as r:
            got = {"outcome": "rejected", "reason": r.reason}
        check(f"bundle {case_dir.name}", got, case["expected"])

    total = len(combination["cases"]) + len(fail_closed["cases"]) + len(bundle_cases)
    print(f"{total} vectors, {failures} failures (cedarpy, cryptography)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
