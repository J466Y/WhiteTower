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
    if not state["state_received"] or not state["agent_in_state"]:
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


class Rejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# The members of a bundle manifest, of its Cedar schema's entry and of a policy
# entry: exactly these, each of them required (bundle-manifest.schema.json).
MANIFEST_MEMBERS = {"format", "agent_id", "version", "created_at", "combining_algorithm", "language",
                    "cedar_schema", "policies"}
FILE_MEMBERS = {"path", "sha256"}
POLICY_MEMBERS = {"id", "name", "version", "scope", "path", "sha256"}
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SHA256 = re.compile(r"[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")


def members(value, names: set) -> dict:
    """An object with exactly the members named, none of them null, or invalid_manifest."""
    if type(value) is not dict or set(value) != names or None in value.values():
        raise Rejected("invalid_manifest")
    return value


def form(pattern: re.Pattern, value) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def positive(value) -> bool:
    return type(value) is int and value >= 1


def check_manifest(manifest: bytes) -> dict:
    """The checks of step V4 that read the manifest alone, in their order (section 7.4).

    A manifest that is not an object, or that has an unknown or a missing member,
    or a member of the wrong type, is invalid_manifest: the types are those of
    bundle-manifest.schema.json, the forms of its strings included. Then a format,
    combining algorithm or language that is not supported is unsupported, even
    though the schema's constant fails too. Paths need only be strings here: V5
    builds them from their entries.
    """
    try:
        m = json.loads(manifest)
    except ValueError:
        raise Rejected("invalid_manifest") from None
    members(m, MANIFEST_MEMBERS)
    schema = members(m["cedar_schema"], FILE_MEMBERS)
    if type(m["policies"]) is not list:
        raise Rejected("invalid_manifest")
    policies = [members(p, POLICY_MEMBERS) for p in m["policies"]]
    if not (all(type(m[k]) is str for k in ("format", "combining_algorithm", "language"))
            and form(UUID, m["agent_id"]) and positive(m["version"]) and form(TIMESTAMP, m["created_at"])
            and type(schema["path"]) is str and form(SHA256, schema["sha256"])
            and all(form(UUID, p["id"]) and type(p["name"]) is str and 1 <= len(p["name"]) <= 200
                    and positive(p["version"]) and p["scope"] in ("global", "agent")
                    and type(p["path"]) is str and form(SHA256, p["sha256"]) for p in policies)):
        raise Rejected("invalid_manifest")
    if m["format"] != "whitetower.bundle.v1" or m["combining_algorithm"] != "wt-deny-overrides-v1" \
            or m["language"] != "cedar":
        raise Rejected("unsupported")
    return m


def parse_static(policy: bytes) -> None:
    """Step V7 for one policy: it parses as static Cedar policies. cedarpy parses
    templates too, so a template is refused here. Nothing validates the policy
    against the bundle's schema, which is the core's job (POL-07)."""
    try:
        if cedarpy.PolicySet.from_str(policy.decode()).templates():
            raise Rejected("parse_error")
    except ValueError:  # a parse error, or text that is not UTF-8
        raise Rejected("parse_error") from None


def verify_bundle(case_dir: Path, trusted: dict[str, Ed25519PublicKey], case: dict) -> dict:
    """The verification steps V1 to V7 of section 7.4, in their order."""
    files = {p.relative_to(case_dir).as_posix(): p.read_bytes() for p in case_dir.rglob("*") if p.is_file()}
    manifest = files.pop("manifest.json")
    signature = files.pop("manifest.jws", b"").decode()
    files.pop("case.json")
    ref = case["ref"]
    # V1. Size.
    size = len(manifest) + sum(len(c) for c in files.values())
    if ref["size_bytes"] > 2 << 20 or size > 2 << 20 or len(files) > 1000:
        raise Rejected("oversized")
    # V2. Signature. The protected header has exactly alg, kid and typ, in any
    # order (section 7.2): any other member, such as b64, is refused.
    parts = signature.split(".")
    if len(parts) != 3 or parts[1] != "":
        raise Rejected("signature")
    try:
        header = json.loads(b64url(parts[0]))
    except ValueError:
        raise Rejected("signature") from None
    if type(header) is not dict or set(header) != {"alg", "kid", "typ"} \
            or header["alg"] != "EdDSA" or header["typ"] != "whitetower-bundle+jws":
        raise Rejected("signature")
    key = trusted.get(header["kid"]) if type(header["kid"]) is str else None
    if key is None:
        raise Rejected("unknown_key")
    signing_input = (parts[0] + "." + base64.urlsafe_b64encode(manifest).decode().rstrip("=")).encode()
    try:
        key.verify(b64url(parts[2]), signing_input)
    except (InvalidSignature, ValueError):
        raise Rejected("signature") from None
    # V3. Reference.
    digest = hashlib.sha256(manifest).hexdigest()
    if digest != ref["manifest_sha256"]:
        raise Rejected("manifest_mismatch")
    # V4. The manifest alone, then against the state.
    m = check_manifest(manifest)
    if m["agent_id"] != case["agent_id"] or m["version"] != ref["version"]:
        raise Rejected("invalid_manifest")
    # V5. Each policy's path is built from its entry, with no duplicates, and
    # the schema sits at schema.cedarschema; then exactly the listed files.
    listed = {}
    for p in m["policies"]:
        path = f"policies/{p['scope']}/{p['id']}.{m['language']}"
        if p["path"] != path or path in listed:
            raise Rejected("invalid_manifest")
        listed[path] = p["sha256"]
    if m["cedar_schema"]["path"] != "schema.cedarschema":
        raise Rejected("invalid_manifest")
    listed["schema.cedarschema"] = m["cedar_schema"]["sha256"]
    for path in sorted(listed):
        if path not in files:
            raise Rejected("missing_file")
        if hashlib.sha256(files[path]).hexdigest() != listed[path]:
            raise Rejected("file_hash")
    if set(files) - set(listed):
        raise Rejected("extra_file")
    # V6. No rollback.
    if m["version"] < case["active_version"] or (
            m["version"] == case["active_version"] and digest != case.get("active_manifest_sha256")):
        raise Rejected("older_version")
    # V7. Static policies.
    for p in m["policies"]:
        parse_static(files[p["path"]])
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

    # The trusted bundle keys, a JWK Set (section 7.3), of which the checker
    # uses the OKP keys on Ed25519 that have a key ID, as RFC 7517 asks.
    keys = json.loads((VECTORS / "bundles" / "trusted-keys.json").read_text(encoding="utf-8"))
    trusted = {k["kid"]: Ed25519PublicKey.from_public_bytes(b64url(k["x"])) for k in keys["keys"]
               if k.get("kty") == "OKP" and k.get("crv") == "Ed25519" and "kid" in k}
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
