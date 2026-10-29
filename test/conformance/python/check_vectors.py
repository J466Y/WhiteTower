"""Checks the conformance vectors with Python: cedarpy for Cedar, cryptography for Ed25519, PyYAML for manifests.

The Go tests in test/conformance check the same vectors with cedar-go, and the
manifest vectors with yaml.v3. Passing both shows that the decision profile
does not depend on one Cedar implementation, nor the reading of manifests on
one YAML parser, and gives the Python enforcement point (plan P1-09) a
reference to start from.

Run from the repository root with a Python that has cedarpy, cryptography and PyYAML:
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
import yaml
from decimal import Decimal

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
    """Base64url as RFC 7515 defines it: the URL-safe alphabet only, without
    padding, line breaks or any other character, which urlsafe_b64decode would
    take or skip. Raises ValueError otherwise."""
    if not re.fullmatch(r"[A-Za-z0-9_-]*", data):
        raise ValueError("not base64url")
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


def trusted_key(jwk: dict) -> Ed25519PublicKey | None:
    """The public key of a JWK of the trusted set (section 7.3), or None for a key
    that the checker cannot use and ignores, as RFC 7517 asks: another type or
    curve, no key ID, or an x that is not the base64url of 32 bytes."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or type(jwk.get("kid")) is not str or not jwk["kid"]:
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(b64url(jwk["x"]))
    except (KeyError, TypeError, ValueError):
        return None


def utf8_json(data: bytes):
    """Parses JSON in the encoding that section 1 states: UTF-8, without a byte order
    mark, which json.loads refuses in text. From bytes, json.loads would take a byte
    order mark, UTF-16 and UTF-32. Raises ValueError otherwise."""
    return json.loads(data.decode("utf-8"))


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

    A manifest that is not JSON in UTF-8 without a byte order mark (section 1), or
    not an object, or that has an unknown or a missing member, or a member of the
    wrong type, is invalid_manifest: the types are those of
    bundle-manifest.schema.json, the forms of its strings included. Then a format,
    combining algorithm or language that is not supported is unsupported, even
    though the schema's constant fails too. Paths need only be strings here: V5
    builds them from their entries.
    """
    try:
        m = utf8_json(manifest)
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
    # V2. Signature. The header and the signature are in base64url as RFC 7515
    # defines it, and the header is JSON in UTF-8 with exactly alg, kid and typ,
    # in any order (section 7.2): any other member, such as b64, is refused.
    parts = signature.split(".")
    if len(parts) != 3 or parts[1] != "":
        raise Rejected("signature")
    try:
        header = utf8_json(b64url(parts[0]))
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


class ManifestRefused(Exception):
    pass


# The manifest reader of section 3.1. PyYAML reads YAML 1.1, so the reader takes
# its events, never its types, and reads each unquoted scalar itself.
LITERALS = {"true": True, "false": False, "null": None}
# A plain decimal number as JSON writes it, the one number MAN-1 accepts unquoted.
PLAIN_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
# What the YAML 1.2 Core schema or YAML 1.1's types (yaml.org/type) read as
# other than a string, with a YAML 1.1 float of one decimal point, as PyYAML
# reads it: the type repository's expression would read 0.1.0 as a float.
NOT_A_STRING = re.compile("|".join([
    # Nulls and booleans, of both versions.
    r"~|null|Null|NULL|",
    r"y|Y|yes|Yes|YES|n|N|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF",
    # YAML 1.2 Core's integers and floats.
    r"[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+",
    r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)",
    # YAML 1.1's integers, floats and timestamps, and its merge and value keys.
    r"[-+]?0b[01_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+",
    r"[-+]?(?:[0-9][0-9_]*)?\.[0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*",
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}",
    r"[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?"
    r"(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?",
    r"<<|=",
]))


def read_manifest(data: bytes) -> bytes:
    """Reads a YAML manifest as MAN-1 does and returns its canonical JSON (sections 1 and 3.1).

    It refuses anchors, aliases, tags, and an unquoted scalar that is not a string in
    both YAML 1.1 and YAML 1.2, a merge key among them, unless it is true, false, null
    or a plain decimal number; and a manifest that is not I-JSON.
    """
    try:
        events = list(yaml.parse(data.decode("utf-8"), Loader=yaml.SafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError) as e:
        raise ManifestRefused(f"not YAML in UTF-8: {e}") from None
    starts = [i for i, e in enumerate(events) if isinstance(e, yaml.DocumentStartEvent)]
    if len(starts) != 1:
        raise ManifestRefused(f"{len(starts)} documents")
    value, _ = manifest_node(events, starts[0] + 1)
    return canonical_json(value).encode()


def manifest_node(events: list, i: int) -> tuple[object, int]:
    """Returns the value of the node whose events start at i, and the index of the next event."""
    e = events[i]
    if isinstance(e, yaml.AliasEvent) or e.anchor is not None:
        raise ManifestRefused("an anchor or an alias")
    if e.tag is not None:
        raise ManifestRefused(f"the tag {e.tag}")
    if isinstance(e, yaml.ScalarEvent):
        # Quoted and block scalars are strings.
        return (plain_scalar(e.value) if e.style is None else ijson_string(e.value)), i + 1
    i += 1
    if isinstance(e, yaml.SequenceStartEvent):
        items = []
        while not isinstance(events[i], yaml.SequenceEndEvent):
            item, i = manifest_node(events, i)
            items.append(item)
        return items, i + 1
    members = {}
    while not isinstance(events[i], yaml.MappingEndEvent):
        key, i = manifest_node(events, i)
        if not isinstance(key, str):
            raise ManifestRefused(f"the key {key!r} is not a string")
        if key in members:
            raise ManifestRefused(f"the key {key!r} twice")
        members[key], i = manifest_node(events, i)
    return members, i + 1


def plain_scalar(text: str) -> object:
    """Reads an unquoted scalar."""
    if text in LITERALS:
        return LITERALS[text]
    if PLAIN_DECIMAL.fullmatch(text):
        return ijson_number(text)
    if NOT_A_STRING.fullmatch(text):
        raise ManifestRefused(f"{text!r} is not a string in both YAML 1.1 and YAML 1.2")
    return ijson_string(text)


def ijson_string(text: str) -> str:
    """I-JSON has no surrogates, which PyYAML reads from escapes, and no noncharacters."""
    for c in text:
        if 0xD800 <= ord(c) <= 0xDFFF or 0xFDD0 <= ord(c) <= 0xFDEF or ord(c) & 0xFFFE == 0xFFFE:
            raise ManifestRefused(f"U+{ord(c):04X} is not I-JSON")
    return text


def ijson_number(text: str) -> int | float:
    """An integer of a magnitude of at most 2^53 - 1, or a number that a double holds as written."""
    exact = Decimal(text)
    if exact == exact.to_integral_value():
        if exact.copy_abs() > 2**53 - 1:
            raise ManifestRefused(f"{text} is not I-JSON: an integer's magnitude is at most 2^53 - 1")
        return int(exact)
    value = float(text)
    if Decimal(repr(value)) != exact:
        raise ManifestRefused(f"{text} is not I-JSON: a double cannot hold it")
    return value


def canonical_json(value: object) -> str:
    """RFC 8785: members in the order of their UTF-16 code units, numbers as ECMAScript writes them."""
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda m: m[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical_json(v) for k, v in members) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, float):
        return ecmascript_number(value)
    return json.dumps(value, ensure_ascii=False)


def ecmascript_number(value: float) -> str:
    """ECMAScript's Number::toString for a double that is not an integer, from its shortest digits."""
    sign, digits, exponent = Decimal(repr(value)).as_tuple()
    digits = "".join(map(str, digits))
    point = len(digits) + exponent
    if 0 < point <= 21:
        text = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        text = "0." + "0" * -point + digits
    else:
        text = digits[0] + ("." + digits[1:] if len(digits) > 1 else "") + f"e{point - 1:+d}"
    return ("-" if sign else "") + text


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

    # The trusted bundle keys, a JWK Set (section 7.3).
    keys = json.loads((VECTORS / "bundles" / "trusted-keys.json").read_text(encoding="utf-8"))
    trusted = {k["kid"]: key for k in keys["keys"] if (key := trusted_key(k)) is not None}
    bundle_cases = sorted(p for p in (VECTORS / "bundles").iterdir() if p.is_dir())
    for case_dir in bundle_cases:
        case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        try:
            got = verify_bundle(case_dir, trusted, case)
        except Rejected as r:
            got = {"outcome": "rejected", "reason": r.reason}
        check(f"bundle {case_dir.name}", got, case["expected"])

    # A failure may name a character that the console cannot encode, such as
    # an emoji on Windows: it is printed as an escape instead.
    sys.stdout.reconfigure(errors="backslashreplace")
    manifest_cases = sorted(p for p in (VECTORS / "manifests").iterdir() if p.is_dir())
    for case_dir in manifest_cases:
        case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        try:
            canonical = read_manifest((case_dir / "manifest.yaml").read_bytes())
        except ManifestRefused:
            got = {"outcome": "refused"}
        else:
            got = {"outcome": "accepted", "sha256": hashlib.sha256(canonical).hexdigest()}
            if case["expected"]["outcome"] == "accepted" and canonical != (case_dir / "canonical.json").read_bytes():
                failures += 1
                print(f"FAIL manifest {case_dir.name}: canonical JSON {canonical.decode()}")
        check(f"manifest {case_dir.name}", got, case["expected"])

    documents = json.loads((VECTORS / "manifests" / "documents.json").read_text(encoding="utf-8"))["documents"]
    for doc in documents:
        try:
            got = {"outcome": "accepted", "canonical_json": read_manifest(doc["yaml"].encode()).decode()}
        except ManifestRefused:
            got = {"outcome": "refused"}
        check(f"manifest document {doc['name']}", got, doc["expected"])

    total = len(combination["cases"]) + len(fail_closed["cases"]) + len(bundle_cases) + len(manifest_cases) + len(documents)
    print(f"{total} vectors, {failures} failures (cedarpy, cryptography, PyYAML)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
