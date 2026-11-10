"""Checks the conformance vectors with Python: cedarpy for Cedar, cryptography for Ed25519, PyYAML for manifests,
jsonschema for the request schema, idna for the hosts of URLs and addresses, and the standard library's json, hashlib
and hmac for canonical JSON, definition hashes and hashed arguments.

The Go tests in test/conformance check the same vectors with cedar-go, the
manifest vectors with yaml.v3, canonical JSON with the kit's own reader and
writer, and hosts with golang.org/x/net/idna. Passing both shows that the
decision profile does not depend on one Cedar implementation, nor the reading
of manifests on one YAML parser, nor canonical JSON on one writer, nor the
reading of URLs on one IDNA library, and gives the Python enforcement point
(plan P1-09) a reference to start from.

Run from the repository root with a Python that has cedarpy, cryptography, PyYAML, jsonschema and idna:
    python test/conformance/python/check_vectors.py
"""

from __future__ import annotations

import base64
import calendar
import copy
import hashlib
import hmac
import ipaddress
import json
import math
import re
import sys
import unicodedata
from pathlib import Path
from typing import NamedTuple

import cedarpy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import idna
import jsonschema
import yaml
from decimal import Decimal

VECTORS = Path(__file__).resolve().parent.parent / "vectors"
CEDAR_SCHEMA = Path(__file__).resolve().parents[3] / "api" / "policy" / "whitetower.cedarschema"
REQUEST_SCHEMA = Path(__file__).resolve().parents[3] / "api" / "policy" / "decision-request.schema.json"

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


def ecma262_pattern(validator, pattern, instance, schema):
    """The keyword pattern as JSON Schema reads it: an ECMA-262 regular expression, whose $ matches at the end of the
    string only, where Python's also matches before a final line break. The request schema's patterns end with $,
    which this reads as \\Z, the end alone."""
    if validator.is_type(instance, "string") and re.search(re.sub(r"\$\Z", r"\\Z", pattern), instance) is None:
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")


# The validator of decision-request.schema.json.
RequestValidator = jsonschema.validators.extend(jsonschema.Draft202012Validator, {"pattern": ecma262_pattern})

INT64 = range(-2**63, 2**63)


def check_integers(value) -> None:
    """Every number of the arguments is a signed 64-bit integer written without a fraction or an exponent (sections
    6.4 and 6.7). json.loads reads such a number as an int, exactly, and any other number as a float."""
    if type(value) is float or (type(value) is int and value not in INT64):
        raise InvalidRequest(f"{value!r} is not a signed 64-bit integer")
    if type(value) is list:
        for item in value:
            check_integers(item)
    elif type(value) is dict:
        for item in value.values():
            check_integers(item)


def check_time(value) -> None:
    """The time has the form of section 1 and exists: a month of 1 to 12, a day of that month, February 29 in leap
    years only, and at most 23:59:59. The schema's pattern checks the form only. calendar counts the days of the year
    0, which RFC 3339 and Go's time allow, and datetime does not."""
    if type(value) is not str or not TIMESTAMP.fullmatch(value):
        raise InvalidRequest(f"the time {value!r} is not in the form of section 1")
    year, month, day = int(value[0:4]), int(value[5:7]), int(value[8:10])
    hour, minute, second = int(value[11:13]), int(value[14:16]), int(value[17:19])
    if not (1 <= month <= 12 and 1 <= day <= calendar.monthrange(year, month)[1]
            and hour <= 23 and minute <= 59 and second <= 59):
        raise InvalidRequest(f"the time {value!r} does not exist")


def uid(entity_type: str, entity_id: str) -> dict:
    return {"type": f"WhiteTower::{entity_type}", "id": entity_id}


def to_cedar(req: dict) -> tuple[dict, list]:
    """Maps an AuthZEN request of the profile to a cedarpy request and entities (section 6.4). It raises
    InvalidRequest for a request that breaks a rule the schema does not state: an agent action for another agent, an
    argument that is not a signed 64-bit integer, or a time that does not exist."""
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
    check_time(ctx["time"])
    context = {"time": {"__extn": {"fn": "datetime", "arg": ctx["time"]}}}
    for key in ("task_id", "trace_id"):
        if key in ctx:
            context[key] = ctx[key]
    if "args" in ctx:
        if want != "tool":
            raise InvalidRequest("args on a non-tool action")
        check_integers(ctx["args"])
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

    def __init__(self, agent_id: str, bundle_version: int, policies: list[dict], validator: RequestValidator):
        self.agent_id = agent_id
        self.bundle_version = bundle_version
        self.validator = validator
        self.owner_of: list[str] = []
        texts = []
        for p in policies:
            count = len(cedarpy.PolicySet.from_str(p["text"]))  # raises if it does not parse
            self.owner_of += [p["id"]] * count
            texts.append(p["text"])
        self.policies = cedarpy.PolicySet.from_str("\n".join(texts))

    def owners(self, policy_ids) -> list[str]:
        return sorted({self.owner_of[int(pid.removeprefix("policy"))] for pid in policy_ids})

    def evaluate(self, req) -> dict:
        """Decides a request after the gate, with the reasons of section 6.6 in their order: error.unknown_agent for a
        request whose subject is not the bundle's agent, read before the profile is checked; error.invalid_request for
        a request outside the profile, which does not match the schema or breaks a rule it does not state; then the
        policies, whose decisions carry the bundle's version."""
        subject = req.get("subject") if type(req) is dict else None
        if type(subject) is not dict or subject.get("type") != "agent" or subject.get("id") != self.agent_id:
            return deny("error.unknown_agent")
        if not self.validator.is_valid(req):
            return deny("error.invalid_request")
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
            return self.decided(False, "error.evaluation", [])
        reasons = list(diag.reasons) if diag else []
        if errors or result.decision not in (cedarpy.Decision.Allow, cedarpy.Decision.Deny):
            return self.decided(False, "error.evaluation", self.owners(errors))
        if result.decision == cedarpy.Decision.Allow:
            return self.decided(True, "policy.permit", self.owners(reasons))
        if reasons:
            return self.decided(False, "policy.forbid", self.owners(reasons))
        return self.decided(False, "policy.no_permit", [])

    def decided(self, decision: bool, reason: str, policies: list[str]) -> dict:
        """A decision of the bundle's policies, which carries the version of the bundle that decided (section 6.6)."""
        return {"decision": decision, "reason": reason, "policies": policies, "bundle_version": self.bundle_version}


def deny(reason: str) -> dict:
    """A denial before the bundle's policies decide, which carries no bundle version: a gate's reason, which never
    carries one, error.unknown_agent or error.invalid_request (section 6.6)."""
    return {"decision": False, "reason": reason, "policies": []}


# The reasons with which a response always carries the version of the bundle that decided, and those with which it
# never does (section 6.6). It may carry it, or not, with error.timeout, error.unknown_agent and error.invalid_request.
ALWAYS_BUNDLE_VERSION = {"policy.permit", "policy.forbid", "policy.no_permit", "error.evaluation"}
NEVER_BUNDLE_VERSION = {"gate.no_state", "gate.lease_expired", "gate.halted", "gate.fleet_halted", "gate.lifecycle",
                        "gate.no_bundle", "gate.evidence_full"}

# The version of the bundle that the policies of a vector make up. Any version would do: what the checker checks is
# that a response carries it where section 6.6 says it always does.
VECTOR_BUNDLE_VERSION = 42


def bundle_version_error(response: dict) -> str | None:
    """What is wrong with a response's bundle_version for its reason (section 6.6), or None."""
    if response["reason"] in ALWAYS_BUNDLE_VERSION and response.get("bundle_version") != VECTOR_BUNDLE_VERSION:
        return f"bundle_version {response.get('bundle_version')}, want {VECTOR_BUNDLE_VERSION}"
    if response["reason"] in NEVER_BUNDLE_VERSION and "bundle_version" in response:
        return f"bundle_version {response['bundle_version']}, want none"
    return None


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
    if not gate_opens_in(state["lifecycle_state"], state["environment"]):
        return "gate.lifecycle"
    if not state["bundle_active"]:
        return "gate.no_bundle"
    if state["evidence_buffer_full"]:
        return "gate.evidence_full"
    return ""


def gate_opens_in(lifecycle_state: str, environment: str) -> bool:
    """Row 5 of section 5.4 and EP-6: active opens the gate with either environment that the registration returns,
    and validated and ready only with non_production, so that no decision is labeled production for an agent that is
    not active. An unknown state, or an environment that is neither, keeps it closed (EP-10)."""
    if environment not in ("production", "non_production"):
        return False
    if lifecycle_state == "active":
        return True
    return lifecycle_state in ("validated", "ready") and environment == "non_production"


def with_environment(req: dict, environment: str) -> dict:
    """A copy of the request whose subject carries the environment given, as an enforcement point builds it from its
    registration (section 6.2)."""
    req = copy.deepcopy(req)
    req["subject"]["properties"]["environment"] = environment
    return req


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


class NoCanonicalJSON(Exception):
    """A value that section 4.10's canonical JSON cannot write: a number with a fraction or an exponent that is not
    finite as a double, a member name that repeats, or a string with a lone surrogate."""


class Members(list):
    """An object as the pairs of its members, in their order, repeated names included."""


def not_json(text: str):
    raise ValueError(f"{text} is not JSON")


def read_json(text: str):
    """Reads JSON text as section 4.10 needs it, keeping what canonical JSON cannot write: objects as Members, so that
    a member name can repeat. json.loads already reads a number without a fraction or an exponent as an exact int, and
    any other as a double, 1e400 as infinity, and keeps a lone surrogate in a string. NaN and Infinity, which it
    accepts, are not JSON."""
    return json.loads(text, object_pairs_hook=Members, parse_constant=not_json)


def pairs(value: dict | Members) -> list:
    """The members of an object, read by json.loads alone or by read_json."""
    return list(value.items()) if isinstance(value, dict) else list(value)


def repeats(value: dict | Members) -> bool:
    """Whether a member name repeats among an object's members, not deeper."""
    names = [name for name, _ in pairs(value)]
    return len(set(names)) != len(names)


def has_lone_surrogate(text: str) -> bool:
    """json.loads joins a surrogate pair into one character, so any surrogate left is lone."""
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


def canonical_json(value: object) -> str:
    """The canonical JSON of section 4.10: RFC 8785, with members in the order of their UTF-16 code units and numbers
    as ECMAScript writes them, except that a number written without a fraction or an exponent is written exactly. It
    raises NoCanonicalJSON for what it cannot write."""
    if isinstance(value, (dict, Members)):
        if repeats(value):
            raise NoCanonicalJSON("a member name repeats")
        members = sorted(pairs(value), key=lambda m: m[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(json_string(k) + ":" + canonical_json(v) for k, v in members) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, str):
        return json_string(value)
    if type(value) is float:
        if not math.isfinite(value):
            raise NoCanonicalJSON(f"{value} is not finite as a double")
        return ecmascript_number(value)
    return json.dumps(value)


def json_string(text: str) -> str:
    """A string as RFC 8785 writes it, which is what json.dumps writes without ensure_ascii."""
    if has_lone_surrogate(text):
        raise NoCanonicalJSON("a string has a lone surrogate")
    return json.dumps(text, ensure_ascii=False)


def ecmascript_number(value: float) -> str:
    """ECMAScript's Number::toString for a double, from its shortest digits, as RFC 8785 writes it: a whole number
    without a fraction, as 1 for 1.0, and 0 for -0.0."""
    if value == 0:
        return "0"
    sign, digits, exponent = Decimal(repr(value)).normalize().as_tuple()
    digits = "".join(map(str, digits))
    point = len(digits) + exponent
    if len(digits) <= point <= 21:
        text = digits + "0" * (point - len(digits))
    elif 0 < point <= 21:
        text = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        text = "0." + "0" * -point + digits
    else:
        text = digits[0] + ("." + digits[1:] if len(digits) > 1 else "") + f"e{point - 1:+d}"
    return ("-" if sign else "") + text


# The members of an MCP tool that its definition hash covers (section 4.10).
MCP_DEFINITION_MEMBERS = {"name", "title", "description", "inputSchema", "outputSchema", "annotations"}


def definition(members: Members) -> dict | None:
    """A definition as section 4.10 hashes it: the canonical JSON of the members given, those that are null left out,
    and its SHA-256. None when it has no hash: a name that repeats among the members, even with a null value, or a
    value that canonical JSON cannot write."""
    try:
        if repeats(members):
            raise NoCanonicalJSON("a member name repeats")
        text = canonical_json(Members((name, v) for name, v in members if v is not None))
    except NoCanonicalJSON:
        return None
    return {"canonical_json": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}


def mcp_definitions(message) -> list | None:
    """The definition of each tool of a tools/list response, read from the JSON-RPC message itself, or None when a
    member name repeats in the message or in its result, which leaves every tool without a hash. Only the members that
    the hash covers count: what a tool carries beside them never takes its hash away."""
    if repeats(message):
        return None
    result = dict(pairs(message))["result"]
    if repeats(result):
        return None
    return [definition(Members(m for m in pairs(tool) if m[0] in MCP_DEFINITION_MEMBERS))
            for tool in dict(pairs(result))["tools"]]


def function_definition(name: str, input_schema) -> dict | None:
    """The definition of a function, http or other tool: its name and the JSON Schema of its parameters, as the
    members name and inputSchema, or its name alone when the framework presents no schema."""
    members = Members([("name", name)])
    if input_schema is not None:
        members.append(("inputSchema", input_schema))
    return definition(members)


# The length, in characters, beyond which an event records an argument name as its SHA-256 (section 8.3).
MAX_NAME_LENGTH = 128


def hashed_arguments(key: bytes, arguments) -> dict:
    """The hashed mode of section 8.3: the HMAC-SHA-256 of the arguments' canonical JSON, with the key given. Arguments
    without one are recorded by their names alone, each once: a name longer than 128 characters, or with a lone
    surrogate, which an event cannot write, as the SHA-256 of its UTF-8 bytes with each lone surrogate replaced by
    U+FFFD."""
    try:
        canonical = canonical_json(arguments).encode()
    except NoCanonicalJSON:
        names, hashed = set(), set()
        for name, _ in pairs(arguments):
            if has_lone_surrogate(name) or len(name) > MAX_NAME_LENGTH:
                replaced = "".join("\N{REPLACEMENT CHARACTER}" if has_lone_surrogate(c) else c for c in name)
                hashed.add(hashlib.sha256(replaced.encode()).hexdigest())
            else:
                names.add(name)
        return {"names": sorted(names), "names_sha256": sorted(hashed)}
    return {"canonical_json": canonical.decode(), "hmac_sha256": hmac.new(key, canonical, hashlib.sha256).hexdigest()}


class CannotRead(Exception):
    """A value that the url_host transform cannot read (section 6.11)."""


class NoReference(Exception):
    """A URL that makes no reference: one that url_host cannot read, whose scheme is not http or https, or with a
    backslash in its path (section 4.10)."""


class URL(NamedTuple):
    """A URL as url_host reads it: its scheme, port digits and path as given, the host that url_host reads, and bare,
    the value as given without its user information, query and fragment, as EP-14 writes a URL of a command line."""
    scheme: str
    host: str
    port: str
    path: str
    bare: str


# What url_host ignores at the start and at the end of a value: spaces and C0 control characters.
IGNORED = "".join(map(chr, range(0x21)))
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
# Unicode's White_Space property, which the standard library cannot read.
WHITE_SPACE = frozenset("\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
                        "\u2028\u2029\u202f\u205f\u3000")
PORT = re.compile(r"[0-9]{1,5}")
NUMBER = re.compile(r"[0-9]+|0x[0-9a-f]*")
IPV4_PART = re.compile(r"[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]")
# A label of a host in A-labels, within the bounds of DNS.
HOST_LABEL = re.compile(r"[a-z0-9_-]{1,63}")
# The characters that versions of UTS #46, or its transitional and non-transitional processing, read differently: the
# sharp s, the final sigma, the zero width non-joiner and joiner, and the capital sharp s (section 6.11, step 7).
READ_DIFFERENTLY = frozenset(map(chr, (0xDF, 0x3C2, 0x200C, 0x200D, 0x1E9E)))


def read_url(value: str) -> URL:
    """Reads a value as url_host does, step by step (section 6.11), or raises CannotRead. A string with a lone
    surrogate, which UTF-8 cannot hold, cannot be read either."""
    if has_lone_surrogate(value):
        raise CannotRead("the value is not Unicode")
    # 1. Leading and trailing spaces and C0 control characters are ignored, and a control character anywhere else
    # cannot be read.
    start, end = len(value) - len(value.lstrip(IGNORED)), len(value.rstrip(IGNORED))
    text = value[start:max(start, end)]
    if any(c < " " or c == "\x7f" for c in text):
        raise CannotRead("a control character")
    # 2. A scheme and //.
    if (m := SCHEME.match(text)) is None:
        raise CannotRead("no scheme followed by //")
    rest = text[m.end():]
    # 3. The authority runs to the first /, ? or #.
    authority = re.match(r"[^/?#]*", rest).group()
    if any(c == "\\" or c in WHITE_SPACE for c in authority):
        raise CannotRead("a backslash or whitespace in the authority")
    # 4. The host follows the last @ of the authority.
    host_port = authority[authority.rfind("@") + 1:]
    host, port = read_host_port(host_port)
    path, cut, _ = re.match(r"([^?#]*)([?#]?)(.*)", rest[len(authority):], re.DOTALL).groups()
    bare = value[:start] + m.group() + host_port + path + ("" if cut else value[max(start, end):])
    return URL(m.group()[:-3], host, port, path, bare)


def read_host_port(host_port: str) -> tuple[str, str]:
    """The host and the port that follow the user information: steps 5 to 8."""
    if host_port.startswith("["):
        address, bracket, after = host_port[1:].partition("]")
        if not bracket:
            raise CannotRead("an IPv6 address without its closing bracket")
        host = read_ipv6(address)
        if after and not after.startswith(":"):
            raise CannotRead("text after an IPv6 address")
        has_port, port = after.startswith(":"), after[1:]
    else:
        name, colon, port = host_port.partition(":")
        host, has_port = read_host(name), bool(colon)
    # 5. A port is 1 to 5 digits, and at most 65535.
    if has_port and not (PORT.fullmatch(port) and int(port) <= 65535):
        raise CannotRead("a port that is not 1 to 5 digits, at most 65535")
    return host, port


def read_ipv6(address: str) -> str:
    """An IPv6 address, given without its brackets: step 6."""
    if "%" in address or "." in address:
        raise CannotRead("an IPv6 address with a zone ID or a dotted part")
    try:
        addr = ipaddress.IPv6Address(address)
    except ValueError:
        raise CannotRead("not an IPv6 address") from None
    if addr.ipv4_mapped is not None:
        raise CannotRead("an IPv6 address in the IPv4-mapped range")
    # compressed writes an IPv6 address as section 4 of RFC 5952 says.
    return f"[{addr.compressed}]"


def u_label(label: str) -> str:
    """A label of a host that UTS #46 has mapped, with an A-label decoded: one that does not decode as IDNA says, to a
    label that is not all ASCII, that UTS #46 maps to itself, and that encodes back to the same A-label, raises."""
    if not label.startswith("xn--"):
        return label
    decoded = label[4:].encode("ascii").decode("punycode")
    if decoded.isascii() or idna.uts46_remap(decoded, std3_rules=False) != decoded \
            or "xn--" + decoded.encode("punycode").decode("ascii") != label:
        raise CannotRead("an A-label that does not decode")
    return decoded


def read_host(name: str) -> str:
    """A host that is not an IPv6 address: steps 7 and 8. Hosts are converted to A-labels as WHATWG's "domain to ASCII"
    does without strictness: the idna package's uts46_remap, without the STD3 rules, then Punycode, rather than
    idna.encode, which applies IDNA 2008 and refuses underscores. uts46_remap does not check Bidi, so it is checked on
    every label of a domain that has a right-to-left one, as UTS #46 says. Joiners need no check in context: a host
    that holds one cannot be read."""
    # 7. A % cannot be read; the rest is converted to A-labels, in lowercase, without one trailing dot.
    if "%" in name:
        raise CannotRead("a % in the host")
    # The bound of DNS applies as written too, so that a host padded with characters that UTS #46 ignores is refused
    # before it is converted, and the idna package's limit of 1024 characters is never met.
    if len(name.removesuffix(".")) > 253:
        raise CannotRead("a host longer than 253 characters as written")
    try:
        labels = [u_label(label) for label in idna.uts46_remap(name, std3_rules=False).split(".")]
        # The characters that UTS #46 reads differently, as written, and within the labels converted, which hold
        # those of the A-labels given. U+1E9E is checked as written, since Unicode 15.0 maps it to ss.
        if READ_DIFFERENTLY.intersection(name) or any(READ_DIFFERENTLY.intersection(label) for label in labels):
            raise CannotRead("a character that versions of UTS #46 read differently")
        # The idna package's tables are of a later version of Unicode than unicodedata's, which gives the Bidi classes:
        # a code point that unicodedata does not know, as written or within the labels converted, cannot be read, so
        # that one host is read with one version.
        if any(unicodedata.category(c) == "Cn" for c in name + "".join(labels)):
            raise CannotRead("a code point that unicodedata does not know")
        rtl = any(unicodedata.bidirectional(c) in ("R", "AL", "AN") for label in labels for c in label)
        for label in filter(None, labels):
            idna.check_initial_combiner(label)
            if rtl:
                idna.check_bidi(label, check_ltr=True)
    except (idna.IDNAError, UnicodeError, ValueError) as e:
        raise CannotRead(f"a host that IDNA cannot convert: {e}") from None
    host = ".".join(label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
                    for label in labels).lower().removesuffix(".")
    labels = host.split(".")
    if len(host) > 253 or not all(HOST_LABEL.fullmatch(label) for label in labels):
        raise CannotRead("an empty label, a character that a host cannot have, or beyond the bounds of DNS")
    # 8. A host whose last label is a number is an IPv4 address of four decimal numbers.
    if NUMBER.fullmatch(labels[-1]) and not (len(labels) == 4 and all(IPV4_PART.fullmatch(p) for p in labels)):
        raise CannotRead("an IPv4 address that is not four decimal numbers")
    return host


DEFAULT_PORTS = {"http": 80, "https": 443}
UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
# What RFC 3986 allows in a path segment as it is (section 3.3): unreserved characters, sub-delimiters, : and @.
IN_SEGMENT = UNRESERVED | frozenset("!$&'()*+,;=:@")
# What is not: one character to percent-encode, or a percent-encoded octet.
NOT_IN_SEGMENT = re.compile(r"%([0-9A-Fa-f]{2})|([^" + re.escape("".join(sorted(IN_SEGMENT))) + "])")


def normalized(url: URL) -> str:
    """A URL normalized as section 4.10 says, or NoReference for a scheme other than http and https, or a backslash in
    the path."""
    scheme = url.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise NoReference(f"the scheme {url.scheme} is not http or https")
    if "\\" in url.path:
        raise NoReference("a backslash in the path")
    port = "" if not url.port or int(url.port) == DEFAULT_PORTS[scheme] else f":{int(url.port)}"
    return f"{scheme}://{url.host}{port}{remove_dot_segments(normalize_percent_encoding(url.path)) or '/'}"


def normalize_percent_encoding(path: str) -> str:
    """Percent-encodes, as UTF-8, each character that RFC 3986 does not allow in a path, and each % that two
    hexadecimal digits do not follow; then writes the hexadecimal digits of every percent-encoded octet in uppercase,
    and decodes those of unreserved characters (RFC 3986, section 6.2.2). A segment that is exactly <redacted> stays as
    it is, so that redacting a reference again changes nothing."""
    def triplet(m: re.Match) -> str:
        if m.group(1):
            c = chr(int(m.group(1), 16))
            return c if c in UNRESERVED else f"%{m.group(1).upper()}"
        return "".join(f"%{b:02X}" for b in m.group(2).encode("utf-8"))
    return "/".join(s if s == REDACTED else NOT_IN_SEGMENT.sub(triplet, s) for s in path.split("/"))


def remove_dot_segments(path: str) -> str:
    """Removes the dot segments of a path as RFC 3986 says, in section 5.2.4."""
    output: list[str] = []
    while path:
        if path.startswith(("../", "./")):
            path = path.partition("/")[2]
        elif path.startswith("/./") or path == "/.":
            path = "/" + path[3:]
        elif path.startswith("/../") or path == "/..":
            path = "/" + path[4:]
            output = output[:-1]
        elif path in (".", ".."):
            path = ""
        else:
            segment = re.match(r"/?[^/]*", path).group()
            output.append(segment)
            path = path[len(segment):]
    return "".join(output)


REDACTED = "<redacted>"
# The flags whose names contain one of these words, in any case, have secrets as values (EP-14).
SECRET_WORDS = ("token", "secret", "password", "passwd", "key", "auth", "credential", "cookie")
# ASCII letters in lowercase, every other character as it is: str.lower would map the Kelvin sign to k.
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def normalized_url(value: str, rules: dict) -> str:
    """A remote server's URL, or a model's endpoint, normalized as section 4.10 says, with the path segment that
    follows each of the deployment's prefixes redacted (EP-14), or NoReference."""
    try:
        url = read_url(value)
    except CannotRead as e:
        raise NoReference(str(e)) from None
    return redact_prefixes(normalized(url), rules.get("url_prefixes", []))


def redact_prefixes(url: str, prefixes: list[str]) -> str:
    """Replaces with <redacted> the path segment, up to the next / or to the end, that follows each prefix that a
    normalized URL starts with, every prefix matched before any replacement. A URL equal to a prefix keeps it whole."""
    out, last = "", 0
    for start in sorted({len(p) for p in prefixes if len(url) > len(p) and url.startswith(p)}):
        if start < last:
            continue
        end = url.find("/", start)
        end = len(url) if end < 0 else end
        out, last = out + url[last:start] + REDACTED, end
    return out + url[last:]


# A named value: a name of ASCII letters, digits, _, . and -, not starting with -, then = (EP-14).
NAMED_VALUE = re.compile(r"([A-Za-z0-9_.][A-Za-z0-9_.-]*)=")
# A header: a name of ASCII letters, digits and -, not starting with -, then : and the spaces after it, as an HTTP
# header is written (EP-14).
HEADER = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]*): *")


def secret_name(name: str, rules: dict) -> bool:
    """Whether the name of a flag, a named value or a header is a secret's: it contains one of EP-14's words, comparing
    ASCII letters without regard to case, or it is one of the deployment's flags, matched exactly, case included."""
    return any(w in name.translate(ASCII_LOWER) for w in SECRET_WORDS) or name in rules.get("flags", [])


def redacts_next(arg: str, rules: dict) -> bool:
    """Whether an argument, read as given, is a flag written without = whose name, after all its leading dashes, is a
    secret's, so that the argument after it is its value."""
    return arg.startswith("-") and "=" not in arg and secret_name(arg.lstrip("-"), rules)


def is_url(value: str) -> bool:
    """Whether an argument or a value starts with a scheme and //, once what url_host ignores at its start is left out."""
    return SCHEME.match(value.lstrip(IGNORED)) is not None


def redact_url(arg: str, rules: dict) -> str:
    """A URL of a command line as EP-14 writes it: normalized and redacted when a deployment prefix matches it, and
    otherwise as given without its user information, query and fragment; <redacted> when url_host cannot read it."""
    try:
        url = read_url(arg)
    except CannotRead:
        return REDACTED
    prefixes = rules.get("url_prefixes", [])
    try:
        n = normalized(url)
    except NoReference:
        return url.bare
    return redact_prefixes(n, prefixes) if any(n.startswith(p) for p in prefixes) else url.bare


def redact_value(value: str, rules: dict) -> str:
    """An argument that is not a flag, or a value, as EP-14 writes it: a URL as redact_url says; then a named value,
    whose value becomes <redacted> when its name is a secret's; then a header, written as its name, :, a space and
    <redacted> when its name is a secret's, and otherwise keeping its name, the : and the spaces after it; and otherwise
    as given. The value of a named value, and the rest of a header, whose name is not a secret's, are values in turn,
    read in a loop, so that no nesting meets Python's limit on recursion."""
    out = ""
    while True:
        if is_url(value):
            return out + redact_url(value, rules)
        for pattern, redacted in ((NAMED_VALUE, "{}=" + REDACTED), (HEADER, "{}: " + REDACTED)):
            if (m := pattern.match(value)) is not None:
                if secret_name(m.group(1), rules):
                    return out + redacted.format(m.group(1))
                out, value = out + m.group(), value[m.end():]
                break
        else:
            return out + value


def redact_argument(arg: str, rules: dict) -> str:
    """An argument as EP-14 writes it: a flag written --flag=value with <redacted> as its value when its name is a
    secret's, and otherwise with its value as redact_value says; any other flag as given; and an argument that is not a
    flag as redact_value says."""
    if not arg.startswith("-"):
        return redact_value(arg, rules)
    flag, joined, value = arg.partition("=")
    if not joined:
        return arg
    return f"{flag}={REDACTED if secret_name(flag.lstrip('-'), rules) else redact_value(value, rules)}"


def redact_command(command: list[str], rules: dict) -> list[str]:
    """A command and its arguments redacted as EP-14 says: the argument after a flag whose name is a secret's becomes
    <redacted>, and every other is written as redact_argument says."""
    return [REDACTED if i > 0 and redacts_next(command[i - 1], rules) else redact_argument(arg, rules)
            for i, arg in enumerate(command)]


def reference(entry: dict, rules: dict) -> str:
    """The reference of an entry, as its string form (section 4.10), or NoReference."""
    kind = entry["kind"]
    if kind == "remote_server":
        return normalized_url(entry["url"], rules)
    if kind == "connector":
        return f"connector:{entry['provider']}/{entry['connector_id']}"
    if kind == "local_server":
        return "stdio:" + canonical_json(redact_command(entry["command"], rules))
    if kind == "mcp_tool":
        return canonical_json({"name": entry["name"], "server": reference(entry["server"], rules)})
    if kind == "tool":
        return canonical_json({"name": entry["name"]})
    if kind == "builtin_tool":
        return canonical_json({"provider": entry["provider"], "type": entry["type"]})
    if kind == "model":
        endpoint = normalized_url(entry["endpoint"], rules)
        return canonical_json({"endpoint": endpoint, "name": entry["name"], "provider": entry["provider"]})
    raise ValueError(f"unknown kind {kind}")


def clean_path(value: str) -> str:
    """The path transform, from the steps of section 6.11 rather than posixpath.normpath, which keeps a leading //."""
    # 1. A control character cannot be read.
    if any(c < " " or c == "\x7f" for c in value):
        raise CannotRead("a control character")
    # 2. Backslashes become slashes.
    value = value.replace("\\", "/")
    absolute = value.startswith("/")
    # 3. Empty segments and . are dropped, and .. removes the segment before it, unless that segment is a .. kept at
    # the start; with no segment before it, .. is dropped in an absolute path and kept in a relative one.
    segments: list[str] = []
    for segment in value.split("/"):
        if segment in ("", "."):
            continue
        if segment != "..":
            segments.append(segment)
        elif segments and segments[-1] != "..":
            segments.pop()
        elif not absolute:
            segments.append(segment)
    # 4. One leading slash for an absolute path, none for a relative one; an empty result is / or .
    text = "/".join(segments)
    return "/" + text if absolute else text or "."


# What a display name cannot hold (section 6.11, email_domain, step 2), and what a local part cannot (step 3).
NOT_IN_NAME = frozenset('"<>@,;:()[]\\')
NOT_IN_LOCAL_PART = frozenset('"()<>[]\\,;:') | WHITE_SPACE


def email_domain(value: str) -> str:
    """The domain of an address as email_domain reads it, step by step (section 6.11), or CannotRead."""
    # 1. Leading and trailing spaces are ignored, and a control character anywhere, of Unicode's Cc category, C1
    # included, cannot be read.
    if any(unicodedata.category(c) == "Cc" for c in value):
        raise CannotRead("a control character")
    # 2. The address, alone or after a name.
    address = angle_address(value.strip(" "))
    # 3. Exactly one @, and a local part that is not empty, without whitespace, Unicode's White_Space property, or the
    # characters that parsers read differently.
    local, _, domain = address.partition("@")
    if address.count("@") != 1:
        raise CannotRead("not exactly one @")
    if not local or NOT_IN_LOCAL_PART.intersection(local):
        raise CannotRead("an empty local part, or one with a character it may not have")
    # 4. The domain, as url_host reads a host. Brackets and colons are characters that a host cannot have, so neither
    # an IPv6 address nor a domain literal can be read.
    host = read_host(domain)
    if NUMBER.fullmatch(host.split(".")[-1]):
        raise CannotRead("a domain whose last label is a number")
    return host


def angle_address(text: str) -> str:
    """The address of a value as step 2 of email_domain reads it: the value itself, Display Name <address> or
    "Quoted Name" <address>. A name that is not empty is followed by at least one space before <."""
    if text.startswith('"'):
        name, closed, after = text[1:].partition('"')
        if not closed or "\\" in name:
            raise CannotRead("a quoted name without its closing quote, or with a backslash")
        rest = after.lstrip(" ")
        if rest == after:
            raise CannotRead("no space after a quoted name")
    elif text.endswith(">"):
        name, opened, _ = text.partition("<")
        if not opened or NOT_IN_NAME.intersection(name) or name and not name.endswith(" "):
            raise CannotRead("a display name with a character it may not have, or no space after it")
        rest = text[len(name):]
    else:
        return text
    if not (rest.startswith("<") and rest.endswith(">")):
        raise CannotRead("no <address> after a name")
    return rest[1:-1]


# The transforms of section 6.11, each from a string to a string, or CannotRead.
TRANSFORMS = {
    "lowercase": lambda value: value.translate(ASCII_LOWER),
    "path": clean_path,
    "url_host": lambda value: read_url(value).host,
    "email_domain": email_domain,
}


class InvalidArgument(Exception):
    """A call's arguments that EP-19 denies with error.invalid_request (section 6.11): a declared argument whose value
    does not fit its declared type, or that its transform cannot read."""


def tool_record(arguments, declared: list[dict]) -> dict:
    """A tool's record of context.args as EP-19 fills it from the call's arguments, an empty object when the call has
    none: each declared argument that the arguments have, under its name, with its transform applied, and nothing else;
    a set as its distinct elements in ascending order. A missing argument is left out. It raises InvalidArgument for
    arguments that are not an object, or that repeat a member name, whatever the tool declares; a path through a value
    that is not an object, or through an object that repeats a member name; and a declared argument's value that does
    not fit its type, null and a string with a lone surrogate included, or that its transform cannot read."""
    if not isinstance(arguments, (dict, Members)):
        raise InvalidArgument("the arguments are not an object")
    if repeats(arguments):
        raise InvalidArgument("a member name repeats in the arguments")
    record = {}
    for arg in declared:
        value, found = arguments, True
        for name in arg["path"]:
            if not isinstance(value, (dict, Members)):
                raise InvalidArgument("the path goes through a value that is not an object")
            if repeats(value):
                raise InvalidArgument("a member name repeats in an object that the path reads")
            members = dict(pairs(value))
            if name not in members:
                found = False
                break
            value = members[name]
        if found:
            record[arg["name"]] = fit(value, arg["type"], arg.get("transform"))
    return record


def fit(value, declared_type: str, transform: str | None):
    """A value as its declared type holds it, with the transform applied to each string, or InvalidArgument."""
    if declared_type == "String":
        return fit_string(value, transform)
    if declared_type == "Long":
        return fit_long(value)
    if declared_type == "Bool":
        if type(value) is not bool:
            raise InvalidArgument("not a boolean")
        return value
    if declared_type in ("Set<String>", "Set<Long>"):
        if type(value) is not list:
            raise InvalidArgument("not an array")
        fit_item = fit_long if declared_type == "Set<Long>" else lambda item: fit_string(item, transform)
        return sorted({fit_item(item) for item in value})
    raise ValueError(f"the type {declared_type} is not one that section 7.7 names")


def fit_string(value, transform: str | None) -> str:
    """A string with the transform applied, if there is one, or InvalidArgument."""
    if type(value) is not str:
        raise InvalidArgument("not a string")
    if has_lone_surrogate(value):
        raise InvalidArgument("a string with a lone surrogate")
    if not transform:
        return value
    try:
        return TRANSFORMS[transform](value)
    except CannotRead as e:
        raise InvalidArgument(str(e)) from None


def fit_long(value) -> int:
    """A signed 64-bit integer written without a fraction or an exponent, which json.loads reads as an int, never a
    bool (section 6.4)."""
    if type(value) is not int or value not in INT64:
        raise InvalidArgument("not a signed 64-bit integer without a fraction or an exponent")
    return value


def main() -> int:
    failures = 0
    # Python converts integers of at most 4300 digits by default. Section 4.10 writes them exactly, whatever their size.
    sys.set_int_max_str_digits(0)

    def check(name: str, got: dict, want: dict) -> None:
        nonlocal failures
        if got != want:
            failures += 1
            print(f"FAIL {name}: got {got}, want {want}")

    def check_response(name: str, got: dict, want: dict) -> None:
        """Compares a response's decision, reason and policies with the vector's, and checks its bundle_version by its
        reason (section 6.6)."""
        nonlocal failures
        check(name, {k: got[k] for k in ("decision", "reason", "policies")}, want)
        if (error := bundle_version_error(got)) is not None:
            failures += 1
            print(f"FAIL {name}: reason {got['reason']} with {error}")

    request_validator = RequestValidator(json.loads(REQUEST_SCHEMA.read_text(encoding="utf-8")))
    combination = json.loads((VECTORS / "combination.json").read_text(encoding="utf-8"))
    schema = CEDAR_SCHEMA.read_text(encoding="utf-8").replace("type ToolArgs = {};", combination["tool_args_extension"], 1)
    for case in combination["cases"]:
        for p in case["policies"]:
            passes = cedarpy.validate_policies(p["text"], schema).validation_passed
            if passes != p["valid"]:
                failures += 1
                print(f"FAIL {case['id']}: policy {p['id']} validation {passes}, want {p['valid']}")
        engine = Engine(combination["agent_id"], VECTOR_BUNDLE_VERSION, case["policies"], request_validator)
        check_response(case["id"], engine.evaluate(case["request"]), case["expected"])

    fail_closed = json.loads((VECTORS / "fail-closed.json").read_text(encoding="utf-8"))
    engine = Engine(fail_closed["agent_id"], VECTOR_BUNDLE_VERSION, fail_closed["policies"], request_validator)
    for case in fail_closed["cases"]:
        reason = gate_reason(case["state"])
        request = with_environment(fail_closed["request"], case["state"]["environment"])
        check_response(case["id"], deny(reason) if reason else engine.evaluate(request), case["expected"])

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

    # The hashed mode of arguments (section 8.3): the HMAC-SHA-256 of their canonical JSON, which canonical_json
    # writes, as it does for manifests, or their names alone, compared as sets. Arguments given as text are read with
    # read_json, which keeps what canonical JSON cannot write.
    hashed = json.loads((VECTORS / "hashed-arguments.json").read_text(encoding="utf-8"))
    key = bytes.fromhex(hashed["key"])
    for case in hashed["cases"]:
        arguments = read_json(case["arguments_text"]) if "arguments_text" in case else case["arguments"]
        if "names" in case:
            want = {"names": sorted(case["names"]), "names_sha256": sorted(case.get("names_sha256", []))}
        else:
            want = {k: case[k] for k in ("canonical_json", "hmac_sha256")}
        check(f"hashed arguments {case['id']}", hashed_arguments(key, arguments), want)

    # Definition hashes (section 4.10), with messages and schemas given as text read with read_json.
    tooling = json.loads((VECTORS / "tooling.json").read_text(encoding="utf-8"))
    for case in tooling["definitions"]:
        if case["kind"] == "mcp":
            got = mcp_definitions(read_json(case["message_text"]) if "message_text" in case else case["message"])
        else:
            schema = read_json(case["input_schema_text"]) if "input_schema_text" in case else case.get("input_schema")
            got = [function_definition(case["name"], schema)]
        check(f"definition {case['id']}", {"definitions": got}, {"definitions": case["definitions"]})

    # URLs as url_host reads them (section 6.11), normalized as section 4.10 says.
    for case in tooling["urls"]:
        try:
            url = read_url(case["url"])
            try:
                got = {"host": url.host, "normalized": normalized(url)}
            except NoReference:
                got = {"host": url.host, "normalized": None}
        except CannotRead:
            got = {"host": None, "normalized": None}
        check(f"url {case['id']}", got, {k: case[k] for k in ("host", "normalized")})

    # References as their string forms, after the redaction of EP-14 with the deployment's rules (section 4.10).
    for case in tooling["references"]:
        try:
            ref = reference(case["entry"], case.get("rules", {}))
            got = {"reference": ref, "reference_sha256": hashlib.sha256(ref.encode()).hexdigest()}
        except NoReference:
            got = {"reference": None, "reference_sha256": None}
        check(f"reference {case['id']}", got, {k: case[k] for k in ("reference", "reference_sha256")})

    # The transforms of section 6.11, and tools' records of context.args as EP-19 fills them, compared as canonical
    # JSON, so that true and 1 differ.
    arguments = json.loads((VECTORS / "arguments.json").read_text(encoding="utf-8"))
    for case in arguments["transforms"]:
        try:
            got = TRANSFORMS[case["transform"]](case["value"])
        except CannotRead:
            got = None
        check(f"transform {case['id']}", {"result": got}, {"result": case["result"]})
    # A case gives the call's arguments as a JSON value, as text read with read_json, or neither when the call has
    # none, which is an empty object.
    for case in arguments["records"]:
        try:
            try:
                args = read_json(case["arguments_text"]) if "arguments_text" in case else case.get("arguments", {})
            except ValueError:
                raise InvalidArgument("the arguments are not JSON") from None
            got = canonical_json(tool_record(args, case["args"]))
        except InvalidArgument:
            got = None
        want = None if case["record"] is None else canonical_json(case["record"])
        check(f"record {case['id']}", {"record": got}, {"record": want})

    total = (len(combination["cases"]) + len(fail_closed["cases"]) + len(bundle_cases) + len(manifest_cases)
             + len(documents) + len(hashed["cases"]) + len(tooling["definitions"]) + len(tooling["urls"])
             + len(tooling["references"]) + len(arguments["transforms"]) + len(arguments["records"]))
    print(f"{total} vectors, {failures} failures (cedarpy, cryptography, PyYAML, jsonschema, idna)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
