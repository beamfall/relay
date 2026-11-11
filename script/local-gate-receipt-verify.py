#!/usr/bin/env python3
"""Fail-closed verifier for Beamfall local-gate receipt v1."""

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import queue
import socket
import ssl
import sys
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urljoin, urlsplit


MAX_RECEIPT_BYTES = 64 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 10
RECEIPT_VERSION = "beamfall.local-gate-receipt/v1"
ISSUER_VERSION = "beamfall.local-gate-receipt-issuers/v1"
REVOCATION_VERSION = "beamfall.local-gate-receipt-revocations/v1"
ISSUER_REGISTRY = {
    "schemaVersion": "beamfall.local-gate-receipt-issuers/v1",
    "currentPolicyVersion": "2026-07-28.1",
    "policies": [
        {
            "policyVersion": "2026-07-28.1",
            "maxAgeSeconds": 604800,
            "maxGateDurationSeconds": 14400,
            "clockSkewSeconds": 300,
            "uploadAuthorities": [],
            "issuers": [],
        }
    ],
}
REVOCATIONS = {
    "schemaVersion": "beamfall.local-gate-receipt-revocations/v1",
    "policyVersion": "2026-07-28.1",
    "issuers": [],
    "keys": [],
    "receiptDigests": [],
}

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

REPOSITORY_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9_.-]{0,98}[a-z0-9])?/"
    r"[a-z0-9](?:[a-z0-9_.-]{0,98}[a-z0-9])?$"
)
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
PRINTABLE_ASCII_RE = re.compile(r"^[\x20-\x7e]+$")

RECEIPT_FIELDS = {
    "schemaVersion",
    "repository",
    "commit",
    "tree",
    "command",
    "startedAt",
    "endedAt",
    "result",
    "outputSHA256",
    "host",
    "toolchain",
    "issuerId",
    "keyId",
    "issuerScope",
    "policyVersion",
    "signature",
}
EXPECTED_FIELDS = {
    "repository",
    "commit",
    "tree",
    "command",
    "outputSHA256",
    "result",
    "host",
    "toolchain",
    "issuerId",
    "issuerScope",
    "policyVersion",
}
HOST_FIELDS = {"os", "architecture", "hardware"}
ISSUER_REGISTRY_FIELDS = {
    "schemaVersion",
    "currentPolicyVersion",
    "policies",
}
POLICY_FIELDS = {
    "policyVersion",
    "maxAgeSeconds",
    "maxGateDurationSeconds",
    "clockSkewSeconds",
    "issuers",
    "uploadAuthorities",
}
ISSUER_FIELDS = {
    "issuerId",
    "validFrom",
    "validUntil",
    "keys",
    "scopes",
    "allowedUploadAuthorityIds",
}
KEY_FIELDS = {"keyId", "publicKey", "validFrom", "validUntil"}
SCOPE_FIELDS = {"scopeId", "repositories", "commands"}
UPLOAD_AUTHORITY_FIELDS = {"authorityId", "keys"}
REVOCATION_FIELDS = {
    "schemaVersion",
    "policyVersion",
    "issuers",
    "keys",
    "receiptDigests",
}
REVOKED_ISSUER_FIELDS = {"issuerId", "revokedAt", "reason"}
REVOKED_KEY_FIELDS = {"issuerId", "keyId", "revokedAt", "reason"}
REVOKED_DIGEST_FIELDS = {"sha256", "revokedAt", "reason"}


class VerificationError(Exception):
    pass


def reject_constant(value: str) -> None:
    raise VerificationError(f"non-finite JSON number is forbidden: {value}")


def unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_json_bytes(data: bytes, label: str, maximum: Optional[int] = None) -> Any:
    if maximum is not None and len(data) > maximum:
        raise VerificationError(f"{label} exceeds {maximum} bytes")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} is not UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except VerificationError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise VerificationError(f"malformed {label}: {error}") from error


def load_json_file(path: Path, label: str, maximum: Optional[int] = None) -> Any:
    try:
        with path.open("rb") as handle:
            data = handle.read(None if maximum is None else maximum + 1)
    except OSError as error:
        raise VerificationError(f"cannot read {label}: {error}") from error
    return load_json_bytes(data, label, maximum)


def load_receipt_file(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_RECEIPT_BYTES + 1)
    except OSError as error:
        raise VerificationError(f"cannot read receipt: {error}") from error
    if len(data) > MAX_RECEIPT_BYTES:
        raise VerificationError(f"receipt exceeds {MAX_RECEIPT_BYTES} bytes")
    return data


def canonical_json(value: Any, newline: bool = False) -> bytes:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return encoded + (b"\n" if newline else b"")


def exact_fields(value: Any, fields: Iterable[str], label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object")
    expected = set(fields)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise VerificationError(f"{label} fields mismatch: missing={missing} unknown={unknown}")
    return value


def required_string(value: Any, label: str, pattern: Optional[re.Pattern] = None) -> str:
    if not isinstance(value, str):
        raise VerificationError(f"{label} must be a string")
    if not value:
        raise VerificationError(f"{label} must not be empty")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise VerificationError(f"{label} has invalid syntax")
    return value


def required_integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerificationError(f"{label} must be an integer")
    if value < minimum:
        raise VerificationError(f"{label} must be at least {minimum}")
    return value


def parse_timestamp(value: Any, label: str) -> dt.datetime:
    text = required_string(value, label, TIMESTAMP_RE)
    try:
        parsed = dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise VerificationError(f"{label} is not a real UTC timestamp") from error
    return parsed.replace(tzinfo=dt.timezone.utc)


def validate_ascii_list(value: Any, label: str) -> List[str]:
    if not isinstance(value, list) or not value:
        raise VerificationError(f"{label} must be a non-empty array")
    result = []
    for index, item in enumerate(value):
        result.append(required_string(item, f"{label}[{index}]", PRINTABLE_ASCII_RE))
    return result


def validate_command(value: Any, label: str) -> List[str]:
    command = validate_ascii_list(value, label)
    if len(command[0]) < 2 or not command[0].startswith("/"):
        raise VerificationError(f"{label}[0] must be an absolute executable path")
    return command


def validate_host(value: Any, label: str) -> Dict[str, str]:
    host = exact_fields(value, HOST_FIELDS, label)
    for field in sorted(HOST_FIELDS):
        required_string(host[field], f"{label}.{field}", PRINTABLE_ASCII_RE)
    return host


def validate_receipt_shape(receipt: Any) -> Dict[str, Any]:
    value = exact_fields(receipt, RECEIPT_FIELDS, "receipt")
    if value["schemaVersion"] != RECEIPT_VERSION:
        raise VerificationError("unsupported receipt schemaVersion")
    required_string(value["repository"], "receipt.repository", REPOSITORY_RE)
    required_string(value["commit"], "receipt.commit", HEX40_RE)
    required_string(value["tree"], "receipt.tree", HEX40_RE)
    validate_command(value["command"], "receipt.command")
    parse_timestamp(value["startedAt"], "receipt.startedAt")
    parse_timestamp(value["endedAt"], "receipt.endedAt")
    if value["result"] != "success":
        raise VerificationError("receipt.result must be success")
    required_string(value["outputSHA256"], "receipt.outputSHA256", HEX64_RE)
    validate_host(value["host"], "receipt.host")
    required_string(value["toolchain"], "receipt.toolchain", PRINTABLE_ASCII_RE)
    required_string(value["issuerId"], "receipt.issuerId", IDENTIFIER_RE)
    required_string(value["keyId"], "receipt.keyId", IDENTIFIER_RE)
    required_string(value["issuerScope"], "receipt.issuerScope", IDENTIFIER_RE)
    required_string(value["policyVersion"], "receipt.policyVersion", IDENTIFIER_RE)
    required_string(value["signature"], "receipt.signature", BASE64URL_RE)
    return value


def validate_expected(value: Any) -> Dict[str, Any]:
    expected = exact_fields(value, EXPECTED_FIELDS, "expected tuple")
    required_string(expected["repository"], "expected.repository", REPOSITORY_RE)
    required_string(expected["commit"], "expected.commit", HEX40_RE)
    required_string(expected["tree"], "expected.tree", HEX40_RE)
    validate_command(expected["command"], "expected.command")
    required_string(expected["outputSHA256"], "expected.outputSHA256", HEX64_RE)
    if expected["result"] != "success":
        raise VerificationError("expected.result must be success")
    validate_host(expected["host"], "expected.host")
    required_string(expected["toolchain"], "expected.toolchain", PRINTABLE_ASCII_RE)
    required_string(expected["issuerId"], "expected.issuerId", IDENTIFIER_RE)
    required_string(expected["issuerScope"], "expected.issuerScope", IDENTIFIER_RE)
    required_string(expected["policyVersion"], "expected.policyVersion", IDENTIFIER_RE)
    return expected


def validate_string_array(value: Any, label: str, pattern: re.Pattern) -> List[str]:
    if not isinstance(value, list) or not value:
        raise VerificationError(f"{label} must be a non-empty array")
    result = [required_string(item, f"{label}[]", pattern) for item in value]
    if len(result) != len(set(result)):
        raise VerificationError(f"{label} contains duplicates")
    return result


def validate_policy_version(value: Any, label: str) -> Dict[str, Any]:
    policy = exact_fields(value, POLICY_FIELDS, label)
    required_string(policy["policyVersion"], f"{label}.policyVersion", IDENTIFIER_RE)
    required_integer(policy["maxAgeSeconds"], f"{label}.maxAgeSeconds", 1)
    required_integer(policy["maxGateDurationSeconds"], f"{label}.maxGateDurationSeconds", 1)
    required_integer(policy["clockSkewSeconds"], f"{label}.clockSkewSeconds", 0)
    if not isinstance(policy["uploadAuthorities"], list):
        raise VerificationError(f"{label}.uploadAuthorities must be an array")
    upload_authority_ids = set()
    upload_key_ids = set()
    upload_public_keys = set()
    for authority_index, authority_value in enumerate(policy["uploadAuthorities"]):
        authority_label = f"{label}.uploadAuthorities[{authority_index}]"
        authority = exact_fields(
            authority_value,
            UPLOAD_AUTHORITY_FIELDS,
            authority_label,
        )
        authority_id = required_string(
            authority["authorityId"],
            f"{authority_label}.authorityId",
            IDENTIFIER_RE,
        )
        if authority_id in upload_authority_ids:
            raise VerificationError(f"{label} has duplicate upload authority ID")
        upload_authority_ids.add(authority_id)
        if not isinstance(authority["keys"], list) or not authority["keys"]:
            raise VerificationError(f"{authority_label}.keys must be a non-empty array")
        local_key_ids = set()
        for key_index, key_value in enumerate(authority["keys"]):
            key_label = f"{authority_label}.keys[{key_index}]"
            key = exact_fields(key_value, KEY_FIELDS, key_label)
            key_id = required_string(key["keyId"], f"{key_label}.keyId", IDENTIFIER_RE)
            if key_id in local_key_ids:
                raise VerificationError(f"{authority_label} has duplicate keyId")
            local_key_ids.add(key_id)
            upload_key_ids.add(key_id)
            public_key = required_string(key["publicKey"], f"{key_label}.publicKey", BASE64URL_RE)
            decode_public_key(public_key)
            upload_public_keys.add(public_key)
            key_from = parse_timestamp(key["validFrom"], f"{key_label}.validFrom")
            key_until = parse_timestamp(key["validUntil"], f"{key_label}.validUntil")
            if key_until < key_from:
                raise VerificationError(f"{key_label} validity interval is reversed")
    if not isinstance(policy["issuers"], list):
        raise VerificationError(f"{label}.issuers must be an array")
    issuer_ids = set()
    all_key_ids = set()
    signer_public_keys = set()
    all_upload_ids = set()
    for issuer_index, issuer_value in enumerate(policy["issuers"]):
        issuer_label = f"{label}.issuers[{issuer_index}]"
        issuer = exact_fields(issuer_value, ISSUER_FIELDS, issuer_label)
        issuer_id = required_string(
            issuer["issuerId"], f"{issuer_label}.issuerId", IDENTIFIER_RE
        )
        if issuer_id in issuer_ids:
            raise VerificationError(f"{label} has duplicate issuerId")
        issuer_ids.add(issuer_id)
        issuer_from = parse_timestamp(issuer["validFrom"], f"{issuer_label}.validFrom")
        issuer_until = parse_timestamp(issuer["validUntil"], f"{issuer_label}.validUntil")
        if issuer_until < issuer_from:
            raise VerificationError(f"{issuer_label} validity interval is reversed")
        if not isinstance(issuer["keys"], list) or not issuer["keys"]:
            raise VerificationError(f"{issuer_label}.keys must be a non-empty array")
        key_ids = set()
        for key_index, key_value in enumerate(issuer["keys"]):
            key_label = f"{issuer_label}.keys[{key_index}]"
            key = exact_fields(key_value, KEY_FIELDS, key_label)
            key_id = required_string(key["keyId"], f"{key_label}.keyId", IDENTIFIER_RE)
            if key_id in key_ids:
                raise VerificationError(f"{issuer_label} has duplicate keyId")
            key_ids.add(key_id)
            all_key_ids.add(key_id)
            public_key = required_string(key["publicKey"], f"{key_label}.publicKey", BASE64URL_RE)
            decode_public_key(public_key)
            signer_public_keys.add(public_key)
            key_from = parse_timestamp(key["validFrom"], f"{key_label}.validFrom")
            key_until = parse_timestamp(key["validUntil"], f"{key_label}.validUntil")
            if key_until < key_from:
                raise VerificationError(f"{key_label} validity interval is reversed")
        if not isinstance(issuer["scopes"], list) or not issuer["scopes"]:
            raise VerificationError(f"{issuer_label}.scopes must be a non-empty array")
        scope_ids = set()
        for scope_index, scope_value in enumerate(issuer["scopes"]):
            scope_label = f"{issuer_label}.scopes[{scope_index}]"
            scope = exact_fields(scope_value, SCOPE_FIELDS, scope_label)
            scope_id = required_string(scope["scopeId"], f"{scope_label}.scopeId", IDENTIFIER_RE)
            if scope_id in scope_ids:
                raise VerificationError(f"{issuer_label} has duplicate scopeId")
            scope_ids.add(scope_id)
            validate_string_array(
                scope["repositories"],
                f"{scope_label}.repositories",
                REPOSITORY_RE,
            )
            if not isinstance(scope["commands"], list) or not scope["commands"]:
                raise VerificationError(f"{scope_label}.commands must be a non-empty array")
            canonical_commands = set()
            for command_index, command in enumerate(scope["commands"]):
                argv = validate_command(command, f"{scope_label}.commands[{command_index}]")
                encoded = canonical_json(argv)
                if encoded in canonical_commands:
                    raise VerificationError(f"{scope_label}.commands contains duplicates")
                canonical_commands.add(encoded)
        upload_ids = validate_string_array(
            issuer["allowedUploadAuthorityIds"],
            f"{issuer_label}.allowedUploadAuthorityIds",
            IDENTIFIER_RE,
        )
        all_upload_ids.update(upload_ids)
        if not set(upload_ids).issubset(upload_authority_ids):
            raise VerificationError(f"{issuer_label} names an unknown upload authority")
    signer_identities = issuer_ids.union(all_key_ids)
    upload_identities = upload_authority_ids.union(upload_key_ids)
    if signer_identities.intersection(upload_identities):
        raise VerificationError("signer and upload authority must be globally distinct")
    if all_upload_ids != upload_authority_ids and policy["issuers"]:
        raise VerificationError("upload authority is not bound to exactly one issuer policy")
    if signer_public_keys.intersection(upload_public_keys):
        raise VerificationError("signer and upload authority public keys must be distinct")
    return policy


def validate_policy(value: Any) -> Dict[str, Any]:
    registry = exact_fields(value, ISSUER_REGISTRY_FIELDS, "issuer registry")
    if registry["schemaVersion"] != ISSUER_VERSION:
        raise VerificationError("unsupported issuer policy schemaVersion")
    current = required_string(
        registry["currentPolicyVersion"],
        "issuer registry.currentPolicyVersion",
        IDENTIFIER_RE,
    )
    if not isinstance(registry["policies"], list) or not registry["policies"]:
        raise VerificationError("issuer registry.policies must be a non-empty array")
    versions = set()
    signer_identities = set()
    upload_identities = set()
    signer_public_keys = set()
    upload_public_keys = set()
    for index, policy_value in enumerate(registry["policies"]):
        policy = validate_policy_version(
            policy_value,
            f"issuer registry.policies[{index}]",
        )
        if policy["policyVersion"] in versions:
            raise VerificationError("issuer registry has duplicate policyVersion")
        versions.add(policy["policyVersion"])
        for issuer in policy["issuers"]:
            signer_identities.add(issuer["issuerId"])
            for key in issuer["keys"]:
                signer_identities.add(key["keyId"])
                signer_public_keys.add(key["publicKey"])
        for authority in policy["uploadAuthorities"]:
            upload_identities.add(authority["authorityId"])
            for key in authority["keys"]:
                upload_identities.add(key["keyId"])
                upload_public_keys.add(key["publicKey"])
    if current not in versions:
        raise VerificationError("currentPolicyVersion is not retained")
    if signer_identities.intersection(upload_identities):
        raise VerificationError("retained signer and upload authority identities overlap")
    if signer_public_keys.intersection(upload_public_keys):
        raise VerificationError("retained signer and upload authority keys overlap")
    return registry


def require_provisioned_trust_store(registry: Dict[str, Any]) -> None:
    current_policy = find_unique(
        registry["policies"],
        "policyVersion",
        registry["currentPolicyVersion"],
        "current policy version",
    )
    if not current_policy["issuers"] or not current_policy["uploadAuthorities"]:
        raise VerificationError(
            "trust store unprovisioned: current policy requires an issuer and upload authority"
        )


def validate_revocations(value: Any) -> Dict[str, Any]:
    revocations = exact_fields(value, REVOCATION_FIELDS, "revocations")
    if revocations["schemaVersion"] != REVOCATION_VERSION:
        raise VerificationError("unsupported revocations schemaVersion")
    required_string(revocations["policyVersion"], "revocations.policyVersion", IDENTIFIER_RE)
    collections = (
        ("issuers", REVOKED_ISSUER_FIELDS),
        ("keys", REVOKED_KEY_FIELDS),
        ("receiptDigests", REVOKED_DIGEST_FIELDS),
    )
    for collection, fields in collections:
        entries = revocations[collection]
        if not isinstance(entries, list):
            raise VerificationError(f"revocations.{collection} must be an array")
        seen = set()
        for index, entry_value in enumerate(entries):
            label = f"revocations.{collection}[{index}]"
            entry = exact_fields(entry_value, fields, label)
            for field in fields:
                pattern = HEX64_RE if field == "sha256" else None
                if field == "revokedAt":
                    parse_timestamp(entry[field], f"{label}.{field}")
                elif field == "reason":
                    required_string(entry[field], f"{label}.{field}", PRINTABLE_ASCII_RE)
                else:
                    required_string(entry[field], f"{label}.{field}", pattern or IDENTIFIER_RE)
            if collection == "issuers":
                identity = entry["issuerId"]
            elif collection == "keys":
                identity = f"{entry['issuerId']}\0{entry['keyId']}"
            else:
                identity = entry["sha256"]
            if identity in seen:
                raise VerificationError(f"revocations.{collection} contains duplicates")
            seen.add(identity)
    return revocations


def decode_base64url(value: str, label: str) -> bytes:
    if BASE64URL_RE.fullmatch(value) is None:
        raise VerificationError(f"{label} is not unpadded base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise VerificationError(f"{label} is not valid base64url") from error
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise VerificationError(f"{label} is not canonical base64url")
    return decoded


def decode_public_key(value: Any) -> Tuple[int, int]:
    text = required_string(value, "publicKey", BASE64URL_RE)
    encoded = decode_base64url(text, "publicKey")
    if len(encoded) != 65 or encoded[0] != 4:
        raise VerificationError("publicKey must be uncompressed P-256 SEC1")
    x = int.from_bytes(encoded[1:33], "big")
    y = int.from_bytes(encoded[33:], "big")
    if x >= P256_P or y >= P256_P:
        raise VerificationError("publicKey coordinate is out of range")
    if (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P != 0:
        raise VerificationError("publicKey is not on P-256")
    return x, y


def parse_der_integer(data: bytes, offset: int) -> Tuple[int, int]:
    if offset + 2 > len(data) or data[offset] != 0x02:
        raise VerificationError("signature has invalid DER INTEGER")
    length = data[offset + 1]
    start = offset + 2
    end = start + length
    if length == 0 or end > len(data):
        raise VerificationError("signature has truncated DER INTEGER")
    encoded = data[start:end]
    if encoded[0] & 0x80:
        raise VerificationError("signature DER INTEGER is negative")
    if len(encoded) > 1 and encoded[0] == 0 and not (encoded[1] & 0x80):
        raise VerificationError("signature DER INTEGER is not minimal")
    return int.from_bytes(encoded, "big"), end


def parse_signature(value: Any) -> Tuple[int, int]:
    text = required_string(value, "receipt.signature", BASE64URL_RE)
    der = decode_base64url(text, "receipt.signature")
    if len(der) < 8 or len(der) > 72:
        raise VerificationError("signature DER length is invalid")
    if der[0] != 0x30 or der[1] & 0x80 or der[1] != len(der) - 2:
        raise VerificationError("signature is not strict DER")
    r, offset = parse_der_integer(der, 2)
    s, offset = parse_der_integer(der, offset)
    if offset != len(der):
        raise VerificationError("signature DER has trailing bytes")
    if not (1 <= r < P256_N and 1 <= s <= P256_N // 2):
        raise VerificationError("signature values are out of range or not low-S")
    return r, s


Point = Optional[Tuple[int, int]]


def point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P256_P)
    slope %= P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    y3 = (slope * (x1 - x3) - y1) % P256_P
    return x3, y3


def scalar_multiply(scalar: int, point: Point) -> Point:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def verify_p256(public_key: Tuple[int, int], message: bytes, signature: Tuple[int, int]) -> bool:
    r, s = signature
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    inverse = pow(s, -1, P256_N)
    point = point_add(
        scalar_multiply((digest * inverse) % P256_N, P256_G),
        scalar_multiply((r * inverse) % P256_N, public_key),
    )
    return point is not None and point[0] % P256_N == r


def find_unique(values: Sequence[Dict[str, Any]], field: str, expected: str, label: str) -> Dict[str, Any]:
    matches = [value for value in values if value[field] == expected]
    if len(matches) != 1:
        raise VerificationError(f"{label} is not uniquely authorized")
    return matches[0]


def enforce_time_policy(
    receipt: Dict[str, Any],
    issuer: Dict[str, Any],
    key: Dict[str, Any],
    policy: Dict[str, Any],
    now: dt.datetime,
) -> None:
    started = parse_timestamp(receipt["startedAt"], "receipt.startedAt")
    ended = parse_timestamp(receipt["endedAt"], "receipt.endedAt")
    skew = dt.timedelta(seconds=policy["clockSkewSeconds"])
    if ended < started:
        raise VerificationError("receipt endedAt precedes startedAt")
    if ended - started > dt.timedelta(seconds=policy["maxGateDurationSeconds"]):
        raise VerificationError("receipt gate duration exceeds policy")
    if started > now + skew or ended > now + skew:
        raise VerificationError("receipt timestamp is in the future")
    if now - ended > dt.timedelta(seconds=policy["maxAgeSeconds"]):
        raise VerificationError("receipt is stale")
    issuer_from = parse_timestamp(issuer["validFrom"], "issuer.validFrom")
    issuer_until = parse_timestamp(issuer["validUntil"], "issuer.validUntil")
    key_from = parse_timestamp(key["validFrom"], "key.validFrom")
    key_until = parse_timestamp(key["validUntil"], "key.validUntil")
    if not (issuer_from <= ended <= issuer_until):
        raise VerificationError("issuer was not valid at receipt endedAt")
    if not (key_from <= ended <= key_until):
        raise VerificationError("key was not valid at receipt endedAt")


def enforce_revocations(
    receipt: Dict[str, Any],
    receipt_digest: str,
    revocations: Dict[str, Any],
) -> None:
    if any(item["issuerId"] == receipt["issuerId"] for item in revocations["issuers"]):
        raise VerificationError("receipt issuer is revoked")
    if any(
        item["issuerId"] == receipt["issuerId"] and item["keyId"] == receipt["keyId"]
        for item in revocations["keys"]
    ):
        raise VerificationError("receipt key is revoked")
    if any(item["sha256"] == receipt_digest for item in revocations["receiptDigests"]):
        raise VerificationError("receipt digest is revoked")


def compare_expected(receipt: Dict[str, Any], expected: Dict[str, Any]) -> None:
    for field in sorted(EXPECTED_FIELDS):
        if receipt[field] != expected[field]:
            raise VerificationError(f"authorization tuple mismatch: {field}")


def preflight_expected(
    expected: Dict[str, Any],
    registry: Dict[str, Any],
    revocations: Dict[str, Any],
) -> None:
    require_provisioned_trust_store(registry)
    policy = find_unique(
        registry["policies"],
        "policyVersion",
        expected["policyVersion"],
        "retained policy version",
    )
    find_unique(
        registry["policies"],
        "policyVersion",
        registry["currentPolicyVersion"],
        "current policy version",
    )
    if revocations["policyVersion"] != registry["currentPolicyVersion"]:
        raise VerificationError("revocations policyVersion is not current")
    issuer = find_unique(policy["issuers"], "issuerId", expected["issuerId"], "issuer")
    scope = find_unique(issuer["scopes"], "scopeId", expected["issuerScope"], "issuer scope")
    if expected["repository"] not in scope["repositories"]:
        raise VerificationError("repository is outside issuer scope")
    allowed_commands = {canonical_json(command) for command in scope["commands"]}
    if canonical_json(expected["command"]) not in allowed_commands:
        raise VerificationError("command is outside issuer scope")
    if any(item["issuerId"] == expected["issuerId"] for item in revocations["issuers"]):
        raise VerificationError("receipt issuer is revoked")


def verify_receipt(
    receipt_bytes: bytes,
    expected: Dict[str, Any],
    policy: Dict[str, Any],
    revocations: Dict[str, Any],
    now: dt.datetime,
) -> Dict[str, Any]:
    receipt_value = load_json_bytes(receipt_bytes, "receipt", MAX_RECEIPT_BYTES)
    receipt = validate_receipt_shape(receipt_value)
    if canonical_json(receipt, newline=True) != receipt_bytes:
        raise VerificationError("receipt bytes are not canonical JSON plus one LF")
    expected = validate_expected(expected)
    registry = validate_policy(policy)
    require_provisioned_trust_store(registry)
    revocations = validate_revocations(revocations)
    if receipt["policyVersion"] != expected["policyVersion"]:
        raise VerificationError("receipt policyVersion does not match expected tuple")
    policy = find_unique(
        registry["policies"],
        "policyVersion",
        receipt["policyVersion"],
        "retained policy version",
    )
    current_policy = find_unique(
        registry["policies"],
        "policyVersion",
        registry["currentPolicyVersion"],
        "current policy version",
    )
    if revocations["policyVersion"] != registry["currentPolicyVersion"]:
        raise VerificationError("revocations policyVersion is not current")
    compare_expected(receipt, expected)
    issuer = find_unique(policy["issuers"], "issuerId", receipt["issuerId"], "issuer")
    key = find_unique(issuer["keys"], "keyId", receipt["keyId"], "key")
    scope = find_unique(issuer["scopes"], "scopeId", receipt["issuerScope"], "issuer scope")
    if receipt["repository"] not in scope["repositories"]:
        raise VerificationError("repository is outside issuer scope")
    if canonical_json(receipt["command"]) not in {
        canonical_json(command) for command in scope["commands"]
    }:
        raise VerificationError("command is outside issuer scope")
    receipt_digest = hashlib.sha256(receipt_bytes).hexdigest()
    enforce_revocations(receipt, receipt_digest, revocations)
    effective_time_policy = dict(policy)
    for field in ("maxAgeSeconds", "maxGateDurationSeconds", "clockSkewSeconds"):
        effective_time_policy[field] = min(policy[field], current_policy[field])
    enforce_time_policy(receipt, issuer, key, effective_time_policy, now)
    signature = parse_signature(receipt["signature"])
    public_key = decode_public_key(key["publicKey"])
    unsigned = dict(receipt)
    del unsigned["signature"]
    if not verify_p256(public_key, canonical_json(unsigned), signature):
        raise VerificationError("receipt signature is invalid")
    return {
        "authorized": True,
        "commit": receipt["commit"],
        "receiptSHA256": receipt_digest,
        "repository": receipt["repository"],
        "tree": receipt["tree"],
    }


def public_addresses(
    host: str,
    port: int = 443,
    deadline: Optional[float] = None,
) -> List[str]:
    deadline = deadline or (time.monotonic() + DOWNLOAD_TIMEOUT_SECONDS)
    results: "queue.Queue[Any]" = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            results.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except BaseException as error:
            results.put(error)

    worker = threading.Thread(target=resolve, daemon=True)
    worker.start()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise VerificationError("receipt download deadline expired during DNS")
    worker.join(remaining)
    if worker.is_alive():
        raise VerificationError(f"DNS resolution timed out for {host}")
    answers = results.get_nowait()
    if isinstance(answers, BaseException):
        raise VerificationError(f"DNS resolution failed for {host}") from answers
    addresses = sorted({answer[4][0] for answer in answers})
    if not addresses:
        raise VerificationError(f"DNS returned no addresses for {host}")
    if len(addresses) > 4:
        raise VerificationError(f"DNS returned too many addresses for {host}")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        forbidden = (
            parsed.is_loopback
            or parsed.is_private
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        )
        if forbidden or not parsed.is_global:
            raise VerificationError(f"DNS returned non-public address for {host}")
        embedded = []
        if isinstance(parsed, ipaddress.IPv6Address):
            if parsed.ipv4_mapped is not None:
                embedded.append(parsed.ipv4_mapped)
            if parsed.sixtofour is not None:
                embedded.append(parsed.sixtofour)
            if parsed.teredo is not None:
                embedded.extend(parsed.teredo)
        if any(
            not value.is_global
            or value.is_loopback
            or value.is_private
            or value.is_link_local
            or value.is_multicast
            or value.is_reserved
            or value.is_unspecified
            for value in embedded
        ):
            raise VerificationError(f"DNS returned transition address to non-public IPv4 for {host}")
    return addresses


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, timeout: float):
        super().__init__(
            host,
            port=443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def request_pinned(
    url: str,
    allowed_host: str,
    deadline: Optional[float] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    deadline = deadline or (time.monotonic() + DOWNLOAD_TIMEOUT_SECONDS)
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url):
        raise VerificationError("download URL contains whitespace or control characters")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise VerificationError("download URL is malformed") from error
    if parsed.scheme != "https" or parsed.hostname != allowed_host:
        raise VerificationError("download URL host is not allowed")
    if parsed.username is not None or parsed.password is not None:
        raise VerificationError("download URL userinfo is forbidden")
    if port not in (None, 443) or parsed.fragment:
        raise VerificationError("download URL port or fragment is forbidden")
    addresses = public_addresses(allowed_host, deadline=deadline)
    last_error: Optional[BaseException] = None
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise VerificationError("receipt download deadline expired")
        connection = PinnedHTTPSConnection(allowed_host, address, remaining)
        deadline_timer = threading.Timer(remaining, connection.close)
        deadline_timer.daemon = True
        deadline_timer.start()
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Accept": "application/octet-stream",
                    "Connection": "close",
                    "Host": allowed_host,
                    "User-Agent": "beamfall-local-gate-receipt-verifier/1",
                },
            )
            response = connection.getresponse()
            headers = {}
            for key, value in response.getheaders():
                normalized = key.lower()
                if normalized in {"content-length", "location"} and normalized in headers:
                    raise VerificationError(f"download has duplicate {key} header")
                headers[normalized] = value
            length = headers.get("content-length")
            if length is not None:
                if re.fullmatch(r"[0-9]+", length) is None:
                    raise VerificationError("download Content-Length is malformed")
                if int(length) > MAX_RECEIPT_BYTES:
                    raise VerificationError("download Content-Length exceeds receipt limit")
            chunks = []
            total = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise VerificationError("receipt download deadline expired")
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(8192, MAX_RECEIPT_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_RECEIPT_BYTES:
                    raise VerificationError("download exceeds receipt limit")
            body = b"".join(chunks)
            return response.status, headers, body
        except VerificationError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as error:
            last_error = error
        finally:
            deadline_timer.cancel()
            connection.close()
    raise VerificationError(f"HTTPS request failed: {last_error}")


def validate_initial_url(url: str, expected: Dict[str, Any]) -> str:
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url):
        raise VerificationError("receipt URL contains whitespace or control characters")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise VerificationError("receipt URL is malformed") from error
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise VerificationError("receipt URL must use https://github.com")
    if parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
        raise VerificationError("receipt URL query, fragment, or userinfo is forbidden")
    if port not in (None, 443):
        raise VerificationError("receipt URL port is forbidden")
    if "%" in parsed.path:
        raise VerificationError("receipt URL percent-encoding is forbidden")
    parts = [unquote(part) for part in parsed.path.split("/") if part]
    if any("/" in part or "\\" in part or part in (".", "..") for part in parts):
        raise VerificationError("receipt URL path encoding is forbidden")
    if len(parts) != 6 or parts[2:4] != ["releases", "download"]:
        raise VerificationError("receipt URL is not a canonical release asset URL")
    repository = f"{parts[0]}/{parts[1]}"
    expected_tag = f"local-gate-receipt-{expected['commit']}"
    if repository != expected["repository"] or parts[4] != expected_tag:
        raise VerificationError("receipt URL repository or candidate tag mismatch")
    asset_match = re.fullmatch(r"local-gate-receipt-([0-9a-f]{64})\.json", parts[5])
    if asset_match is None:
        raise VerificationError("receipt URL asset name is not digest-bound")
    canonical_path = f"/{repository}/releases/download/{expected_tag}/{parts[5]}"
    if parsed.path != canonical_path:
        raise VerificationError("receipt URL path is not canonical")
    return asset_match.group(1)


def fetch_receipt(url: str, expected: Dict[str, Any]) -> bytes:
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT_SECONDS
    expected_digest = validate_initial_url(url, expected)
    status, headers, body = request_pinned(url, "github.com", deadline)
    if status in (301, 302, 303, 307, 308):
        location = headers.get("location")
        if location is None:
            raise VerificationError("redirect is missing Location")
        redirect = urljoin(url, location)
        try:
            target = urlsplit(redirect)
            target_port = target.port
        except ValueError as error:
            raise VerificationError("redirect target is malformed") from error
        if target.hostname != "release-assets.githubusercontent.com":
            raise VerificationError("redirect target is not GitHub release asset storage")
        if target_port not in (None, 443):
            raise VerificationError("redirect target port is forbidden")
        status, _, body = request_pinned(
            redirect,
            "release-assets.githubusercontent.com",
            deadline,
        )
        if status in (301, 302, 303, 307, 308):
            raise VerificationError("receipt download exceeded one redirect")
    if status != 200:
        raise VerificationError(f"receipt download returned HTTP {status}")
    actual_digest = hashlib.sha256(body).hexdigest()
    if actual_digest != expected_digest:
        raise VerificationError("downloaded receipt does not match digest asset name")
    return body


def current_time() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--receipt", type=Path, help="explicit local receipt bytes")
    source.add_argument("--url", help="explicit canonical public GitHub Release asset URL")
    parser.add_argument("--expected", required=True, type=Path, help="trusted exact tuple JSON")
    return parser.parse_args(argv)


def acquire_receipt(
    receipt_path: Optional[Path],
    url: Optional[str],
    expected: Dict[str, Any],
    policy: Dict[str, Any],
    revocations: Dict[str, Any],
) -> bytes:
    preflight_expected(expected, policy, revocations)
    if receipt_path is not None:
        return load_receipt_file(receipt_path)
    if url is None:
        raise VerificationError("an explicit receipt path or URL is required")
    return fetch_receipt(url, expected)


def main(argv: Sequence[str]) -> int:
    try:
        args = parse_args(argv)
        expected = validate_expected(load_json_file(args.expected, "expected tuple", 64 * 1024))
        policy = validate_policy(ISSUER_REGISTRY)
        revocations = validate_revocations(REVOCATIONS)
        receipt_bytes = acquire_receipt(
            args.receipt,
            args.url,
            expected,
            policy,
            revocations,
        )
        result = verify_receipt(receipt_bytes, expected, policy, revocations, current_time())
        print(canonical_json(result).decode("utf-8"))
        return 0
    except (OSError, VerificationError) as error:
        print(f"local-gate-receipt: denied: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
