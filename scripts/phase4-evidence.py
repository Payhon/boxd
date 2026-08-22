#!/usr/bin/env python3
"""Fail-closed validator for boxd-phase4-evidence-v1 JSON.

The committed JSON Schema is the portable contract. This validator deliberately
uses only Python's standard library so the hermetic release gate has no network
or package-install dependency. It enforces the schema's closed object shapes and
the cross-field invariants JSON Schema cannot express concisely.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,191}$")
TOOL = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


class EvidenceError(ValueError):
    """The evidence cannot be trusted as a Phase 4 gate input."""


def require_object(value: Any, where: str, required: set[str], optional: set[str] = set()) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{where} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise EvidenceError(f"{where} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise EvidenceError(f"{where} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def require_string(value: Any, where: str, *, minimum: int = 1, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise EvidenceError(f"{where} must be a string of length {minimum}..{maximum}")
    return value


def require_integer(value: Any, where: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceError(f"{where} must be an integer >= {minimum}")
    return value


def require_sha(value: Any, where: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise EvidenceError(f"{where} must be a lowercase SHA-256")
    return value


def require_relative_path(value: Any, where: str) -> str:
    path = require_string(value, where, maximum=512)
    pure = PurePosixPath(path)
    if path.startswith("/") or "//" in path or any(part in ("", ".", "..") for part in pure.parts):
        raise EvidenceError(f"{where} must be a normalized relative POSIX path")
    if not re.fullmatch(r"[A-Za-z0-9._/+@=-]+", path):
        raise EvidenceError(f"{where} contains unsupported characters")
    return path


def validate_evidence(document: Any) -> None:
    root = require_object(
        document,
        "evidence",
        {
            "schema", "suite", "commit", "platform", "toolchain", "inputs", "cases",
            "artifacts", "external_requirements", "secret_scan", "summary",
        },
    )
    if root["schema"] != "boxd-phase4-evidence-v1":
        raise EvidenceError("unsupported evidence schema")
    suite = require_string(root["suite"], "suite", maximum=128)
    if not TOKEN.fullmatch(suite):
        raise EvidenceError("suite has an invalid identifier")
    if not isinstance(root["commit"], str) or not COMMIT.fullmatch(root["commit"]):
        raise EvidenceError("commit must be a full lowercase 40-character Git object id")

    platform = require_object(root["platform"], "platform", {"os", "arch", "virtualization"})
    if platform["os"] not in ("linux", "macos"):
        raise EvidenceError("platform.os is unsupported")
    if platform["arch"] not in ("x86_64", "aarch64"):
        raise EvidenceError("platform.arch is unsupported")
    if platform["virtualization"] not in ("none", "kvm", "hvf"):
        raise EvidenceError("platform.virtualization is unsupported")
    if platform["virtualization"] == "kvm" and platform["os"] != "linux":
        raise EvidenceError("KVM evidence must identify Linux")
    if platform["virtualization"] == "hvf" and (platform["os"], platform["arch"]) != ("macos", "aarch64"):
        raise EvidenceError("HVF evidence must identify macOS aarch64")

    toolchain = require_object(root["toolchain"], "toolchain", set(), set(root["toolchain"]) if isinstance(root["toolchain"], dict) else set())
    if not toolchain:
        raise EvidenceError("toolchain must not be empty")
    for key, value in toolchain.items():
        if not TOOL.fullmatch(key):
            raise EvidenceError(f"invalid toolchain key: {key}")
        require_string(value, f"toolchain.{key}", maximum=256)

    inputs = root["inputs"]
    if not isinstance(inputs, list) or not inputs:
        raise EvidenceError("inputs must be a non-empty array")
    input_names: set[str] = set()
    for index, raw in enumerate(inputs):
        item = require_object(raw, f"inputs[{index}]", {"name", "sha256"})
        name = require_string(item["name"], f"inputs[{index}].name", maximum=128)
        if not TOKEN.fullmatch(name) or name in input_names:
            raise EvidenceError(f"inputs[{index}].name is invalid or duplicated")
        input_names.add(name)
        require_sha(item["sha256"], f"inputs[{index}].sha256")

    cases = root["cases"]
    if not isinstance(cases, list) or not cases:
        raise EvidenceError("cases must be a non-empty array")
    case_ids: set[str] = set()
    counts = {"pass": 0, "fail": 0, "blocked": 0}
    for index, raw in enumerate(cases):
        case = require_object(raw, f"cases[{index}]", {"id", "expected", "observed", "status"}, {"artifact_sha256"})
        case_id = require_string(case["id"], f"cases[{index}].id", maximum=192)
        if not CASE_ID.fullmatch(case_id) or case_id in case_ids:
            raise EvidenceError(f"cases[{index}].id is invalid or duplicated")
        case_ids.add(case_id)
        require_string(case["expected"], f"cases[{index}].expected")
        require_string(case["observed"], f"cases[{index}].observed")
        if case["status"] not in counts:
            raise EvidenceError(f"cases[{index}].status is invalid")
        counts[case["status"]] += 1
        if "artifact_sha256" in case:
            require_sha(case["artifact_sha256"], f"cases[{index}].artifact_sha256")

    artifacts = root["artifacts"]
    if not isinstance(artifacts, list):
        raise EvidenceError("artifacts must be an array")
    artifact_paths: set[str] = set()
    artifact_hashes: set[str] = set()
    for index, raw in enumerate(artifacts):
        artifact = require_object(raw, f"artifacts[{index}]", {"path", "sha256"})
        path = require_relative_path(artifact["path"], f"artifacts[{index}].path")
        if path in artifact_paths:
            raise EvidenceError(f"duplicate artifact path: {path}")
        artifact_paths.add(path)
        artifact_hashes.add(require_sha(artifact["sha256"], f"artifacts[{index}].sha256"))
    for index, case in enumerate(cases):
        if "artifact_sha256" in case and case["artifact_sha256"] not in artifact_hashes:
            raise EvidenceError(f"cases[{index}].artifact_sha256 is not bound by artifacts")

    requirements = root["external_requirements"]
    if not isinstance(requirements, list):
        raise EvidenceError("external_requirements must be an array")
    requirement_ids: set[str] = set()
    blocked_external = 0
    for index, raw in enumerate(requirements):
        requirement = require_object(raw, f"external_requirements[{index}]", {"id", "status", "detail"})
        identifier = require_string(requirement["id"], f"external_requirements[{index}].id", maximum=128)
        if not TOKEN.fullmatch(identifier) or identifier in requirement_ids:
            raise EvidenceError(f"external_requirements[{index}].id is invalid or duplicated")
        requirement_ids.add(identifier)
        if requirement["status"] not in ("satisfied", "blocked"):
            raise EvidenceError(f"external_requirements[{index}].status is invalid")
        blocked_external += requirement["status"] == "blocked"
        require_string(requirement["detail"], f"external_requirements[{index}].detail")

    secret_scan = require_object(root["secret_scan"], "secret_scan", {"status", "scanner", "findings"})
    if secret_scan["status"] not in counts:
        raise EvidenceError("secret_scan.status is invalid")
    require_string(secret_scan["scanner"], "secret_scan.scanner", maximum=256)
    findings = require_integer(secret_scan["findings"], "secret_scan.findings")
    if secret_scan["status"] == "pass" and findings != 0:
        raise EvidenceError("a passing secret scan must have zero findings")

    summary = require_object(root["summary"], "summary", {"status", "passed", "failed", "blocked", "total"})
    for field in ("passed", "failed", "blocked"):
        value = require_integer(summary[field], f"summary.{field}")
        if value != counts[{"passed": "pass", "failed": "fail", "blocked": "blocked"}[field]]:
            raise EvidenceError(f"summary.{field} does not match cases")
    total = require_integer(summary["total"], "summary.total", minimum=1)
    if total != len(cases) or total != sum(counts.values()):
        raise EvidenceError("summary.total does not match cases")
    expected_status = "fail" if counts["fail"] or secret_scan["status"] == "fail" else (
        "blocked" if counts["blocked"] or blocked_external or secret_scan["status"] == "blocked" else "pass"
    )
    if summary["status"] != expected_status:
        raise EvidenceError(f"summary.status must be {expected_status}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.evidence.read_text(encoding="utf-8"))
        validate_evidence(document)
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"invalid Phase 4 evidence: {error}", file=sys.stderr)
        return 1
    print(f"valid Phase 4 evidence: {args.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
