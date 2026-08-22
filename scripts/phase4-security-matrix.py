#!/usr/bin/env python3
"""Validate a redacted, machine-readable Phase 4 security matrix.

This validator only reports aggregate counts. It never echoes case inputs or
fixture values into an evidence artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

SCHEMA = "boxd-phase4-security-matrix-v1"
CATEGORIES = {"tenant", "ssrf", "path", "redaction", "resource", "runtime"}
EXPECTED = {"allow", "deny", "deny_leak"}
SECRET_LIKE = re.compile(r"(?:gh[pous]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|Bearer\s+\S+)")


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def scan_values(value: object) -> None:
    if isinstance(value, str):
        if SECRET_LIKE.search(value):
            fail("secret-like value in matrix")
        return
    if isinstance(value, list):
        for item in value:
            scan_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            scan_values(item)


def validate(document: object) -> dict[str, object]:
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        fail("invalid security matrix schema")
    scan_values(document)
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        fail("cases must be a non-empty list")
    ids: set[str] = set()
    categories: set[str] = set()
    positives = negatives = 0
    for case in cases:
        if not isinstance(case, dict):
            fail("case must be an object")
        case_id = case.get("id")
        category = case.get("category")
        expected = case.get("expected")
        positive = case.get("positive")
        if not isinstance(case_id, str) or not re.fullmatch(r"[A-Z]+-[0-9]{3}", case_id):
            fail("invalid case id")
        if case_id in ids:
            fail("duplicate case id")
        ids.add(case_id)
        if category not in CATEGORIES:
            fail(f"unsupported category: {category}")
        categories.add(category)
        if expected not in EXPECTED:
            fail("case expected result is not fail-closed")
        if not isinstance(positive, bool):
            fail("case positive must be boolean")
        positives += positive
        negatives += not positive
    if categories != CATEGORIES:
        fail("matrix must cover every security category")
    if positives == 0 or negatives == 0:
        fail("matrix requires both positive and negative cases")
    digest = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema": SCHEMA,
        "status": "pass",
        "case_count": len(cases),
        "positive_cases": positives,
        "negative_cases": negatives,
        "categories": sorted(categories),
        "matrix_sha256": digest,
        "platform_gate": "blocked: requires real HVF/KVM runner",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True, type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.cases.read_text(encoding="utf-8"))
        result = validate(document)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"security matrix rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
