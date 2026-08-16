#!/usr/bin/env python3
"""Verify the committed historical macOS Phase 1 evidence projection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "phase1-evidence"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name: str) -> dict[str, object]:
    value = json.loads((EVIDENCE / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{name} must contain a JSON object")
    return value


def main() -> None:
    manifest = load("manifest.json")
    if manifest.get("schema") != "boxd-phase1-redacted-evidence-manifest-v1":
        raise AssertionError("unsupported Phase 1 evidence manifest")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != {
        "final-artifact.json",
        "lifecycle.json",
        "restart.json",
        "egress-lifecycle.json",
        "egress-restart.json",
    }:
        raise AssertionError("evidence manifest must bind exactly five projections")
    for name, expected in files.items():
        if not isinstance(name, str) or Path(name).name != name:
            raise AssertionError("unsafe evidence filename")
        if not isinstance(expected, str) or sha256(EVIDENCE / name) != expected:
            raise AssertionError(f"evidence projection hash mismatch: {name}")

    final = load("final-artifact.json")
    agent_source = final.get("box_agent_source_sha256")
    if (
        not isinstance(agent_source, str)
        or len(agent_source) != 64
        or any(character not in "0123456789abcdef" for character in agent_source)
    ):
        raise AssertionError("macOS evidence has an invalid historical box-agent source hash")
    for field in (
        "production_import",
        "doctor_minimum_free_gib_10",
        "doctor_smoke_minimum_free_gib_1",
        "macos_hvf_deny_all_smoke",
        "macos_hvf_restricted_default_smoke",
        "macos_hvf_restricted_default_restart",
    ):
        if final.get(field) != "pass":
            raise AssertionError(f"macOS evidence field did not pass: {field}")

    lifecycle = load("lifecycle.json")
    restart = load("restart.json")
    egress_restart = load("egress-restart.json")
    links = manifest.get("cross_links")
    if not isinstance(links, dict):
        raise AssertionError("evidence manifest cross_links is missing")
    if restart.get("lifecycle_evidence_sha256") != files["lifecycle.json"]:
        raise AssertionError("platform restart does not bind the lifecycle projection")
    if lifecycle.get("status") != "idle" or restart.get("status") != "deleted":
        raise AssertionError("platform lifecycle/restart status is incomplete")
    if egress_restart.get("lifecycle_evidence_sha256") != links.get(
        "egress_lifecycle_raw_sha256_used_by_restart"
    ):
        raise AssertionError("egress restart raw lifecycle hash drifted")
    if links.get("egress_lifecycle_redacted_projection_sha256") != files["egress-lifecycle.json"]:
        raise AssertionError("egress redacted lifecycle projection hash drifted")
    if egress_restart.get("status") != "deleted":
        raise AssertionError("egress restart status is incomplete")

    print("macOS Phase 1 redacted evidence verification passed")


if __name__ == "__main__":
    main()
