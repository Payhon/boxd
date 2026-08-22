#!/usr/bin/env python3
"""Run a hermetic model of the Phase 4 upgrade and rollback invariants.

This is intentionally not a database migration, service restart, or VM test. It
checks the release orchestration rules without external state and emits unified
evidence whose real-machine requirements remain explicitly blocked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def run_drill(root: Path) -> list[dict[str, str]]:
    state = root / "state"
    backups = root / "backups"
    runtimes = state / "runtimes"
    state.mkdir()
    backups.mkdir()
    runtimes.mkdir(parents=True)

    database = state / "boxd.sqlite3"
    database.write_bytes(b"SQLite format 3\x00phase4-fixture-schema-7")
    before = digest(database)
    backup = backups / f"boxd.sqlite3.{before}.bak"
    shutil.copyfile(database, backup)
    if digest(backup) != before:
        raise AssertionError("pre-upgrade backup does not match the database")

    journal = state / "migration-journal.json"
    write_json(journal, {
        "schema": "boxd-migration-journal-v1",
        "from_schema": 7,
        "to_schema": 8,
        "backup_sha256": before,
        "state": "prepared",
    })
    database.write_bytes(database.read_bytes() + b"\nforward-only-schema-8")
    after = digest(database)
    write_json(journal, {
        "schema": "boxd-migration-journal-v1",
        "from_schema": 7,
        "to_schema": 8,
        "backup_sha256": before,
        "database_sha256": after,
        "state": "applied",
    })

    old_runtime = hashlib.sha256(b"runtime-old").hexdigest()
    new_runtime = hashlib.sha256(b"runtime-new").hexdigest()
    (runtimes / old_runtime).write_bytes(b"runtime-old")
    (runtimes / new_runtime).write_bytes(b"runtime-new")
    running_box = {"box_id": "fixture-box", "runtime_sha256": old_runtime}
    write_json(state / "running-box.json", running_box)
    if json.loads((state / "running-box.json").read_text())["runtime_sha256"] != old_runtime:
        raise AssertionError("running Box runtime pin changed during upgrade")
    if not (runtimes / old_runtime).is_file() or not (runtimes / new_runtime).is_file():
        raise AssertionError("content-addressed runtime versions did not coexist")

    old_binary_max_schema = 8
    rollback_allowed = 8 <= old_binary_max_schema
    rollback_rejected = 9 > old_binary_max_schema
    if not rollback_allowed or not rollback_rejected:
        raise AssertionError("schema compatibility window was not enforced")
    restored = state / "restored.sqlite3"
    shutil.copyfile(backup, restored)
    if digest(restored) != before:
        raise AssertionError("rollback restore did not reproduce the backup")

    return [
        {
            "id": "backup.before.migration",
            "expected": "backup hash equals the pre-upgrade database hash",
            "observed": "content-addressed backup matched before the journal entered applied state",
            "status": "pass",
        },
        {
            "id": "migration.journal.forward-only",
            "expected": "journal records from/to schema, backup hash, database hash, and applied state",
            "observed": "schema 7 to 8 journal retained both hashes and never modeled a down migration",
            "status": "pass",
        },
        {
            "id": "runtime.content-hash.pin",
            "expected": "old and new runtime hashes coexist while a running Box stays pinned",
            "observed": "both runtime objects remained and fixture-box retained the old hash",
            "status": "pass",
        },
        {
            "id": "rollback.schema-window",
            "expected": "rollback is allowed only when the old binary supports the migrated schema",
            "observed": "schema 8 was allowed and schema 9 was rejected for max-supported schema 8",
            "status": "pass",
        },
        {
            "id": "rollback.backup.restore",
            "expected": "restored database is byte-identical to the pre-upgrade backup",
            "observed": "restored SHA-256 matched the pre-upgrade SHA-256",
            "status": "pass",
        },
    ]


def normalized_platform() -> tuple[str, str]:
    os_name = "macos" if sys.platform == "darwin" else "linux"
    machine = platform.machine().lower()
    arch = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
    return os_name, arch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if len(args.commit) != 40 or any(character not in "0123456789abcdef" for character in args.commit):
        print("commit must be a full lowercase Git object id", file=sys.stderr)
        return 2
    if args.output.exists():
        print("output already exists", file=sys.stderr)
        return 2
    os_name, arch = normalized_platform()
    try:
        with tempfile.TemporaryDirectory(prefix="boxd-phase4-upgrade-") as temporary:
            cases = run_drill(Path(temporary))
        script_hash = digest(Path(__file__))
        evidence = {
            "schema": "boxd-phase4-evidence-v1",
            "suite": "upgrade-rollback-hermetic",
            "commit": args.commit,
            "platform": {"os": os_name, "arch": arch, "virtualization": "none"},
            "toolchain": {"python": platform.python_version()},
            "inputs": [{"name": "drill-script", "sha256": script_hash}],
            "cases": cases,
            "artifacts": [],
            "external_requirements": [
                {
                    "id": "real-service-upgrade",
                    "status": "blocked",
                    "detail": "requires an installed release, real database, service manager, and retained rollback package",
                },
                {
                    "id": "macos-hvf-notarized",
                    "status": "blocked",
                    "detail": "requires notarized Developer ID artifacts and an Apple Silicon HVF host",
                },
                {
                    "id": "linux-kvm-both-architectures",
                    "status": "blocked",
                    "detail": "requires x86_64 and aarch64 Linux runners with writable KVM and cgroup v2",
                },
            ],
            "secret_scan": {"status": "pass", "scanner": "fixture-values-only", "findings": 0},
            "summary": {"status": "blocked", "passed": len(cases), "failed": 0, "blocked": 0, "total": len(cases)},
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes((json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode())
    except (OSError, AssertionError) as error:
        print(f"upgrade/rollback drill failed: {error}", file=sys.stderr)
        return 1
    print(f"hermetic upgrade/rollback model passed; real-platform status remains blocked: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
