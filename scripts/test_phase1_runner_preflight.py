#!/usr/bin/env python3
"""Hermetic preflight tests for the cross-platform runtime matrix runner."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "phase1-runtime-matrix-smoke.sh"
RUNTIMES = (
    "node",
    "python",
    "golang",
    "ruby",
    "rust",
    "node-alpine",
    "python-alpine",
    "golang-alpine",
    "ruby-alpine",
    "rust-alpine",
)


def invoke(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(RUNNER)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="boxd-runner-preflight-") as raw:
        root = Path(raw)
        boxd = root / "boxd"
        boxd.write_bytes(b"not executed during preflight")
        boxd.chmod(0o700)
        config = root / "boxd.toml"
        config.write_text("version = 1\n", encoding="utf-8")
        manifest = root / "matrix.json"
        manifest.write_text("{}\n", encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "BOXD_MATRIX_BOXD": str(boxd),
                "BOXD_MATRIX_BOXD_SHA256": hashlib.sha256(boxd.read_bytes()).hexdigest(),
                "BOXD_MATRIX_CONFIG": str(config),
                "BOXD_MATRIX_MANIFEST": str(manifest),
                "BOXD_MATRIX_EVIDENCE_DIR": str(root / "evidence-invalid-url"),
                "BOXD_MASTER_KEY": "fixture-master-key",
                "BOXD_ADMIN_PASSWORD": "fixture-admin-password",
                "UPSTASH_BOX_API_KEY": "fixture-api-key",
                "UPSTASH_BOX_BASE_URL": "http://user@localhost:7331/path?query=1",
            }
        )
        invalid_url = invoke(environment)
        assert invalid_url.returncode != 0
        assert "bare loopback HTTP origin" in invalid_url.stderr

        host_arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(
            os.uname().machine
        )
        if host_arch is None:
            raise AssertionError(f"unsupported test host architecture: {os.uname().machine}")
        bundles = {}
        for runtime in RUNTIMES:
            bundle = root / f"{runtime}.tar.zst"
            bundle.write_bytes(runtime.encode("utf-8"))
            bundles[runtime] = str(bundle)
        manifest.write_text(
            json.dumps(
                {
                    "schema": "boxd-phase1-runtime-matrix-input-v1",
                    "arch": host_arch,
                    "bundles": bundles,
                    "unexpected": True,
                }
            ),
            encoding="utf-8",
        )
        environment["BOXD_MATRIX_EVIDENCE_DIR"] = str(root / "evidence-extra-field")
        environment["UPSTASH_BOX_BASE_URL"] = "http://127.0.0.1:9"
        extra_field = invoke(environment)
        assert extra_field.returncode != 0
        assert "unexpected or missing fields" in extra_field.stderr

        bundles["ruby"] = str(root / "ruby\ncontrol.tar.zst")
        manifest.write_text(
            json.dumps(
                {
                    "schema": "boxd-phase1-runtime-matrix-input-v1",
                    "arch": host_arch,
                    "bundles": bundles,
                }
            ),
            encoding="utf-8",
        )
        environment["BOXD_MATRIX_EVIDENCE_DIR"] = str(root / "evidence-control-path")
        control_path = invoke(environment)
        assert control_path.returncode != 0
        assert "invalid bundle path for ruby" in control_path.stderr

    print("Phase 1 runner preflight tests passed")


if __name__ == "__main__":
    main()
