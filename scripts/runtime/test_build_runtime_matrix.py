#!/usr/bin/env python3
"""Hermetic validation tests for the ten-runtime build orchestrator."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "build_runtime_matrix.py"
SPEC = importlib.util.spec_from_file_location("build_runtime_matrix", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="boxd-runtime-matrix-test-") as raw:
        root = Path(raw)
        items = {}
        for runtime in MODULE.RUNTIMES:
            source_user = "node" if runtime.startswith("node") else "boxuser"
            items[runtime] = {
                "version": "1.2.3",
                "runtime_image": f"example.invalid/{runtime}:1.2.3@sha256:" + "a" * 64,
                "rust_image": "example.invalid/rust:1.94.0@sha256:" + "b" * 64,
                "source_user": source_user,
                "runtime_license_source": "usr/local/share/licenses/runtime/LICENSE",
                "runtime_license_id": "NOASSERTION",
            }
        value = {
            "schema": "boxd-runtime-matrix-build-input-v1",
            "arch": "aarch64",
            "source_date_epoch": 1700000000,
            "default_disk_gib": 20,
            "kernel_version": "6.1.0",
            "items": items,
        }
        source = root / "matrix.json"
        source.write_text(json.dumps(value), encoding="utf-8")
        parsed = MODULE.load_pins(source)
        assert parsed.arch == "aarch64"
        assert len(parsed.items) == 10
        assert parsed.items[0].runtime == "node"
        assert parsed.items[-1].runtime == "rust-alpine"
        validate = subprocess.run(
            [sys.executable, str(SCRIPT), "--input", str(source), "--validate-only"],
            check=True,
            capture_output=True,
            text=True,
        )
        assert json.loads(validate.stdout) == {
            "valid": True,
            "arch": "aarch64",
            "runtimes": 10,
        }

        prerelease = json.loads(json.dumps(value))
        prerelease["items"]["rust"]["version"] = "1.94.0-rc.1+build.7"
        source.write_text(json.dumps(prerelease), encoding="utf-8")
        assert MODULE.load_pins(source).items[4].version == "1.94.0-rc.1+build.7"

        invalid_semver = json.loads(json.dumps(value))
        invalid_semver["items"]["rust"]["version"] = "01.94.0"
        source.write_text(json.dumps(invalid_semver), encoding="utf-8")
        try:
            MODULE.load_pins(source)
        except ValueError as error:
            assert "complete SemVer" in str(error)
        else:
            raise AssertionError("invalid SemVer with a leading zero was accepted")

        missing = json.loads(json.dumps(value))
        del missing["items"]["ruby-alpine"]
        source.write_text(json.dumps(missing), encoding="utf-8")
        try:
            MODULE.load_pins(source)
        except ValueError as error:
            assert "exactly all ten" in str(error)
        else:
            raise AssertionError("missing runtime was accepted")

        mutable = json.loads(json.dumps(value))
        mutable["items"]["node"]["runtime_image"] = "node:latest"
        source.write_text(json.dumps(mutable), encoding="utf-8")
        try:
            MODULE.load_pins(source)
        except ValueError as error:
            assert "immutable tag@sha256" in str(error)
        else:
            raise AssertionError("mutable image tag was accepted")

        unsafe_license = json.loads(json.dumps(value))
        unsafe_license["items"]["python"]["runtime_license_source"] = "../LICENSE"
        source.write_text(json.dumps(unsafe_license), encoding="utf-8")
        try:
            MODULE.load_pins(source)
        except ValueError as error:
            assert "canonical relative OCI path" in str(error)
        else:
            raise AssertionError("traversing runtime license path was accepted")

        output_target = root / "output-target"
        output_target.mkdir()
        output_link = root / "output-link"
        output_link.symlink_to(output_target, target_is_directory=True)
        manifest = root / "matrix-output.json"
        source.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--input",
                str(source),
                "--output-dir",
                str(output_link),
                "--matrix-manifest",
                str(manifest),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "output directory must be absolute and not a symlink" in result.stderr

        MODULE.atomic_json(manifest, {"first": True})
        try:
            MODULE.atomic_json(manifest, {"second": True})
        except FileExistsError:
            pass
        else:
            raise AssertionError("atomic JSON output overwrote an existing manifest")
        assert json.loads(manifest.read_text(encoding="utf-8")) == {"first": True}

    print("runtime matrix build input tests passed")


if __name__ == "__main__":
    main()
