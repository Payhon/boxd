#!/usr/bin/env python3
"""Validate release pins, build ten bundles serially, emit the smoke manifest."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


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
PINNED_IMAGE = re.compile(r"^[^\s@]+:[^\s@]+@sha256:[0-9a-f]{64}$")
SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


@dataclass(frozen=True)
class RuntimePin:
    runtime: str
    version: str
    runtime_image: str
    rust_image: str
    source_user: str
    runtime_license_source: str
    runtime_license_id: str


@dataclass(frozen=True)
class MatrixPins:
    arch: str
    source_date_epoch: int
    default_disk_gib: int
    kernel_version: str
    items: tuple[RuntimePin, ...]


def canonical_oci_path(raw: object, field: str) -> str:
    if not isinstance(raw, str) or not raw or raw.startswith("/") or "\x00" in raw:
        raise ValueError(f"{field} must be a canonical relative OCI path")
    path = Path(raw)
    if (
        len(raw.encode("utf-8")) > 4096
        or any(part in {"", ".", ".."} or len(part.encode("utf-8")) > 255 for part in path.parts)
        or path.as_posix() != raw
    ):
        raise ValueError(f"{field} must be a canonical relative OCI path")
    return raw


def parse_pin(runtime: str, raw: object) -> RuntimePin:
    if not isinstance(raw, dict) or set(raw) != {
        "version",
        "runtime_image",
        "rust_image",
        "source_user",
        "runtime_license_source",
        "runtime_license_id",
    }:
        raise ValueError(f"{runtime} has unexpected or missing fields")
    version = raw["version"]
    runtime_image = raw["runtime_image"]
    rust_image = raw["rust_image"]
    source_user = raw["source_user"]
    license_id = raw["runtime_license_id"]
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise ValueError(f"{runtime}.version must be complete SemVer")
    for value, field in ((runtime_image, "runtime_image"), (rust_image, "rust_image")):
        if not isinstance(value, str) or not PINNED_IMAGE.fullmatch(value):
            raise ValueError(f"{runtime}.{field} must be immutable tag@sha256")
    if not isinstance(source_user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", source_user):
        raise ValueError(f"{runtime}.source_user is invalid")
    if (
        not isinstance(license_id, str)
        or not re.fullmatch(r"[A-Za-z0-9.+() -]{1,128}", license_id)
    ):
        raise ValueError(f"{runtime}.runtime_license_id is invalid")
    return RuntimePin(
        runtime=runtime,
        version=version,
        runtime_image=runtime_image,
        rust_image=rust_image,
        source_user=source_user,
        runtime_license_source=canonical_oci_path(
            raw["runtime_license_source"], f"{runtime}.runtime_license_source"
        ),
        runtime_license_id=license_id,
    )


def load_pins(path: Path) -> MatrixPins:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("input must be an absolute regular non-symlink file")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {
        "schema",
        "arch",
        "source_date_epoch",
        "default_disk_gib",
        "kernel_version",
        "items",
    }:
        raise ValueError("matrix input has unexpected or missing top-level fields")
    if raw["schema"] != "boxd-runtime-matrix-build-input-v1":
        raise ValueError("matrix input schema is unsupported")
    if raw["arch"] not in {"aarch64", "x86_64"}:
        raise ValueError("matrix architecture is unsupported")
    if not isinstance(raw["source_date_epoch"], int) or raw["source_date_epoch"] < 0:
        raise ValueError("source_date_epoch must be a non-negative integer")
    if not isinstance(raw["default_disk_gib"], int) or not 1 <= raw["default_disk_gib"] <= 60:
        raise ValueError("default_disk_gib must be in 1..60")
    if not isinstance(raw["kernel_version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", raw["kernel_version"]):
        raise ValueError("kernel_version must be numeric x.y.z")
    items = raw["items"]
    if not isinstance(items, dict) or set(items) != set(RUNTIMES):
        raise ValueError("matrix input must contain exactly all ten runtime names")
    return MatrixPins(
        arch=raw["arch"],
        source_date_epoch=raw["source_date_epoch"],
        default_disk_gib=raw["default_disk_gib"],
        kernel_version=raw["kernel_version"],
        items=tuple(parse_pin(runtime, items[runtime]) for runtime in RUNTIMES),
    )


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.link(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate reviewed pins and serially build all ten runtime bundles for one architecture.",
        epilog=(
            "A build also requires BOXD_SIGNING_KEY, BOXD_SIGNING_KEY_ID, "
            "BOXD_AGENT_LICENSE_FILE, and an offline BOXD_CARGO_REGISTRY_DIR; "
            "see docs/runtime-artifact-build.md. No version or OCI digest is discovered automatically."
        ),
    )
    parser.add_argument("--input", required=True, type=Path, help="absolute build-input-v1 JSON path")
    parser.add_argument("--output-dir", type=Path, help="absolute non-symlink bundle output directory")
    parser.add_argument("--matrix-manifest", type=Path, help="absolute new smoke-manifest output path")
    parser.add_argument("--validate-only", action="store_true", help="validate pins without Docker or writes")
    args = parser.parse_args()
    pins = load_pins(args.input)
    if args.validate_only:
        print(json.dumps({"valid": True, "arch": pins.arch, "runtimes": len(pins.items)}))
        return
    if args.output_dir is None or args.matrix_manifest is None:
        raise SystemExit("--output-dir and --matrix-manifest are required for a build")
    output_dir = args.output_dir
    manifest = args.matrix_manifest
    if not output_dir.is_absolute() or output_dir.is_symlink():
        raise SystemExit("output directory must be absolute and not a symlink")
    if not manifest.is_absolute() or manifest.exists() or manifest.is_symlink():
        raise SystemExit("matrix manifest output must not already exist")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir = output_dir.resolve()
    builder = Path(__file__).resolve().parent / "build-runtime-bundle.sh"
    bundles: dict[str, str] = {}
    for pin in pins.items:
        environment = os.environ.copy()
        environment.update(
            {
                "BOXD_RUNTIME_NAME": pin.runtime,
                "BOXD_RUNTIME_VERSION": pin.version,
                "BOXD_RUNTIME_IMAGE": pin.runtime_image,
                "BOXD_RUST_IMAGE": pin.rust_image,
                "BOXD_TARGET_ARCH": pins.arch,
                "BOXD_SOURCE_USER": pin.source_user,
                "BOXD_RUNTIME_LICENSE_SOURCE": pin.runtime_license_source,
                "BOXD_RUNTIME_LICENSE_ID": pin.runtime_license_id,
                "BOXD_SOURCE_DATE_EPOCH": str(pins.source_date_epoch),
                "BOXD_DEFAULT_DISK_GIB": str(pins.default_disk_gib),
                "BOXD_KERNEL_VERSION": pins.kernel_version,
                "BOXD_OUTPUT_DIR": str(output_dir),
            }
        )
        subprocess.run([str(builder)], env=environment, check=True)
        bundle = output_dir / f"box-runtime-{pin.runtime}-{pins.arch}-{pin.version}.tar.zst"
        if bundle.is_symlink() or not bundle.is_file():
            raise SystemExit(f"builder did not produce expected bundle: {bundle}")
        bundles[pin.runtime] = str(bundle)
    atomic_json(
        manifest,
        {
            "schema": "boxd-phase1-runtime-matrix-input-v1",
            "arch": pins.arch,
            "bundles": bundles,
        },
    )
    print(json.dumps({"built": len(bundles), "matrix_manifest": str(manifest)}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error
