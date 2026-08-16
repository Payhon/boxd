#!/usr/bin/env python3
"""Create canonical bundle-v1 metadata and a deterministic tar stream."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from pathlib import Path


def descriptor(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def manifest(args: argparse.Namespace) -> None:
    licenses_root = args.stage / "licenses"
    licenses = {
        path.relative_to(args.stage).as_posix(): descriptor(path)
        for path in sorted(licenses_root.rglob("*"))
        if path.is_file()
    }
    if not licenses:
        raise SystemExit("bundle requires at least one license file")
    value = {
        "format_version": 1,
        "runtime": args.runtime,
        "runtime_version": args.runtime_version,
        "arch": args.arch,
        "libkrun_version": "1.19.4",
        "kernel_version": args.kernel_version,
        "agent_protocol": 1,
        "build_toolchain": args.build_toolchain,
        "features": sorted(set(args.feature)),
        "rootfs": descriptor(args.stage / "rootfs.raw"),
        "sbom": descriptor(args.stage / "sbom.spdx.json"),
        "licenses": licenses,
        "signature": {"algorithm": "ed25519", "key_id": args.key_id},
    }
    # The exact bytes below are signed. Compact, sorted JSON avoids host locale
    # and pretty-printer differences.
    args.output.write_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    )


def archive(args: argparse.Namespace) -> None:
    entries = [
        args.stage / "manifest.json",
        args.stage / "manifest.sig",
        args.stage / "rootfs.raw",
        args.stage / "sbom.spdx.json",
        *sorted(path for path in (args.stage / "licenses").rglob("*") if path.is_file()),
    ]
    if str(args.output) == "-":
        output = tarfile.open(fileobj=sys.stdout.buffer, mode="w|", format=tarfile.GNU_FORMAT)
    else:
        output = tarfile.open(args.output, "w", format=tarfile.GNU_FORMAT)
    with output:
        for path in entries:
            relative = path.relative_to(args.stage).as_posix()
            if len(relative.encode("utf-8")) > 100:
                raise SystemExit(f"bundle path exceeds deterministic GNU header limit: {relative}")
            info = output.gettarinfo(str(path), arcname=relative)
            if not info.isfile():
                raise SystemExit(f"bundle entry is not a regular file: {relative}")
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = args.epoch
            info.mode = 0o444
            with path.open("rb") as source:
                output.addfile(info, source)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    metadata = subparsers.add_parser("manifest")
    metadata.add_argument("--stage", required=True, type=Path)
    metadata.add_argument("--output", required=True, type=Path)
    metadata.add_argument("--runtime", required=True)
    metadata.add_argument("--runtime-version", required=True)
    metadata.add_argument("--arch", required=True, choices=("aarch64", "x86_64"))
    metadata.add_argument("--kernel-version", required=True)
    metadata.add_argument("--build-toolchain", required=True)
    metadata.add_argument("--key-id", required=True)
    metadata.add_argument("--feature", action="append", default=[])
    metadata.set_defaults(handler=manifest)
    bundle = subparsers.add_parser("archive")
    bundle.add_argument("--stage", required=True, type=Path)
    bundle.add_argument("--output", required=True, type=Path, help="tar path or - for stdout")
    bundle.add_argument("--epoch", required=True, type=int)
    bundle.set_defaults(handler=archive)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
