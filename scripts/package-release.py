#!/usr/bin/env python3
"""Create deterministic, target-specific boxd preview archives.

This packager does not build, sign, notarize, or execute boxd. Those operations
belong to the native release workflow. It only closes the public archive over a
previously verified executable and repository-owned installation material.
"""

from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import io
import json
import pathlib
import re
import stat
import tarfile
import zipfile


TARGETS = {
    "darwin-arm64": ".zip",
    "linux-x86_64": ".tar.gz",
    "linux-aarch64": ".tar.gz",
}
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def regular_file(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise argparse.ArgumentTypeError(f"file does not exist: {path}") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise argparse.ArgumentTypeError(f"must be a regular non-symlink file: {path}")
    return path.resolve()


def bounded_epoch(value: str) -> int:
    try:
        epoch = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("source date epoch must be an integer") from error
    if epoch < 315532800:
        raise argparse.ArgumentTypeError("source date epoch must be on or after 1980-01-01")
    return epoch


def digest(path: pathlib.Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def install_text(target: str) -> bytes:
    service = (
        "Copy systemd/boxd.service only after reviewing its service user, paths, "
        "KVM access, and configuration."
        if target.startswith("linux-")
        else (
            "Copy launchd/com.payhon.boxd.plist only after reviewing its service "
            "user, paths, and configuration."
        )
    )
    return (
        "boxd preview binary\n"
        "===================\n\n"
        "1. Copy bin/boxd to a directory on PATH.\n"
        "2. Start from config/boxd.example.toml or run `boxd init`.\n"
        "3. Configure a trusted, signed runtime bundle before `boxd serve`.\n"
        "4. Run `boxd doctor --json` and require overall=true before use.\n\n"
        f"{service}\n\n"
        "This preview is not a boxd 1.0 or full-compatibility claim. See the\n"
        "release notes and https://payhon.github.io/boxd/ for current gates.\n"
    ).encode()


def archive_entries(args: argparse.Namespace) -> list[tuple[str, bytes, int]]:
    root = repository_root()
    binary_bytes = args.binary.read_bytes()
    binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()
    libkrun_license = args.libkrun_license.read_bytes()
    libkrunfw_license = args.libkrunfw_license.read_bytes()
    manifest = {
        "schema": "boxd-download-archive-v1",
        "version": args.version,
        "commit": args.commit,
        "target": args.target,
        "source_date_epoch": args.source_date_epoch,
        "stage": "preview",
        "binary_sha256": binary_sha256,
        "embedded_libkrun": {
            "version": "1.19.4",
            "sha256": args.libkrun_sha256,
        },
        "embedded_libkrunfw": {
            "abi": 5,
            "sha256": args.libkrunfw_sha256,
        },
        "claims": {
            "boxd_1_0": False,
            "full_upstash_compatibility": False,
            "runtime_bundle_included": False,
            "spdx_sbom_included": True,
        },
    }
    created = datetime.datetime.fromtimestamp(
        args.source_date_epoch, datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"boxd-{args.version}-{args.target}",
        "documentNamespace": (
            "https://github.com/Payhon/boxd/releases/preview/"
            f"{args.commit}/{args.target}/{args.version}"
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Tool: boxd-package-release-v1"],
        },
        "packages": [
            {
                "name": "boxd",
                "SPDXID": "SPDXRef-Package-boxd",
                "versionInfo": args.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "MIT",
                "checksums": [{"algorithm": "SHA256", "checksumValue": binary_sha256}],
            },
            {
                "name": "boxd-console",
                "SPDXID": "SPDXRef-Package-boxd-console",
                "versionInfo": args.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "MIT",
                "checksums": [{"algorithm": "SHA256", "checksumValue": binary_sha256}],
                "comment": "The Console is embedded in the boxd executable.",
            },
            {
                "name": "libkrun",
                "SPDXID": "SPDXRef-Package-libkrun",
                "versionInfo": "1.19.4",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": args.libkrun_sha256}
                ],
            },
            {
                "name": "libkrunfw",
                "SPDXID": "SPDXRef-Package-libkrunfw",
                "versionInfo": "firmware-abi-5",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": args.libkrunfw_sha256}
                ],
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": identifier,
            }
            for identifier in (
                "SPDXRef-Package-boxd",
                "SPDXRef-Package-boxd-console",
                "SPDXRef-Package-libkrun",
                "SPDXRef-Package-libkrunfw",
            )
        ],
    }
    entries = [
        ("bin/boxd", binary_bytes, 0o755),
        (
            "config/boxd.example.toml",
            (root / "config/boxd.example.toml").read_bytes(),
            0o644,
        ),
        ("licenses/LICENSE.boxd", (root / "LICENSE").read_bytes(), 0o644),
        ("licenses/LICENSE.libkrun", libkrun_license, 0o644),
        ("licenses/LICENSE.libkrunfw", libkrunfw_license, 0o644),
        ("INSTALL.txt", install_text(args.target), 0o644),
        (
            "build-manifest.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
            0o644,
        ),
        (
            "sbom.spdx.json",
            (json.dumps(sbom, indent=2, sort_keys=True) + "\n").encode(),
            0o644,
        ),
    ]
    if args.target.startswith("linux-"):
        entries.append(
            (
                "systemd/boxd.service",
                (root / "release/services/boxd.service").read_bytes(),
                0o644,
            )
        )
    else:
        entries.append(
            (
                "launchd/com.payhon.boxd.plist",
                (root / "release/services/com.payhon.boxd.plist").read_bytes(),
                0o644,
            )
        )
    return entries


def write_tar(
    path: pathlib.Path,
    prefix: str,
    entries: list[tuple[str, bytes, int]],
    epoch: int,
) -> None:
    with path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(mode="w", fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
                for name, content, mode in entries:
                    info = tarfile.TarInfo(f"{prefix}/{name}")
                    info.size = len(content)
                    info.mode = mode
                    info.mtime = epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    archive.addfile(info, io.BytesIO(content))


def write_zip(
    path: pathlib.Path,
    prefix: str,
    entries: list[tuple[str, bytes, int]],
    epoch: int,
) -> None:
    timestamp = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    date_time = (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )
    with zipfile.ZipFile(
        path, mode="x", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, content, mode in entries:
            info = zipfile.ZipInfo(f"{prefix}/{name}", date_time=date_time)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=regular_file)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=bounded_epoch)
    parser.add_argument("--libkrun-sha256", required=True)
    parser.add_argument("--libkrunfw-sha256", required=True)
    parser.add_argument("--libkrun-license", required=True, type=regular_file)
    parser.add_argument("--libkrunfw-license", required=True, type=regular_file)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--summary", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not SEMVER.fullmatch(args.version):
        parser.error("--version must be SemVer without a leading v")
    if not COMMIT.fullmatch(args.commit):
        parser.error("--commit must be a 40-character lowercase Git commit")
    for field in ("libkrun_sha256", "libkrunfw_sha256"):
        if not SHA256.fullmatch(getattr(args, field)):
            parser.error(f"--{field.replace('_', '-')} must be a lowercase SHA-256")
    return args


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.output_dir.is_symlink() or not args.output_dir.is_dir():
        raise SystemExit("output directory must be a non-symlink directory")
    prefix = f"boxd-{args.version}-{args.target}"
    archive = args.output_dir / f"{prefix}{TARGETS[args.target]}"
    if archive.exists() or archive.is_symlink():
        raise SystemExit(f"refusing to overwrite archive: {archive}")
    entries = archive_entries(args)
    if args.target == "darwin-arm64":
        write_zip(archive, prefix, entries, args.source_date_epoch)
    else:
        write_tar(archive, prefix, entries, args.source_date_epoch)
    summary = {
        "schema": "boxd-download-summary-v1",
        "archive": archive.name,
        "sha256": digest(archive),
        "size": archive.stat().st_size,
        "target": args.target,
        "version": args.version,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    with args.summary.open("x", encoding="utf-8") as output:
        json.dump(summary, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
