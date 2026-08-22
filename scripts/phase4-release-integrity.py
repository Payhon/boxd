#!/usr/bin/env python3
"""Generate and verify deterministic boxd release integrity metadata.

This tool does not sign, notarize, build, or execute a VM. It binds already
produced release payloads, an SPDX document, license evidence, native libraries,
and a runtime bundle into canonical SHA256SUMS and release-manifest.json files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

ROLES = ("boxd", "libkrun", "libkrunfw", "runtime_bundle", "sbom", "licenses")
ALL_ROLES = (*ROLES, "checksums")
TARGETS = ("darwin-arm64", "linux-x86_64", "linux-aarch64")
COMPONENT_FOR_ROLE = {
    "boxd": "boxd",
    "libkrun": "libkrun",
    "libkrunfw": "libkrunfw",
    "runtime_bundle": "runtime-bundle",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


class IntegrityError(ValueError):
    """Release input or output is incomplete, ambiguous, or has drifted."""


def closed_object(value: Any, where: str, required: set[str], optional: set[str] = set()) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IntegrityError(f"{where} must be an object")
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        raise IntegrityError(f"{where} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise IntegrityError(f"{where} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def text(value: Any, where: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise IntegrityError(f"{where} must be a non-empty string up to {maximum} bytes")
    return value


def integer(value: Any, where: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise IntegrityError(f"{where} must be an integer >= {minimum}")
    return value


def sha(value: Any, where: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise IntegrityError(f"{where} must be a lowercase SHA-256")
    return value


def relative_path(value: Any, where: str) -> str:
    path = text(value, where, 512)
    pure = PurePosixPath(path)
    if path.startswith("/") or "//" in path or any(part in ("", ".", "..") for part in pure.parts):
        raise IntegrityError(f"{where} must be a normalized relative POSIX path")
    if not re.fullmatch(r"[A-Za-z0-9._/+@=-]+", path):
        raise IntegrityError(f"{where} contains unsupported characters")
    return path


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def secure_file(root: Path, relative: str) -> Path:
    path = root
    for component in PurePosixPath(relative).parts:
        path = path / component
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise IntegrityError(f"missing release file {relative}: {error}") from error
        if stat.S_ISLNK(mode):
            raise IntegrityError(f"release path must not traverse a symlink: {relative}")
    status = path.stat()
    if not stat.S_ISREG(status.st_mode):
        raise IntegrityError(f"release artifact must be a regular file: {relative}")
    if status.st_nlink != 1:
        raise IntegrityError(f"release artifact must not be hard-linked: {relative}")
    return path


def read_json(path: Path, where: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError(f"invalid {where}: {error}") from error


def atomic_write(path: Path, payload: bytes) -> None:
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise


def validate_license_index(root: Path, relative: str) -> None:
    index = closed_object(read_json(secure_file(root, relative), "license index"), "license index", {"schema", "entries"})
    if index["schema"] != "boxd-license-index-v1":
        raise IntegrityError("unsupported license index schema")
    entries = index["entries"]
    if not isinstance(entries, list) or not entries:
        raise IntegrityError("license index entries must be a non-empty array")
    required = {"boxd", "boxd-console", "libkrun", "libkrunfw", "runtime-bundle"}
    components: set[str] = set()
    paths: set[str] = set()
    for offset, raw in enumerate(entries):
        entry = closed_object(raw, f"license entries[{offset}]", {"component", "path", "sha256"})
        component = text(entry["component"], f"license entries[{offset}].component", 128)
        license_path = relative_path(entry["path"], f"license entries[{offset}].path")
        if not license_path.startswith("licenses/") or license_path == relative:
            raise IntegrityError("license evidence must be a file below licenses/ and not the index")
        if component in components or license_path in paths:
            raise IntegrityError("license index component and path must be unique")
        components.add(component)
        paths.add(license_path)
        actual = file_sha256(secure_file(root, license_path))
        if sha(entry["sha256"], f"license entries[{offset}].sha256") != actual:
            raise IntegrityError(f"license evidence hash mismatch: {license_path}")
    missing = required - components
    if missing:
        raise IntegrityError(f"license index missing components: {', '.join(sorted(missing))}")


def package_checksum(package: dict[str, Any], where: str) -> str:
    checksums = package.get("checksums")
    if not isinstance(checksums, list):
        raise IntegrityError(f"{where}.checksums must be an array")
    values = [item.get("checksumValue") for item in checksums if isinstance(item, dict) and item.get("algorithm") == "SHA256"]
    if len(values) != 1:
        raise IntegrityError(f"{where} must have exactly one SHA256 checksum")
    return sha(values[0], f"{where}.checksums.SHA256")


def validate_sbom(root: Path, relative: str, role_hashes: dict[str, str]) -> None:
    document = read_json(secure_file(root, relative), "SPDX SBOM")
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3" or document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise IntegrityError("SBOM must be an SPDX 2.3 document")
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise IntegrityError("SBOM packages must be an array")
    by_name: dict[str, dict[str, Any]] = {}
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise IntegrityError(f"SBOM packages[{index}] must be an object")
        name = package.get("name")
        if not isinstance(name, str) or name in by_name:
            raise IntegrityError("SBOM package names must be non-empty and unique")
        by_name[name] = package
        text(package.get("licenseDeclared"), f"SBOM package {name}.licenseDeclared", 256)
    required = {"boxd", "boxd-console", "libkrun", "libkrunfw", "runtime-bundle"}
    missing = required - set(by_name)
    if missing:
        raise IntegrityError(f"SBOM missing packages: {', '.join(sorted(missing))}")
    for role, component in COMPONENT_FOR_ROLE.items():
        if package_checksum(by_name[component], f"SBOM package {component}") != role_hashes[role]:
            raise IntegrityError(f"SBOM checksum does not bind {role}")
    # The console is embedded in the boxd payload in this release layout.  It
    # has no independent artifact path, so its SPDX checksum must bind the
    # exact boxd payload hash rather than an unverified placeholder.
    if package_checksum(by_name["boxd-console"], "SBOM package boxd-console") != role_hashes["boxd"]:
        raise IntegrityError("SBOM checksum does not bind embedded boxd-console")
    relationships = document.get("relationships")
    described = {
        item.get("relatedSpdxElement")
        for item in relationships if isinstance(item, dict) and item.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and item.get("relationshipType") == "DESCRIBES"
    } if isinstance(relationships, list) else set()
    for name in required:
        identifier = by_name[name].get("SPDXID")
        if not isinstance(identifier, str) or identifier not in described:
            raise IntegrityError(f"SBOM document does not DESCRIBE {name}")


def validate_metadata(value: Any) -> dict[str, Any]:
    metadata = closed_object(
        value, "release input",
        {"schema", "version", "commit", "target", "source_date_epoch", "toolchain", "builder", "provenance", "artifacts"},
    )
    if metadata["schema"] != "boxd-release-input-v1":
        raise IntegrityError("unsupported release input schema")
    if not isinstance(metadata["version"], str) or not VERSION.fullmatch(metadata["version"]):
        raise IntegrityError("version must be a SemVer core with optional prerelease")
    if not isinstance(metadata["commit"], str) or not COMMIT.fullmatch(metadata["commit"]):
        raise IntegrityError("commit must be a full lowercase 40-character Git object id")
    if metadata["target"] not in TARGETS:
        raise IntegrityError("unsupported release target")
    integer(metadata["source_date_epoch"], "source_date_epoch")
    toolchain = metadata["toolchain"]
    if not isinstance(toolchain, dict) or not toolchain:
        raise IntegrityError("toolchain must be a non-empty object")
    for key, value in toolchain.items():
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", key):
            raise IntegrityError(f"invalid toolchain key: {key}")
        text(value, f"toolchain.{key}", 256)
    builder = closed_object(metadata["builder"], "builder", {"id", "kind"})
    text(builder["id"], "builder.id", 256)
    if builder["kind"] not in ("github-actions", "local-hermetic", "release-builder"):
        raise IntegrityError("unsupported builder kind")
    provenance = closed_object(metadata["provenance"], "provenance", {"uri", "path", "sha256"})
    uri = text(provenance["uri"], "provenance.uri")
    if not (uri.startswith("https://") or uri.startswith("urn:")) or " " in uri:
        raise IntegrityError("provenance.uri must use https or urn")
    provenance_path = relative_path(provenance["path"], "provenance.path")
    if provenance_path in ("SHA256SUMS", "release-manifest.json"):
        raise IntegrityError("provenance.path must not reserve generated output names")
    sha(provenance["sha256"], "provenance.sha256")
    artifacts = closed_object(metadata["artifacts"], "artifacts", set(ROLES))
    paths = [relative_path(artifacts[role], f"artifacts.{role}") for role in ROLES]
    if len(paths) != len(set(paths)) or "SHA256SUMS" in paths or "release-manifest.json" in paths:
        raise IntegrityError("artifact paths must be unique and must not reserve generated output names")
    if provenance_path in paths:
        raise IntegrityError("provenance.path must be distinct from release artifact paths")
    expected_names = {
        "darwin-arm64": ("boxd-darwin-arm64", "libkrun.1.dylib", "libkrunfw.5.dylib", "arm64"),
        "linux-x86_64": ("boxd-linux-x86_64", "libkrun.so.1", "libkrunfw.so.5", "x86_64"),
        "linux-aarch64": ("boxd-linux-aarch64", "libkrun.so.1", "libkrunfw.so.5", "aarch64"),
    }[metadata["target"]]
    for role, expected in zip(("boxd", "libkrun", "libkrunfw"), expected_names[:3], strict=True):
        if PurePosixPath(artifacts[role]).name != expected:
            raise IntegrityError(f"{metadata['target']} {role} must use the reviewed filename {expected}")
    if expected_names[3] not in PurePosixPath(artifacts["runtime_bundle"]).name:
        raise IntegrityError("runtime bundle filename must bind the release architecture")
    return metadata


def artifact_records(root: Path, paths: dict[str, str]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    records: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    for role in ROLES:
        relative = paths[role]
        path = secure_file(root, relative)
        digest = file_sha256(path)
        hashes[role] = digest
        records.append({"role": role, "path": relative, "sha256": digest, "size": path.stat().st_size})
    return records, hashes


def validate_provenance(root: Path, provenance: dict[str, Any]) -> None:
    path = secure_file(root, relative_path(provenance["path"], "provenance.path"))
    actual = file_sha256(path)
    if actual != provenance["sha256"]:
        raise IntegrityError("provenance file hash mismatch")


def checksum_bytes(records: list[dict[str, Any]]) -> bytes:
    return "".join(f"{item['sha256']}  {item['path']}\n" for item in sorted(records, key=lambda item: item["path"])).encode()


def generate(root: Path, input_path: Path) -> None:
    metadata = validate_metadata(read_json(input_path, "release input"))
    paths = {role: metadata["artifacts"][role] for role in ROLES}
    records, hashes = artifact_records(root, paths)
    validate_provenance(root, metadata["provenance"])
    validate_license_index(root, paths["licenses"])
    validate_sbom(root, paths["sbom"], hashes)
    checksums = checksum_bytes(records)
    checksum_path = root / "SHA256SUMS"
    manifest_path = root / "release-manifest.json"
    for output in (checksum_path, manifest_path):
        if output.exists():
            mode = output.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode) or output.stat().st_nlink != 1:
                raise IntegrityError("generated outputs must be unique regular files")
    atomic_write(checksum_path, checksums)
    records.append({"role": "checksums", "path": "SHA256SUMS", "sha256": hashlib.sha256(checksums).hexdigest(), "size": len(checksums)})
    manifest = {
        "schema": "boxd-release-manifest-v1",
        "version": metadata["version"],
        "commit": metadata["commit"],
        "target": metadata["target"],
        "source_date_epoch": metadata["source_date_epoch"],
        "toolchain": metadata["toolchain"],
        "builder": metadata["builder"],
        "provenance": metadata["provenance"],
        "artifacts": records,
    }
    atomic_write(manifest_path, canonical_json(manifest))
    verify(root, manifest_path)


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = closed_object(
        value, "release manifest",
        {"schema", "version", "commit", "target", "source_date_epoch", "toolchain", "builder", "provenance", "artifacts"},
    )
    metadata = dict(manifest)
    metadata["schema"] = "boxd-release-input-v1"
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list):
        raise IntegrityError("release manifest artifacts must be an array")
    by_role: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(artifacts):
        record = closed_object(raw, f"artifacts[{index}]", {"role", "path", "sha256", "size"})
        role = record["role"]
        if role not in ALL_ROLES or role in by_role:
            raise IntegrityError(f"artifacts[{index}].role is invalid or duplicated")
        relative_path(record["path"], f"artifacts[{index}].path")
        sha(record["sha256"], f"artifacts[{index}].sha256")
        integer(record["size"], f"artifacts[{index}].size", 1)
        by_role[role] = record
    if set(by_role) != set(ALL_ROLES):
        raise IntegrityError("release manifest must bind each required artifact role exactly once")
    if by_role["checksums"]["path"] != "SHA256SUMS":
        raise IntegrityError("checksums role must bind SHA256SUMS")
    metadata["artifacts"] = {role: by_role[role]["path"] for role in ROLES}
    validate_metadata(metadata)
    return manifest


def verify(root: Path, manifest_path: Path) -> None:
    if manifest_path != root / "release-manifest.json":
        raise IntegrityError("manifest must be the release root release-manifest.json")
    manifest = validate_manifest(read_json(secure_file(root, "release-manifest.json"), "release manifest"))
    by_role = {item["role"]: item for item in manifest["artifacts"]}
    paths = {role: by_role[role]["path"] for role in ROLES}
    records, hashes = artifact_records(root, paths)
    validate_provenance(root, manifest["provenance"])
    for record in records:
        expected = by_role[record["role"]]
        if record["sha256"] != expected["sha256"] or record["size"] != expected["size"]:
            raise IntegrityError(f"release artifact drift: {record['role']}")
    validate_license_index(root, paths["licenses"])
    validate_sbom(root, paths["sbom"], hashes)
    checksum_file = secure_file(root, by_role["checksums"]["path"])
    actual_checksums = checksum_file.read_bytes()
    if actual_checksums != checksum_bytes(records):
        raise IntegrityError("SHA256SUMS is not the canonical release payload projection")
    if hashlib.sha256(actual_checksums).hexdigest() != by_role["checksums"]["sha256"] or len(actual_checksums) != by_role["checksums"]["size"]:
        raise IntegrityError("SHA256SUMS manifest binding mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate_parser = subparsers.add_parser("generate")
    generate_parser.add_argument("--release-dir", required=True, type=Path)
    generate_parser.add_argument("--input", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--release-dir", required=True, type=Path)
    verify_parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        root = args.release_dir.resolve(strict=True)
        if not root.is_dir():
            raise IntegrityError("release-dir must be a directory")
        if args.command == "generate":
            generate(root, args.input)
        else:
            verify(root, args.manifest or root / "release-manifest.json")
    except (OSError, IntegrityError) as error:
        print(f"release integrity failed: {error}", file=sys.stderr)
        return 1
    print(f"release integrity {args.command} passed: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
