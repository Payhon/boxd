#!/usr/bin/env python3
"""Emit a deterministic SPDX 2.3 SBOM for a pinned runtime artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def package_entry(name: str, version: str, architecture: str, family: str) -> dict[str, object]:
    identity = f"{name}@{version}:{architecture}"
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:16]
    purl_family = "deb/debian" if family == "debian" else "apk/alpine"
    license_name = "debian-copyrights.tar" if family == "debian" else "alpine-licenses.tar"
    return {
        "name": name,
        "SPDXID": f"SPDXRef-OS-{suffix}",
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "licenseComments": (
            f"Copyright evidence is stored in licenses/{license_name}; "
            f"licenses/{family}-licenses.index.json maps every source path to its SHA-256."
        ),
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:{purl_family}/"
                + re.sub(r"[^A-Za-z0-9._+-]", "-", name)
                + f"@{version}?arch={architecture}",
            }
        ],
    }


def dpkg_packages(path: Path) -> list[dict[str, object]]:
    packages: list[dict[str, object]] = []
    for paragraph in path.read_text(encoding="utf-8").split("\n\n"):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if not line or line[0].isspace() or ": " not in line:
                continue
            key, value = line.split(": ", 1)
            fields[key] = value
        if not all(key in fields for key in ("Package", "Version", "Architecture")):
            continue
        packages.append(package_entry(fields["Package"], fields["Version"], fields["Architecture"], "debian"))
    if not packages:
        raise SystemExit("dpkg status contains no installed packages")
    return sorted(packages, key=lambda package: (str(package["name"]), str(package["versionInfo"])))


def apk_packages(path: Path) -> list[dict[str, object]]:
    packages: list[dict[str, object]] = []
    for paragraph in path.read_text(encoding="utf-8").split("\n\n"):
        fields = {
            key: value
            for line in paragraph.splitlines()
            if len(line) >= 3 and line[1] == ":"
            for key, value in [line.split(":", 1)]
        }
        if not all(key in fields for key in ("P", "V", "A")):
            continue
        packages.append(package_entry(fields["P"], fields["V"], fields["A"], "alpine"))
    if not packages:
        raise SystemExit("apk installed database contains no packages")
    return sorted(packages, key=lambda package: (str(package["name"]), str(package["versionInfo"])))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--runtime", default="node")
    parser.add_argument("--runtime-version")
    parser.add_argument("--runtime-image")
    parser.add_argument("--runtime-license", default="NOASSERTION")
    parser.add_argument("--runtime-license-file", default="runtime-license.txt")
    parser.add_argument("--family", choices=("debian", "alpine"), default="debian")
    parser.add_argument("--arch", choices=("aarch64", "x86_64"), default="aarch64")
    parser.add_argument("--package-status", type=Path)
    # Legacy aliases for the existing reviewed Node builder.
    parser.add_argument("--node-version")
    parser.add_argument("--node-image")
    parser.add_argument("--agent-sha256", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--browser-version")
    parser.add_argument("--browser-license")
    parser.add_argument("--browser-license-file")
    parser.add_argument("--dpkg-status", type=Path)
    args = parser.parse_args()
    runtime_version = args.runtime_version or args.node_version
    runtime_image = args.runtime_image or args.node_image
    package_status = args.package_status or args.dpkg_status
    if not runtime_version or not runtime_image or not package_status:
        raise SystemExit("runtime version, image, and package status are required")
    if not args.agent_sha256.isascii() or len(args.agent_sha256) != 64:
        raise SystemExit("invalid agent SHA-256")
    base_packages = [
        {
            "name": args.runtime,
            "SPDXID": "SPDXRef-Package-Runtime",
            "versionInfo": runtime_version,
            "downloadLocation": f"pkg:docker/{args.runtime}@{runtime_version}?repository_url={runtime_image}",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": args.runtime_license,
            "licenseComments": f"Runtime license evidence is stored in licenses/{args.runtime_license_file}.",
            "copyrightText": "NOASSERTION",
        },
        {
            "name": "box-agent",
            "SPDXID": "SPDXRef-Package-BoxAgent",
            "versionInfo": "0.0.0",
            "downloadLocation": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": args.agent_sha256}],
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "licenseComments": "License text is stored in licenses/box-agent-Apache-2.0.txt.",
            "copyrightText": "NOASSERTION",
        },
    ]
    os_packages = dpkg_packages(package_status) if args.family == "debian" else apk_packages(package_status)
    packages = [*base_packages, *os_packages]
    browser_values = (args.browser_version, args.browser_license, args.browser_license_file)
    if any(browser_values) and not all(browser_values):
        raise SystemExit("browser version, license and license file must be provided together")
    if args.browser_version:
        packages.append(
            {
                "name": "chromium",
                "SPDXID": "SPDXRef-Package-Chromium",
                "versionInfo": args.browser_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": args.browser_license,
                "licenseDeclared": args.browser_license,
                "licenseComments": f"License text is stored in licenses/{args.browser_license_file}.",
                "copyrightText": "NOASSERTION",
            }
        )
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"boxd-{args.runtime}-{runtime_version}-{args.arch}",
        "documentNamespace": args.namespace,
        "creationInfo": {
            "created": args.created,
            "creators": ["Tool: boxd/scripts/runtime/generate_sbom.py"],
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": package["SPDXID"],
            }
            for package in packages
        ],
    }
    args.output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
