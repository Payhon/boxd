#!/usr/bin/env python3
"""Hermetic regression tests for the generic runtime artifact metadata tools."""

from __future__ import annotations

import io
import importlib.util
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PREPARE_SPEC = importlib.util.spec_from_file_location("prepare_rootfs_tar", ROOT / "prepare_rootfs_tar.py")
assert PREPARE_SPEC is not None and PREPARE_SPEC.loader is not None
PREPARE = importlib.util.module_from_spec(PREPARE_SPEC)
PREPARE_SPEC.loader.exec_module(PREPARE)


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    archive.addfile(info, io.BytesIO(data))


def add_dir(archive: tarfile.TarFile, name: str, mode: int = 0o755) -> None:
    info = tarfile.TarInfo(name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = mode
    archive.addfile(info)


def add_symlink(archive: tarfile.TarFile, name: str, target: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.mode = 0o777
    info.linkname = target
    archive.addfile(info)


def fake_agent(path: Path) -> None:
    path.write_bytes(b"\x7fELF" + b"fixture-agent")
    path.chmod(0o755)


def alpine_fixture(path: Path) -> None:
    with tarfile.open(path, "w") as archive:
        add_bytes(archive, "etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n")
        add_bytes(archive, "etc/group", b"root:x:0:\n")
        add_bytes(archive, "lib/apk/db/installed", b"P:busybox\nV:1.37.0-r0\nA:aarch64\n\n")
        add_dir(archive, "usr/share/licenses/busybox")
        add_bytes(archive, "usr/share/licenses/busybox/GPL-2.0-only", b"fixture GPL text\n")
        add_bytes(archive, "usr/bin/python3", b"fixture-python", 0o755)
        add_dir(archive, "home/python")
        add_bytes(archive, "home/python/should-not-survive", b"stale home\n")


def debian_fixture(path: Path) -> None:
    with tarfile.open(path, "w") as archive:
        add_bytes(archive, "etc/passwd", b"root:x:0:0:root:/root:/bin/bash\nnode:x:1000:1000::/home/node:/bin/bash\n")
        add_bytes(archive, "etc/group", b"root:x:0:\nnode:x:1000:\n")
        add_bytes(archive, "var/lib/dpkg/status", b"Package: nodejs\nVersion: 22.16.0\nArchitecture: arm64\n\n")
        add_dir(archive, "usr/share/doc/nodejs")
        add_bytes(archive, "usr/share/doc/nodejs/copyright", b"fixture MIT text\n")
        add_dir(archive, "usr/share/doc/openssl")
        add_symlink(archive, "usr/share/doc/openssl/copyright", "../nodejs/copyright")
        add_dir(archive, "usr/share/doc/removed-package")
        add_symlink(archive, "usr/share/doc/removed-package/copyright", "../missing/copyright")
        add_bytes(archive, "usr/local/LICENSE", b"fixture Node license\n")
        add_bytes(archive, "usr/local/bin/node", b"fixture-node", 0o755)
        add_dir(archive, "ms-playwright/chromium-fixture/chrome-linux", 0o777)
        add_bytes(
            archive,
            "ms-playwright/chromium-fixture/chrome-linux/chrome",
            b"\x7fELFfixture-chromium",
            0o777,
        )
        add_bytes(
            archive,
            "ms-playwright/chromium-fixture/chrome-linux/chrome_sandbox",
            b"\x7fELFfixture-sandbox",
            0o777,
        )


def run(*args: object) -> None:
    subprocess.run([sys.executable, *(str(value) for value in args)], check=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="boxd-runtime-tools-test-") as raw:
        root = Path(raw)
        oci = root / "alpine.tar"
        agent = root / "box-agent"
        normalized = root / "rootfs.tar"
        status = root / "apk-installed"
        licenses = root / "alpine-licenses.tar"
        license_index = root / "alpine-licenses.index.json"
        alpine_fixture(oci)
        fake_agent(agent)
        run(
            ROOT / "prepare_rootfs_tar.py",
            "--oci-export",
            oci,
            "--agent",
            agent,
            "--output",
            normalized,
            "--family",
            "alpine",
            "--source-user",
            "python",
            "--package-status-output",
            status,
            "--os-licenses-output",
            licenses,
            "--os-licenses-index-output",
            license_index,
            "--epoch",
            "1700000000",
            "--release",
            "runtime=python-alpine arch=aarch64 agent_protocol=1",
        )
        with tarfile.open(normalized) as archive:
            members = {member.name.rstrip("/"): member for member in archive.getmembers()}
            assert members["usr/local/bin/box-agent"].mode == 0o755
            passwd = archive.extractfile(members["etc/passwd"]).read().decode()
            assert "boxuser:x:1000:1000:" in passwd
            assert "workspace/home" in members
            assert "home/python" not in members
            assert "home/python/should-not-survive" not in members
        index = json.loads(license_index.read_text(encoding="utf-8"))
        assert index["files"][0]["path"] == "busybox/GPL-2.0-only"

        sbom = root / "sbom.json"
        run(
            ROOT / "generate_sbom.py",
            "--output",
            sbom,
            "--namespace",
            "https://boxd.invalid/fixture",
            "--runtime",
            "python-alpine",
            "--runtime-version",
            "3.13.0",
            "--runtime-image",
            "python:3.13-alpine@sha256:" + "a" * 64,
            "--runtime-license",
            "PSF-2.0",
            "--runtime-license-file",
            "python-runtime-license.txt",
            "--family",
            "alpine",
            "--arch",
            "aarch64",
            "--package-status",
            status,
            "--agent-sha256",
            "b" * 64,
            "--created",
            "2023-11-14T22:13:20Z",
            "--browser-version",
            "140.0.7339.16",
            "--browser-license",
            "BSD-3-Clause",
            "--browser-license-file",
            "chromium-BSD-3-Clause.txt",
        )
        document = json.loads(sbom.read_text(encoding="utf-8"))
        assert document["name"] == "boxd-python-alpine-3.13.0-aarch64"
        assert any(package["name"] == "busybox" for package in document["packages"])
        chromium_package = next(package for package in document["packages"] if package["name"] == "chromium")
        assert chromium_package["versionInfo"] == "140.0.7339.16"
        assert chromium_package["licenseDeclared"] == "BSD-3-Clause"
        runtime_package = next(package for package in document["packages"] if package["name"] == "python-alpine")
        assert runtime_package["licenseComments"].endswith("licenses/python-runtime-license.txt.")

        stage = root / "stage"
        (stage / "licenses").mkdir(parents=True)
        (stage / "rootfs.raw").write_bytes(b"rootfs")
        (stage / "sbom.spdx.json").write_bytes(sbom.read_bytes())
        (stage / "licenses" / "alpine-licenses.tar").write_bytes(licenses.read_bytes())
        manifest = stage / "manifest.json"
        run(
            ROOT / "bundle_v1.py",
            "manifest",
            "--stage",
            stage,
            "--output",
            manifest,
            "--runtime",
            "python-alpine",
            "--runtime-version",
            "3.13.0",
            "--arch",
            "aarch64",
            "--kernel-version",
            "6.1.0",
            "--build-toolchain",
            "fixture",
            "--key-id",
            "fixture",
            "--feature",
            "browser-cdp-v1",
        )
        value = json.loads(manifest.read_text(encoding="utf-8"))
        assert value["runtime"] == "python-alpine"
        assert value["arch"] == "aarch64"
        assert value["runtime_version"] == "3.13.0"
        assert value["features"] == ["browser-cdp-v1"]

        debian = root / "debian.tar"
        debian_normalized = root / "debian-rootfs.tar"
        debian_status = root / "dpkg-status"
        debian_licenses = root / "debian-licenses.tar"
        debian_index = root / "debian-licenses.index.json"
        node_license = root / "node-license"
        debian_fixture(debian)
        run(
            ROOT / "prepare_rootfs_tar.py",
            "--oci-export",
            debian,
            "--agent",
            agent,
            "--output",
            debian_normalized,
            "--node-license-output",
            node_license,
            "--dpkg-status-output",
            debian_status,
            "--debian-licenses-output",
            debian_licenses,
            "--debian-licenses-index-output",
            debian_index,
            "--epoch",
            "1700000000",
            "--release",
            "node=22.16.0 arch=aarch64 agent_protocol=1",
            "--browser-chromium-source",
            "ms-playwright/chromium-fixture/chrome-linux/chrome",
            "--browser-chromium-version",
            "140.0.7339.16",
        )
        with tarfile.open(debian_normalized) as archive:
            members = {member.name.rstrip("/"): member for member in archive.getmembers()}
            passwd = archive.extractfile(members["etc/passwd"]).read().decode()
            assert "node:x:1000:" not in passwd
            assert "boxuser:x:1000:1000:" in passwd
            assert members["usr/bin/chromium"].issym()
            assert members["usr/bin/chromium"].linkname == "../../ms-playwright/chromium-fixture/chrome-linux/chrome"
            assert members["ms-playwright/chromium-fixture/chrome-linux/chrome"].mode == 0o555
            assert members["ms-playwright/chromium-fixture/chrome-linux/chrome_sandbox"].mode == 0o4755
            browser_release = archive.extractfile(members["etc/boxd-browser-release"]).read().decode()
            assert browser_release == "chromium=140.0.7339.16\n"
        assert node_license.read_text(encoding="utf-8") == "fixture Node license\n"
        license_entries = json.loads(debian_index.read_text(encoding="utf-8"))["files"]
        license_hashes = {entry["path"]: entry["sha256"] for entry in license_entries}
        assert license_hashes["openssl/copyright"] == license_hashes["nodejs/copyright"]
        assert "removed-package/copyright" not in license_hashes

        hostile = root / "hostile-links.tar"
        with tarfile.open(hostile, "w") as archive:
            add_symlink(archive, "licenses/escape", "../../../outside")
            add_symlink(archive, "licenses/cycle-a", "cycle-b")
            add_symlink(archive, "licenses/cycle-b", "cycle-a")
        with tarfile.open(hostile) as archive:
            indexed = PREPARE.member_index(archive)
            try:
                PREPARE.resolved_regular_bytes(archive, indexed, indexed["licenses/escape"], "licenses/escape")
            except SystemExit as error:
                assert "escapes guest root" in str(error)
            else:
                raise AssertionError("escaping OCI symlink was accepted")
            try:
                PREPARE.resolved_regular_bytes(archive, indexed, indexed["licenses/cycle-a"], "licenses/cycle-a")
            except SystemExit as error:
                assert "cycle" in str(error)
            else:
                raise AssertionError("cyclic OCI symlink was accepted")

    print("runtime artifact metadata tool tests passed")


if __name__ == "__main__":
    main()
