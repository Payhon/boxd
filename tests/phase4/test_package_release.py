import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/package-release.py"
COMMIT = "1" * 40
ASSET_SHA = "2" * 64
FW_SHA = "3" * 64


class PackageReleaseTests(unittest.TestCase):
    def package(
        self, root: pathlib.Path, target: str, output: str = "out"
    ) -> tuple[pathlib.Path, dict]:
        binary = root / "boxd"
        binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        output_dir = root / output
        summary = root / f"{output}.json"
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--binary",
                str(binary),
                "--target",
                target,
                "--version",
                "0.0.0-preview.1",
                "--commit",
                COMMIT,
                "--source-date-epoch",
                "1700000000",
                "--libkrun-sha256",
                ASSET_SHA,
                "--libkrunfw-sha256",
                FW_SHA,
                "--libkrun-license",
                str(ROOT / "LICENSE"),
                "--libkrunfw-license",
                str(ROOT / "LICENSE"),
                "--output-dir",
                str(output_dir),
                "--summary",
                str(summary),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(summary.read_text())
        return output_dir / data["archive"], data

    def test_linux_archive_is_closed_and_reproducible(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            archive, summary = self.package(pathlib.Path(first), "linux-x86_64")
            other, _ = self.package(pathlib.Path(second), "linux-x86_64")
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), summary["sha256"])
            self.assertEqual(archive.read_bytes(), other.read_bytes())
            with tarfile.open(archive, "r:gz") as package:
                names = package.getnames()
                prefix = "boxd-0.0.0-preview.1-linux-x86_64/"
                self.assertIn(prefix + "bin/boxd", names)
                self.assertIn(prefix + "systemd/boxd.service", names)
                self.assertNotIn(prefix + "launchd/com.payhon.boxd.plist", names)
                self.assertIn(prefix + "licenses/LICENSE.libkrun", names)
                self.assertIn(prefix + "licenses/LICENSE.libkrunfw", names)
                self.assertIn(prefix + "sbom.spdx.json", names)
                manifest = json.load(package.extractfile(prefix + "build-manifest.json"))
                self.assertFalse(manifest["claims"]["boxd_1_0"])
                self.assertFalse(manifest["claims"]["runtime_bundle_included"])
                sbom = json.load(package.extractfile(prefix + "sbom.spdx.json"))
                self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
                self.assertEqual(len(sbom["packages"]), 4)

    def test_macos_archive_contains_launchd_definition(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, _ = self.package(pathlib.Path(directory), "darwin-arm64")
            with zipfile.ZipFile(archive) as package:
                names = package.namelist()
                prefix = "boxd-0.0.0-preview.1-darwin-arm64/"
                self.assertIn(prefix + "bin/boxd", names)
                self.assertIn(prefix + "launchd/com.payhon.boxd.plist", names)
                self.assertNotIn(prefix + "systemd/boxd.service", names)

    def test_rejects_symlink_binary(self):
        if os.name == "nt":
            self.skipTest("symlink semantics differ on Windows")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            real = root / "real"
            real.write_bytes(b"binary")
            link = root / "boxd"
            link.symlink_to(real)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--binary",
                    str(link),
                    "--target",
                    "linux-aarch64",
                    "--version",
                    "0.0.0-preview.1",
                    "--commit",
                    COMMIT,
                    "--source-date-epoch",
                    "1700000000",
                    "--libkrun-sha256",
                    ASSET_SHA,
                    "--libkrunfw-sha256",
                    FW_SHA,
                    "--libkrun-license",
                    str(ROOT / "LICENSE"),
                    "--libkrunfw-license",
                    str(ROOT / "LICENSE"),
                    "--output-dir",
                    str(root / "out"),
                    "--summary",
                    str(root / "summary.json"),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("regular non-symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
