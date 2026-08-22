from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "phase4" / "fixtures"
EVIDENCE = ROOT / "scripts" / "phase4-evidence.py"
RELEASE = ROOT / "scripts" / "phase4-release-integrity.py"
SERVICES = ROOT / "scripts" / "phase4-validate-services.py"
DRILL = ROOT / "scripts" / "phase4-upgrade-rollback-drill.py"


def run(*arguments: object, expect: int = 0) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        [sys.executable, *(str(argument) for argument in arguments)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != expect:
        raise AssertionError(
            f"unexpected exit {process.returncode}, expected {expect}\nstdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    return process


class EvidenceTests(unittest.TestCase):
    def test_schemas_are_valid_json(self) -> None:
        for name in ("phase4-evidence-v1.schema.json", "release-manifest-v1.schema.json"):
            document = json.loads((ROOT / "release" / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(document["additionalProperties"])

    def test_valid_blocked_fixture(self) -> None:
        run(EVIDENCE, FIXTURES / "evidence" / "valid-blocked.json")

    def test_invalid_fixtures_fail_closed(self) -> None:
        for path in sorted((FIXTURES / "evidence").glob("invalid-*.json")):
            result = run(EVIDENCE, path, expect=1)
            self.assertIn("invalid Phase 4 evidence", result.stderr)

    def test_case_artifact_must_be_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = json.loads((FIXTURES / "evidence" / "valid-blocked.json").read_text())
            value["cases"][0]["artifact_sha256"] = "c" * 64
            path = Path(temporary) / "unbound.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = run(EVIDENCE, path, expect=1)
            self.assertIn("not bound by artifacts", result.stderr)

    def test_blocked_secret_scanner_can_have_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = json.loads((FIXTURES / "evidence" / "valid-blocked.json").read_text())
            value["external_requirements"] = []
            value["secret_scan"] = {"status": "blocked", "scanner": "scanner-unavailable", "findings": 0}
            path = Path(temporary) / "blocked-scanner.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            run(EVIDENCE, path)


class ReleaseTests(unittest.TestCase):
    def staged_release(self, root: Path) -> Path:
        destination = root / "payload"
        shutil.copytree(FIXTURES / "release" / "payload", destination)
        return destination

    def generate(self, destination: Path) -> None:
        run(RELEASE, "generate", "--release-dir", destination, "--input", FIXTURES / "release" / "release-input.json")

    def test_generation_is_reproducible_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            self.generate(destination)
            first_manifest = (destination / "release-manifest.json").read_bytes()
            first_sums = (destination / "SHA256SUMS").read_bytes()
            self.generate(destination)
            self.assertEqual(first_manifest, (destination / "release-manifest.json").read_bytes())
            self.assertEqual(first_sums, (destination / "SHA256SUMS").read_bytes())
            run(RELEASE, "verify", "--release-dir", destination)
            manifest = json.loads(first_manifest)
            self.assertEqual({entry["role"] for entry in manifest["artifacts"]}, {
                "boxd", "libkrun", "libkrunfw", "runtime_bundle", "sbom", "licenses", "checksums",
            })

    def test_unbound_service_definitions_are_rejected_from_release_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            services = destination / "services"
            services.mkdir()
            shutil.copy(ROOT / "release/services/boxd.service", services / "boxd.service")
            shutil.copy(ROOT / "release/services/com.payhon.boxd.plist", services / "com.payhon.boxd.plist")
            result = run(
                RELEASE, "generate", "--release-dir", destination,
                "--input", FIXTURES / "release" / "release-input.json", expect=1,
            )
            self.assertIn("not declared", result.stderr)

    def test_payload_tamper_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            self.generate(destination)
            (destination / "lib" / "libkrun.so.1").write_text("tampered", encoding="utf-8")
            result = run(RELEASE, "verify", "--release-dir", destination, expect=1)
            self.assertIn("artifact drift", result.stderr)

    def test_symlink_payload_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = self.staged_release(root)
            native = destination / "lib" / "libkrun.so.1"
            target = root / "outside-libkrun"
            target.write_bytes(native.read_bytes())
            native.unlink()
            native.symlink_to(target)
            result = run(
                RELEASE, "generate", "--release-dir", destination,
                "--input", FIXTURES / "release" / "release-input.json", expect=1,
            )
            self.assertIn("symlink", result.stderr)

    def test_extra_regular_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            (destination / "unexpected.txt").write_text("tool output", encoding="utf-8")
            result = run(
                RELEASE, "generate", "--release-dir", destination,
                "--input", FIXTURES / "release" / "release-input.json", expect=1,
            )
            self.assertIn("not declared", result.stderr)

    def test_nested_extra_regular_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            (destination / "licenses" / "unexpected-license.txt").write_text("extra", encoding="utf-8")
            result = run(
                RELEASE, "generate", "--release-dir", destination,
                "--input", FIXTURES / "release" / "release-input.json", expect=1,
            )
            self.assertIn("not declared", result.stderr)

    def test_extra_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            (destination / "tool-tmp").mkdir()
            result = run(
                RELEASE, "generate", "--release-dir", destination,
                "--input", FIXTURES / "release" / "release-input.json", expect=1,
            )
            self.assertIn("directory is not declared", result.stderr)

    def test_extra_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = self.staged_release(root)
            (destination / "unexpected-link").symlink_to(destination / "boxd-linux-x86_64")
            result = run(
                RELEASE, "generate", "--release-dir", destination,
                "--input", FIXTURES / "release" / "release-input.json", expect=1,
            )
            self.assertIn("symlink", result.stderr)

    def test_extra_hardlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = self.staged_release(root)
            (destination / "unexpected-hardlink").hardlink_to(destination / "boxd-linux-x86_64")
            result = run(
                RELEASE, "generate", "--release-dir", destination,
                "--input", FIXTURES / "release" / "release-input.json", expect=1,
            )
            self.assertIn("hard-linked", result.stderr)

    def test_provenance_must_be_a_local_hashed_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            input_value = json.loads((FIXTURES / "release" / "release-input.json").read_text())
            input_value["provenance"]["sha256"] = "0" * 64
            input_path = Path(temporary) / "input.json"
            input_path.write_text(json.dumps(input_value), encoding="utf-8")
            result = run(RELEASE, "generate", "--release-dir", destination, "--input", input_path, expect=1)
            self.assertIn("provenance file hash mismatch", result.stderr)

    def test_provenance_path_cannot_alias_a_payload_role(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            input_value = json.loads((FIXTURES / "release" / "release-input.json").read_text())
            boxd_path = input_value["artifacts"]["boxd"]
            input_value["provenance"]["path"] = boxd_path
            input_value["provenance"]["sha256"] = hashlib.sha256((destination / boxd_path).read_bytes()).hexdigest()
            input_path = Path(temporary) / "input.json"
            input_path.write_text(json.dumps(input_value), encoding="utf-8")
            result = run(RELEASE, "generate", "--release-dir", destination, "--input", input_path, expect=1)
            self.assertIn("distinct from release artifact", result.stderr)

    def test_embedded_console_sbom_checksum_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            sbom_path = destination / "sbom.spdx.json"
            sbom = json.loads(sbom_path.read_text())
            next(package for package in sbom["packages"] if package["name"] == "boxd-console")["checksums"][0]["checksumValue"] = "1" * 64
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            result = run(RELEASE, "generate", "--release-dir", destination, "--input", FIXTURES / "release" / "release-input.json", expect=1)
            self.assertIn("embedded boxd-console", result.stderr)

    def test_generated_outputs_reject_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            self.generate(destination)
            linked = Path(temporary) / "linked-sums"
            linked.hardlink_to(destination / "SHA256SUMS")
            (destination / "SHA256SUMS").unlink()
            (destination / "SHA256SUMS").hardlink_to(linked)
            result = run(RELEASE, "generate", "--release-dir", destination, "--input", FIXTURES / "release" / "release-input.json", expect=1)
            self.assertIn("unique regular files", result.stderr)

    def test_incomplete_sbom_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = self.staged_release(Path(temporary))
            sbom_path = destination / "sbom.spdx.json"
            sbom = json.loads(sbom_path.read_text())
            sbom["packages"] = [package for package in sbom["packages"] if package["name"] != "boxd-console"]
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            result = run(
                RELEASE, "generate", "--release-dir", destination,
                "--input", FIXTURES / "release" / "release-input.json", expect=1,
            )
            self.assertIn("SBOM missing packages", result.stderr)


class ServiceAndDrillTests(unittest.TestCase):
    def test_service_templates(self) -> None:
        run(
            SERVICES,
            "--systemd", ROOT / "release" / "services" / "boxd.service",
            "--launchd", ROOT / "release" / "services" / "com.payhon.boxd.plist",
        )

    def test_relaxed_systemd_template_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unit = Path(temporary) / "boxd.service"
            source = (ROOT / "release" / "services" / "boxd.service").read_text()
            unit.write_text(source.replace("ProtectSystem=strict", "ProtectSystem=false"), encoding="utf-8")
            result = run(
                SERVICES, "--systemd", unit,
                "--launchd", ROOT / "release" / "services" / "com.payhon.boxd.plist", expect=1,
            )
            self.assertIn("ProtectSystem", result.stderr)

    def test_service_symlink_and_hardlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            systemd = root / "boxd.service"
            launchd = root / "com.payhon.boxd.plist"
            systemd.symlink_to(ROOT / "release/services/boxd.service")
            launchd.write_bytes((ROOT / "release/services/com.payhon.boxd.plist").read_bytes())
            linked = root / "launchd-link"
            linked.hardlink_to(launchd)
            launchd.unlink()
            launchd.hardlink_to(linked)
            result = run(SERVICES, "--systemd", systemd, "--launchd", launchd, expect=1)
            self.assertIn("unique regular file", result.stderr)

    def test_hermetic_drill_emits_valid_blocked_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "upgrade.json"
            run(DRILL, "--commit", "0123456789abcdef0123456789abcdef01234567", "--output", evidence)
            run(EVIDENCE, evidence)
            value = json.loads(evidence.read_text())
            self.assertEqual(value["summary"]["status"], "blocked")
            self.assertTrue(all(item["status"] == "blocked" for item in value["external_requirements"]))


if __name__ == "__main__":
    unittest.main()
