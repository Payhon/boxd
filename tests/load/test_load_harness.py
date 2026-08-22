import hashlib, importlib.util, json, pathlib, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).parents[2]
def load():
    spec = importlib.util.spec_from_file_location("load", ROOT / "scripts/phase4-load-harness.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class LoadHarnessTests(unittest.TestCase):
    def live_doc(self, root):
        d = json.loads((ROOT / "tests/load/fixture.json").read_text())
        artifacts = {}
        for name, relative in (("binary", "release/boxd"), ("runtime_bundle", "release/runtime.bundle")):
            content = f"{name}-payload".encode(); path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            artifacts[name] = {"path": relative, "sha256": hashlib.sha256(content).hexdigest()}
        d.update({"mode": "live", "commit": "a" * 40, "platform": {"os": "linux", "arch": "x86_64", "virtualization": "kvm"},
                  "pinned_sdk_commit": "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934", "artifacts": artifacts,
                  "daemon": {"cpu_percent": 1, "rss_bytes": 2, "fd_count": 3, "disk_bytes": 4}})
        return d

    def test_matrix_is_complete_but_blocked(self):
        m = load(); d = json.loads((ROOT / "tests/load/fixture.json").read_text()); m.validate_fixture(d); self.assertEqual(m.evidence(d)["summary"]["status"], "blocked")
    def test_secret_rejected(self):
        m = load(); d = {"schema":m.SCHEMA,"mode":"fixture","runs":[]}; self.assertRaises(m.HarnessError, m.validate_fixture, d)
    def test_live_requires_native_hashes_and_matrix(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); d = self.live_doc(root)
            self.assertEqual(m.live_evidence(d, root)["summary"]["status"], "pass")
            d["runs"][0]["metrics"]["error_rate"] = 0.1
            self.assertEqual(m.live_evidence(d, root)["summary"]["status"], "fail")

    def test_live_evidence_matches_phase4_evidence_validator(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); d = self.live_doc(root); evidence = m.live_evidence(d, root)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
                json.dump(evidence, handle); handle.flush()
                result = subprocess.run([sys.executable, str(ROOT / "scripts/phase4-evidence.py"), handle.name], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_rejects_unbound_or_unsafe_artifacts(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); d = self.live_doc(root)
            with self.assertRaises(m.HarnessError): m.live_evidence(d, None)
            (root / d["artifacts"]["binary"]["path"]).write_bytes(b"tampered")
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)
            d = self.live_doc(root); target = root / d["artifacts"]["binary"]["path"]
            link = target.with_name("boxd-link"); link.symlink_to(target)
            d["artifacts"]["binary"]["path"] = "release/boxd-link"
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)
