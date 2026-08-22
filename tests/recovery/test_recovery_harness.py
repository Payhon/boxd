import hashlib, importlib.util, json, pathlib, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).parents[2]
def load():
    spec = importlib.util.spec_from_file_location("recovery", ROOT / "scripts/phase4-recovery-harness.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class RecoveryHarnessTests(unittest.TestCase):
    def test_matrix_is_complete_but_blocked(self):
        m = load(); d = json.loads((ROOT / "tests/recovery/fixture.json").read_text()); m.validate(d); self.assertEqual(m.evidence(d)["summary"]["status"], "blocked")

    def live_doc(self, root):
        m = load()
        def write(relative, content):
            path = root / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            return hashlib.sha256(content).hexdigest()
        input_paths = {name: f"inputs/{name}.bin" for name in ("boxd", "runtime", "db", "artifact")}
        input_hashes = {name: write(path, f"{name}-evidence".encode()) for name, path in input_paths.items()}
        return {"schema": "boxd-phase4-recovery-v1", "mode": "live", "commit": "b" * 40,
                "platform": {"os": "linux", "arch": "x86_64", "virtualization": "kvm"},
                "inputs": [{"name": name, "path": input_paths[name], "sha256": input_hashes[name]} for name in input_paths],
                "cases": [{"scenario": scenario, "expected": "recovery", "observed": "artifact observed", "status": "pass", "artifact_path": f"cases/{scenario}.json", "artifact_sha256": write(f"cases/{scenario}.json", scenario.encode())} for scenario in m.SCENARIOS]}

    def test_live_evidence_is_bound_and_accepted_by_evidence_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "artifacts"; root.mkdir(); d = self.live_doc(root)
            source = pathlib.Path(directory) / "live.json"; evidence = pathlib.Path(directory) / "evidence.json"
            source.write_text(json.dumps(d));
            result = subprocess.run([sys.executable, str(ROOT / "scripts/phase4-recovery-harness.py"), "--live", str(source), "--artifact-root", str(root), "--emit-evidence", str(evidence)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            gate = subprocess.run([sys.executable, str(ROOT / "scripts/phase4-evidence.py"), str(evidence)], capture_output=True, text=True)
            self.assertEqual(gate.returncode, 0, gate.stderr)

    def test_live_rejects_fixture_and_missing_artifact_or_native_virtualization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); m = load(); d = self.live_doc(root)
            d["platform"]["virtualization"] = "none"
            with self.assertRaises(m.HarnessError): m.validate_live(d)
            d = self.live_doc(root); d["cases"][0]["observed"] = "fixture validated"
            with self.assertRaises(m.HarnessError): m.validate_live(d)
            d = self.live_doc(root); d["cases"][0].pop("artifact_sha256")
            with self.assertRaises(m.HarnessError): m.validate_live(d)
            d = self.live_doc(root); d["cases"][0]["artifact_sha256"] = "0" * 64
            with self.assertRaises(m.HarnessError): m.verify_live_artifacts(d, root)
            d = self.live_doc(root); (root / "cases/link.json").symlink_to(root / "cases/graceful-stop.json")
            d["cases"][0]["artifact_path"] = "cases/link.json"
            with self.assertRaises(m.HarnessError): m.verify_live_artifacts(d, root)
            d = self.live_doc(root)
            with self.assertRaises(m.HarnessError): m.live_evidence(d, None)
            source = pathlib.Path(directory) / "live.json"; source.write_text(json.dumps(d))
            result = subprocess.run([sys.executable, str(ROOT / "scripts/phase4-recovery-harness.py"), "--live", str(source)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
