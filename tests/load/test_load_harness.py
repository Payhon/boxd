import hashlib, importlib.util, json, pathlib, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).parents[2]
def load():
    spec = importlib.util.spec_from_file_location("load", ROOT / "scripts/phase4-load-harness.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class LoadHarnessTests(unittest.TestCase):
    def live_doc(self, root):
        d = json.loads((ROOT / "tests/load/fixture.json").read_text())
        artifacts = {}
        payloads = {
            "binary": ("release/boxd", b"binary-payload"),
            "runtime_bundle": ("release/runtime.bundle", b"runtime_bundle-payload"),
            "config": ("release/load-profile.toml", b"[resources]\nmax_running_boxes = 64\nmax_total_memory_mib = 262144\nmax_total_vcpus = 128\ndefault_disk_gib = 20\n[quotas]\ntenant_max_boxes = 64\ntenant_max_disk_gib = 1280\ntenant_max_concurrent_runs = 64\n"),
        }
        for name, (relative, content) in payloads.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            artifacts[name] = {"path": relative, "sha256": hashlib.sha256(content).hexdigest()}
        for run in d["runs"]:
            run["metrics"] = {name: run["metrics"][name] for name in ("p50_ms", "p95_ms", "p99_ms", "error_rate")}
            run["resource_sampling"] = {"interval_ms": 250, "sample_count": 2, "ceiling": {"cpu_percent": 10, "rss_bytes": 20, "fd_count": 30, "disk_bytes": 40}}
            preview_bytes = [1] * run["boxes"] if run["scenario"] == "preview" else []
            run["proof"] = {"created_count": run["boxes"], "create_failure_count": 0, "operation_attempted_count": run["boxes"], "operation_succeeded_count": run["boxes"], "operation_failure_count": 0, "deleted_count": run["boxes"], "cleanup_failure_count": 0, "failure_count": 0, "started_at_unix_ms": 1, "finished_at_unix_ms": 2, "created_ids_sha256": "0" * 64}
            run["proof"].update(preview_fetch_count=len(preview_bytes), preview_bytes_consumed=sum(preview_bytes), preview_response_bytes=preview_bytes, resource_sample_count=2, resource_sampling_error_count=0)
        profile_requirements = {"max_running_boxes": 64, "max_total_memory_mib": 262144, "max_total_vcpus": 128, "default_disk_gib": 20, "tenant_max_boxes": 64, "tenant_max_disk_gib": 1280, "tenant_max_concurrent_runs": 64}
        d.update({"mode": "live", "commit": "a" * 40, "platform": {"os": "linux", "arch": "x86_64", "virtualization": "kvm"},
                  "pinned_sdk_commit": "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934", "profile": {"name": "phase4-64", "max_boxes": 64, "runtime": "node", "requirements": profile_requirements, "configured": profile_requirements, "runtime_asserted": True}, "artifacts": artifacts,
                  "daemon": {"cpu_percent": 10, "rss_bytes": 20, "fd_count": 30, "disk_bytes": 40}, "daemon_sampling": {"interval_ms": 250, "sample_count": 33}})
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
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)

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
            d = self.live_doc(root)
            (root / d["artifacts"]["config"]["path"]).write_bytes(b"tampered-config")
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)

    def test_live_proof_is_closed_and_counts_cannot_be_faked(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); d = self.live_doc(root)
            d["runs"][0]["proof"]["created_count"] = 0
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)
            d = self.live_doc(root); d["runs"][0]["proof"]["unexpected"] = 1
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)
            d = self.live_doc(root); d["runs"][0]["resource_sampling"].pop("sample_count")
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)
            d = self.live_doc(root); target = root / d["artifacts"]["binary"]["path"]
            link = target.with_name("boxd-link"); link.symlink_to(target)
            d["artifacts"]["binary"]["path"] = "release/boxd-link"
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)

    def test_live_profile_must_bind_full_resource_matrix(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); d = self.live_doc(root)
            d["profile"]["configured"]["tenant_max_disk_gib"] = 20
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)
            d = self.live_doc(root)
            d["profile"]["configured"]["tenant_max_concurrent_runs"] = 4
            with self.assertRaises(m.HarnessError): m.live_evidence(d, root)

    def test_live_secret_scan_runs_before_profile_validation(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); d = self.live_doc(root)
            d["profile"]["configured"]["leaked"] = "Bearer " + "x" * 20
            with self.assertRaisesRegex(m.HarnessError, "secret-like"):
                m.live_evidence(d, root)

    def test_failure_transcripts_are_valid_but_summary_fails(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for kind in ("create", "operation", "cleanup"):
                d = self.live_doc(root); p = d["runs"][0]["proof"]; boxes = d["runs"][0]["boxes"]
                if kind == "create": p.update(created_count=boxes-1, create_failure_count=1, operation_attempted_count=boxes-1, operation_succeeded_count=boxes-1, deleted_count=boxes-1, failure_count=1); d["runs"][0]["metrics"]["error_rate"] = 1 / boxes
                elif kind == "operation": p.update(operation_succeeded_count=boxes-1, operation_failure_count=1, failure_count=1); d["runs"][0]["metrics"]["error_rate"] = 1 / boxes
                else: p.update(deleted_count=boxes-1, cleanup_failure_count=1)
                self.assertEqual(m.live_evidence(d, root)["summary"]["status"], "fail")
