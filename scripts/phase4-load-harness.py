#!/usr/bin/env python3
"""Hermetic Phase 4 load matrix validator and blocked evidence producer.

The harness never claims runtime performance.  ``--fixture`` validates the
shape of a dry-run fixture and deliberately emits ``blocked`` evidence.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, re, stat, sys
from pathlib import Path
from statistics import median

SCHEMA = "boxd-phase4-load-v1"
BOX_COUNTS = (1, 4, 16, 64)
SCENARIOS = ("exec", "sse", "browser", "preview")
METRICS = ("p50_ms", "p95_ms", "p99_ms", "error_rate", "cpu_percent", "rss_bytes", "fd_count", "disk_bytes")
SECRET = re.compile(r"(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{16,}|gh[pous]_[A-Za-z0-9_]{16,})")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RELATIVE_PATH = re.compile(r"^[A-Za-z0-9._/+@=-]+$")

class HarnessError(ValueError): pass

def _finite_number(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < minimum:
        raise HarnessError(f"{name} must be a number >= {minimum}")
    return value

def scan_secrets(value):
    if isinstance(value, str) and SECRET.search(value): raise HarnessError("secret-like value detected")
    if isinstance(value, dict):
        for v in value.values(): scan_secrets(v)
    elif isinstance(value, list):
        for v in value: scan_secrets(v)

def validate_fixture(doc):
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA: raise HarnessError("invalid load schema")
    scan_secrets(doc)
    if doc.get("mode") not in ("fixture", "live"): raise HarnessError("mode must be fixture or live")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs: raise HarnessError("runs must be non-empty")
    seen = set()
    for run in runs:
        if not isinstance(run, dict) or set(run) != {"boxes", "scenario", "metrics"}: raise HarnessError("run shape is closed")
        boxes, scenario = run["boxes"], run["scenario"]
        if boxes not in BOX_COUNTS or scenario not in SCENARIOS: raise HarnessError("unsupported load cell")
        key = (boxes, scenario)
        if key in seen: raise HarnessError("duplicate load cell")
        seen.add(key)
        metrics = run["metrics"]
        if not isinstance(metrics, dict) or set(metrics) != set(METRICS): raise HarnessError("metrics schema mismatch")
        for name in METRICS: _finite_number(metrics[name], f"{key}.{name}", 0)
        if metrics["error_rate"] > 1: raise HarnessError("error_rate must be between 0 and 1")
        if not (metrics["p50_ms"] <= metrics["p95_ms"] <= metrics["p99_ms"]): raise HarnessError("latency percentiles out of order")
    missing = {(b, s) for b in BOX_COUNTS for s in SCENARIOS} - seen
    if missing: raise HarnessError("incomplete matrix: " + ",".join(f"{b}/{s}" for b,s in sorted(missing)))
    return doc

def evidence(doc, *, commit="0" * 40, platform=None):
    validate_fixture(doc)
    platform = platform or {"os": "macos" if sys.platform == "darwin" else "linux", "arch": "aarch64" if platform_module().startswith("arm") else "x86_64", "virtualization": "none"}
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    cases = [{"id": f"{b}/{s}", "expected": "measured on real boxd", "observed": "fixture validated; runtime unavailable", "status": "blocked"} for b in BOX_COUNTS for s in SCENARIOS]
    return {"schema":"boxd-phase4-evidence-v1", "suite":"load", "commit":commit, "platform":platform,
      "toolchain":{"python":"stdlib", "harness":"phase4-load-harness"}, "inputs":[{"name":"load-fixture", "sha256":digest}],
      "cases":cases, "artifacts":[], "external_requirements":[{"id":"boxd-runtime", "status":"blocked", "detail":"requires real boxd and signed runtime"},{"id":"hvf-or-kvm", "status":"blocked", "detail":"requires native HVF or KVM runner"}],
      "secret_scan":{"status":"pass", "scanner":"stdlib recursive scan", "findings":0}, "summary":{"status":"blocked", "passed":0,"failed":0,"blocked":len(cases),"total":len(cases)}}

def platform_module():
    return __import__("platform").machine()

def validate_path(value, where):
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value or "//" in value or not RELATIVE_PATH.fullmatch(value):
        raise HarnessError(f"{where} must be a normalized relative POSIX path")
    if any(part in ("", ".", "..") for part in value.split("/")):
        raise HarnessError(f"{where} must not contain dot or empty components")
    return value

def artifact_sha(root, relative, where):
    validate_path(relative, where)
    root_path = Path(root)
    root_info = root_path.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise HarnessError("artifact root must be a real directory")
    root_path = root_path.resolve(strict=True)
    current = root_path
    for part in relative.split("/"):
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise HarnessError(f"{where} may not traverse symlinks")
    info = current.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise HarnessError(f"{where} must be a single-link regular file")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise HarnessError(f"{where} escaped artifact root") from exc
    digest = hashlib.sha256()
    with resolved.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def verify_live_artifacts(doc, artifact_root):
    if artifact_root is None:
        raise HarnessError("--artifact-root is required for live mode")
    for name, item in doc["artifacts"].items():
        digest = artifact_sha(artifact_root, item["path"], f"{name} artifact")
        if digest != item["sha256"]:
            raise HarnessError(f"{name} artifact SHA-256 does not match")

def live_evidence(doc, artifact_root=None):
    validate_fixture(doc)
    if doc.get("mode") != "live": raise HarnessError("live evidence requires mode=live")
    if set(doc) != {"schema", "mode", "commit", "platform", "pinned_sdk_commit", "artifacts", "daemon", "runs"}:
        raise HarnessError("live input has unknown fields")
    commit, plat, artifacts = doc.get("commit", ""), doc.get("platform", {}), doc.get("artifacts", {})
    if not COMMIT.fullmatch(commit): raise HarnessError("live evidence requires a full commit hash")
    if plat not in ({"os": "linux", "arch": "x86_64", "virtualization": "kvm"}, {"os": "linux", "arch": "aarch64", "virtualization": "kvm"}, {"os": "macos", "arch": "aarch64", "virtualization": "hvf"}):
        raise HarnessError("live evidence requires Linux x86_64/aarch64 KVM or macOS aarch64 HVF")
    if doc.get("pinned_sdk_commit") != "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934": raise HarnessError("unexpected pinned SDK commit")
    if not isinstance(artifacts, dict) or set(artifacts) != {"binary", "runtime_bundle"}: raise HarnessError("live artifacts are not closed")
    for name, item in artifacts.items():
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}: raise HarnessError(f"{name} artifact shape is closed")
        validate_path(item.get("path"), f"{name} artifact path")
        if not SHA256.fullmatch(str(item.get("sha256", ""))): raise HarnessError(f"live evidence requires {name} artifact SHA-256")
    verify_live_artifacts(doc, artifact_root)
    failures = [run for run in doc["runs"] if run["metrics"]["error_rate"] != 0]
    daemon = doc.get("daemon")
    daemon_metrics = {"cpu_percent", "rss_bytes", "fd_count", "disk_bytes"}
    if not isinstance(daemon, dict) or set(daemon) != daemon_metrics:
        raise HarnessError("live evidence requires daemon metrics")
    for name in daemon_metrics: _finite_number(daemon[name], f"daemon.{name}")
    status = "fail" if failures else "pass"
    cases = [{"id": f"{run['boxes']}/{run['scenario']}", "expected": "zero-error live boxd load cell", "observed": "live cell completed" if run not in failures else "live cell reported errors", "status": "fail" if run in failures else "pass"} for run in doc["runs"]]
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema":"boxd-phase4-evidence-v1", "suite":"load", "commit":commit, "platform":plat,
      "toolchain":{"harness":"phase4-load-harness", "sdk":"upstash-box-0.6.3", "runtime":"boxd"},
      "inputs":[{"name":"live-load-result", "sha256":digest}],
      "cases":cases, "artifacts":[{"path":artifacts["binary"]["path"], "sha256":artifacts["binary"]["sha256"]}, {"path":artifacts["runtime_bundle"]["path"], "sha256":artifacts["runtime_bundle"]["sha256"]}],
      "external_requirements":[{"id":"native-virtualization", "status":"satisfied", "detail":"native HVF/KVM identified"}],
      "secret_scan":{"status":"pass", "scanner":"stdlib recursive scan", "findings":0},
      "summary":{"status":status,"passed":len(cases)-len(failures),"failed":len(failures),"blocked":0,"total":len(cases)}}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--fixture", type=Path); p.add_argument("--result", type=Path); p.add_argument("--artifact-root", type=Path); p.add_argument("--emit-evidence", type=Path); p.add_argument("--commit", default="0"*40)
    a=p.parse_args(argv)
    if not a.fixture and not a.result: p.error("--fixture or --result is required")
    try:
        doc=json.loads((a.fixture or a.result).read_text())
        out=live_evidence(doc, a.artifact_root) if a.result else evidence(doc, commit=a.commit)
        if a.emit_evidence: a.emit_evidence.write_text(json.dumps(out, indent=2)+"\n")
        status = out.get("summary", {}).get("status", "blocked")
        print(json.dumps({"schema":SCHEMA,"status":status,"matrix_cells":len(doc["runs"]),"reason":"fixture mode cannot prove runtime performance" if a.fixture else "live evidence validated"}, indent=2))
        return 0 if a.fixture or status == "pass" else 1
    except (OSError, json.JSONDecodeError, HarnessError) as e: print(f"load harness rejected: {e}", file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())
