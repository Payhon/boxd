#!/usr/bin/env python3
"""Hermetic Phase 4 load matrix validator and blocked evidence producer.

The harness never claims runtime performance.  ``--fixture`` validates the
shape of a dry-run fixture and deliberately emits ``blocked`` evidence.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, re, sys
from pathlib import Path
from statistics import median

SCHEMA = "boxd-phase4-load-v1"
BOX_COUNTS = (1, 4, 16, 64)
SCENARIOS = ("exec", "sse", "browser", "preview")
METRICS = ("p50_ms", "p95_ms", "p99_ms", "error_rate", "cpu_percent", "rss_bytes", "fd_count", "disk_bytes")
SECRET = re.compile(r"(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{16,}|gh[pous]_[A-Za-z0-9_]{16,})")

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

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--fixture", type=Path); p.add_argument("--emit-evidence", type=Path); p.add_argument("--commit", default="0"*40)
    a=p.parse_args(argv)
    if not a.fixture: p.error("--fixture is required; live execution requires a future native runner")
    try:
        doc=json.loads(a.fixture.read_text()); validate_fixture(doc)
        out=evidence(doc, commit=a.commit)
        if a.emit_evidence: a.emit_evidence.write_text(json.dumps(out, indent=2)+"\n")
        print(json.dumps({"schema":SCHEMA,"status":"blocked","matrix_cells":len(doc["runs"]),"reason":"fixture mode cannot prove runtime performance"}, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, HarnessError) as e: print(f"load harness rejected: {e}", file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())
