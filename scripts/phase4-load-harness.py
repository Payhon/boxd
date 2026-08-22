#!/usr/bin/env python3
"""Hermetic Phase 4 load matrix validator and blocked evidence producer.

The harness never claims runtime performance.  ``--fixture`` validates the
shape of a dry-run fixture and deliberately emits ``blocked`` evidence.
"""
from __future__ import annotations
import argparse, hashlib, json, re, stat, sys
from pathlib import Path

SCHEMA = "boxd-phase4-load-v1"
BOX_COUNTS = (1, 4, 16, 64)
SCENARIOS = ("exec", "sse", "browser", "preview")
METRICS = ("p50_ms", "p95_ms", "p99_ms", "error_rate")
RESOURCE_METRICS = ("cpu_percent", "rss_bytes", "fd_count", "disk_bytes")
PROFILE_RESOURCES = ("max_running_boxes", "max_total_memory_mib", "max_total_vcpus", "default_disk_gib", "tenant_max_boxes", "tenant_max_disk_gib", "tenant_max_concurrent_runs")
PROFILE_REQUIREMENTS = {
    "phase4-1": {"max_boxes": 1, "max_running_boxes": 1, "max_total_memory_mib": 4096, "max_total_vcpus": 2, "default_disk_gib": 20, "tenant_max_boxes": 1, "tenant_max_disk_gib": 20, "tenant_max_concurrent_runs": 1},
    "phase4-4": {"max_boxes": 4, "max_running_boxes": 4, "max_total_memory_mib": 16384, "max_total_vcpus": 8, "default_disk_gib": 20, "tenant_max_boxes": 4, "tenant_max_disk_gib": 80, "tenant_max_concurrent_runs": 4},
    "phase4-16": {"max_boxes": 16, "max_running_boxes": 16, "max_total_memory_mib": 65536, "max_total_vcpus": 32, "default_disk_gib": 20, "tenant_max_boxes": 16, "tenant_max_disk_gib": 320, "tenant_max_concurrent_runs": 16},
    "phase4-64": {"max_boxes": 64, "max_running_boxes": 64, "max_total_memory_mib": 262144, "max_total_vcpus": 128, "default_disk_gib": 20, "tenant_max_boxes": 64, "tenant_max_disk_gib": 1280, "tenant_max_concurrent_runs": 64},
}
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

def validate_profile(profile, *, live):
    if not isinstance(profile, dict) or set(profile) != {"name", "max_boxes", "runtime", "requirements", "configured", "runtime_asserted"}:
        raise HarnessError("load profile shape is closed")
    name = profile["name"]
    if not live and name == "fixture-blocked":
        if profile["max_boxes"] != max(BOX_COUNTS) or profile["runtime"] != "fixture" or profile["runtime_asserted"] is not False:
            raise HarnessError("fixture load profile must remain explicitly blocked")
        for label in ("requirements", "configured"):
            resources = profile[label]
            if not isinstance(resources, dict) or set(resources) != set(PROFILE_RESOURCES) or any(resources[key] != 0 for key in PROFILE_RESOURCES):
                raise HarnessError("fixture load profile resources must be zero")
        return
    if not isinstance(name, str) or name not in PROFILE_REQUIREMENTS:
        raise HarnessError("load profile name is unsupported")
    if type(profile["max_boxes"]) is not int or profile["max_boxes"] != PROFILE_REQUIREMENTS[name]["max_boxes"]:
        raise HarnessError("load profile max_boxes does not match the named profile")
    requirements = profile["requirements"]
    configured = profile["configured"]
    for label, resources in (("requirements", requirements), ("configured", configured)):
        if not isinstance(resources, dict) or set(resources) != set(PROFILE_RESOURCES):
            raise HarnessError(f"load profile {label} shape is closed")
        for key in PROFILE_RESOURCES:
            value = resources[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise HarnessError(f"load profile {label}.{key} must be a non-negative integer")
    expected = PROFILE_REQUIREMENTS[name]
    if profile["runtime"] != "node":
        raise HarnessError("complete live load profile requires runtime=node")
    for key in PROFILE_RESOURCES:
        if requirements[key] != expected[key] or configured[key] < requirements[key]:
            raise HarnessError(f"load profile resource precondition is not satisfied: {key}")
    if type(profile["runtime_asserted"]) is not bool or profile["runtime_asserted"] != live:
        raise HarnessError("load profile runtime_asserted does not match evidence mode")
    if live and profile["max_boxes"] < max(BOX_COUNTS):
        raise HarnessError("live load profile cannot prove the complete matrix")

def validate_resource_sampling(value, *, live):
    if not isinstance(value, dict) or set(value) != {"interval_ms", "sample_count", "ceiling"}:
        raise HarnessError("resource_sampling shape is closed")
    if isinstance(value["interval_ms"], bool) or not isinstance(value["interval_ms"], int) or not 0 <= value["interval_ms"] <= 10_000:
        raise HarnessError("resource_sampling.interval_ms is invalid")
    if isinstance(value["sample_count"], bool) or not isinstance(value["sample_count"], int) or value["sample_count"] < 0:
        raise HarnessError("resource_sampling.sample_count is invalid")
    if live and (value["interval_ms"] < 50 or value["sample_count"] < 1):
        raise HarnessError("live resource sampling requires a positive interval and at least one sample")
    ceiling = value["ceiling"]
    if not isinstance(ceiling, dict) or set(ceiling) != set(RESOURCE_METRICS):
        raise HarnessError("resource_sampling.ceiling shape is closed")
    for name in RESOURCE_METRICS: _finite_number(ceiling[name], f"resource_sampling.ceiling.{name}", 0)

def validate_fixture(doc):
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA: raise HarnessError("invalid load schema")
    scan_secrets(doc)
    if doc.get("mode") not in ("fixture", "live"): raise HarnessError("mode must be fixture or live")
    # The committed dry-run fixture predates live resource transcripts. Keep it
    # permanently blocked and closed under its original shape; it is never
    # accepted by live_evidence.
    if doc["mode"] == "fixture" and "profile" not in doc:
        legacy_metrics = set(METRICS) | set(RESOURCE_METRICS)
        seen = set()
        for run in doc.get("runs", []):
            if not isinstance(run, dict) or set(run) != {"boxes", "scenario", "metrics"}:
                raise HarnessError("legacy fixture run shape is closed")
            key = (run["boxes"], run["scenario"])
            if key in seen or run["boxes"] not in BOX_COUNTS or run["scenario"] not in SCENARIOS:
                raise HarnessError("unsupported or duplicate legacy fixture cell")
            seen.add(key)
            if not isinstance(run["metrics"], dict) or set(run["metrics"]) != legacy_metrics:
                raise HarnessError("legacy fixture metrics schema mismatch")
            for name in legacy_metrics: _finite_number(run["metrics"][name], f"{key}.{name}", 0)
            if run["metrics"]["error_rate"] > 1 or not (run["metrics"]["p50_ms"] <= run["metrics"]["p95_ms"] <= run["metrics"]["p99_ms"]):
                raise HarnessError("legacy fixture latency/error metrics are invalid")
        if seen != {(b, s) for b in BOX_COUNTS for s in SCENARIOS}:
            raise HarnessError("incomplete matrix")
        return doc
    validate_profile(doc.get("profile"), live=doc["mode"] == "live")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs: raise HarnessError("runs must be non-empty")
    seen = set()
    for run in runs:
        if not isinstance(run, dict) or set(run) != {"boxes", "scenario", "metrics", "resource_sampling", "proof"}:
            raise HarnessError("load run shape is closed")
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
        validate_resource_sampling(run["resource_sampling"], live=doc["mode"] == "live")
        proof = run["proof"]
        if not isinstance(proof, dict) or set(proof) != {"created_count", "create_failure_count", "operation_attempted_count", "operation_succeeded_count", "operation_failure_count", "deleted_count", "cleanup_failure_count", "failure_count", "preview_fetch_count", "preview_bytes_consumed", "preview_response_bytes", "resource_sample_count", "resource_sampling_error_count", "started_at_unix_ms", "finished_at_unix_ms", "created_ids_sha256"}:
            raise HarnessError("load proof shape is closed")
    missing = {(b, s) for b in BOX_COUNTS for s in SCENARIOS} - seen
    if missing: raise HarnessError("incomplete matrix: " + ",".join(f"{b}/{s}" for b,s in sorted(missing)))
    return doc

def validate_live_proof(run):
    if not isinstance(run, dict) or set(run) != {"boxes", "scenario", "metrics", "resource_sampling", "proof"}:
        raise HarnessError("live run must contain a closed proof transcript")
    boxes, proof = run["boxes"], run["proof"]
    metrics = run["metrics"]
    if not isinstance(metrics, dict) or set(metrics) != set(METRICS):
        raise HarnessError("live metrics schema is not closed")
    for name in METRICS: _finite_number(metrics[name], f"live.{run['boxes']}/{run['scenario']}.metrics.{name}", 0)
    if metrics["error_rate"] > 1 or not (metrics["p50_ms"] <= metrics["p95_ms"] <= metrics["p99_ms"]):
        raise HarnessError("live latency/error metrics are invalid")
    required = {"created_count", "create_failure_count", "operation_attempted_count", "operation_succeeded_count", "operation_failure_count", "deleted_count", "cleanup_failure_count", "failure_count", "preview_fetch_count", "preview_bytes_consumed", "preview_response_bytes", "resource_sample_count", "resource_sampling_error_count", "started_at_unix_ms", "finished_at_unix_ms", "created_ids_sha256"}
    allowed = required
    if not isinstance(proof, dict) or set(proof) - allowed or not required <= set(proof): raise HarnessError("proof fields are incomplete")
    for name in ("created_count", "create_failure_count", "operation_attempted_count", "operation_succeeded_count", "operation_failure_count", "deleted_count", "cleanup_failure_count", "failure_count", "preview_fetch_count", "preview_bytes_consumed", "resource_sample_count", "resource_sampling_error_count"):
        value = proof[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0: raise HarnessError(f"proof.{name} must be a non-negative integer")
    for name in ("started_at_unix_ms", "finished_at_unix_ms"):
        value = proof[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0: raise HarnessError(f"proof.{name} must be a unix millisecond integer")
    if proof["finished_at_unix_ms"] < proof["started_at_unix_ms"]: raise HarnessError("proof timestamps are not monotonic")
    if not SHA256.fullmatch(proof["created_ids_sha256"]): raise HarnessError("proof created id hash is invalid")
    preview_bytes = proof["preview_response_bytes"]
    if not isinstance(preview_bytes, list) or any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in preview_bytes):
        raise HarnessError("preview response byte transcript is invalid")
    if len(preview_bytes) != proof["preview_fetch_count"] or sum(preview_bytes) != proof["preview_bytes_consumed"]:
        raise HarnessError("preview bytes do not close against successful fetches")
    validate_resource_sampling(run["resource_sampling"], live=True)
    if proof["resource_sample_count"] != run["resource_sampling"]["sample_count"] or proof["resource_sampling_error_count"] != 0:
        raise HarnessError("resource sampling proof does not close")
    if run["scenario"] == "preview" and proof["preview_fetch_count"] != proof["operation_succeeded_count"]:
        raise HarnessError("preview fetch count does not equal successful operations")
    if run["scenario"] != "preview" and (proof["preview_fetch_count"] != 0 or proof["preview_bytes_consumed"] != 0 or preview_bytes):
        raise HarnessError("non-preview transcript contains preview fetches")
    cleanup_failures = proof["cleanup_failure_count"]
    if proof["created_count"] + proof["create_failure_count"] != boxes: raise HarnessError("live proof create counts do not close")
    if proof["operation_attempted_count"] != proof["created_count"]: raise HarnessError("live proof attempted count is not actual created count")
    if proof["operation_succeeded_count"] + proof["operation_failure_count"] != proof["operation_attempted_count"]: raise HarnessError("live proof operation counts do not close")
    if proof["deleted_count"] + cleanup_failures != proof["created_count"]: raise HarnessError("live proof cleanup counts do not close")
    if proof["failure_count"] != proof["create_failure_count"] + proof["operation_failure_count"]: raise HarnessError("live proof failure counts do not close")
    if proof["failure_count"] != metrics["error_rate"] * boxes: raise HarnessError("proof failure count disagrees with error_rate")

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
    if doc.get("mode") != "live": raise HarnessError("live evidence requires mode=live")
    if set(doc) != {"schema", "mode", "commit", "platform", "pinned_sdk_commit", "profile", "artifacts", "daemon", "daemon_sampling", "runs"}:
        raise HarnessError("live input has unknown fields")
    scan_secrets(doc)
    commit, plat, artifacts = doc.get("commit", ""), doc.get("platform", {}), doc.get("artifacts", {})
    if not COMMIT.fullmatch(commit): raise HarnessError("live evidence requires a full commit hash")
    if plat not in ({"os": "linux", "arch": "x86_64", "virtualization": "kvm"}, {"os": "linux", "arch": "aarch64", "virtualization": "kvm"}, {"os": "macos", "arch": "aarch64", "virtualization": "hvf"}):
        raise HarnessError("live evidence requires Linux x86_64/aarch64 KVM or macOS aarch64 HVF")
    if doc.get("pinned_sdk_commit") != "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934": raise HarnessError("unexpected pinned SDK commit")
    validate_profile(doc["profile"], live=True)
    if not isinstance(doc.get("runs"), list): raise HarnessError("live runs must be a list")
    for run in doc["runs"]:
        validate_live_proof(run)
    # Reuse the metric and matrix checks after stripping only the transcript envelope.
    expected_cells = {(boxes, scenario) for boxes in BOX_COUNTS for scenario in SCENARIOS}
    actual_cells = {(run["boxes"], run["scenario"]) for run in doc["runs"]}
    if len(doc["runs"]) != len(expected_cells) or actual_cells != expected_cells: raise HarnessError("live load matrix is incomplete or duplicated")
    if not isinstance(artifacts, dict) or set(artifacts) != {"binary", "runtime_bundle", "config"}: raise HarnessError("live artifacts are not closed")
    for name, item in artifacts.items():
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}: raise HarnessError(f"{name} artifact shape is closed")
        validate_path(item.get("path"), f"{name} artifact path")
        if not SHA256.fullmatch(str(item.get("sha256", ""))): raise HarnessError(f"live evidence requires {name} artifact SHA-256")
    verify_live_artifacts(doc, artifact_root)
    failures = [run for run in doc["runs"] if run["metrics"]["error_rate"] != 0 or run["proof"]["cleanup_failure_count"] != 0]
    daemon = doc.get("daemon")
    daemon_metrics = set(RESOURCE_METRICS)
    if not isinstance(daemon, dict) or set(daemon) != daemon_metrics:
        raise HarnessError("live evidence requires daemon metrics")
    for name in daemon_metrics: _finite_number(daemon[name], f"daemon.{name}")
    daemon_sampling = doc.get("daemon_sampling")
    if not isinstance(daemon_sampling, dict) or set(daemon_sampling) != {"interval_ms", "sample_count"}:
        raise HarnessError("live evidence requires daemon sampling metadata")
    if isinstance(daemon_sampling["interval_ms"], bool) or not isinstance(daemon_sampling["interval_ms"], int) or not 50 <= daemon_sampling["interval_ms"] <= 10_000:
        raise HarnessError("daemon sampling interval is invalid")
    if isinstance(daemon_sampling["sample_count"], bool) or not isinstance(daemon_sampling["sample_count"], int) or daemon_sampling["sample_count"] < 1:
        raise HarnessError("daemon sampling count is invalid")
    expected_sample_count = 1 + sum(run["resource_sampling"]["sample_count"] for run in doc["runs"])
    if daemon_sampling["sample_count"] != expected_sample_count:
        raise HarnessError("daemon sample count does not close against cell samples")
    for run in doc["runs"]:
        for name in RESOURCE_METRICS:
            if daemon[name] < run["resource_sampling"]["ceiling"][name]:
                raise HarnessError(f"daemon ceiling is below cell ceiling: {name}")
    status = "fail" if failures else "pass"
    cases = [{"id": f"{run['boxes']}/{run['scenario']}", "expected": "zero-error live boxd load cell", "observed": "live cell completed" if run not in failures else "live cell reported errors", "status": "fail" if run in failures else "pass"} for run in doc["runs"]]
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema":"boxd-phase4-evidence-v1", "suite":"load", "commit":commit, "platform":plat,
      "toolchain":{"harness":"phase4-load-harness", "sdk":"upstash-box-0.6.3", "runtime":"boxd"},
      "inputs":[{"name":"live-load-result", "sha256":digest}],
      "cases":cases, "artifacts":[{"path":artifacts[name]["path"], "sha256":artifacts[name]["sha256"]} for name in ("binary", "runtime_bundle", "config")],
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
