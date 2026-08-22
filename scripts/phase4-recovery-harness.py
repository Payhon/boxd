#!/usr/bin/env python3
"""Hermetic Phase 4 recovery matrix validator; real recovery is fail-closed."""
from __future__ import annotations
import argparse, hashlib, json, os, platform, re, stat, sys
from pathlib import Path
SCHEMA="boxd-phase4-recovery-v1"
SCENARIOS=("graceful-stop","sigterm","worker-sigkill","daemon-restart","disk-full","runtime-pull-interruption","sqlite-backup-restore","migration-journal")
SECRET=re.compile(r"(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{16,}|gh[pous]_[A-Za-z0-9_]{16,})")
SHA256=re.compile(r"^[0-9a-f]{64}$")
COMMIT=re.compile(r"^[0-9a-f]{40}$")
RELATIVE_PATH=re.compile(r"^[A-Za-z0-9._/+@=-]+$")
FORBIDDEN_LIVE=re.compile(r"(?:fixture|mock|model|virtualization\s*[:=]\s*none)", re.I)
ARTIFACT_SCHEMA="boxd-phase4-recovery-artifact-v1"
ARTIFACT_PRODUCER="boxd-phase4-recovery-runner"
class HarnessError(ValueError): pass
def scan(v):
    if isinstance(v,str) and SECRET.search(v): raise HarnessError("secret-like value detected")
    if isinstance(v,dict):
        for x in v.values(): scan(x)
    elif isinstance(v,list):
        for x in v: scan(x)
def validate(doc):
    if not isinstance(doc,dict) or doc.get("schema")!=SCHEMA: raise HarnessError("invalid recovery schema")
    scan(doc)
    if doc.get("mode") not in ("fixture","live"): raise HarnessError("mode must be fixture or live")
    cases=doc.get("cases")
    if not isinstance(cases,list) or {x.get("scenario") for x in cases if isinstance(x,dict)} != set(SCENARIOS): raise HarnessError("recovery matrix must cover all scenarios")
    seen=set()
    for c in cases:
        if not isinstance(c,dict) or set(c)!={"scenario","expected","observed","artifacts"}: raise HarnessError("case shape is closed")
        if c["scenario"] not in SCENARIOS or c["scenario"] in seen: raise HarnessError("duplicate/unknown recovery scenario")
        seen.add(c["scenario"])
        if not all(isinstance(c[k],str) and c[k] for k in ("expected","observed")): raise HarnessError("recovery text required")
        if not isinstance(c["artifacts"],list) or any(not isinstance(x,str) or not x for x in c["artifacts"]): raise HarnessError("artifact list invalid")
    return doc
def validate_live(doc):
    """Validate a closed, runtime-backed report; no fixture promotion is possible."""
    if not isinstance(doc, dict) or set(doc) != {"schema", "mode", "commit", "platform", "inputs", "cases"}:
        raise HarnessError("live recovery schema is closed")
    if doc["schema"] != SCHEMA or doc["mode"] != "live" or not COMMIT.fullmatch(doc["commit"]):
        raise HarnessError("live recovery requires schema, mode and full commit")
    p = doc["platform"]
    if not isinstance(p, dict) or set(p) != {"os", "arch", "virtualization"}:
        raise HarnessError("live platform shape is closed")
    if p["virtualization"] == "none" or (p["os"], p["arch"], p["virtualization"]) not in (("linux", "x86_64", "kvm"), ("linux", "aarch64", "kvm"), ("macos", "aarch64", "hvf")):
        raise HarnessError("live recovery requires native KVM or macOS aarch64 HVF")
    inputs = doc["inputs"]
    if not isinstance(inputs, list) or len(inputs) != 4 or {x.get("name") for x in inputs if isinstance(x, dict)} != {"boxd", "runtime", "db", "artifact"}:
        raise HarnessError("live inputs must bind boxd, runtime, db and artifact")
    input_paths = set()
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {"name", "path", "sha256"} or not SHA256.fullmatch(item["sha256"]):
            raise HarnessError("live input must contain only a normalized path and SHA-256 binding")
        validate_path(item["path"], "live input path")
        if item["path"] in input_paths:
            raise HarnessError("live input paths must be unique")
        input_paths.add(item["path"])
    cases = doc["cases"]
    if not isinstance(cases, list) or len(cases) != len(SCENARIOS):
        raise HarnessError("live recovery must contain exactly eight cases")
    seen = set(); artifact_paths = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"scenario", "expected", "observed", "status", "artifact_path", "artifact_sha256"}:
            raise HarnessError("live case shape is closed")
        scenario = case["scenario"]
        if scenario not in SCENARIOS or scenario in seen or case["status"] not in ("pass", "fail"):
            raise HarnessError("live cases must be unique pass/fail scenarios")
        seen.add(scenario)
        if any(not isinstance(case[key], str) or not case[key] for key in ("expected", "observed")) or not SHA256.fullmatch(case["artifact_sha256"]):
            raise HarnessError("live case requires observed text and artifact SHA-256")
        validate_path(case["artifact_path"], "live artifact path")
        if case["artifact_path"] in artifact_paths:
            raise HarnessError("live case artifact paths must be unique")
        artifact_paths.add(case["artifact_path"])
        if FORBIDDEN_LIVE.search(json.dumps(case, sort_keys=True)):
            raise HarnessError("fixture/mock/model-like live evidence is forbidden")
    scan(doc)
    return doc

def validate_path(value, where):
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value or "//" in value or not RELATIVE_PATH.fullmatch(value):
        raise HarnessError(f"{where} must be a normalized relative POSIX path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise HarnessError(f"{where} must not contain dot or empty components")
    return value

def artifact_sha(root, relative, where):
    validate_path(relative, where)
    root = Path(root).resolve(strict=True)
    candidate = root.joinpath(*relative.split("/"))
    current = root
    for part in relative.split("/"):
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise HarnessError(f"{where} may not traverse symlinks")
    info = candidate.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise HarnessError(f"{where} must be a single-link regular file")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
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
    actual_inputs = {item["name"]: artifact_sha(artifact_root, item["path"], f"input {item['name']}") for item in doc["inputs"]}
    for item in doc["inputs"]:
        if actual_inputs[item["name"]] != item["sha256"]:
            raise HarnessError(f"input {item['name']} SHA-256 does not match artifact")
    for case in doc["cases"]:
        actual = artifact_sha(artifact_root, case["artifact_path"], f"case {case['scenario']} artifact")
        if actual != case["artifact_sha256"]:
            raise HarnessError(f"case {case['scenario']} artifact SHA-256 does not match artifact")
        path = Path(artifact_root).resolve(strict=True) / Path(case["artifact_path"])
        try:
            artifact = json.loads(path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HarnessError(f"case {case['scenario']} artifact is not JSON") from exc
        validate_recovery_artifact(artifact, doc, case)
    return actual_inputs

def validate_recovery_artifact(artifact, doc, case):
    required = {"schema", "scenario", "commit", "platform", "input_hashes", "producer", "steps", "started_at_unix_ms", "finished_at_unix_ms", "status"}
    if not isinstance(artifact, dict) or set(artifact) != required: raise HarnessError("recovery artifact schema is not closed")
    if artifact["schema"] != ARTIFACT_SCHEMA or artifact["producer"] != ARTIFACT_PRODUCER: raise HarnessError("invalid recovery artifact identity")
    if artifact["scenario"] != case["scenario"] or artifact["status"] != case["status"] or artifact["commit"] != doc["commit"] or artifact["platform"] != doc["platform"]: raise HarnessError("recovery artifact cross-binding mismatch")
    expected_inputs = {item["name"]: item["sha256"] for item in doc["inputs"] if item["name"] in ("boxd", "runtime", "db")}
    if artifact["input_hashes"] != expected_inputs: raise HarnessError("recovery artifact input hashes do not match live inputs")
    for value in expected_inputs.values():
        if not SHA256.fullmatch(value): raise HarnessError("invalid recovery input hash")
    if not isinstance(artifact["platform"], dict) or set(artifact["platform"]) != {"os", "arch", "virtualization"}: raise HarnessError("artifact platform shape is closed")
    for name in ("started_at_unix_ms", "finished_at_unix_ms"):
        if isinstance(artifact[name], bool) or not isinstance(artifact[name], int) or artifact[name] < 0: raise HarnessError("artifact timestamps are invalid")
    if artifact["finished_at_unix_ms"] < artifact["started_at_unix_ms"]: raise HarnessError("artifact timestamps are not monotonic")
    steps = artifact["steps"]
    if not isinstance(steps, list) or not steps: raise HarnessError("recovery artifact steps must be non-empty")
    for step in steps:
        if not isinstance(step, dict) or set(step) != {"operation", "expected", "observed", "status"}: raise HarnessError("recovery step schema is not closed")
        if any(not isinstance(step[k], str) or not step[k] for k in ("operation", "expected", "observed")) or step["status"] not in ("pass", "fail", "blocked"): raise HarnessError("recovery step is invalid")
    if artifact["status"] not in ("pass", "fail"): raise HarnessError("recovery artifact status is invalid")
    if artifact["status"] == "pass" and any(step["status"] != "pass" for step in steps): raise HarnessError("non-pass step cannot produce a pass case")
    scan(artifact)
    if FORBIDDEN_LIVE.search(json.dumps(artifact, sort_keys=True)): raise HarnessError("fixture/mock/model-like artifact is forbidden")

def evidence(doc,commit="0"*40):
    validate(doc); digest=hashlib.sha256(json.dumps(doc,sort_keys=True,separators=(",",":")).encode()).hexdigest(); n=len(SCENARIOS)
    return {"schema":"boxd-phase4-evidence-v1","suite":"recovery","commit":commit,"platform":{"os":"macos" if sys.platform=="darwin" else "linux","arch":"aarch64" if platform.machine().startswith("arm") else "x86_64","virtualization":"none"},"toolchain":{"python":"stdlib","harness":"phase4-recovery-harness"},"inputs":[{"name":"recovery-fixture","sha256":digest}],"cases":[{"id":c,"expected":"recovery verified on real boxd","observed":"fixture validated; runtime unavailable","status":"blocked"} for c in SCENARIOS],"artifacts":[],"external_requirements":[{"id":"boxd-runtime","status":"blocked","detail":"requires real daemon, worker and signed runtime"},{"id":"native-platform","status":"blocked","detail":"requires HVF or KVM"}],"secret_scan":{"status":"pass","scanner":"stdlib recursive scan","findings":0},"summary":{"status":"blocked","passed":0,"failed":0,"blocked":n,"total":n}}

def live_evidence(doc, artifact_root):
    validate_live(doc)
    verify_live_artifacts(doc, artifact_root)
    artifacts = [{"path": case["artifact_path"], "sha256": case["artifact_sha256"]} for case in doc["cases"]]
    cases = [{"id": c["scenario"], "expected": c["expected"], "observed": c["observed"], "status": c["status"], "artifact_sha256": c["artifact_sha256"]} for c in doc["cases"]]
    passed = sum(c["status"] == "pass" for c in doc["cases"]); failed = len(cases) - passed
    evidence_inputs = [{"name": item["name"], "sha256": item["sha256"]} for item in doc["inputs"]]
    return {"schema":"boxd-phase4-evidence-v1","suite":"recovery","commit":doc["commit"],"platform":doc["platform"],"toolchain":{"python":"stdlib","harness":"phase4-recovery-harness","boxd":next(x["sha256"] for x in doc["inputs"] if x["name"] == "boxd"),"runtime":next(x["sha256"] for x in doc["inputs"] if x["name"] == "runtime"),"db":next(x["sha256"] for x in doc["inputs"] if x["name"] == "db")},"inputs":evidence_inputs,"cases":cases,"artifacts":artifacts,"external_requirements":[{"id":"boxd-runtime","status":"satisfied","detail":"live daemon and worker evidence supplied"},{"id":"native-platform","status":"satisfied","detail":"native KVM/HVF platform evidence supplied"}],"secret_scan":{"status":"pass","scanner":"stdlib recursive scan","findings":0},"summary":{"status":"fail" if failed else "pass","passed":passed,"failed":failed,"blocked":0,"total":len(cases)}}
def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__); source=p.add_mutually_exclusive_group(required=True); source.add_argument("--fixture",type=Path); source.add_argument("--live",type=Path); p.add_argument("--artifact-root",type=Path); p.add_argument("--emit-evidence",type=Path); p.add_argument("--commit"); a=p.parse_args(argv)
    try:
        source_path = a.fixture or a.live
        d=json.loads(source_path.read_text()); out = evidence(d, a.commit or "0"*40) if a.fixture else live_evidence(d, a.artifact_root)
        if a.live and a.commit and a.commit != d["commit"]: raise HarnessError("--commit does not match live input")
        if a.emit_evidence: a.emit_evidence.write_text(json.dumps(out,indent=2)+"\n")
        print(json.dumps({"schema":SCHEMA,"status":out["summary"]["status"],"scenario_count":len(d["cases"]),"reason":"fixture mode cannot prove recovery" if a.fixture else "live evidence validated"},indent=2)); return 0
    except (OSError,json.JSONDecodeError,HarnessError) as e: print(f"recovery harness rejected: {e}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
