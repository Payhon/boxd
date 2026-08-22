#!/usr/bin/env python3
"""Hermetic Phase 4 recovery matrix validator; real recovery is fail-closed."""
from __future__ import annotations
import argparse, hashlib, json, platform, re, sys
from pathlib import Path
SCHEMA="boxd-phase4-recovery-v1"
SCENARIOS=("graceful-stop","sigterm","worker-sigkill","daemon-restart","disk-full","runtime-pull-interruption","sqlite-backup-restore","migration-journal")
SECRET=re.compile(r"(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{16,}|gh[pous]_[A-Za-z0-9_]{16,})")
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
def evidence(doc,commit="0"*40):
    validate(doc); digest=hashlib.sha256(json.dumps(doc,sort_keys=True,separators=(",",":")).encode()).hexdigest(); n=len(SCENARIOS)
    return {"schema":"boxd-phase4-evidence-v1","suite":"recovery","commit":commit,"platform":{"os":"macos" if sys.platform=="darwin" else "linux","arch":"aarch64" if platform.machine().startswith("arm") else "x86_64","virtualization":"none"},"toolchain":{"python":"stdlib","harness":"phase4-recovery-harness"},"inputs":[{"name":"recovery-fixture","sha256":digest}],"cases":[{"id":c,"expected":"recovery verified on real boxd","observed":"fixture validated; runtime unavailable","status":"blocked"} for c in SCENARIOS],"artifacts":[],"external_requirements":[{"id":"boxd-runtime","status":"blocked","detail":"requires real daemon, worker and signed runtime"},{"id":"native-platform","status":"blocked","detail":"requires HVF or KVM"}],"secret_scan":{"status":"pass","scanner":"stdlib recursive scan","findings":0},"summary":{"status":"blocked","passed":0,"failed":0,"blocked":n,"total":n}}
def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--fixture",type=Path); p.add_argument("--emit-evidence",type=Path); p.add_argument("--commit",default="0"*40); a=p.parse_args(argv)
    if not a.fixture: p.error("--fixture is required; live execution requires a future native runner")
    try:
        d=json.loads(a.fixture.read_text()); validate(d); out=evidence(d,a.commit)
        if a.emit_evidence: a.emit_evidence.write_text(json.dumps(out,indent=2)+"\n")
        print(json.dumps({"schema":SCHEMA,"status":"blocked","scenario_count":len(d["cases"]),"reason":"fixture mode cannot prove recovery"},indent=2)); return 0
    except (OSError,json.JSONDecodeError,HarnessError) as e: print(f"recovery harness rejected: {e}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
