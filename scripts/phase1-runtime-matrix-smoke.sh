#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C
export TZ=UTC

usage() {
  cat <<'EOF'
Run the ten-runtime Phase 1 lifecycle/restart matrix on a real HVF or KVM host.

Required environment:
  BOXD_MATRIX_BOXD            absolute already-signed/entitled platform boxd
  BOXD_MATRIX_BOXD_SHA256     expected lowercase SHA-256
  BOXD_MATRIX_CONFIG          absolute dedicated test config
  BOXD_MATRIX_MANIFEST        absolute JSON mapping all ten runtimes to bundles
  BOXD_MATRIX_EVIDENCE_DIR    absolute new/empty evidence directory
  BOXD_MASTER_KEY
  BOXD_ADMIN_PASSWORD
  UPSTASH_BOX_API_KEY

Optional environment:
  UPSTASH_BOX_BASE_URL        default: http://127.0.0.1:7331

Manifest schema:
  {"schema":"boxd-phase1-runtime-matrix-input-v1","arch":"aarch64",
   "bundles":{"node":"/abs/...tar.zst", ... all ten runtime names ...}}

The runner imports every signed bundle, requires doctor overall=true, then keeps
only one Box at a time: lifecycle, full daemon stop, restart/reconcile/delete.
It never creates or signs release artifacts and cannot turn a hermetic check
into real HVF/KVM evidence.
EOF
}

if [[ ${1:-} == --help ]]; then usage; exit 0; fi
if (($# != 0)); then usage >&2; exit 64; fi

required=(
  BOXD_MATRIX_BOXD BOXD_MATRIX_BOXD_SHA256 BOXD_MATRIX_CONFIG
  BOXD_MATRIX_MANIFEST BOXD_MATRIX_EVIDENCE_DIR BOXD_MASTER_KEY
  BOXD_ADMIN_PASSWORD UPSTASH_BOX_API_KEY
)
for variable in "${required[@]}"; do
  [[ -n ${!variable:-} ]] || {
    printf 'missing required environment variable: %s\n' "$variable" >&2
    exit 64
  }
done
for command in curl find kill node npm pgrep python3 seq uname; do
  command -v "$command" >/dev/null || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 69
  }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
cd -- "$repo_root"
bounded=(python3 "$script_dir/run_bounded.py")
for path in "$BOXD_MATRIX_BOXD" "$BOXD_MATRIX_CONFIG" "$BOXD_MATRIX_MANIFEST"; do
  [[ $path == /* && -f $path && ! -L $path ]] || {
    printf 'matrix input must be an absolute regular non-symlink file\n' >&2
    exit 66
  }
done
[[ $BOXD_MATRIX_BOXD_SHA256 =~ ^[0-9a-f]{64}$ ]] || {
  printf 'BOXD_MATRIX_BOXD_SHA256 must be lowercase hexadecimal SHA-256\n' >&2
  exit 64
}
actual_boxd_sha=$(python3 - "$BOXD_MATRIX_BOXD" <<'PY'
import hashlib, pathlib, sys
digest = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as source:
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
print(digest.hexdigest())
PY
)
[[ $actual_boxd_sha == "$BOXD_MATRIX_BOXD_SHA256" ]] || {
  printf 'boxd SHA-256 mismatch\n' >&2
  exit 65
}

evidence_dir=$BOXD_MATRIX_EVIDENCE_DIR
[[ $evidence_dir == /* && ! -L $evidence_dir ]] || {
  printf 'BOXD_MATRIX_EVIDENCE_DIR must be absolute and not a symlink\n' >&2
  exit 64
}
if [[ -e $evidence_dir ]]; then
  [[ -d $evidence_dir && -z $(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
    printf 'BOXD_MATRIX_EVIDENCE_DIR must be new or empty\n' >&2
    exit 73
  }
else
  mkdir -p -- "$evidence_dir"
fi
chmod 700 "$evidence_dir"
evidence_dir=$(cd -- "$evidence_dir" && pwd -P)

base_url=${UPSTASH_BOX_BASE_URL:-http://127.0.0.1:7331}
python3 - "$base_url" <<'PY'
import sys
from urllib.parse import urlsplit
url = urlsplit(sys.argv[1])
if (
    url.scheme != "http"
    or url.hostname not in {"127.0.0.1", "localhost"}
    or url.port is None
    or url.username is not None
    or url.password is not None
    or url.path
    or url.query
    or url.fragment
):
    raise SystemExit("UPSTASH_BOX_BASE_URL must be a bare loopback HTTP origin with explicit port")
PY
if curl --silent --show-error --fail --max-time 2 "$base_url/health/ready" >/dev/null 2>&1; then
  printf 'refusing an address already serving boxd: %s\n' "$base_url" >&2
  exit 73
fi

matrix_tsv=$evidence_dir/matrix-input.tsv
python3 - "$BOXD_MATRIX_MANIFEST" "$matrix_tsv" "$(uname -m)" <<'PY'
import hashlib, json, pathlib, sys
runtimes = [
    "node", "python", "golang", "ruby", "rust",
    "node-alpine", "python-alpine", "golang-alpine", "ruby-alpine", "rust-alpine",
]
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
host_arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(sys.argv[3])
if host_arch is None:
    raise SystemExit("unsupported host architecture")
value = json.loads(source.read_text(encoding="utf-8"))
if not isinstance(value, dict) or set(value) != {"schema", "arch", "bundles"}:
    raise SystemExit("runtime matrix has unexpected or missing fields")
if value["schema"] != "boxd-phase1-runtime-matrix-input-v1" or value["arch"] != host_arch:
    raise SystemExit("runtime matrix schema or architecture mismatch")
bundles = value.get("bundles")
if not isinstance(bundles, dict) or set(bundles) != set(runtimes):
    raise SystemExit("runtime matrix must contain exactly all ten runtimes")
lines = []
for runtime in runtimes:
    raw_path = bundles[runtime]
    if not isinstance(raw_path, str) or any(character in raw_path for character in "\t\r\n"):
        raise SystemExit(f"invalid bundle path for {runtime}")
    path = pathlib.Path(raw_path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit(f"unsafe or missing bundle for {runtime}")
    digest = hashlib.sha256()
    with path.open("rb") as source_file:
        while chunk := source_file.read(1024 * 1024):
            digest.update(chunk)
    lines.append(f"{runtime}\t{path}\t{digest.hexdigest()}\n")
target.write_text("".join(lines), encoding="utf-8")
PY

"${bounded[@]}" --timeout 60 -- \
  "$BOXD_MATRIX_BOXD" config validate --config "$BOXD_MATRIX_CONFIG"
while IFS=$'\t' read -r runtime bundle _bundle_sha256; do
  "${bounded[@]}" --timeout 1800 -- \
    "$BOXD_MATRIX_BOXD" runtime import --config "$BOXD_MATRIX_CONFIG" "$bundle" \
    >"$evidence_dir/import-${runtime}.stdout" 2>"$evidence_dir/import-${runtime}.stderr"
done <"$matrix_tsv"
"${bounded[@]}" --timeout 120 -- \
  "$BOXD_MATRIX_BOXD" doctor --config "$BOXD_MATRIX_CONFIG" --json \
  >"$evidence_dir/doctor.json" 2>"$evidence_dir/doctor.stderr"
python3 - "$evidence_dir/doctor.json" <<'PY'
import json, sys
doctor = json.load(open(sys.argv[1], encoding="utf-8"))
if doctor.get("overall") is not True:
    raise SystemExit("doctor overall is not true")
failed = [item.get("name") for item in doctor.get("checks", []) if item.get("required") and item.get("status") != "pass"]
if failed:
    raise SystemExit(f"required doctor checks failed: {failed}")
PY

daemon_pid=''
worker_pids=()
sdk_built=0
capture_workers() {
  worker_pids=()
  [[ -n $daemon_pid ]] || return 0
  while IFS= read -r pid; do
    [[ $pid =~ ^[0-9]+$ ]] && worker_pids+=("$pid")
  done < <(pgrep -P "$daemon_pid" 2>/dev/null || true)
}
stop_daemon() {
  [[ -n $daemon_pid ]] || return 0
  capture_workers
  if kill -0 "$daemon_pid" 2>/dev/null; then
    kill -TERM "$daemon_pid" 2>/dev/null || true
    for _ in $(seq 1 40); do
      kill -0 "$daemon_pid" 2>/dev/null || break
      sleep 1
    done
  fi
  if kill -0 "$daemon_pid" 2>/dev/null; then
    kill -KILL "$daemon_pid" 2>/dev/null || true
  fi
  wait "$daemon_pid" 2>/dev/null || true
  for pid in "${worker_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      printf 'owned worker survived daemon stop: %s\n' "$pid" >&2
      return 1
    fi
  done
  daemon_pid=''
}
cleanup_sdk() {
  python3 - "$evidence_dir/sdk-build.json" <<'PY'
import hashlib, json, pathlib, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
cleanup = data["cleanup"]
path = pathlib.Path(cleanup["dir"])
if hashlib.sha256(str(path).encode()).hexdigest() != cleanup["token"]:
    raise SystemExit("pinned SDK cleanup token mismatch")
resolved = path.resolve()
if path.is_symlink() or not path.is_dir() or "boxd-pinned-sdk-" not in path.name:
    raise SystemExit("refusing unexpected pinned SDK cleanup path")
for child in sorted(resolved.rglob("*"), key=lambda value: len(value.parts), reverse=True):
    child.unlink() if child.is_symlink() or child.is_file() else child.rmdir()
resolved.rmdir()
PY
}
trap 'if ((sdk_built == 1)); then cleanup_sdk || true; fi' EXIT

"${bounded[@]}" --timeout 600 -- npm --prefix compat/upstash-box-0.6.3 ci --offline
"${bounded[@]}" --timeout 120 -- \
  node compat/upstash-box-0.6.3/scripts/build-pinned-sdk.mjs --json \
  >"$evidence_dir/sdk-build.json"
sdk_built=1
sdk_entry=$(python3 - "$evidence_dir/sdk-build.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("source_commit") != "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934":
    raise SystemExit("unexpected pinned SDK commit")
print(data["entry"])
PY
)
cleanup_on_exit() {
  local status=$?
  trap - EXIT
  stop_daemon || true
  if ((sdk_built == 1)); then cleanup_sdk || true; fi
  exit "$status"
}
trap cleanup_on_exit EXIT
start_daemon() {
  local log_name=$1
  "$BOXD_MATRIX_BOXD" serve --config "$BOXD_MATRIX_CONFIG" \
    >"$evidence_dir/${log_name}.stdout" 2>"$evidence_dir/${log_name}.stderr" &
  daemon_pid=$!
  for _ in $(seq 1 300); do
    kill -0 "$daemon_pid" 2>/dev/null || return 1
    code=$(curl --silent --show-error --output "$evidence_dir/ready.json" \
      --write-out '%{http_code}' --max-time 3 "$base_url/health/ready" || true)
    [[ $code == 200 ]] && return 0
    sleep 1
  done
  printf 'boxd readiness timed out\n' >&2
  return 1
}

while IFS=$'\t' read -r runtime _bundle _bundle_sha256; do
  lifecycle=$evidence_dir/${runtime}-lifecycle.json
  restart=$evidence_dir/${runtime}-restart.json
  start_daemon "serve-${runtime}-lifecycle"
  UPSTASH_BOX_BASE_URL=$base_url "${bounded[@]}" --timeout 900 -- \
    node scripts/phase1-runtime-matrix-smoke.mjs \
    lifecycle "$runtime" "$sdk_entry" "$lifecycle"
  stop_daemon
  start_daemon "serve-${runtime}-restart"
  BOXD_RUNTIME_MATRIX_LIFECYCLE_EVIDENCE=$lifecycle UPSTASH_BOX_BASE_URL=$base_url \
    "${bounded[@]}" --timeout 600 -- \
      node scripts/phase1-runtime-matrix-smoke.mjs restart "$runtime" "$sdk_entry" "$restart"
  stop_daemon
done <"$matrix_tsv"

python3 - "$evidence_dir" "$actual_boxd_sha" "$(uname -s)" "$(uname -m)" \
  "$BOXD_MATRIX_MANIFEST" <<'PY'
import datetime, hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
runtimes = ["node", "python", "golang", "ruby", "rust", "node-alpine", "python-alpine", "golang-alpine", "ruby-alpine", "rust-alpine"]
bundle_hashes = {}
for line in (root / "matrix-input.tsv").read_text(encoding="utf-8").splitlines():
    runtime, _path, digest = line.split("\t")
    bundle_hashes[runtime] = digest
items = []
for runtime in runtimes:
    lifecycle = root / f"{runtime}-lifecycle.json"
    restart = root / f"{runtime}-restart.json"
    items.append({
        "runtime": runtime,
        "runtime_bundle_sha256": bundle_hashes[runtime],
        "lifecycle_sha256": hashlib.sha256(lifecycle.read_bytes()).hexdigest(),
        "restart_sha256": hashlib.sha256(restart.read_bytes()).hexdigest(),
        "passed": True,
    })
summary = {
    "schema": "boxd-phase1-runtime-matrix-evidence-v1",
    "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "boxd_sha256": sys.argv[2],
    "host_os": sys.argv[3],
    "host_arch": sys.argv[4],
    "pinned_sdk_commit": "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934",
    "doctor_sha256": hashlib.sha256((root / "doctor.json").read_bytes()).hexdigest(),
    "matrix_manifest_sha256": hashlib.sha256(pathlib.Path(sys.argv[5]).read_bytes()).hexdigest(),
    "all_ten_runtimes": True,
    "items": items,
}
(root / "runtime-matrix-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
PY
cleanup_sdk
sdk_built=0
trap - EXIT
printf 'Phase 1 runtime matrix passed; evidence: %s\n' "$evidence_dir"
