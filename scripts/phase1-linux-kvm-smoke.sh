#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C
export TZ=UTC

usage() {
  cat <<'EOF'
Run the Phase 1 pinned-SDK lifecycle and restricted-egress gate on native Linux KVM.

Required environment:
  BOXD_SMOKE_CONFIG                 absolute dedicated test config path
  BOXD_RUNTIME_BUNDLE               absolute signed bundle matching the host architecture
  BOXD_EVIDENCE_DIR                 absolute new/empty evidence directory
  BOXD_MASTER_KEY                   configured 32-byte master key (hex or base64)
  BOXD_ADMIN_PASSWORD               configured bootstrap administrator password
  UPSTASH_BOX_API_KEY               one-time compatibility API key for the test database
  BOXD_EMBEDDED_LIBKRUN_PATH
  BOXD_EMBEDDED_LIBKRUN_SHA256
  BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH
  BOXD_EMBEDDED_LIBKRUNFW_PATH
  BOXD_EMBEDDED_LIBKRUNFW_SHA256
  BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH

Optional environment:
  UPSTASH_BOX_BASE_URL               default: http://127.0.0.1:7331
  BOXD_KVM_TARGET_DIR                Cargo target directory outside evidence
  BOXD_SKIP_SOURCE_GATES             exactly 1 to skip fmt/clippy/workspace tests

The config/data directory and release assets are runner-owned inputs and are
never deleted. Evidence contains no credential values. This script exits before
building when /dev/kvm or the delegated cgroup v2 controllers are unavailable.
EOF
}

if [[ ${1:-} == --help ]]; then
  usage
  exit 0
fi
if (($# != 0)); then
  usage >&2
  exit 64
fi

required=(
  BOXD_SMOKE_CONFIG BOXD_RUNTIME_BUNDLE BOXD_EVIDENCE_DIR BOXD_MASTER_KEY
  BOXD_ADMIN_PASSWORD UPSTASH_BOX_API_KEY BOXD_EMBEDDED_LIBKRUN_PATH
  BOXD_EMBEDDED_LIBKRUN_SHA256 BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH
  BOXD_EMBEDDED_LIBKRUNFW_PATH BOXD_EMBEDDED_LIBKRUNFW_SHA256
  BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH
)
for variable in "${required[@]}"; do
  if [[ -z ${!variable:-} ]]; then
    printf 'missing required environment variable: %s\n' "$variable" >&2
    exit 64
  fi
done
for command in cargo curl cut find kill node npm pgrep python3 rg seq sha256sum stat uname; do
  command -v "$command" >/dev/null || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 69
  }
done

[[ $(uname -s) == Linux ]] || {
  printf 'native Linux is required\n' >&2
  exit 69
}
host_arch=$(uname -m)
[[ $host_arch == x86_64 || $host_arch == aarch64 ]] || {
  printf 'unsupported Linux KVM architecture: %s\n' "$host_arch" >&2
  exit 69
}
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || {
  printf '/dev/kvm must be a readable and writable character device\n' >&2
  exit 77
}
[[ -f /sys/fs/cgroup/cgroup.controllers ]] || {
  printf 'cgroup v2 is required\n' >&2
  exit 77
}
for controller in cpu memory pids; do
  rg -q "(^| )${controller}( |$)" /sys/fs/cgroup/cgroup.controllers || {
    printf 'cgroup v2 controller is unavailable: %s\n' "$controller" >&2
    exit 77
  }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
cd -- "$repo_root"
bounded=(python3 "$script_dir/run_bounded.py")

for path_variable in \
  BOXD_SMOKE_CONFIG BOXD_RUNTIME_BUNDLE BOXD_EMBEDDED_LIBKRUN_PATH \
  BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH BOXD_EMBEDDED_LIBKRUNFW_PATH \
  BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH; do
  path=${!path_variable}
  [[ $path == /* && -f $path && ! -L $path ]] || {
    printf '%s must name an absolute regular non-symlink file\n' "$path_variable" >&2
    exit 66
  }
done
for hash_variable in BOXD_EMBEDDED_LIBKRUN_SHA256 BOXD_EMBEDDED_LIBKRUNFW_SHA256; do
  [[ ${!hash_variable} =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s must be 64 lowercase hexadecimal characters\n' "$hash_variable" >&2
    exit 64
  }
done
actual_libkrun=$(sha256sum "$BOXD_EMBEDDED_LIBKRUN_PATH" | cut -d' ' -f1)
actual_firmware=$(sha256sum "$BOXD_EMBEDDED_LIBKRUNFW_PATH" | cut -d' ' -f1)
[[ $actual_libkrun == "$BOXD_EMBEDDED_LIBKRUN_SHA256" ]] || {
  printf 'libkrun artifact hash mismatch\n' >&2
  exit 65
}
[[ $actual_firmware == "$BOXD_EMBEDDED_LIBKRUNFW_SHA256" ]] || {
  printf 'libkrun firmware artifact hash mismatch\n' >&2
  exit 65
}

evidence_dir=$BOXD_EVIDENCE_DIR
[[ $evidence_dir == /* && ! -L $evidence_dir ]] || {
  printf 'BOXD_EVIDENCE_DIR must be an absolute non-symlink path\n' >&2
  exit 64
}
if [[ -e $evidence_dir ]]; then
  [[ -d $evidence_dir && -z $(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
    printf 'BOXD_EVIDENCE_DIR must be new or empty\n' >&2
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
  printf 'refusing to reuse an address that already serves boxd: %s\n' "$base_url" >&2
  exit 73
fi

skip_source_gates=${BOXD_SKIP_SOURCE_GATES:-0}
[[ $skip_source_gates == 0 || $skip_source_gates == 1 ]] || {
  printf 'BOXD_SKIP_SOURCE_GATES must be exactly 0 or 1\n' >&2
  exit 64
}
if [[ $skip_source_gates == 0 ]]; then
  "${bounded[@]}" --timeout 600 -- cargo fmt --all -- --check
  CARGO_INCREMENTAL=0 "${bounded[@]}" --timeout 1800 -- \
    cargo clippy --workspace --all-targets --all-features -- -D warnings
  CARGO_INCREMENTAL=0 "${bounded[@]}" --timeout 1800 -- \
    cargo test --workspace --all-features
fi

target_dir=${BOXD_KVM_TARGET_DIR:-$repo_root/target/phase1-linux-kvm}
[[ $target_dir == /* && ! -L $target_dir ]] || {
  printf 'BOXD_KVM_TARGET_DIR must be an absolute non-symlink path\n' >&2
  exit 64
}
mkdir -p -- "$target_dir"
target_dir=$(cd -- "$target_dir" && pwd -P)
export CARGO_TARGET_DIR=$target_dir
export CARGO_INCREMENTAL=0
"${bounded[@]}" --timeout 1800 -- cargo build --release --locked -p boxd
boxd=$target_dir/release/boxd
boxd_sha256=$(sha256sum "$boxd" | cut -d' ' -f1)
bundle_sha256=$(sha256sum "$BOXD_RUNTIME_BUNDLE" | cut -d' ' -f1)

"${bounded[@]}" --timeout 60 -- "$boxd" config validate --config "$BOXD_SMOKE_CONFIG"
"${bounded[@]}" --timeout 1800 -- \
  "$boxd" runtime import --config "$BOXD_SMOKE_CONFIG" "$BOXD_RUNTIME_BUNDLE" \
  >"$evidence_dir/import.stdout" 2>"$evidence_dir/import.stderr"
"${bounded[@]}" --timeout 120 -- "$boxd" doctor --config "$BOXD_SMOKE_CONFIG" --json \
  >"$evidence_dir/doctor.json" 2>"$evidence_dir/doctor.stderr"
python3 - "$evidence_dir/doctor.json" <<'PY'
import json, sys
doctor = json.load(open(sys.argv[1], encoding="utf-8"))
if doctor.get("overall") is not True:
    raise SystemExit("doctor overall is not true")
required = {item.get("name"): item.get("status") for item in doctor.get("checks", []) if item.get("required")}
for name in ("kvm_device", "worker_cgroup_enforcement", "worker_seccomp_enforcement"):
    if required.get(name) != "pass":
        raise SystemExit(f"required Linux doctor check did not pass: {name}")
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
import hashlib, json, os, pathlib, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
cleanup = data["cleanup"]
path = pathlib.Path(cleanup["dir"])
if hashlib.sha256(str(path).encode()).hexdigest() != cleanup["token"]:
    raise SystemExit("pinned SDK cleanup token mismatch")
resolved = path.resolve()
if path.is_symlink() or not path.is_dir() or "boxd-pinned-sdk-" not in path.name:
    raise SystemExit("refusing unexpected pinned SDK cleanup path")
for child in sorted(resolved.rglob("*"), key=lambda value: len(value.parts), reverse=True):
    if child.is_symlink() or child.is_file():
        child.unlink()
    else:
        child.rmdir()
resolved.rmdir()
PY
}
trap 'if ((sdk_built == 1)); then cleanup_sdk || true; fi' EXIT

"${bounded[@]}" --timeout 600 -- npm --prefix compat/upstash-box-0.6.3 ci
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
  if ((sdk_built == 1)); then
    cleanup_sdk || true
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT

start_daemon() {
  local log_name=$1
  "$boxd" serve --config "$BOXD_SMOKE_CONFIG" \
    >"$evidence_dir/${log_name}.stdout" 2>"$evidence_dir/${log_name}.stderr" &
  daemon_pid=$!
  for _ in $(seq 1 300); do
    kill -0 "$daemon_pid" 2>/dev/null || {
      printf 'boxd exited before readiness\n' >&2
      return 1
    }
    code=$(curl --silent --show-error --output "$evidence_dir/ready.json" \
      --write-out '%{http_code}' --max-time 3 "$base_url/health/ready" || true)
    [[ $code == 200 ]] && return 0
    sleep 1
  done
  printf 'boxd readiness timed out\n' >&2
  return 1
}

start_daemon serve-platform-initial
UPSTASH_BOX_BASE_URL=$base_url "${bounded[@]}" --timeout 900 -- \
  node scripts/phase1-sdk-smoke.mjs lifecycle \
  "$sdk_entry" "$evidence_dir/lifecycle.json"
stop_daemon

start_daemon serve-platform-restart
BOXD_SMOKE_LIFECYCLE_EVIDENCE=$evidence_dir/lifecycle.json \
  UPSTASH_BOX_BASE_URL=$base_url "${bounded[@]}" --timeout 600 -- \
    node scripts/phase1-sdk-smoke.mjs restart \
    "$sdk_entry" "$evidence_dir/restart.json"
stop_daemon

start_daemon serve-egress-initial
UPSTASH_BOX_BASE_URL=$base_url "${bounded[@]}" --timeout 900 -- \
  node scripts/phase1-egress-smoke.mjs lifecycle \
  "$sdk_entry" "$evidence_dir/egress-lifecycle.json"
stop_daemon

start_daemon serve-egress-restart
BOXD_SMOKE_EGRESS_EVIDENCE=$evidence_dir/egress-lifecycle.json \
  UPSTASH_BOX_BASE_URL=$base_url "${bounded[@]}" --timeout 600 -- \
    node scripts/phase1-egress-smoke.mjs restart \
    "$sdk_entry" "$evidence_dir/egress-restart.json"
stop_daemon

python3 - "$evidence_dir" "$host_arch" "$boxd_sha256" "$bundle_sha256" \
  "$skip_source_gates" "$BOXD_EMBEDDED_LIBKRUN_SHA256" \
  "$BOXD_EMBEDDED_LIBKRUNFW_SHA256" "$(uname -r)" <<'PY'
import datetime, hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
files = {
    name: hashlib.sha256((root / name).read_bytes()).hexdigest()
    for name in (
        "doctor.json",
        "lifecycle.json",
        "restart.json",
        "egress-lifecycle.json",
        "egress-restart.json",
    )
}
evidence = {
    "schema": "boxd-phase1-linux-kvm-evidence-v1",
    "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "host_arch": sys.argv[2],
    "boxd_sha256": sys.argv[3],
    "runtime_bundle_sha256": sys.argv[4],
    "source_gates": "skipped" if sys.argv[5] == "1" else "passed",
    "libkrun_sha256": sys.argv[6],
    "libkrunfw_sha256": sys.argv[7],
    "kernel_release": sys.argv[8],
    "pinned_sdk_commit": "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934",
    "evidence_sha256": files,
    "doctor_overall": True,
    "native_kvm": True,
    "cgroup_v2": True,
    "seccomp_policy_v1": True,
    "pinned_sdk_lifecycle_restart": True,
    "restricted_default_restart": True,
}
path = root / "linux-kvm-summary.json"
with path.open("x", encoding="utf-8") as output:
    json.dump(evidence, output, indent=2)
    output.write("\n")
PY
cleanup_sdk
sdk_built=0
trap - EXIT
printf 'Phase 1 Linux KVM smoke passed; evidence: %s\n' "$evidence_dir"
