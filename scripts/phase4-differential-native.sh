#!/usr/bin/env bash
# Native Phase 4 differential lifecycle. Source this file in the workflow step
# that runs the differential so the EXIT trap owns the daemon for that job.
set -Eeuo pipefail
umask 077
export LC_ALL=C TZ=UTC

phase4_native_die() { printf 'phase4 native preflight: %s\n' "$*" >&2; return 1; }
phase4_native_regular() {
  local name=$1 path=$2
  [[ $path == /* && -f $path && ! -L $path ]] || {
    phase4_native_die "$name must be an absolute regular non-symlink file"
    return 1
  }
  [[ $(python3 - "$path" <<'PY'
import os, sys
print(os.stat(sys.argv[1]).st_nlink)
PY
) == 1 ]] || {
    phase4_native_die "$name must have one hard link"
    return 1
  }
}
phase4_native_hash() {
  local name=$1 path=$2 expected=$3 actual
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || phase4_native_die "$name SHA-256 is invalid"
  actual=$(sha256sum -- "$path" | cut -d' ' -f1)
  [[ $actual == "$expected" ]] || phase4_native_die "$name SHA-256 mismatch"
}
phase4_native_origin() {
  python3 - "$BOXD_DIFF_LOCAL_BASE_URL" <<'PY'
import sys
from urllib.parse import urlsplit
u = urlsplit(sys.argv[1])
if (u.scheme != "http" or u.hostname not in {"127.0.0.1", "localhost", "::1"}
        or u.port is None or u.username or u.password or u.path not in {"", "/"}
        or u.query or u.fragment):
    raise SystemExit("BOXD_DIFF_LOCAL_BASE_URL must be a bare loopback HTTP origin with explicit port")
PY
}
phase4_native_port_free() {
  python3 - "$BOXD_DIFF_LOCAL_BASE_URL" <<'PY'
import socket, sys
from urllib.parse import urlsplit
u = urlsplit(sys.argv[1])
family = socket.AF_INET6 if ":" in u.hostname else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM)
try:
    s.bind((u.hostname, u.port))
except OSError as exc:
    raise SystemExit(f"local endpoint is already occupied: {exc}")
finally:
    s.close()
PY
}

phase4_native_write_config() {
  local template=$1 generated=$2 run_root=$3 port=$4
  python3 - "$template" "$generated" "$run_root" "$port" <<'PY'
import json, os, pathlib, re, sys

template, generated, root = map(pathlib.Path, sys.argv[1:4])
port = int(sys.argv[4])
raw = template.read_bytes()
root = root.resolve()
values = {
    ("server", "listen"): f"127.0.0.1:{port}",
    ("server", "public_url"): f"http://127.0.0.1:{port}",
    ("preview", "base_url"): f"http://127.0.0.1:{port}",
    ("database", "url"): f"sqlite://{root / 'data' / 'boxd.sqlite3'}?mode=rwc",
    ("storage", "data_dir"): str(root / "data"),
    ("storage", "images_dir"): str(root / "data" / "images"),
    ("storage", "boxes_dir"): str(root / "data" / "boxes"),
    ("storage", "snapshots_dir"): str(root / "data" / "snapshots"),
    ("storage", "recordings_dir"): str(root / "data" / "recordings"),
}
section = None
seen = set()
out = []
for line in raw.decode("utf-8").splitlines(keepends=True):
    section_match = re.match(r"^\s*\[([^]]+)\]\s*$", line.rstrip("\r\n"))
    if section_match:
        section = section_match.group(1)
        out.append(line)
        continue
    key_match = re.match(r"^(\s*)([A-Za-z0-9_-]+)(\s*=).*(\r?\n)?$", line)
    key = (section, key_match.group(2)) if key_match else None
    if key in values:
        newline = "\r\n" if line.endswith("\r\n") else "\n"
        out.append(f"{key_match.group(1)}{key_match.group(2)} = {json.dumps(values[key])}{newline}")
        seen.add(key)
    else:
        out.append(line)
missing = set(values) - seen
if missing:
    raise SystemExit("config template is missing required keys: " + ", ".join(".".join(k) for k in sorted(missing)))
encoded = "".join(out).encode("utf-8")
fd = os.open(generated, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
text = encoded.decode("utf-8")
for value in values.values():
    if json.dumps(value) not in text: raise SystemExit("generated config replacement is missing")
PY
}

phase4_native_prepare_run() {
  local run_root port
  [[ -n ${RUNNER_TEMP:-} && $RUNNER_TEMP == /* && -d $RUNNER_TEMP && ! -L $RUNNER_TEMP ]] || phase4_native_die "RUNNER_TEMP must be an absolute real directory"
  run_root=$(mktemp -d -- "$RUNNER_TEMP/boxd-phase4-native.XXXXXX")
  chmod 700 "$run_root"
  port=$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)
  export BOXD_DIFF_RUN_ROOT=$run_root
  export BOXD_DIFF_LOCAL_PORT=$port
  export BOXD_DIFF_LOCAL_BASE_URL="http://127.0.0.1:$port"
}

phase4_native_capture_compat_key() {
  local stdout_file=$1 key_count key_line key
  if ! phase4_native_regular init-stdout "$stdout_file"; then
    rm -f -- "$stdout_file"
    phase4_native_die "init stdout is not a unique regular file"
  fi
  if [[ $(python3 - "$stdout_file" <<'PY'
import os, stat, sys
print(format(stat.S_IMODE(os.stat(sys.argv[1]).st_mode), "o"))
PY
) != 600 ]]; then
    rm -f -- "$stdout_file"
    phase4_native_die "init stdout must be mode 0600"
  fi
  key_count=$(grep -c '^compat_api_key=' -- "$stdout_file" || true)
  [[ $key_count == 1 ]] || { rm -f -- "$stdout_file"; phase4_native_die "boxd init must return exactly one compatibility key"; }
  key_line=$(grep '^compat_api_key=' -- "$stdout_file")
  [[ $key_line =~ ^compat_api_key=(boxd_compat_[A-Za-z0-9]+_[A-Za-z0-9]+)$ ]] || { rm -f -- "$stdout_file"; phase4_native_die "boxd init compatibility key format is invalid"; }
  key=${BASH_REMATCH[1]}
  printf '::add-mask::%s\n' "$key"
  export BOXD_DIFF_LOCAL_API_KEY=$key
  export UPSTASH_BOX_API_KEY=$key
  rm -f -- "$stdout_file"
  [[ ! -e $stdout_file ]] || phase4_native_die "init stdout cleanup failed"
}

phase4_native_stop() {
  local status=$?; trap - EXIT
  if [[ -n ${BOXD_DIFF_DAEMON_PID:-} ]] && kill -0 "$BOXD_DIFF_DAEMON_PID" 2>/dev/null; then
    kill -TERM "$BOXD_DIFF_DAEMON_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do
      kill -0 "$BOXD_DIFF_DAEMON_PID" 2>/dev/null || break
      sleep 1
    done
    kill -KILL "$BOXD_DIFF_DAEMON_PID" 2>/dev/null || true
  fi
  wait "${BOXD_DIFF_DAEMON_PID:-}" 2>/dev/null || true
  exit "$status"
}

phase4_native_start() {
  local repo_root script_dir target_dir boxd doctor_json template_config
  script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  repo_root=$(cd -- "$script_dir/.." && pwd -P)
  cd -- "$repo_root"
  if [[ -n ${GITHUB_SHA:-} ]]; then
    [[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]] || phase4_native_die "checkout HEAD is not GITHUB_SHA"
  fi
  for name in BOXD_DIFF_LOCAL_CONFIG BOXD_DIFF_LOCAL_CONFIG_SHA256 BOXD_DIFF_RUNTIME_BUNDLE BOXD_DIFF_RUNTIME_BUNDLE_SHA256 BOXD_DIFF_LIBKRUN_PATH BOXD_DIFF_LIBKRUN_SHA256 BOXD_DIFF_LIBKRUN_LICENSE_PATH BOXD_DIFF_LIBKRUNFW_PATH BOXD_DIFF_LIBKRUNFW_SHA256 BOXD_DIFF_LIBKRUNFW_LICENSE_PATH BOXD_MASTER_KEY BOXD_ADMIN_PASSWORD; do
    [[ -n ${!name:-} ]] || phase4_native_die "missing $name"
  done
  [[ -f /sys/fs/cgroup/cgroup.controllers ]] || phase4_native_die "cgroup v2 is required"
  for controller in cpu memory pids; do
    grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers || phase4_native_die "cgroup controller unavailable: $controller"
  done
  template_config=$BOXD_DIFF_LOCAL_CONFIG
  phase4_native_regular config-template "$template_config"
  phase4_native_regular runtime-bundle "$BOXD_DIFF_RUNTIME_BUNDLE"
  phase4_native_regular libkrun "$BOXD_DIFF_LIBKRUN_PATH"
  phase4_native_regular libkrun-license "$BOXD_DIFF_LIBKRUN_LICENSE_PATH"
  phase4_native_regular libkrunfw "$BOXD_DIFF_LIBKRUNFW_PATH"
  phase4_native_regular libkrunfw-license "$BOXD_DIFF_LIBKRUNFW_LICENSE_PATH"
  phase4_native_hash libkrun "$BOXD_DIFF_LIBKRUN_PATH" "$BOXD_DIFF_LIBKRUN_SHA256"
  phase4_native_hash libkrunfw "$BOXD_DIFF_LIBKRUNFW_PATH" "$BOXD_DIFF_LIBKRUNFW_SHA256"
  phase4_native_hash runtime-bundle "$BOXD_DIFF_RUNTIME_BUNDLE" "$BOXD_DIFF_RUNTIME_BUNDLE_SHA256"
  phase4_native_hash config-template "$template_config" "$BOXD_DIFF_LOCAL_CONFIG_SHA256"
  phase4_native_prepare_run
  phase4_native_origin
  phase4_native_port_free

  target_dir=$BOXD_DIFF_RUN_ROOT/cargo-target
  [[ $target_dir == "$RUNNER_TEMP"/* && ! -L $target_dir ]] || phase4_native_die "cargo target must be under RUNNER_TEMP"
  mkdir -p -- "$target_dir"
  export CARGO_TARGET_DIR=$target_dir CARGO_INCREMENTAL=0
  export BOXD_EMBEDDED_LIBKRUN_PATH=$BOXD_DIFF_LIBKRUN_PATH
  export BOXD_EMBEDDED_LIBKRUN_SHA256=$BOXD_DIFF_LIBKRUN_SHA256
  export BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH=$BOXD_DIFF_LIBKRUN_LICENSE_PATH
  export BOXD_EMBEDDED_LIBKRUNFW_PATH=$BOXD_DIFF_LIBKRUNFW_PATH
  export BOXD_EMBEDDED_LIBKRUNFW_SHA256=$BOXD_DIFF_LIBKRUNFW_SHA256
  export BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH=$BOXD_DIFF_LIBKRUNFW_LICENSE_PATH
  cargo build --release --locked -p boxd
  boxd="$target_dir/release/boxd"
  phase4_native_regular local-binary "$boxd"
  export BOXD_DIFF_LOCAL_BINARY=$boxd
  export BOXD_RUNTIME_BUNDLE=$BOXD_DIFF_RUNTIME_BUNDLE
  local init_config init_stdout
  init_config=$BOXD_DIFF_RUN_ROOT/init.toml
  init_stdout=$BOXD_DIFF_RUN_ROOT/init.stdout
  if ! (umask 077; "$boxd" init --config "$init_config" >"$init_stdout" 2>/dev/null); then
    rm -f -- "$init_stdout"
    phase4_native_die "boxd init failed"
  fi
  chmod 600 -- "$init_stdout"
  phase4_native_capture_compat_key "$init_stdout"
  phase4_native_write_config "$template_config" "$BOXD_DIFF_RUN_ROOT/boxd.toml" "$BOXD_DIFF_RUN_ROOT" "$BOXD_DIFF_LOCAL_PORT"
  export BOXD_DIFF_LOCAL_CONFIG=$BOXD_DIFF_RUN_ROOT/boxd.toml
  export BOXD_DIFF_LOCAL_CONFIG_SHA256=$(sha256sum -- "$BOXD_DIFF_LOCAL_CONFIG" | cut -d' ' -f1)
  phase4_native_regular config "$BOXD_DIFF_LOCAL_CONFIG"
  "$boxd" config validate --config "$BOXD_DIFF_LOCAL_CONFIG"
  "$boxd" runtime import --config "$BOXD_DIFF_LOCAL_CONFIG" "$BOXD_DIFF_RUNTIME_BUNDLE"
  doctor_json=${RUNNER_TEMP:-$target_dir}/boxd-phase4-doctor.json
  "$boxd" doctor --config "$BOXD_DIFF_LOCAL_CONFIG" --json >"$doctor_json"
  python3 - "$doctor_json" <<'PY'
import json, sys
if json.load(open(sys.argv[1], encoding="utf-8")).get("overall") is not True:
    raise SystemExit("boxd doctor overall is not true")
PY
  "$boxd" serve --config "$BOXD_DIFF_LOCAL_CONFIG" >"${RUNNER_TEMP:-$target_dir}/boxd-phase4-daemon.stdout" 2>"${RUNNER_TEMP:-$target_dir}/boxd-phase4-daemon.stderr" &
  export BOXD_DIFF_DAEMON_PID=$!
  trap phase4_native_stop EXIT INT TERM
  for _ in $(seq 1 180); do
    kill -0 "$BOXD_DIFF_DAEMON_PID" 2>/dev/null || phase4_native_die "owned daemon exited before ready"
    if curl --fail --silent --show-error --max-time 2 "$BOXD_DIFF_LOCAL_BASE_URL/health/ready" >/dev/null; then return 0; fi
    sleep 1
  done
  phase4_native_die "owned daemon did not become ready"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  [[ ${1:-} == "--help" ]] && { printf 'source scripts/phase4-differential-native.sh and call phase4_native_start\n'; exit 0; }
  [[ ${1:-} == "start" ]] || { printf 'use: %s start\n' "$0" >&2; exit 64; }
  phase4_native_start
  wait "$BOXD_DIFF_DAEMON_PID"
fi
