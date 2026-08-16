#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C
export TZ=UTC

usage() {
  cat <<'EOF'
Build one signed Debian/Alpine runtime bundle for aarch64 or x86_64.

Required environment:
  BOXD_RUNTIME_NAME          node|python|golang|ruby|rust and optional -alpine
  BOXD_RUNTIME_VERSION       complete semantic version
  BOXD_RUNTIME_IMAGE         immutable OCI tag@sha256 digest for target arch
  BOXD_RUST_IMAGE            immutable Rust 1.94 OCI tag@sha256 digest;
                              Debian runtime requires GNU, Alpine requires musl
  BOXD_TARGET_ARCH           aarch64|x86_64
  BOXD_SIGNING_KEY           Ed25519 private key outside workspace, mode 0600
  BOXD_SIGNING_KEY_ID        [A-Za-z0-9._-], 1..128
  BOXD_AGENT_LICENSE_FILE    current box-agent Apache-2.0 text
  BOXD_SOURCE_DATE_EPOCH     non-negative integer
  BOXD_RUNTIME_LICENSE_SOURCE canonical relative path inside the pinned runtime
                              OCI image, copied as license evidence
  BOXD_RUNTIME_LICENSE_ID    reviewed SPDX expression or NOASSERTION

Optional environment:
  BOXD_OUTPUT_DIR            default: ./dist/runtime
  BOXD_DEFAULT_DISK_GIB      default: 20
  BOXD_KERNEL_VERSION        default: 6.1.0
  BOXD_DOCKER_PULL_TIMEOUT_SECONDS default: 300
  BOXD_CARGO_REGISTRY_DIR    default: ~/.cargo/registry
  BOXD_SOURCE_USER           default: node for Node, otherwise boxuser
  BOXD_BROWSER_CHROMIUM_SOURCE canonical Chromium executable path inside OCI;
                              requires BOXD_BROWSER_CHROMIUM_VERSION
  BOXD_BROWSER_CHROMIUM_VERSION exact reviewed Chromium version
  BOXD_BROWSER_LICENSE_FILE     reviewed Chromium BSD-3-Clause text outside
                              workspace; required for browser bundles

The source OCI image must contain CA certificates, git, /bin/sh, the selected
runtime executable, package metadata, and OS license evidence. It must either
have no uid/gid 1000 account or exactly the configured source user at 1000.
The builder does not discover tags, install packages, mutate an image, or
generate a signing key. Every release input remains caller-reviewed.
EOF
}

if [[ ${1:-} == --help ]]; then usage; exit 0; fi
if (($# != 0)); then usage >&2; exit 64; fi

required=(
  BOXD_RUNTIME_NAME BOXD_RUNTIME_VERSION BOXD_RUNTIME_IMAGE BOXD_RUST_IMAGE
  BOXD_TARGET_ARCH BOXD_SIGNING_KEY BOXD_SIGNING_KEY_ID
  BOXD_AGENT_LICENSE_FILE BOXD_SOURCE_DATE_EPOCH BOXD_RUNTIME_LICENSE_SOURCE
  BOXD_RUNTIME_LICENSE_ID
)
for variable in "${required[@]}"; do
  [[ -n ${!variable:-} ]] || {
    printf 'missing required environment variable: %s\n' "$variable" >&2
    exit 64
  }
done
for command in cmp docker file openssl python3 shasum stat zstd; do
  command -v "$command" >/dev/null || {
    printf 'missing required build dependency: %s\n' "$command" >&2
    exit 69
  }
done
[[ $(zstd --version) == *' v1.5.7,'* ]] || {
  printf 'zstd 1.5.7 is required for reproducible compression\n' >&2
  exit 69
}

case "$BOXD_RUNTIME_NAME" in
  node|python|golang|ruby|rust) family=debian; base_runtime=$BOXD_RUNTIME_NAME ;;
  node-alpine|python-alpine|golang-alpine|ruby-alpine|rust-alpine)
    family=alpine; base_runtime=${BOXD_RUNTIME_NAME%-alpine} ;;
  *) printf 'unsupported runtime name: %s\n' "$BOXD_RUNTIME_NAME" >&2; exit 64 ;;
esac
case "$BOXD_TARGET_ARCH" in
  aarch64) docker_platform=linux/arm64; rust_machine=aarch64; file_pattern='ARM aarch64|ARM64' ;;
  x86_64) docker_platform=linux/amd64; rust_machine=x86_64; file_pattern='x86-64|x86_64' ;;
  *) printf 'BOXD_TARGET_ARCH must be aarch64 or x86_64\n' >&2; exit 64 ;;
esac
if [[ $family == alpine ]]; then rust_target=${rust_machine}-unknown-linux-musl; else rust_target=${rust_machine}-unknown-linux-gnu; fi
runtime_command=${base_runtime/node/node}
runtime_command=${runtime_command/python/python3}
runtime_command=${runtime_command/golang/go}
runtime_command=${runtime_command/ruby/ruby}
runtime_command=${runtime_command/rust/rustc}
source_user=${BOXD_SOURCE_USER:-}
if [[ -z $source_user ]]; then
  [[ $base_runtime == node ]] && source_user=node || source_user=boxuser
fi
[[ $source_user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || {
  printf 'BOXD_SOURCE_USER is invalid\n' >&2
  exit 64
}

pinned_image='^[^[:space:]@]+:[^[:space:]@]+@sha256:[0-9a-f]{64}$'
[[ $BOXD_RUNTIME_IMAGE =~ $pinned_image && $BOXD_RUST_IMAGE =~ $pinned_image ]] || {
  printf 'OCI images must include immutable version tags and sha256 digests\n' >&2
  exit 64
}
semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
[[ $BOXD_RUNTIME_VERSION =~ $semver_pattern ]] || {
  printf 'BOXD_RUNTIME_VERSION must be complete SemVer\n' >&2
  exit 64
}
[[ $BOXD_SIGNING_KEY_ID =~ ^[A-Za-z0-9._-]{1,128}$ ]] || {
  printf 'BOXD_SIGNING_KEY_ID is invalid\n' >&2
  exit 64
}
license_id_pattern='^[A-Za-z0-9.+() _-]{1,128}$'
[[ $BOXD_RUNTIME_LICENSE_ID =~ $license_id_pattern ]] || {
  printf 'BOXD_RUNTIME_LICENSE_ID is invalid\n' >&2
  exit 64
}
[[ $BOXD_SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || {
  printf 'BOXD_SOURCE_DATE_EPOCH must be a non-negative integer\n' >&2
  exit 64
}
disk_gib=${BOXD_DEFAULT_DISK_GIB:-20}
pull_timeout=${BOXD_DOCKER_PULL_TIMEOUT_SECONDS:-300}
kernel_version=${BOXD_KERNEL_VERSION:-6.1.0}
[[ $disk_gib =~ ^[1-9][0-9]*$ && $pull_timeout =~ ^[1-9][0-9]*$ ]] || {
  printf 'disk size and pull timeout must be positive integers\n' >&2
  exit 64
}
((disk_gib <= 60)) || { printf 'disk size exceeds importer limit\n' >&2; exit 64; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/../.." && pwd -P)
output_dir=${BOXD_OUTPUT_DIR:-$repo_root/dist/runtime}
cargo_registry_dir=${BOXD_CARGO_REGISTRY_DIR:-$HOME/.cargo/registry}
for path in "$BOXD_SIGNING_KEY" "$BOXD_AGENT_LICENSE_FILE"; do
  [[ $path == /* && -f $path && ! -L $path ]] || {
    printf 'key and agent license must be absolute regular non-symlink files\n' >&2
    exit 66
  }
done
python3 - "$BOXD_RUNTIME_LICENSE_SOURCE" <<'PY'
import pathlib, sys
raw = sys.argv[1]
path = pathlib.PurePosixPath(raw)
if (
    not raw
    or raw.startswith("/")
    or "\x00" in raw
    or len(raw.encode("utf-8")) > 4096
    or any(part in {"", ".", ".."} or len(part.encode("utf-8")) > 255 for part in path.parts)
    or path.as_posix() != raw
):
    raise SystemExit("runtime license source must be a canonical relative OCI path")
PY
key_dir=$(cd -- "$(dirname -- "$BOXD_SIGNING_KEY")" && pwd -P)
key_path=$key_dir/$(basename -- "$BOXD_SIGNING_KEY")
[[ $key_path != "$repo_root"/* ]] || { printf 'signing key must be outside workspace\n' >&2; exit 77; }
if [[ $(uname -s) == Darwin ]]; then key_mode=$(stat -f '%Lp' "$key_path"); else key_mode=$(stat -c '%a' "$key_path"); fi
((8#$key_mode & 077)) && { printf 'signing key is accessible by group or others\n' >&2; exit 77; }
openssl pkey -in "$key_path" -text -noout 2>/dev/null | grep -q ED25519 || {
  printf 'signing key must be Ed25519\n' >&2
  exit 65
}
[[ $cargo_registry_dir == /* && -d $cargo_registry_dir && $cargo_registry_dir != "$repo_root"/* ]] || {
  printf 'BOXD_CARGO_REGISTRY_DIR must be an existing absolute path outside workspace\n' >&2
  exit 64
}
cargo_registry_dir=$(cd -- "$cargo_registry_dir" && pwd -P)

mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd -P)
bundle_name="box-runtime-${BOXD_RUNTIME_NAME}-${BOXD_TARGET_ARCH}-${BOXD_RUNTIME_VERSION}.tar.zst"
for name in "$bundle_name" "$bundle_name.sha256"; do
  [[ ! -e $output_dir/$name && ! -L $output_dir/$name ]] || {
    printf 'refusing to overwrite output: %s\n' "$output_dir/$name" >&2
    exit 73
  }
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/boxd-runtime-build.XXXXXXXX")
container_id=''
cleanup() {
  if [[ -n $container_id ]]; then docker rm -f "$container_id" >/dev/null 2>&1 || true; fi
  python3 - "$work_dir" <<'PY'
import pathlib, shutil, sys
path = pathlib.Path(sys.argv[1])
if path.is_symlink() or not path.name.startswith("boxd-runtime-build."):
    raise SystemExit("refusing unsafe work cleanup")
shutil.rmtree(path)
PY
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

docker_pull_bounded() {
  local image=$1
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    python3 - "$image" "$pull_timeout" "$docker_platform" <<'PY'
import subprocess, sys
try:
    result = subprocess.run(["docker", "pull", "--platform", sys.argv[3], sys.argv[1]], timeout=int(sys.argv[2]))
except subprocess.TimeoutExpired as error:
    raise SystemExit(f"docker pull timed out: {sys.argv[1]}") from error
raise SystemExit(result.returncode)
PY
  fi
  local actual_arch
  actual_arch=$(docker image inspect --format '{{.Architecture}}' "$image")
  local expected_arch=${docker_platform#linux/}
  [[ $actual_arch == "$expected_arch" ]] || {
    printf 'OCI architecture mismatch: expected %s, got %s\n' "$expected_arch" "$actual_arch" >&2
    return 65
  }
}

docker_pull_bounded "$BOXD_RUST_IMAGE"
rust_toolchain=$(docker run --rm --platform "$docker_platform" --network none \
  --read-only "$BOXD_RUST_IMAGE" sh -euc 'rustup show active-toolchain | awk "{print \$1}"')
[[ $rust_toolchain =~ ^1\.94\.[0-9]+-${rust_target}$ ]] || {
  printf 'Rust image toolchain mismatch: expected 1.94.x-%s, got %s\n' \
    "$rust_target" "$rust_toolchain" >&2
  exit 65
}
cargo_container=(docker run --rm --platform "$docker_platform" --network none
  --mount "type=bind,src=$repo_root,dst=/src,readonly"
  --mount "type=bind,src=$cargo_registry_dir,dst=/cargo-ro/registry,readonly"
  --mount "type=bind,src=$work_dir,dst=/out"
  --workdir /src
  --env CARGO_HOME=/out/cargo-home
  --env CARGO_TARGET_DIR=/out/target
  --env CARGO_INCREMENTAL=0
  --env EXPECTED_RUST_TARGET="$rust_target"
  --env RUSTUP_TOOLCHAIN="$rust_toolchain"
  --env SOURCE_DATE_EPOCH="$BOXD_SOURCE_DATE_EPOCH"
  "$BOXD_RUST_IMAGE")
# The quoted program is evaluated inside the container; its variables must not
# expand in the host shell.
# shellcheck disable=SC2016
"${cargo_container[@]}" sh -euc '
  actual_release=$(rustc -Vv | sed -n "s/^release: //p")
  actual_host=$(rustc -Vv | sed -n "s/^host: //p")
  case "$actual_release" in 1.94.*) ;; *)
    printf "Rust image must contain a 1.94.x compiler, got %s\n" "$actual_release" >&2
    exit 69
  esac
  test "$actual_host" = "$EXPECTED_RUST_TARGET" || {
    printf "Rust image target mismatch: expected %s, got %s\n" "$EXPECTED_RUST_TARGET" "$actual_host" >&2
    exit 65
  }
  mkdir -p /out/cargo-home
  cp -a /cargo-ro/registry /out/cargo-home/registry
  cargo build --locked --offline --release -p box-agent
'
agent=$work_dir/target/release/box-agent
[[ -x $agent ]] || { printf 'box-agent build did not produce an executable\n' >&2; exit 70; }
file "$agent" | grep -Eq "ELF 64-bit.*($file_pattern)" || {
  printf 'box-agent architecture mismatch\n' >&2
  exit 70
}

docker_pull_bounded "$BOXD_RUNTIME_IMAGE"
docker run --rm --platform "$docker_platform" --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,mode=0700 \
  --mount "type=bind,src=$agent,dst=/box-agent,readonly" \
  --entrypoint /bin/sh "$BOXD_RUNTIME_IMAGE" -euc '
    set +e
    env -i /box-agent </dev/null >/tmp/box-agent-loader.stdout 2>/tmp/box-agent-loader.stderr
    status=$?
    set -e
    test "$status" -ne 126 -a "$status" -ne 127
    ! grep -Eqi "not found|No such file|bad ELF|exec format" /tmp/box-agent-loader.stderr
  ' || {
    printf 'box-agent cannot be loaded by the selected runtime image ABI\n' >&2
    exit 70
  }
container_id=$(docker create --platform "$docker_platform" "$BOXD_RUNTIME_IMAGE" /bin/true)
docker export --output "$work_dir/runtime-oci-export.tar" "$container_id"
docker rm "$container_id" >/dev/null
container_id=''
stage=$work_dir/stage
mkdir -p -- "$stage/licenses"
status=$work_dir/package-status
os_licenses=$stage/licenses/${family}-licenses.tar
os_index=$stage/licenses/${family}-licenses.index.json
runtime_license=$stage/licenses/${BOXD_RUNTIME_NAME}-runtime-license.txt
prepare_args=(
  --oci-export "$work_dir/runtime-oci-export.tar"
  --agent "$agent"
  --output "$work_dir/rootfs.tar"
  --family "$family"
  --source-user "$source_user"
  --package-status-output "$status"
  --os-licenses-output "$os_licenses"
  --os-licenses-index-output "$os_index"
  --epoch "$BOXD_SOURCE_DATE_EPOCH"
  --release "runtime=$BOXD_RUNTIME_NAME version=$BOXD_RUNTIME_VERSION arch=$BOXD_TARGET_ARCH agent_protocol=1"
)
prepare_args+=(--runtime-license-source "$BOXD_RUNTIME_LICENSE_SOURCE" --runtime-license-output "$runtime_license")
browser_feature=()
if [[ -n ${BOXD_BROWSER_CHROMIUM_SOURCE:-} || -n ${BOXD_BROWSER_CHROMIUM_VERSION:-} || -n ${BOXD_BROWSER_LICENSE_FILE:-} ]]; then
  [[ -n ${BOXD_BROWSER_CHROMIUM_SOURCE:-} && -n ${BOXD_BROWSER_CHROMIUM_VERSION:-} && -n ${BOXD_BROWSER_LICENSE_FILE:-} ]] || {
    printf 'browser Chromium source, version and license must be configured together\n' >&2
    exit 64
  }
  python3 - "$BOXD_BROWSER_CHROMIUM_SOURCE" "$BOXD_BROWSER_CHROMIUM_VERSION" <<'PY'
import pathlib, re, sys
path = pathlib.PurePosixPath(sys.argv[1])
if sys.argv[1].startswith("/") or path.as_posix() != sys.argv[1] or ".." in path.parts:
    raise SystemExit("browser Chromium source must be a canonical relative OCI path")
if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", sys.argv[2]):
    raise SystemExit("browser Chromium version must contain four numeric components")
PY
  [[ $BOXD_BROWSER_LICENSE_FILE == /* && -f $BOXD_BROWSER_LICENSE_FILE && ! -L $BOXD_BROWSER_LICENSE_FILE ]] || {
    printf 'browser license must be an absolute regular non-symlink file\n' >&2
    exit 66
  }
  browser_license_dir=$(cd -- "$(dirname -- "$BOXD_BROWSER_LICENSE_FILE")" && pwd -P)
  browser_license=$browser_license_dir/$(basename -- "$BOXD_BROWSER_LICENSE_FILE")
  [[ $browser_license != "$repo_root"/* && -s $browser_license ]] || {
    printf 'browser license must be non-empty and outside workspace\n' >&2
    exit 66
  }
  prepare_args+=(
    --browser-chromium-source "$BOXD_BROWSER_CHROMIUM_SOURCE"
    --browser-chromium-version "$BOXD_BROWSER_CHROMIUM_VERSION"
  )
  browser_feature=(--feature browser-cdp-v1)
fi
python3 "$script_dir/prepare_rootfs_tar.py" "${prepare_args[@]}"
if [[ ! -s $runtime_license ]]; then
  printf 'runtime license source is required and must be non-empty\n' >&2
  exit 66
fi

disk_bytes=$((disk_gib * 1024 * 1024 * 1024))
docker run --rm --platform "$docker_platform" --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,mode=0700 \
  --mount "type=bind,src=$work_dir,dst=/work" \
  --env DISK_BYTES="$disk_bytes" \
  --env SOURCE_DATE_EPOCH="$BOXD_SOURCE_DATE_EPOCH" \
  --env RUNTIME_COMMAND="$runtime_command" \
  --env RUNTIME_FAMILY="$family" \
  "$BOXD_RUNTIME_IMAGE" sh -euc '
    command -v "$RUNTIME_COMMAND" >/dev/null
    command -v git >/dev/null
    test -s /etc/ssl/certs/ca-certificates.crt
    test "$(mke2fs -V 2>&1 | sed -n "1p")" = "mke2fs 1.47.0 (5-Feb-2023)"
    mkdir /tmp/rootfs
    tar --numeric-owner --same-owner -xf /work/rootfs.tar -C /tmp/rootfs
    truncate -s "$DISK_BYTES" /work/stage/rootfs.raw
    E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" mke2fs -q -F -t ext4 \
      -d /tmp/rootfs -L boxd-runtime -U 00000000-0000-4000-8000-000000000001 \
      -E lazy_itable_init=0,lazy_journal_init=0,hash_seed=00000000-0000-4000-8000-000000000001 \
      /work/stage/rootfs.raw
  '
rootfs=$stage/rootfs.raw
if [[ $(uname -s) == Darwin ]]; then actual_bytes=$(stat -f '%z' "$rootfs"); else actual_bytes=$(stat -c '%s' "$rootfs"); fi
[[ $actual_bytes == "$disk_bytes" ]] || { printf 'rootfs size mismatch\n' >&2; exit 70; }
cp -- "$BOXD_AGENT_LICENSE_FILE" "$stage/licenses/box-agent-Apache-2.0.txt"
if [[ -n ${browser_license:-} ]]; then
  cp -- "$browser_license" "$stage/licenses/chromium-BSD-3-Clause.txt"
fi

agent_sha=$(shasum -a 256 "$agent" | awk '{print $1}')
created=$(python3 -c 'import datetime,sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$BOXD_SOURCE_DATE_EPOCH")
namespace="https://boxd.invalid/spdx/${BOXD_RUNTIME_NAME}-${BOXD_RUNTIME_VERSION}-${BOXD_TARGET_ARCH}-${agent_sha}"
sbom_browser=()
if [[ -n ${BOXD_BROWSER_CHROMIUM_VERSION:-} ]]; then
  sbom_browser=(
    --browser-version "$BOXD_BROWSER_CHROMIUM_VERSION"
    --browser-license BSD-3-Clause
    --browser-license-file chromium-BSD-3-Clause.txt
  )
fi
python3 "$script_dir/generate_sbom.py" \
  --output "$stage/sbom.spdx.json" \
  --namespace "$namespace" \
  --runtime "$BOXD_RUNTIME_NAME" \
  --runtime-version "$BOXD_RUNTIME_VERSION" \
  --runtime-image "$BOXD_RUNTIME_IMAGE" \
  --runtime-license "$BOXD_RUNTIME_LICENSE_ID" \
  --runtime-license-file "${BOXD_RUNTIME_NAME}-runtime-license.txt" \
  --family "$family" \
  --arch "$BOXD_TARGET_ARCH" \
  --package-status "$status" \
  --agent-sha256 "$agent_sha" \
  --created "$created" \
  "${sbom_browser[@]}"
toolchain="rust=$BOXD_RUST_IMAGE;runtime=$BOXD_RUNTIME_IMAGE;mke2fs=1.47.0;zstd=1.5.7;source_date_epoch=$BOXD_SOURCE_DATE_EPOCH"
python3 "$script_dir/bundle_v1.py" manifest \
  --stage "$stage" \
  --output "$stage/manifest.json" \
  --runtime "$BOXD_RUNTIME_NAME" \
  --runtime-version "$BOXD_RUNTIME_VERSION" \
  --arch "$BOXD_TARGET_ARCH" \
  --kernel-version "$kernel_version" \
  --build-toolchain "$toolchain" \
  --key-id "$BOXD_SIGNING_KEY_ID" \
  "${browser_feature[@]}"
openssl pkeyutl -sign -rawin -inkey "$key_path" -in "$stage/manifest.json" -out "$work_dir/manifest.sig.bin"
openssl base64 -A -in "$work_dir/manifest.sig.bin" -out "$stage/manifest.sig"
printf '\n' >>"$stage/manifest.sig"
python3 "$script_dir/bundle_v1.py" archive --stage "$stage" --output - --epoch "$BOXD_SOURCE_DATE_EPOCH" \
  | zstd --quiet --threads=1 -19 --no-progress -o "$work_dir/$bundle_name"
openssl pkey -in "$key_path" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | openssl base64 -A >"$work_dir/trusted-public-key.base64"
printf '\n' >>"$work_dir/trusted-public-key.base64"
(cd -- "$work_dir" && shasum -a 256 "$bundle_name" >"$bundle_name.sha256")
mv -- "$work_dir/$bundle_name" "$output_dir/$bundle_name"
mv -- "$work_dir/$bundle_name.sha256" "$output_dir/$bundle_name.sha256"
public_key_output=$output_dir/$BOXD_SIGNING_KEY_ID.public-key.base64
if [[ -e $public_key_output || -L $public_key_output ]]; then
  [[ -f $public_key_output && ! -L $public_key_output ]] || {
    printf 'existing public key output is unsafe\n' >&2
    exit 73
  }
  cmp --silent "$work_dir/trusted-public-key.base64" "$public_key_output" || {
    printf 'existing public key output does not match signing key\n' >&2
    exit 65
  }
else
  mv -- "$work_dir/trusted-public-key.base64" "$public_key_output"
fi
printf 'bundle=%s\n' "$output_dir/$bundle_name"
printf 'bundle_sha256=%s\n' "$(shasum -a 256 "$output_dir/$bundle_name" | awk '{print $1}')"
printf 'rootfs_bytes=%s\n' "$actual_bytes"
