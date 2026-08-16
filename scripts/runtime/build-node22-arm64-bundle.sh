#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C
export TZ=UTC

usage() {
  cat <<'EOF'
Build a signed Node 22 Debian arm64 runtime bundle from pinned OCI images.

Required environment:
  BOXD_NODE_IMAGE          node:<version>-bookworm-slim@sha256:<64 lowercase hex>
  BOXD_RUST_IMAGE          arm64v8/rust:<version>-bullseye@sha256:<64 lowercase hex>
  BOXD_SIGNING_KEY         external Ed25519 private key in PEM format (mode 0600)
  BOXD_SIGNING_KEY_ID      manifest key id: [A-Za-z0-9._-], 1..128 bytes
  BOXD_AGENT_LICENSE_FILE  Apache-2.0 license text for the current box-agent source
  BOXD_SOURCE_DATE_EPOCH   non-negative integer build epoch

Optional environment:
  BOXD_OUTPUT_DIR          default: ./dist/runtime
  BOXD_NODE_VERSION        default: 22.16.0
  BOXD_DEFAULT_DISK_GIB    default: 20
  BOXD_KERNEL_VERSION      default: 6.1.0
  BOXD_DOCKER_PULL_TIMEOUT_SECONDS default: 300
  BOXD_CARGO_REGISTRY_DIR  default: ~/.cargo/registry (read-only source cache)
EOF
}

if [[ ${1:-} == "--help" ]]; then
  usage
  exit 0
fi
if (($# != 0)); then
  usage >&2
  exit 64
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/../.." && pwd -P)
output_dir=${BOXD_OUTPUT_DIR:-$repo_root/dist/runtime}
node_version=${BOXD_NODE_VERSION:-22.16.0}
disk_gib=${BOXD_DEFAULT_DISK_GIB:-20}
kernel_version=${BOXD_KERNEL_VERSION:-6.1.0}
pull_timeout=${BOXD_DOCKER_PULL_TIMEOUT_SECONDS:-300}
cargo_registry_dir=${BOXD_CARGO_REGISTRY_DIR:-$HOME/.cargo/registry}

for variable in BOXD_NODE_IMAGE BOXD_RUST_IMAGE BOXD_SIGNING_KEY BOXD_SIGNING_KEY_ID BOXD_AGENT_LICENSE_FILE BOXD_SOURCE_DATE_EPOCH; do
  if [[ -z ${!variable:-} ]]; then
    printf 'missing required environment variable: %s\n' "$variable" >&2
    exit 64
  fi
done
for command in docker python3 openssl zstd shasum file; do
  command -v "$command" >/dev/null || {
    printf 'missing required build dependency: %s\n' "$command" >&2
    exit 69
  }
done
[[ $(zstd --version) == *' v1.5.7,'* ]] || {
  printf 'zstd 1.5.7 is required for reproducible compression\n' >&2
  exit 69
}

pinned_image='^[^[:space:]@]+:[^[:space:]@]+@sha256:[0-9a-f]{64}$'
[[ $BOXD_NODE_IMAGE =~ $pinned_image ]] || {
  printf 'BOXD_NODE_IMAGE must include an immutable version tag and sha256 digest\n' >&2
  exit 64
}
[[ $BOXD_RUST_IMAGE =~ $pinned_image ]] || {
  printf 'BOXD_RUST_IMAGE must include an immutable version tag and sha256 digest\n' >&2
  exit 64
}
[[ $BOXD_NODE_IMAGE == *"node:${node_version}-bookworm-slim@"* ]] || {
  printf 'BOXD_NODE_IMAGE tag must exactly match BOXD_NODE_VERSION and bookworm-slim\n' >&2
  exit 64
}
[[ $node_version =~ ^22\.[0-9]+\.[0-9]+$ ]] || {
  printf 'BOXD_NODE_VERSION must be a complete Node 22 semantic version\n' >&2
  exit 64
}
[[ $disk_gib =~ ^[1-9][0-9]*$ ]] || {
  printf 'BOXD_DEFAULT_DISK_GIB must be a positive integer\n' >&2
  exit 64
}
((disk_gib <= 60)) || {
  printf 'BOXD_DEFAULT_DISK_GIB exceeds the bundle importer 60 GiB limit\n' >&2
  exit 64
}
[[ $BOXD_SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || {
  printf 'BOXD_SOURCE_DATE_EPOCH must be a non-negative integer\n' >&2
  exit 64
}
[[ $pull_timeout =~ ^[1-9][0-9]*$ ]] || {
  printf 'BOXD_DOCKER_PULL_TIMEOUT_SECONDS must be a positive integer\n' >&2
  exit 64
}
[[ $BOXD_SIGNING_KEY_ID =~ ^[A-Za-z0-9._-]{1,128}$ ]] || {
  printf 'BOXD_SIGNING_KEY_ID is invalid\n' >&2
  exit 64
}
[[ -f $BOXD_SIGNING_KEY && ! -L $BOXD_SIGNING_KEY ]] || {
  printf 'BOXD_SIGNING_KEY must be a regular non-symlink file\n' >&2
  exit 66
}
[[ -f $BOXD_AGENT_LICENSE_FILE && ! -L $BOXD_AGENT_LICENSE_FILE ]] || {
  printf 'BOXD_AGENT_LICENSE_FILE must be a regular non-symlink file\n' >&2
  exit 66
}
[[ -s $BOXD_AGENT_LICENSE_FILE ]] || {
  printf 'BOXD_AGENT_LICENSE_FILE must not be empty\n' >&2
  exit 66
}
if [[ $(uname -s) == Darwin ]]; then
  license_bytes=$(stat -f '%z' "$BOXD_AGENT_LICENSE_FILE")
else
  license_bytes=$(stat -c '%s' "$BOXD_AGENT_LICENSE_FILE")
fi
((license_bytes <= 4 * 1024 * 1024)) || {
  printf 'BOXD_AGENT_LICENSE_FILE exceeds the bundle per-file limit\n' >&2
  exit 66
}
signing_key_dir=$(cd -- "$(dirname -- "$BOXD_SIGNING_KEY")" && pwd -P)
signing_key_path=$signing_key_dir/$(basename -- "$BOXD_SIGNING_KEY")
if [[ $signing_key_path == "$repo_root"/* ]]; then
  printf 'BOXD_SIGNING_KEY must be stored outside the source workspace\n' >&2
  exit 77
fi
if [[ $cargo_registry_dir != /* || ! -d $cargo_registry_dir ]]; then
  printf 'BOXD_CARGO_REGISTRY_DIR must be an existing absolute directory\n' >&2
  exit 64
fi
cargo_registry_dir=$(cd -- "$cargo_registry_dir" && pwd -P)
if [[ $cargo_registry_dir == "$repo_root" || $cargo_registry_dir == "$repo_root"/* ]]; then
  printf 'BOXD_CARGO_REGISTRY_DIR must be outside the source workspace\n' >&2
  exit 77
fi
if [[ $(uname -s) == Darwin ]]; then
  key_mode=$(stat -f '%Lp' "$BOXD_SIGNING_KEY")
else
  key_mode=$(stat -c '%a' "$BOXD_SIGNING_KEY")
fi
if ((8#$key_mode & 077)); then
  printf 'BOXD_SIGNING_KEY must not be accessible by group or other users\n' >&2
  exit 77
fi
openssl pkey -in "$BOXD_SIGNING_KEY" -pubout -out /dev/null 2>/dev/null || {
  printf 'BOXD_SIGNING_KEY is not a readable private key\n' >&2
  exit 65
}
openssl pkey -in "$BOXD_SIGNING_KEY" -text -noout 2>/dev/null | grep -q 'ED25519' || {
  printf 'BOXD_SIGNING_KEY must be an Ed25519 private key\n' >&2
  exit 65
}

mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd -P)
bundle_name="box-runtime-node-aarch64-${node_version}.tar.zst"
for output_name in \
  "$bundle_name" \
  "$bundle_name.sha256" \
  "$BOXD_SIGNING_KEY_ID.public-key.base64"; do
  [[ ! -e $output_dir/$output_name && ! -L $output_dir/$output_name ]] || {
    printf 'refusing to overwrite existing output: %s\n' "$output_dir/$output_name" >&2
    exit 73
  }
done
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/boxd-runtime-build.XXXXXXXX")
container_id=''
cleanup() {
  if [[ -n $container_id ]]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

docker_pull_bounded() {
  if docker image inspect "$1" >/dev/null 2>&1; then
    local_arch=$(docker image inspect --format '{{.Architecture}}' "$1")
    [[ $local_arch == arm64 ]] || {
      printf 'cached pinned image has unexpected architecture: %s\n' "$local_arch" >&2
      return 65
    }
    return 0
  fi
  python3 - "$1" "$pull_timeout" <<'PY'
import subprocess
import sys

image = sys.argv[1]
timeout = int(sys.argv[2])
try:
    result = subprocess.run(
        ["docker", "pull", "--platform", "linux/arm64", image],
        timeout=timeout,
        check=False,
    )
except subprocess.TimeoutExpired as error:
    raise SystemExit(f"docker pull exceeded {timeout} seconds: {image}") from error
raise SystemExit(result.returncode)
PY
}

printf 'building box-agent for linux/arm64 from the current locked workspace\n'
docker_pull_bounded "$BOXD_RUST_IMAGE" >/dev/null
cargo_container=(docker run --rm --platform linux/arm64 --network none
  --mount "type=bind,src=$repo_root,dst=/src,readonly" \
  --mount "type=bind,src=$cargo_registry_dir,dst=/cargo-ro/registry,readonly" \
  --mount "type=bind,src=$work_dir,dst=/out" \
  --workdir /src \
  --env CARGO_HOME=/out/cargo-home \
  --env CARGO_TARGET_DIR=/out/target \
  --env CARGO_INCREMENTAL=0 \
  --env RUSTUP_TOOLCHAIN=1.94.0-aarch64-unknown-linux-gnu \
  --env SOURCE_DATE_EPOCH="$BOXD_SOURCE_DATE_EPOCH" \
  "$BOXD_RUST_IMAGE")
"${cargo_container[@]}" sh -euc '
  mkdir -p /out/cargo-home
  cp -a /cargo-ro/registry /out/cargo-home/registry
  cargo build --locked --offline --release -p box-agent
'
agent=$work_dir/target/release/box-agent
[[ -x $agent ]] || {
  printf 'linux/arm64 box-agent build did not produce an executable\n' >&2
  exit 70
}
file "$agent" | grep -Eq 'ELF 64-bit.*(ARM aarch64|ARM64)' || {
  printf 'box-agent output is not a linux/arm64 ELF executable\n' >&2
  exit 70
}

printf 'exporting pinned Node OCI rootfs\n'
docker_pull_bounded "$BOXD_NODE_IMAGE" >/dev/null
image_arch=$(docker image inspect --format '{{.Architecture}}' "$BOXD_NODE_IMAGE")
[[ $image_arch == arm64 ]] || {
  printf 'pinned Node image resolved to unexpected architecture: %s\n' "$image_arch" >&2
  exit 65
}
container_id=$(docker create --platform linux/arm64 "$BOXD_NODE_IMAGE" /bin/true)
docker export --output "$work_dir/node-oci-export.tar" "$container_id"
docker rm "$container_id" >/dev/null
container_id=''

release="node=$node_version arch=aarch64 agent_protocol=1"
stage=$work_dir/stage
mkdir -p -- "$stage/licenses"
python3 "$script_dir/prepare_rootfs_tar.py" \
  --oci-export "$work_dir/node-oci-export.tar" \
  --agent "$agent" \
  --output "$work_dir/rootfs.tar" \
  --node-license-output "$work_dir/node-LICENSE" \
  --dpkg-status-output "$work_dir/dpkg-status" \
  --debian-licenses-output "$stage/licenses/debian-copyrights.tar" \
  --debian-licenses-index-output "$stage/licenses/debian-copyrights.index.json" \
  --epoch "$BOXD_SOURCE_DATE_EPOCH" \
  --release "$release"

rootfs=$stage/rootfs.raw
disk_bytes=$((disk_gib * 1024 * 1024 * 1024))
docker run --rm --platform linux/arm64 --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,mode=0700 \
  --mount "type=bind,src=$work_dir,dst=/work" \
  --env DISK_BYTES="$disk_bytes" \
  --env SOURCE_DATE_EPOCH="$BOXD_SOURCE_DATE_EPOCH" \
  "$BOXD_NODE_IMAGE" sh -euc '
    test "$(dpkg --print-architecture)" = arm64
    test "$(mke2fs -V 2>&1 | sed -n "1p")" = "mke2fs 1.47.0 (5-Feb-2023)"
    mkdir /tmp/rootfs
    tar --numeric-owner --same-owner -xf /work/rootfs.tar -C /tmp/rootfs
    truncate -s "$DISK_BYTES" /work/stage/rootfs.raw
    E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" mke2fs -q -F -t ext4 \
      -d /tmp/rootfs -L boxd-node -U 00000000-0000-4000-8000-000000000001 \
      -E lazy_itable_init=0,lazy_journal_init=0,hash_seed=00000000-0000-4000-8000-000000000001 \
      /work/stage/rootfs.raw
  '
if [[ $(uname -s) == Darwin ]]; then
  actual_bytes=$(stat -f '%z' "$rootfs")
else
  actual_bytes=$(stat -c '%s' "$rootfs")
fi
[[ $actual_bytes == "$disk_bytes" ]] || {
  printf 'rootfs.raw size mismatch: expected %s, got %s\n' "$disk_bytes" "$actual_bytes" >&2
  exit 70
}

cp -- "$work_dir/node-LICENSE" "$stage/licenses/node-MIT.txt"
cp -- "$BOXD_AGENT_LICENSE_FILE" "$stage/licenses/box-agent-Apache-2.0.txt"
agent_sha256=$(shasum -a 256 "$agent" | awk '{print $1}')
created=$(python3 -c 'import datetime,sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$BOXD_SOURCE_DATE_EPOCH")
namespace="https://boxd.invalid/spdx/node-${node_version}-aarch64-${agent_sha256}"
python3 "$script_dir/generate_sbom.py" \
  --output "$stage/sbom.spdx.json" \
  --namespace "$namespace" \
  --runtime node \
  --node-version "$node_version" \
  --node-image "$BOXD_NODE_IMAGE" \
  --runtime-license MIT \
  --runtime-license-file node-MIT.txt \
  --family debian \
  --arch aarch64 \
  --agent-sha256 "$agent_sha256" \
  --created "$created" \
  --dpkg-status "$work_dir/dpkg-status"

toolchain="rust=$BOXD_RUST_IMAGE;node=$BOXD_NODE_IMAGE;mke2fs=1.47.0;zstd=1.5.7;source_date_epoch=$BOXD_SOURCE_DATE_EPOCH"
python3 "$script_dir/bundle_v1.py" manifest \
  --stage "$stage" \
  --output "$stage/manifest.json" \
  --runtime node \
  --runtime-version "$node_version" \
  --arch aarch64 \
  --kernel-version "$kernel_version" \
  --build-toolchain "$toolchain" \
  --key-id "$BOXD_SIGNING_KEY_ID"
openssl pkeyutl -sign -rawin -inkey "$BOXD_SIGNING_KEY" \
  -in "$stage/manifest.json" -out "$work_dir/manifest.sig.bin"
openssl base64 -A -in "$work_dir/manifest.sig.bin" -out "$stage/manifest.sig"
printf '\n' >>"$stage/manifest.sig"

bundle_path=$output_dir/$bundle_name
python3 "$script_dir/bundle_v1.py" archive \
  --stage "$stage" \
  --output - \
  --epoch "$BOXD_SOURCE_DATE_EPOCH" \
  | zstd --quiet --threads=1 -19 --no-progress -o "$work_dir/$bundle_name"

openssl pkey -in "$BOXD_SIGNING_KEY" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | openssl base64 -A >"$work_dir/trusted-public-key.base64"
printf '\n' >>"$work_dir/trusted-public-key.base64"
(cd -- "$work_dir" && shasum -a 256 "$bundle_name" >"$bundle_name.sha256")
mv -- "$work_dir/$bundle_name" "$bundle_path"
mv -- "$work_dir/$bundle_name.sha256" "$output_dir/$bundle_name.sha256"
mv -- "$work_dir/trusted-public-key.base64" "$output_dir/$BOXD_SIGNING_KEY_ID.public-key.base64"

printf 'bundle=%s\n' "$bundle_path"
printf 'bundle_sha256=%s\n' "$(shasum -a 256 "$bundle_path" | awk '{print $1}')"
printf 'rootfs_sha256=%s\n' "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["rootfs"]["sha256"])' "$stage/manifest.json")"
printf 'rootfs_bytes=%s\n' "$actual_bytes"
