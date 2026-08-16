# Runtime artifact build and Phase 1 smoke

## Reproducible Node 22 arm64 bundle

`scripts/runtime/build-node22-arm64-bundle.sh` builds the current workspace's
`box-agent` as a Linux arm64 ELF, exports a digest-pinned official Node 22
Debian Bookworm root filesystem, installs the agent and creates `boxuser`,
`/home/boxuser`, `/workspace`, and `/workspace/home`. It then creates an ext4
`rootfs.raw` whose **raw byte length is exactly** `BOXD_DEFAULT_DISK_GIB` GiB.
It does not use `truncate` as a substitute for growing an existing filesystem:
`mke2fs` creates the final-sized filesystem directly.

Both OCI inputs must contain an explicit version tag and immutable digest. The
following pins identify the arm64 images recorded by Docker Hub; re-resolve and
review them deliberately before changing either value:

```sh
export BOXD_NODE_IMAGE='node:22.16.0-bookworm-slim@sha256:6b84a3d695387c70b7d5f45224899d5bf5bf96c4345bed678f07822927c850a0'
export BOXD_RUST_IMAGE='arm64v8/rust:1.94.0-bullseye@sha256:7fbe0a2b512eb22093007c61965f455510846a6f0b0a352f11b0c2c83c6a1b56'
```

Pin review sources: [Node 22.16.0 Bookworm slim arm64 manifest](https://hub.docker.com/layers/library/node/22.16.0-bookworm-slim/images/sha256-6b84a3d695387c70b7d5f45224899d5bf5bf96c4345bed678f07822927c850a0)
and [Rust 1.94.0 Bullseye arm64 manifest](https://hub.docker.com/layers/arm64v8/rust/1.94.0-bullseye/images/sha256-7fbe0a2b512eb22093007c61965f455510846a6f0b0a352f11b0c2c83c6a1b56).
The environment values above pin the reviewed `linux/arm64` child manifests,
not only a mutable tag or multi-platform index.

The build requires Docker with `linux/arm64` support, Python 3, OpenSSL 3,
zstd `1.5.7`, `shasum`, and `file`. The digest-pinned Node image itself contains
e2fsprogs `1.47.0`; a network-disabled, read-only container extracts the
normalized OCI tar as root so UID/GID remain intact, then creates the final
ext4 from that directory. Filesystem UUID, directory hash seed, timestamps,
lazy initialization, locale, and timezone are fixed. No host `mke2fs`, mount,
or privileged container is needed. `Cargo.lock` is used with `cargo build
--locked`. The repository currently declares
Apache-2.0 but does not contain a top-level license text, so the exact reviewed
license file must be provided explicitly.

Generate or retrieve the release signing key outside the source tree. The
script rejects symlinks, keys inside the repository, and keys accessible to
group/other users. It never mounts the key into a container, copies it to the
artifact staging tree, or prints private key material.

```sh
key_dir=$(mktemp -d)
chmod 700 "$key_dir"
openssl genpkey -algorithm Ed25519 -out "$key_dir/runtime-signing.pem"
chmod 600 "$key_dir/runtime-signing.pem"

export BOXD_SIGNING_KEY="$key_dir/runtime-signing.pem"
export BOXD_SIGNING_KEY_ID='phase1-release-2026'
export BOXD_AGENT_LICENSE_FILE='/absolute/reviewed/path/LICENSE-APACHE-2.0'
export BOXD_SOURCE_DATE_EPOCH='1786492800'
export BOXD_NODE_VERSION='22.16.0'
export BOXD_DEFAULT_DISK_GIB='20'
export BOXD_KERNEL_VERSION='6.1.0'
export BOXD_DOCKER_PULL_TIMEOUT_SECONDS='300'
export BOXD_CARGO_REGISTRY_DIR="$HOME/.cargo/registry"
export BOXD_OUTPUT_DIR="$PWD/dist/runtime"

scripts/runtime/build-node22-arm64-bundle.sh
```

The output contains:

```text
box-runtime-node-aarch64-22.16.0.tar.zst
box-runtime-node-aarch64-22.16.0.tar.zst.sha256
phase1-release-2026.public-key.base64
```

The bundle contains only regular `manifest.json`, `manifest.sig`,
`rootfs.raw`, `sbom.spdx.json`, and `licenses/...` entries. The manifest is
stable compact JSON; its exact bytes are signed with Ed25519. The SPDX 2.3
document records the two pinned OCI/toolchain inputs and the agent SHA-256.
Temporary directories and the Docker container are removed by the exit trap.
Existing output bundles are never overwritten.
The final tar is streamed directly into single-threaded zstd, so the build does
not create a second uncompressed `default_disk_gib`-sized tar beside
`rootfs.raw`.

The Rust container runs `cargo build --locked --offline`. It receives the
caller-selected host Cargo registry cache as a read-only bind, copies it into
the private build directory, and performs no crate download. The default is
`~/.cargo/registry`; populate and review that cache before the release build.
Docker image pulls are separately bounded by
`BOXD_DOCKER_PULL_TIMEOUT_SECONDS`.

The SPDX 2.3 SBOM includes Node, the current `box-agent`, and every installed
Debian package parsed from the pinned image's dpkg status database. The license
tree includes Node's MIT file, the externally reviewed agent Apache-2.0 text,
and a deterministic `debian-copyrights.tar` containing every pinned Debian
image `/usr/share/doc/*/copyright` file. Its adjacent canonical JSON index
records each safe relative path, SHA-256, byte length, mode, UID/GID, and mtime;
both archive and index are hashed in the signed manifest.
The aggregation keeps the outer bundle below the production importer's strict
entry-count limit without dropping license text.

To configure trust, copy only the emitted raw public key value into
`runtime.trusted_signing_keys.<key-id>`. Never place the private key in the
configuration, data directory, artifact directory, repository, or command
arguments.

After publishing or importing the artifact, securely dispose of any ephemeral
test signing key and its private temporary directory. The build script never
deletes a caller-owned key.

## Static gates

```sh
bash -n scripts/runtime/build-node22-arm64-bundle.sh
shellcheck scripts/runtime/build-node22-arm64-bundle.sh scripts/runtime/build-runtime-bundle.sh
python3 -c 'import ast,pathlib; [ast.parse(pathlib.Path(p).read_text()) for p in ("scripts/runtime/prepare_rootfs_tar.py","scripts/runtime/generate_sbom.py","scripts/runtime/bundle_v1.py")]'
python3 scripts/runtime/test_metadata_tools.py
python3 scripts/runtime/test_build_runtime_matrix.py
node --check scripts/phase1-sdk-smoke.mjs
```

`shellcheck` is a required release gate even when it is not installed on a
developer workstation; absence must be reported, not treated as a pass.

The metadata helpers are runtime-neutral: manifests take explicit runtime and
architecture values; the rootfs normalizer supports Debian `dpkg` and Alpine
`apk` package/license layouts; the SPDX generator records the selected runtime,
base family, target architecture, and package manager. The hermetic
`test_metadata_tools.py` fixture exercises an Alpine Python-shaped rootfs with
no pre-existing uid 1000 user and proves that the normalized image, SPDX data,
and signed manifest inputs remain coherent. This prepares the shared publisher
boundary; it is not evidence that the nine remaining release bundles exist.

`scripts/runtime/build-runtime-bundle.sh` is the generic publisher entrypoint.
It accepts only one of the ten frozen runtime names, complete SemVer, a target
architecture, immutable runtime/Rust OCI digests, external Ed25519 key, a
canonical relative license path inside the pinned runtime OCI image, and a
reproducible build epoch. Debian builds compile a GNU
`box-agent`; Alpine builds require a matching Rust-musl builder and compile a
musl agent. The resulting agent is executed inside the selected runtime image
before packaging so a loader/architecture mismatch fails before signing. The
publisher never installs packages into an image, discovers a mutable tag, or
generates a key. Shared public-key output may be reused only when its bytes
match the external signing key.

`scripts/runtime/build_runtime_matrix.py` is the serial orchestration layer. It
accepts a strict external `boxd-runtime-matrix-build-input-v1` JSON containing
exactly all ten runtime pins, target architecture, reproducible epoch, disk
capacity, kernel version, immutable runtime/Rust OCI digests, source user and
an in-image license evidence path. It has no default versions and rejects
unknown fields, missing runtimes, mutable tags, absolute paths and traversal.
Only after
all ten publisher invocations succeed does it atomically emit the
`boxd-phase1-runtime-matrix-input-v1` manifest consumed by the real VM matrix
gate. Run `python3 scripts/runtime/build_runtime_matrix.py --help` for the
interface; use `--validate-only` to review a release-pin document without
pulling or building anything.

## Public SDK smoke

Use the executable SDK entry built from the pinned `@upstash/box@0.6.3`
contract. The lifecycle mode verifies the visible asynchronous `creating` plus
poll sequence, a command lasting over one second, TypeScript execution, file
mtime across pause/resume, a deterministic binary upload/download larger than
4 MiB, and root filesystem capacity. It also verifies the pinned SDK's
client-side rejection of `initCommand` with `keepAlive=false`, creates a
separate `keepAlive=true` Box whose init command writes a verified file and is
then deleted, and creates a second ordinary Box for the later bulk-delete
check. Flat/direct-folder download must succeed. Because the pinned SDK does not
create local parents for nested entries, the smoke also requires nested-tree
download to fail before partial transfer with HTTP 501
`feature_not_supported`.

```sh
export UPSTASH_BOX_API_KEY='...'
export UPSTASH_BOX_BASE_URL='http://127.0.0.1:7331'
export BOXD_SMOKE_EXPECTED_DISK_BYTES="$((20 * 1024 * 1024 * 1024))"
node scripts/phase1-sdk-smoke.mjs lifecycle /absolute/sdk-entry.js /tmp/lifecycle.json
```

Fully stop and restart `boxd`, wait for readiness, then run restart mode. It
proves disk/agent reconciliation, executes another command, and bulk-deletes
both retained smoke Boxes.

```sh
export BOXD_SMOKE_LIFECYCLE_EVIDENCE=/tmp/lifecycle.json
node scripts/phase1-sdk-smoke.mjs restart /absolute/sdk-entry.js /tmp/restart.json
```

The script never prints the API key or response headers. Evidence files use
exclusive creation and mode `0600`. Lifecycle failure attempts best-effort
bulk cleanup; a successful lifecycle intentionally retains its two Boxes until
restart mode so daemon restart can be tested.

## Cross-platform runtime matrix gate

The Node artifact above is one concrete bundle, not evidence for the other nine
accepted runtime names. After producing and independently reviewing all ten
signed bundles for one target architecture, create an input manifest outside
the repository:

```json
{
  "schema": "boxd-phase1-runtime-matrix-input-v1",
  "arch": "aarch64",
  "bundles": {
    "node": "/absolute/box-runtime-node-aarch64-22.16.0.tar.zst",
    "python": "/absolute/box-runtime-python-aarch64-3.13.0.tar.zst",
    "golang": "/absolute/box-runtime-golang-aarch64-1.24.0.tar.zst",
    "ruby": "/absolute/box-runtime-ruby-aarch64-3.4.0.tar.zst",
    "rust": "/absolute/box-runtime-rust-aarch64-1.94.0.tar.zst",
    "node-alpine": "/absolute/box-runtime-node-alpine-aarch64-22.16.0.tar.zst",
    "python-alpine": "/absolute/box-runtime-python-alpine-aarch64-3.13.0.tar.zst",
    "golang-alpine": "/absolute/box-runtime-golang-alpine-aarch64-1.24.0.tar.zst",
    "ruby-alpine": "/absolute/box-runtime-ruby-alpine-aarch64-3.4.0.tar.zst",
    "rust-alpine": "/absolute/box-runtime-rust-alpine-aarch64-1.94.0.tar.zst"
  }
}
```

The example versions are placeholders, not approved release pins. Every path
must be replaced with a reviewed, immutable artifact for the host architecture.
Run `scripts/phase1-runtime-matrix-smoke.sh --help` for required hashes,
credentials, config, and evidence paths. The gate imports and executes each
bundle serially through the hash-verified pinned SDK, performs a full daemon
restart/reconciliation, and records bundle hashes. A manifest or a successful
import alone is never reported as execution evidence. Imports, doctor probes
and SDK phases have explicit hard timeouts enforced against an owned process
group; timeout cleanup is covered by `scripts/test_run_bounded.py`, and
manifest/URL fail-closed preflight is covered by
`scripts/test_phase1_runner_preflight.py`.

For native Linux, `scripts/phase1-linux-kvm-smoke.sh --help` is the preceding
Node lifecycle/egress platform gate. The manual self-hosted workflow is
`.github/workflows/phase1-linux-kvm.yml`; Docker Desktop without `/dev/kvm` is
rejected before compilation.
