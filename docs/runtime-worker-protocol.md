# Runtime worker protocol

The control plane starts the current executable as `boxd __vmm-worker --spec-fd 0`. Child stdin is the dedicated spec pipe. A u32 big-endian length-prefixed JSON `WorkerSpec` travels only on that pipe, never argv/environment. The wire may contain Box secrets such as guest environment values, so the pipe is a private control channel rather than a secret-free payload. The launcher clears the host worker environment completely, uses the Box work directory, discards stdout, and inherits stderr for worker startup diagnostics. Validated user Box environment variables are guest-only values; they are passed in the explicit envp of the pinned `krun_set_exec` ABI together with mandatory `BOXD_BOOT_NONCE_HEX`, `BOXD_BOX_ID`, `BOXD_AGENT_PROTOCOL_VERSION`, `BOXD_RUNTIME`, and `BOXD_ARCH`. They are never used to impersonate guest state in the host environment, and user input cannot override any `BOXD_` identity variable.

The frame has a 64 KiB maximum and strict unknown-field rejection. The parent has a five-second total write-and-close deadline; failure kills and reaps the child. The worker has a five-second total read deadline, requires EOF immediately after the single complete frame, rejects trailing bytes, and takes ownership of FD 0 (so it is closed on every return path). Tokio creates the pipe descriptors close-on-exec; only the child-side stdin survives into the worker. A short or stalled frame is a protocol failure, never a partially applied configuration.

Version 2 includes a strict UUIDv7 Box ID, expected parent PID, agent protocol v1, supported runtime/architecture, data-root-confined raw read-only base and private writable data disks, vCPU/memory, host-worker limits, console, Unix agent socket, fixed guest vsock port 18080, a 64-character ASCII-hex boot nonce (32 bytes, matching the guest handshake), workdir, a bounded general guest environment, a bounded network mode/resolver list, and the controlled libkrun artifact path plus its exact manifest identity. Guest environment names use `[A-Za-z_][A-Za-z0-9_]*`, are at most 255 bytes, and may not start with reserved `BOXD_`; the map permits at most 128 variables, each value at most 16 KiB, and 48 KiB total `name=value` bytes. Values may be empty but may not contain NUL. Paths are absolute/canonical below the data root and must be valid UTF-8 without interior NUL. Sensitive files are opened component-by-component with `openat`/`O_NOFOLLOW`, must be regular files with one link, and base/writable disks must have different device/inode identities. Linux loads libkrun from an immediately unlinked, checksum-pinned `/dev/fd/N` snapshot. macOS system policy rejects signed dylibs from such unlinked paths, so it instead retains linked copies in an unpredictable mode-0700, worker-owned private directory; both copies are owner/mode/link-count checked, hashed, validated with `codesign --verify --strict`, re-hashed immediately before `dlopen`, and removed by dirfd only after the dynamic libraries drop. Both disks are passed through pinned descriptors retained across `krun_start_enter`. Source-path symlink, rename, modification, and hardlink swaps therefore fail verification or cannot change the opened object.

`host_worker_max_open_files` and `host_worker_max_processes` are enforced before libkrun load as `RLIMIT_NOFILE` and `RLIMIT_NPROC`. The latter is a host per-real-UID limit on Linux/macOS, not a guest PID quota; on macOS it can affect/saturate against other processes for the same account. Linux additionally enables `PR_SET_NO_NEW_PRIVS`; after consuming FD 0, the worker closes all descriptors above stderr.

On Linux, the service must run in a cgroup v2 delegation whose `cgroup.subtree_control` already contains `cpu`, `memory`, and `pids`. The worker creates `boxd/<UUIDv7>`, writes `memory.max`, `pids.max`, and `cpu.max`, and only then writes its PID to `cgroup.procs`. `memory.max` is guest RAM plus a fixed 256 MiB VMM allowance; `cpu.max` is one full CPU-period quota per configured vCPU; `pids.max` bounds host worker tasks/threads and must not be described as a guest process limit. The supervisor removes the empty leaf only after its owned child handle reports exit. Doctor proves delegation by creating an empty transient leaf and writing all three controller files without moving the doctor process.

Linux seccomp policy v1 is installed with TSYNC after the pinned library has loaded and the libkrun context is fully configured, but before the network backend is armed or `krun_start_enter` is called. It returns `EPERM` for post-configuration exec, ptrace, cross-process memory, namespaces, mounts and filesystem-handle mount APIs, swap/reboot, BPF, userfaultfd, perf events, keyrings, kernel modules, and kexec. It deliberately does not claim to be a speculative syscall allowlist: libkrun's KVM/vCPU threads retain the ordinary syscall surface they need. `PR_SET_NO_NEW_PRIVS` is a required precondition, and TSYNC covers the existing parent watchdog plus all subsequently created threads. Doctor forks an isolated child, installs the real filter, and verifies that a representative ptrace call is denied with `EPERM`; failure is required-fail. macOS reports cgroup and seccomp checks as not applicable. The policy and all Linux-only tests pass on a Linux 6.10 arm64 kernel, which proves enforcement but not KVM VM operation.

Phase 1 wire specs accept `network_mode = "deny-all"` or `"restricted-default"`. Both configure the pinned `krun_add_net_unixstream` ABI before VM entry so v1.19.4 never auto-enables INET TSI. Deny-all reads and discards framed Ethernet. Restricted-default starts the bounded in-process proxy, waits for readiness, serves fixed DHCP, proxies only validated DNS A, answers AAAA with NODATA, and terminates guest TCP while opening numeric host connections only to public IPv4 port 80/443. Metadata, loopback, link-local, private/special ranges, other TCP ports, arbitrary UDP, ICMP and IPv6 fail closed. The source-inspected net worker takes ownership with `OwnedFd::from_raw_fd`; Rust therefore holds both endpoints through configuration and transfers the guest endpoint only immediately before `krun_start_enter`. Missing symbols, invalid resolvers, proxy startup, framing, capacity or I/O failures close the endpoint rather than falling back to TSI.

The supervisor identifies a launch by PID, parent-owned `tokio::process::Child`, start time, and a monotonic per-control-plane launch marker. `inspect`, including exited state, returns that strong identity instead of treating a bare PID as proof. Watcher generation comparison and state commit occur while the process-generation guard is held, so an old watcher cannot overwrite a replacement launch. A watcher polls and reaps the owned handle, then records the exit automatically. Graceful shutdown sends TERM while holding the verified child handle, waits the requested grace period, escalates to KILL, and waits for reaping. Failed spawn also requires confirmed reaping. Cleanup is idempotent and removes the retained process record only after exit. The launcher writes the expected parent PID into the wire; the worker verifies it, Linux uses `PR_SET_PDEATHSIG`, and all Unix workers retain a parent watchdog so a control-plane crash kills rather than orphans the VMM worker.

ABI evidence: libkrun `v1.19.4` (`728df8125077d0db44265f6e997c72b81b65c015`), header SHA-256 `0ce40e378736b6ac409aa7f7db37f9ecc02069cff0d83b2148423dacb970ae96`. The wire carries exact paths and SHA-256 identities for both libkrun and firmware ABI 5 (`libkrunfw.5.dylib` on macOS or `libkrunfw.so.5` on Linux). Stage one opens both paths component-by-component without symlinks/hardlinks, copies and hashes them into a private directory using only the exact fixed filenames, then re-execs the same worker before Tokio starts with a cleared environment and the private loader directory as its sole loader path. Stage two re-reads the pipe and revalidates both private copies. Linux loads libkrun from a checksum-pinned fixed-FD snapshot and unlinks private names after `krun_create_ctx` initializes the firmware `LazyLock`; macOS keeps its signed linked names until the loaded libraries/context are dropped. Missing or mismatched firmware fails closed and no host-global firmware installation is accepted. The wire-writer PID is recorded explicitly and reaped by identity, not `waitpid(-1)`.

Readiness uses the platform-specific pinned loading policy above, separately loads and validates the checksum-pinned firmware ABI symbol, requires the complete worker ABI, calls `krun_has_feature` for BLK/NET, and requires vsock; a hash-only check is not readiness. The immutable base is attached read-only first as `/dev/vda`. The Box-private writable clone is attached second as `/dev/vdb` and selected as the ext4 root with `krun_set_root_disk_remount(ctx, "/dev/vdb", "ext4", NULL)`. The worker then calls `krun_set_exec` for `/usr/local/bin/box-agent` with explicit NUL-terminated argv and the complete controlled guest environment; neither argv nor envp is NULL, so v1.19.4 cannot inherit the host environment. `krun_start_enter` runs only in the worker and consumes its context. An absent, mismatched, unsigned, or unloadable libkrun/firmware artifact is a real worker failure; tests never substitute a fake VM.

Worker exit codes are stable at the executable boundary: malformed hidden-command usage exits 64, while spec, identity, dynamic-loader, configuration, and VMM startup failures exit 70. `krun_start_enter` normally terminates the worker itself; if it returns a negative libkrun code, the worker exits 70. Hermetic process tests cover pipe secrecy, automatic exit observation, TERM-to-KILL escalation/reaping, and malformed input. Matching HVF/KVM smoke must still be explicitly run on a provisioned host.

## Linux KVM acceptance gate

Linux is not accepted by unit tests, Docker Desktop, or a successful compile. The
runner must be a native x86_64 or aarch64 Linux host with writable `/dev/kvm`, a
delegated cgroup v2 subtree containing `cpu`, `memory`, and `pids`, and the
versioned seccomp policy for this exact worker/libkrun ABI. Doctor must report
`worker_seccomp_enforcement` as required-pass before VM entry.

After the policy lands, the platform smoke uses release assets and the same
signed runtime-bundle and pinned-SDK scripts used by the macOS acceptance run:

```sh
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64 -o "$(uname -m)" = aarch64
test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm
test -f /sys/fs/cgroup/cgroup.controllers
rg -q '(^| )cpu( |$)' /sys/fs/cgroup/cgroup.controllers
rg -q '(^| )memory( |$)' /sys/fs/cgroup/cgroup.controllers
rg -q '(^| )pids( |$)' /sys/fs/cgroup/cgroup.controllers

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

# Build with the release pipeline's pinned libkrun/libkrunfw assets and hashes.
BOXD_EMBEDDED_LIBKRUN_PATH="$LIBKRUN_ARTIFACT" \
BOXD_EMBEDDED_LIBKRUN_SHA256="$LIBKRUN_SHA256" \
BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH="$LIBKRUN_LICENSE" \
BOXD_EMBEDDED_LIBKRUNFW_PATH="$LIBKRUNFW_ARTIFACT" \
BOXD_EMBEDDED_LIBKRUNFW_SHA256="$LIBKRUNFW_SHA256" \
BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH="$LIBKRUNFW_LICENSE" \
  cargo build --release -p boxd

target/release/boxd doctor --json -c "$BOXD_SMOKE_CONFIG"

# Build the hash-verified SDK snapshot. The JSON contains a runner-owned
# cleanup token; validate it and remove the exact temp directory after smoke.
npm --prefix compat/upstash-box-0.6.3 ci
SDK_BUILD_JSON="$(mktemp)"
node compat/upstash-box-0.6.3/scripts/build-pinned-sdk.mjs --json >"$SDK_BUILD_JSON"
SDK_ENTRY="$(jq -r '.entry | sub("^file://"; "")' "$SDK_BUILD_JSON")"

# Start boxd with secrets supplied through env names, then run lifecycle mode.
SMOKE_EVIDENCE_DIR="$(mktemp -d)"
LIFECYCLE_EVIDENCE="$SMOKE_EVIDENCE_DIR/phase1-lifecycle.json"
node scripts/phase1-sdk-smoke.mjs lifecycle "$SDK_ENTRY" "$LIFECYCLE_EVIDENCE"

# Fully stop boxd and every worker; restart against the same SQLite/data dir,
# wait for readiness, then prove persisted-file and post-reconcile exec.
BOXD_SMOKE_LIFECYCLE_EVIDENCE="$LIFECYCLE_EVIDENCE" \
  node scripts/phase1-sdk-smoke.mjs restart "$SDK_ENTRY" \
    "$SMOKE_EVIDENCE_DIR/phase1-restart.json"

# Delete only the accepted Box, then validate the builder's cleanup capability
# before deleting its exact throw-away tree.
BOX_ID="$(jq -r .box_id "$LIFECYCLE_EVIDENCE")"
curl --fail --silent --show-error -X DELETE \
  -H "X-Box-Api-Key: $UPSTASH_BOX_API_KEY" \
  "$UPSTASH_BOX_BASE_URL/v2/box/$BOX_ID"
SDK_DIR="$(jq -r .dir "$SDK_BUILD_JSON")"
test "$SDK_DIR" = "$(jq -r .cleanup.dir "$SDK_BUILD_JSON")"
test "$(printf %s "$SDK_DIR" | sha256sum | cut -d' ' -f1)" = \
  "$(jq -r .cleanup.token "$SDK_BUILD_JSON")"
case "$SDK_DIR" in /tmp/boxd-pinned-sdk-*|/var/*/T/boxd-pinned-sdk-*) ;; *) exit 1;; esac
find "$SDK_DIR" -depth -delete
```

Secret values are supplied only through the configured environment-variable
names and must never appear in shell history, JSON evidence, logs, or Git.
The script never serializes either credential. The caller owns deletion of the
Box, evidence, SDK build directory, config, database, runtime data and keys.
