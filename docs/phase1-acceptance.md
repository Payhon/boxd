# Phase 1 acceptance record

Status: **current-host macOS Phase 1 lifecycle and restricted-default network
baseline accepted; Linux KVM and cross-runtime validation tracked as TODO**.

This record separates hermetic/unit evidence from real VM evidence. It does not
claim Linux KVM, all ten runtime bundles, release signing/notarization, custom
network policy, or full SDK compatibility.

## Final-source macOS HVF run

The run used macOS 26.4.1 on arm64 with `kern.hv_support=1`, an ad-hoc signed
`boxd` carrying the Hypervisor entitlement, signed libkrun v1.19.4/firmware ABI
5, a signed Node 22.16.0 Debian arm64 ext4 runtime, and the public SDK built
from pinned upstream commit
`677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`.

The repository has no Git commit yet. The artifact is therefore bound to the
frozen working-tree inputs by the source and binary hashes in
[final artifact evidence](phase1-evidence/final-artifact.json), rather than by
an invented `HEAD`.

Verified results:

- The production importer verified and atomically installed the signed 20 GiB
  bundle. The imported copy was deleted after verification and the bundle was
  retained.
- `boxd doctor --json` returned `overall=true`; every required check passed.
  The only warning was the documented SQLite single-active-instance boundary;
  Linux cgroup/seccomp checks were not applicable on macOS.
- The public SDK observed the asynchronous `creating` response and 133 polls.
  Main-Box create completed in 266,292 ms, below its 300,000 ms deadline.
- A 2,017 ms command, TypeScript execution, init command, file write/read/list,
  mtime, pause/resume, and post-resume execution all succeeded.
- A deterministic 5,242,897-byte upload and download matched SHA-256
  `d97ad7b4df620ac2f558898cac08bab937b11379eb177b0a3afa05d8a747acfb`.
- Guest `df` reported 20,957,446,144 bytes for the configured 20 GiB private
  filesystem.
- Nested tree download returned the documented HTTP 501
  `feature_not_supported`; flat/direct-folder download remained successful.
- The daemon was fully stopped and restarted with the same SQLite/data
  directory. Readiness opened after reconciliation; the persisted file and a
  post-restart exec succeeded.
- Public SDK bulk delete removed both retained Boxes. All workers and the
  daemon exited after the run.
- Credential-bearing config, bootstrap data, SQLite/data directories, private
  signing key, VM disks, and importer copies were deleted. Only redacted
  evidence, the public key, and the signed bundle were retained. The raw versus
  redacted hash boundary is documented in the
  [evidence manifest](phase1-evidence/README.md).

Artifact identities:

| Artifact | Size | SHA-256 |
|---|---:|---|
| signed runtime bundle | 53,917,206 bytes | `b1957bb7a26b5d12c77423e440c3577d48626be13fff1d43311702a4da835303` |
| runtime `rootfs.raw` | 21,474,836,480 bytes | `9f4bf99b7b69ea5565a1c73f90c7680e40aa5375dec5fe7639da0f4e949bacc2` |
| guest `box-agent` | 3,708,432 bytes | `784ff7f5b5ecf5aad86ce4fb5fd179cb79d20dfbe13d41141e3c43037a95d07c` |
| deny-all smoke `boxd` | — | `416cc5868bdb0023670a53954f12c5efe963087bf079bdea1122b970a5f72580` |
| restricted-default smoke `boxd` | — | `67e7ea0a58c740fcae76fdf368f75c9aa40441f21f618d0e405a85c6baacba2c` |
| signed libkrun v1.19.4 | — | `768d6eb49dffe9457ca86d8aceeda3b3fbd87bc2c3c81c57955a3a9db6e26164` |
| signed libkrunfw ABI 5 | — | `3e52be139692c517c2fbb0aaf1e5dad45bf60238dfbd14375915581a8282c4cb` |

The local binaries were ad-hoc signed for HVF testing. An initial hardened-
runtime signing attempt correctly failed library validation because the local
ad-hoc process and dylibs had no matching Team ID; the successful smoke used an
ad-hoc entitlement signature without hardened runtime. This proves the pinned
loader, BLK/NET/vsock, and HVF paths only. It is not Developer ID, Team-ID,
hardened-runtime, notarization, or stapling evidence.

The normal smoke configuration kept `minimum_free_gib=10` and passed doctor.
Retaining two simultaneous 20 GiB Boxes for the bulk-delete test exceeded the
temporary machine's available-space equation and was correctly rejected with
422. The final two-Box smoke used `minimum_free_gib=1`, re-ran doctor
successfully, and did not modify repository defaults or product code. The 422
failure is retained as capacity-admission evidence.

## Reproducible local gates

```sh
cargo fmt --all -- --check
CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
CARGO_INCREMENTAL=0 cargo test --workspace --all-features --offline

cd compat/upstash-box-0.6.3
npm ci --offline
npm run check:manifest
npm run check:coverage
npm test

cd ../../web/console
# Activate Node 22.x before these commands.
npm ci --offline
npm run lint
npm run typecheck
npm test -- --run
npm run build
```

Latest results: workspace fmt/clippy/tests pass; compat reports 86 raw
callsites, 80 normalized operations, 77 direct plus one response-linked
contract, 82 public cases, and 159 captures; compat tests pass 17/17. Console
Node 22.19.0 lint/typecheck/tests 6/6/build pass. The console build reports
non-fatal Ant Design circular chunk warnings; npm audit reports zero known
vulnerabilities. Runtime artifact Bash syntax/ShellCheck, workflow YAML parse,
metadata-tool tests, and matrix-input regression tests also pass. The matrix
tests cover canonical in-image license paths, complete SemVer, symlink output
rejection, CLI validation, and exclusive no-overwrite manifest publication.

## Accepted restricted default egress

The pinned SDK treats omitted `networkPolicy` as `allow-all`; Phase 1 narrows
that wire spelling to DNS plus public IPv4 HTTP(S). The current-source macOS
HVF run proved public A DNS, HTTP/80 and HTTPS/443 success while metadata,
loopback, RFC1918 and non-web TCP ports were blocked. Explicit `deny-all`
blocked public HTTPS. After a full daemon stop/restart, readiness opened only
after both Boxes reconciled, both policies remained unchanged, all assertions
passed again, and pinned-SDK bulk delete succeeded.

The first real run exposed an AAAA timeout: A resolution succeeded, but the
proxy dropped a valid AAAA response and Node waited until fetch timed out. The
fixed data plane returns immediate transaction-bound AAAA/NODATA; 28 egress
tests and the repeated HVF lifecycle/restart run passed. Evidence is stored in
`phase1-evidence/egress-lifecycle.json` and `egress-restart.json`.

Complete/custom domain-CIDR-port policy and HTTPS `attach_headers` remain
Phase 4 work; they are not conflated with this accepted Phase 1 baseline.

## Follow-up TODOs outside the current macOS acceptance

### Linux KVM and runtime matrix

Linux seccomp policy v1 has a real Linux/arm64 kernel enforcement probe, but
Docker Desktop does not expose `/dev/kvm`. Linux release validation remains a
documented TODO: run the same SDK lifecycle and daemon-restart smoke on native
Linux x86_64 and aarch64 KVM hosts. Its absence does not invalidate the current
macOS acceptance, and no Linux execution claim is made before it passes.

The repository now provides the executable gate
[`scripts/phase1-linux-kvm-smoke.sh`](../scripts/phase1-linux-kvm-smoke.sh) and
the manual self-hosted workflow
[`phase1-linux-kvm.yml`](../.github/workflows/phase1-linux-kvm.yml). The runner
fails before building unless `/dev/kvm`, cgroup v2 CPU/memory/PID controllers,
the pinned libkrun artifacts, and a dedicated test configuration are present.
It runs the platform lifecycle/restart pair first and deletes those Boxes before
running the restricted-egress lifecycle/restart pair, so disk admission is not
accidentally tested as KVM failure. Evidence and build output are kept in
separate directories, and the hash-verified pinned SDK temp tree is removed on
both success and failure. This is a reproducible pending gate, not Linux KVM
execution evidence.

Every build/import/doctor/SDK phase is wrapped by the repository-owned process-
group timeout runner, so a timed-out command receives TERM, then KILL, without
leaving descendants on a persistent self-hosted runner. The final Linux summary
records whether source gates ran, the kernel/libkrun/firmware identities, the
pinned SDK commit, and SHA-256 for doctor plus all four lifecycle/restart
evidence files. Hermetic tests exercise timeout cleanup and fail-closed runner
preflight; they do not substitute for `/dev/kvm` execution.

The final HVF run proves the Node 22.16.0/aarch64 bundle only. The other nine
runtime names and the target-architecture matrix have static/import paths but
no equivalent real execution evidence yet.

The generic publisher and serial build orchestrator are now present. They
deliberately have no default release versions: the remaining matrix requires a
reviewed external pin document containing each runtime version, immutable
runtime OCI digest, matching GNU or musl Rust 1.94 builder digest, source user,
an in-image runtime license evidence path, and architecture. The current
repository contains only the already accepted Node/aarch64 artifact and cannot
safely invent the other release inputs.

[`scripts/phase1-runtime-matrix-smoke.sh`](../scripts/phase1-runtime-matrix-smoke.sh)
is the pending real-platform gate for that evidence. It requires an input
manifest containing exactly the ten signed bundles for the current host
architecture and a hash-pinned, already entitled/signed `boxd`. For each
runtime it imports the bundle, creates one deny-all Box through the pinned SDK,
runs the language-specific executable, performs a file roundtrip and
pause/resume, fully stops the daemon, reconciles after restart, repeats the
language/file checks, and deletes the Box before advancing. The final summary
binds each result to the bundle SHA-256, binary SHA-256, host, and pinned SDK
commit. No ten-runtime input manifest is available in the current workspace,
so the matrix remains explicitly unexecuted.

The matrix runner uses the same bounded process-group execution, rejects
unknown manifest fields and control characters in artifact paths, and binds its
summary to both the doctor evidence and exact matrix-input SHA-256.

The executable follow-up checklist is maintained in
[Linux validation TODO](linux-validation-todo.md).

## Pinned SDK file-download boundary

`@upstash/box@0.6.3` creates only the top-level local destination directory,
skips directory entries, and does not create parents for relative file names.
boxd therefore supports flat/direct-folder download and fails an encountered
nested tree before returning the list, with HTTP 501
`feature_not_supported`. Contract tests compile the hash-verified pinned source,
reproduce its original `ENOENT`, and prove both the explicit 501 and flat-file
success. See [known limitations](../compat/upstash-box-0.6.3/KNOWN-LIMITATIONS.md).
