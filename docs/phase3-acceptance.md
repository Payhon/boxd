# Phase 3 acceptance record

Status: **blueprint Phase 3 accepted on the current macOS Apple Silicon host;
SQLite, PostgreSQL, and MySQL repository/migration suites accepted**.

This record covers schedules, Browser, recording, quota/audit/observability, and
the three-database gate defined by blueprint Phase 3. It does not claim Linux
KVM, all ten runtime bundles, complete custom network policy, HTTPS
`attach_headers`, full authenticated differential compatibility, or production
release signing/notarization.

## Current-source macOS HVF evidence

The final run used macOS 26.4.1 arm64 with `kern.hv_support=1`, libkrun v1.19.4,
firmware ABI 5, a signed Node 22.18.0/aarch64 20 GiB ext4 Browser runtime, and
the public SDK rebuilt from hash-verified upstream commit
`677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`.

`boxd doctor --json` returned `overall=true`: all 12 required checks passed;
the only warning was the documented SQLite single-active-instance boundary.
The ad-hoc test signature contained the Hypervisor entitlement and passed
`codesign --deep --strict`. This is HVF execution evidence, not Developer ID,
Team-ID, hardened-runtime, notarization, or stapling evidence.

Artifact identities:

| Artifact | Size | SHA-256 |
|---|---:|---|
| current-source entitlement-signed `boxd` | — | `a3c512d935ed773dca4eeec471ab348e2bda9dd51509af79154d9b00d84ae308` |
| signed Node/Browser runtime bundle | 630,948,206 bytes | `b0c7a6cb91d19c84c79caec1a358d4594392213bb2afd99b382e88fa67c4e008` |
| imported `rootfs.raw` | 21,474,836,480 bytes | `473dbb4945aaa11fcf468d4dd147e7d366eeb99c25d4e575b889206b1a051636` |
| signed libkrun v1.19.4 | — | `768d6eb49dffe9457ca86d8aceeda3b3fbd87bc2c3c81c57955a3a9db6e26164` |
| signed libkrunfw ABI 5 | — | `3e52be139692c517c2fbb0aaf1e5dad45bf60238dfbd14375915581a8282c4cb` |

The pinned SDK observed asynchronous creation and completed it in 158,195 ms,
below the 300,000 ms deadline. The real guest then proved:

- opaque tab create/list/goto/content/close and a 9,090-byte PNG screenshot;
- model-backed extract/observe/act/run, exactly one authenticated fixture request
  for each operation;
- single-use CDP access with `Chrome/140.0.7339.16` and an 8,074-byte JPEG
  screencast frame;
- restricted-default egress rejecting metadata navigation with HTTP 403;
- recording requested-stop finalization, two HLS segments, run/tab-switch
  markers, and a 13,357-byte MP4 download with SHA-256
  `db05ed922fc351555bf447fbe97e617d71cb36a0e4e6ed06de4e4da09e84efe6`;
- exec schedule CRUD/pause/resume/delete and one real guest filesystem side
  effect with `total_runs=1`;
- stable quota HTTP 429, tenant-scoped durable mutation audit, and Phase 3
  Prometheus metrics;
- 55 OTLP/HTTP protobuf exports totaling 121,929 bytes, with Browser model
  authorization verified by the local fixture.

The daemon then received a real graceful stop. The guest quiesced and synced its
filesystem before the independently grouped VMM worker exited. Restart used the
same binary, SQLite database, runtime binding, and private disk. Readiness opened
only after reconciliation; the schedule-created file persisted, a new Browser
tab/content/screenshot succeeded, and pinned-SDK bulk delete removed the Box.
No daemon, worker, fixture process, or private Box disk remained afterward.

The run also exercised migration safety for historical data: four active
schedule rows belonging to previously soft-deleted Boxes were purged without
guest execution or tenant run-quota consumption. New Box deletion now removes
all tenant-scoped schedules, with DB and application regression tests.

## Three-database acceptance

The same repository and migration tests are selected by environment URL, not by
dialect-specific business code:

```sh
BOXD_TEST_POSTGRES_URL='postgres://.../boxd_test' \
BOXD_TEST_MYSQL_URL='mysql://.../boxd_test?ssl-mode=DISABLED' \
cargo test -p box-migration optional_postgres_and_mysql_migrations \
  -- --nocapture --test-threads=1

BOXD_TEST_POSTGRES_URL='postgres://.../boxd_test' \
BOXD_TEST_MYSQL_URL='mysql://.../boxd_test?ssl-mode=DISABLED' \
cargo test -p box-db optional_postgres_and_mysql_repository_matrix \
  -- --nocapture --test-threads=1
```

The final gate used dedicated PostgreSQL 18 and MySQL 8.4 containers in addition
to the workspace SQLite suite. Both external URLs were present, both migration
up/down paths ran, and both repository matrices passed. Test containers and
their volumes were removed after the evidence was collected.

## Reproducible source gates

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
# Node 22.x
npm ci --offline
npm run lint
npm run typecheck
npm test -- --run
npm run build
npm run test:e2e
```

The compatibility gate retains 86 raw callsites, 80 normalized operations,
77 direct plus one response-linked contract, 82 public cases, and 159 captures.
The pinned Node contract suite passes 20/20. The final Rust workspace run passes
all crate and documentation tests (including 39 `box-agent`, 33 `box-api`, 15
`box-db`, 28 `box-egress`, 71 `box-service`, and 58 `boxd` unit/integration
tests). With Node 22.19.0, the Console passes lint, typecheck, Vitest 11/11,
production build, and Playwright 1/1.
Unsupported compatibility behavior remains an explicit HTTP 501
`feature_not_supported`; the current admin capability document reports
`phase_3_complete` and keeps later-phase features in `unsupported`.

## Explicit next-phase boundary

Phase 4 still owns complete custom network policy and HTTPS `attach_headers`,
authenticated success differential against the official service, security and
load validation, upgrade/rollback and disaster-recovery drills, and production
release hardening. Linux KVM and the ten-runtime target-architecture matrix also
remain explicit platform validation TODOs. None is inferred from this macOS
Node/Browser acceptance.
