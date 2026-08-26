# boxd

[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-087f73)](https://payhon.github.io/boxd/)
[![License: MIT](https://img.shields.io/badge/License-MIT-46b59f.svg)](LICENSE)

**Website & documentation:** [https://payhon.github.io/boxd/](https://payhon.github.io/boxd/)

## Download preview binaries

Precompiled compatibility-subset previews for macOS Apple Silicon, Linux x86_64,
and Linux aarch64 are published on the
[GitHub Releases page](https://github.com/Payhon/boxd/releases). Each release
contains target-specific archives, `SHA256SUMS`, and GitHub build provenance;
users do not need Rust or a local source build. A separately signed runtime
bundle is still required before a real Box can boot. See the
[binary download guide](https://payhon.github.io/boxd/guide/download) for exact
verification and installation steps.

`boxd` is a local Sandbox-as-a-Service control plane whose compatibility target is
the public API of `@upstash/box@0.6.3` at upstream commit
`677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`.

The project is under active development. Phase 0 contract freezing is complete,
and the Phase 1 control plane has passed a real macOS Apple Silicon HVF smoke with
the pinned public SDK, including daemon-restart recovery. The current-host
macOS Phase 1 acceptance is complete for the documented compatibility subset,
including restricted-default DNS/HTTP(S) egress and explicit `deny-all`.

The blueprint-defined Phase 2 scope is complete. The pinned custom-harness run/SSE/replay/cancel flow, durable
at-least-once webhook runs, Git/Snapshot/Skills, Preview/WebSocket, and Console
management/terminal surfaces are implemented. Managed-agent-only prompt files,
response schemas, and agent options remain explicit HTTP 501 boundaries.

Blueprint Phase 3 is complete. Exec and prompt schedules use durable UTC claims,
encrypted at-least-once webhooks, restart-safe occurrence identities, and Console
management. Browser provisioning now boots real Chromium in the guest and implements
tabs, navigation/content/screenshot, model-backed extract/observe/act/run, single-use
CDP connect, view-only screencast, and recording/HLS/download/retention. API-key and
tenant quotas, durable mutation audit, Prometheus/OTLP observability, and the same
repository/migration suite on SQLite, PostgreSQL, and MySQL have executable evidence.
See [Phase 3 acceptance](docs/phase3-acceptance.md) for the exact current-source
macOS HVF and database-matrix boundary.

Phase 4 is in progress. Custom network policy and HTTPS `attach_headers` are
implemented, and the repository now contains fail-closed gates for the full
authenticated differential, native load/recovery, release integrity, fuzzing,
and security checks. Those gates do not make Phase 4 complete by themselves:
the protected self-hosted KVM/HVF runs, official-service credentials, signed
release artifacts, notarization, and real upgrade/rollback evidence are still
required.

Linux KVM and the ten-runtime target-architecture execution matrix are explicit
follow-up TODOs; they do not invalidate the completed macOS acceptance, but the
project must not be described as a cross-platform release or a fully compatible
implementation until those and later compatibility gates pass. The TODO gates
are executable rather than implicit:
[`scripts/phase1-linux-kvm-smoke.sh`](scripts/phase1-linux-kvm-smoke.sh)
requires a native KVM host, and
[`scripts/phase1-runtime-matrix-smoke.sh`](scripts/phase1-runtime-matrix-smoke.sh)
requires exactly ten signed bundles for the current HVF/KVM architecture.

## Authoritative documents

- [Development blueprint](blueprint/boxd-development-blueprint.md)
- [Architecture](docs/architecture.md)
- [API compatibility](docs/api-compatibility.md)
- [Implementation status](docs/implementation-status.md)
- [Phase 3 implementation plan](docs/phase3-implementation-plan.md)
- [Phase 3 acceptance](docs/phase3-acceptance.md)
- [Local build, run, and sandbox testing manual](docs/manual/boxd-local-sandbox-testing.md)
- [GitHub Actions Linux testing manual](docs/manual/github-actions-linux-testing.md)
- [Phase 4 authenticated differential manual](docs/manual/github-actions-phase4-differential.md)
- [Phase 4 native recovery manual](docs/manual/github-actions-phase4-recovery.md)
- [Phase 4 implementation plan](docs/phase4-implementation-plan.md)
- [Linux validation TODO](docs/linux-validation-todo.md)
- [Architecture decisions](docs/adr/)

## SDK examples

Runnable examples using the published `@upstash/box@0.6.3` package live in
[`examples/`](examples/). They cover lifecycle, Browser, schedules, snapshots,
and ephemeral boxes. The examples require an explicit
`UPSTASH_BOX_BASE_URL` and clean up the boxes they create.

```sh
cd examples
npm ci
export UPSTASH_BOX_BASE_URL=http://127.0.0.1:7331
export UPSTASH_BOX_API_KEY='<one-time compatibility API key>'
npm run lifecycle
```

## GitHub Actions

[`linux-ci.yml`](.github/workflows/linux-ci.yml) runs the full Rust workspace,
the SQLite/PostgreSQL/MySQL repository matrix, pinned SDK contracts, Console,
artifact scripts, and SDK example syntax on GitHub-hosted Ubuntu runners.
[`phase1-linux-kvm.yml`](.github/workflows/phase1-linux-kvm.yml) is a manual,
native KVM gate routed only to a self-hosted Linux runner labeled `boxd-kvm`.
Hosted source tests are not presented as real KVM evidence.
[`release-binaries.yml`](.github/workflows/release-binaries.yml) builds the three
native download archives on protected self-hosted release runners. Both Linux
targets must pass the real KVM lifecycle/restart/egress gate; the macOS target
must pass Developer ID signing and Apple notarization before a tag can become a
GitHub prerelease. Runner assets, signing secrets, and trigger instructions are
documented in the
[release workflow manual](docs/manual/github-actions-release.md).
The Phase 4 manual workflows similarly require protected self-hosted native
runners: `phase4-authenticated-differential.yml` owns a fresh local daemon and
executes all 82 pinned SDK cases; `phase4-load-recovery.yml` runs the 64-Box
load matrix; and `phase4-native-recovery.yml` emits hash-bound recovery
evidence. Until their required environments, assets, and runners are present,
they remain executable gates rather than completed acceptance evidence.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace

npm ci --prefix compat/upstash-box-0.6.3
npm run check:manifest --prefix compat/upstash-box-0.6.3
npm run check:coverage --prefix compat/upstash-box-0.6.3
npm test --prefix compat/upstash-box-0.6.3

npm ci --prefix examples
npm run check --prefix examples

# Run the console gates with Node 22.x active.
node --version
npm --prefix web/console run lint
npm --prefix web/console run typecheck
npm --prefix web/console test -- --run
npm --prefix web/console run build
npm --prefix web/console run test:e2e
```

See [Phase 1 acceptance](docs/phase1-acceptance.md) for the real macOS evidence,
artifact boundary, and the exact Linux KVM gate that is still outstanding.

Any unsupported compatibility endpoint must eventually return HTTP 501 with the
stable error code `feature_not_supported`. Accepting and silently ignoring an
unsupported parameter is forbidden.

## Documentation website

The Rspress website lives in [`docs/`](docs/) and is published to GitHub Pages
from `main` by [the Pages workflow](.github/workflows/docs-pages.yml).

```sh
npm ci --prefix docs
npm run dev --prefix docs
npm run check --prefix docs
```

## License

boxd is available under the permissive [MIT License](LICENSE). Third-party
runtime assets and dependencies retain their own licenses and must ship with
their corresponding license inventory and SBOM.
