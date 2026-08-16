# boxd

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
