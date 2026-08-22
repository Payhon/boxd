# `@upstash/box@0.6.3` compatibility evidence

This directory pins the executable SDK contract to npm `@upstash/box@0.6.3`
and upstream commit `677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`.
The route/type/stream manifests and public SDK captures are the compatibility
source; no boxd-only transport bypass is allowed.

## Hermetic gates

```bash
npm ci
npm test
npm run check:manifest
npm run check:coverage
npm run check:differential
```

`differential/case-matrix.json` is generated from `route-manifest.json` and
`public-case-registry.mjs`. It must contain exactly 78 server contracts and 82
public SDK cases with no uncovered contract. Regenerate it only after reviewing
the pinned-source or public-case diff:

```bash
npm run generate:differential
```

## Authenticated differential executor

`npm run run:differential` uses the hash-verified vendored SDK to make real
requests to the explicit official and local base URLs. Missing credentials,
base URLs, resource prefixes, runtime or provider requirements is reported as
`status: "blocked"` with `executed_cases: 0`; it is never counted as passed.

Required target isolation:

- `BOXD_DIFF_OFFICIAL_BASE_URL`; the native helper generates a fresh
  `BOXD_DIFF_LOCAL_BASE_URL` loopback origin for each run;
- distinct official and run-local bootstrap credentials; the helper creates
  the local compatibility key from the fresh database;
- distinct safe `BOXD_DIFF_OFFICIAL_PREFIX` and `BOXD_DIFF_LOCAL_PREFIX`.

`read_only` and `sandbox_mutating` cases need no extra opt-in.
`externally_mutating` cases require
`BOXD_DIFF_EXTERNALLY_MUTATING_OPT_IN=1`. `cost_incurring` cases require
`BOXD_DIFF_COST_OPT_IN=1` and a sufficient `BOXD_DIFF_BUDGET_USD`. Cases that
create a Box require `BOXD_DIFF_RUNTIME`; agent/provider cases additionally
require `BOXD_DIFF_PROVIDER_API_KEY`.

Full environment replacement additionally requires
`BOXD_DIFF_DEDICATED_ACCOUNTS_OPT_IN=1`, because the pinned SDK operation
replaces the entire account-level environment. Remote Git cases use target-
specific `BOXD_DIFF_OFFICIAL_GIT_*` and `BOXD_DIFF_LOCAL_GIT_*` variables
(`REPO`, `BRANCH`, `BASE_BRANCH`, `TOKEN`); the unscoped `BOXD_DIFF_GIT_*`
names are only shared fallbacks. Create-PR requires distinct disposable head
branches, and the executor closes each created GitHub PR during cleanup. These
must point at disposable differential fixtures, not a production repository.

Timeout and concurrency bounds are controlled with
`BOXD_DIFF_REQUEST_TIMEOUT_MS`, `BOXD_DIFF_GLOBAL_TIMEOUT_MS`, and
`BOXD_DIFF_CONCURRENCY` (hard-capped at 8).

All 82 public cases now have pinned-SDK adapters. Stateful adapters create their
own Box, tab, recording, schedule, snapshot, file or Git fixture and run cleanup
in `finally`; a cleanup failure fails the whole case. Adapter coverage proves
only that the executor is ready: without distinct official/local credentials,
runtime/provider inputs, explicit mutation/cost opt-ins and sufficient budget,
the authenticated run remains `blocked`. Evidence contains only normalized
response hashes and counts, never response bodies, API keys or resource values.

Response comparison helpers live in `differential/normalizers.mjs`. They
normalize volatile JSON fields, selected response headers, and SSE frames while
preserving status codes, array order, event order, and non-volatile payloads.

The protected native run is manual only:
`.github/workflows/phase4-authenticated-differential.yml` requires the
`phase4-authenticated-differential` environment and a self-hosted Linux runner
labelled `boxd-differential`. `scripts/phase4-differential-native.sh` validates
the runner-owned config, signed runtime, libkrun/libkrunfw files and hashes,
builds the current checkout with `cargo build --release --locked -p boxd`,
validates/imports/runs doctor (`overall=true`), rejects an occupied port, then
starts and traps the job-owned daemon until `/health/ready`. A pre-running
endpoint is not an accepted local target. The workflow runs the complete
matrix, keeps the raw manifest in runner temporary storage until conversion,
and uploads it only after redaction/validation together with the evidence
directory. The converter emits the repository-wide
`boxd-phase4-evidence-v1` schema and refuses symlink/hardlink inputs, unknown
fields, response bodies, secret-like values, forged counts or case IDs,
invalid target origins, non-native pass evidence, and output overwrite. It
hashes the local binary, runtime bundle, and config as evidence inputs. A
missing evidence artifact is an upload error.

For a complete 82-case run the protected environment must provide official/local
base URLs and prefixes, `BOXD_DIFF_RUNTIME`, disposable official/local Git
repositories with distinct head/base branches, `BOXD_DIFF_BUDGET_USD` (at least
`3.85` for the current 77 cost-bearing cases), timeout/concurrency limits, both
API keys, the provider key, and both disposable Git tokens. The workflow sets
`BOXD_DIFF_EXTERNALLY_MUTATING_OPT_IN`, `BOXD_DIFF_COST_OPT_IN`, and
`BOXD_DIFF_DEDICATED_ACCOUNTS_OPT_IN` to `1` only after protected-environment
approval. Git push/create-PR and account-wide environment replacement are never
suitable for production accounts.

The additional protected variables are `BOXD_DIFF_LOCAL_CONFIG` (template),
`BOXD_DIFF_LOCAL_CONFIG_SHA256` (template hash), `BOXD_DIFF_RUNTIME_BUNDLE`,
`BOXD_DIFF_RUNTIME_BUNDLE_SHA256`, `BOXD_DIFF_LIBKRUN_PATH`,
`BOXD_DIFF_LIBKRUN_SHA256`, `BOXD_DIFF_LIBKRUN_LICENSE_PATH`,
`BOXD_DIFF_LIBKRUNFW_PATH`, `BOXD_DIFF_LIBKRUNFW_SHA256`, and
`BOXD_DIFF_LIBKRUNFW_LICENSE_PATH`. The protected secrets
`BOXD_DIFF_MASTER_KEY` and `BOXD_DIFF_ADMIN_PASSWORD` are used by the current
checkout's `boxd init` to create a fresh run-local account and compatibility
key. The key is masked, used only in the current shell, and never enters
evidence; no pre-provisioned local API-key secret is accepted.

Evidence is `blocked` (exit 2) when a gate or external requirement is missing,
`failed` (exit 1) for response/cleanup/evidence failure, and `pass` (exit 0)
only when all 82 cases and cleanup succeed on native virtualization.
