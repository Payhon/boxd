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

- `BOXD_DIFF_OFFICIAL_BASE_URL` and `BOXD_DIFF_LOCAL_BASE_URL`;
- distinct `BOXD_DIFF_OFFICIAL_API_KEY` and `BOXD_DIFF_LOCAL_API_KEY`;
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
