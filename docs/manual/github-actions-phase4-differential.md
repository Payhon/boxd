# Phase 4 authenticated differential

`.github/workflows/phase4-authenticated-differential.yml` is a protected,
manual-only workflow. It is the only supported entry point for the full
78-contract/82-case official-vs-local differential gate.

## Runner and protection

Configure a dedicated self-hosted Linux runner with labels:

```text
self-hosted, linux, boxd-differential, x64
```

or `ARM64` for an aarch64 runner. The runner account must be able to open
`/dev/kvm` read/write and expose cgroup v2. Do not use a production host,
production database, production API key, or a shared Git fixture.

Create a GitHub protected environment named
`phase4-authenticated-differential`. Put the differential secrets and variables
in that environment, require a reviewer, and trigger only with
`workflow_dispatch`. The workflow has `contents: read` only and does not run on
pull requests or forks.

## Required environment inputs

Variables:

| Name | Meaning |
| --- | --- |
| `BOXD_DIFF_OFFICIAL_BASE_URL` | approved official service URL |
| generated `BOXD_DIFF_LOCAL_BASE_URL` | helper chooses a fresh loopback port and exports the job-owned origin |
| `BOXD_DIFF_LOCAL_CONFIG` / `BOXD_DIFF_LOCAL_CONFIG_SHA256` | runner-owned config template and exact template SHA-256; helper generates the run-local config |
| `BOXD_DIFF_RUNTIME_BUNDLE` / `BOXD_DIFF_RUNTIME_BUNDLE_SHA256` | signed runtime bundle and exact SHA-256 |
| `BOXD_DIFF_LIBKRUN_PATH` / `BOXD_DIFF_LIBKRUN_SHA256` | libkrun 1.19.4 file and exact SHA-256 |
| `BOXD_DIFF_LIBKRUN_LICENSE_PATH` | libkrun license file |
| `BOXD_DIFF_LIBKRUNFW_PATH` / `BOXD_DIFF_LIBKRUNFW_SHA256` | libkrunfw file and exact SHA-256 |
| `BOXD_DIFF_LIBKRUNFW_LICENSE_PATH` | libkrunfw license file |
| `BOXD_DIFF_OFFICIAL_PREFIX` | safe official disposable resource prefix |
| `BOXD_DIFF_LOCAL_PREFIX` | distinct local disposable resource prefix |
| `BOXD_DIFF_RUNTIME` | runtime accepted by both services |
| `BOXD_DIFF_BUDGET_USD` | budget; full run requires at least `3.85` today |
| `BOXD_DIFF_REQUEST_TIMEOUT_MS` | per-request timeout |
| `BOXD_DIFF_GLOBAL_TIMEOUT_MS` | whole-run timeout |
| `BOXD_DIFF_CONCURRENCY` | concurrency, capped by the executor at 8 |
| `BOXD_DIFF_OFFICIAL_GIT_REPO` | disposable official GitHub fixture |
| `BOXD_DIFF_OFFICIAL_GIT_BRANCH` | disposable official head branch |
| `BOXD_DIFF_OFFICIAL_GIT_BASE_BRANCH` | official PR base branch |
| `BOXD_DIFF_LOCAL_GIT_REPO` | disposable local GitHub fixture |
| `BOXD_DIFF_LOCAL_GIT_BRANCH` | distinct disposable local head branch |
| `BOXD_DIFF_LOCAL_GIT_BASE_BRANCH` | local PR base branch |

Secrets:

| Name | Meaning |
| --- | --- |
| `BOXD_DIFF_OFFICIAL_API_KEY` | official account key |
| `BOXD_DIFF_PROVIDER_API_KEY` | provider key for agent/browser cases |
| `BOXD_DIFF_OFFICIAL_GIT_TOKEN` | disposable official Git token |
| `BOXD_DIFF_LOCAL_GIT_TOKEN` | disposable local Git token |
| `BOXD_DIFF_MASTER_KEY` / `BOXD_DIFF_ADMIN_PASSWORD` | protected local daemon bootstrap secrets |

The workflow sets these only after environment approval:

```text
BOXD_DIFF_EXTERNALLY_MUTATING_OPT_IN=1
BOXD_DIFF_COST_OPT_IN=1
BOXD_DIFF_DEDICATED_ACCOUNTS_OPT_IN=1
```

The last opt-in is mandatory because the pinned SDK full environment operation
replaces the entire account environment. The Git repository and branches must
be disposable. `git push` changes the remote branch; create-PR cleanup closes
the PR but does not make a production branch safe.

## Evidence and exit status

The runner first sources `scripts/phase4-differential-native.sh`. It rejects
symlinks/hardlinks, validates native/runtime/config hashes, builds
`cargo build --release --locked -p boxd` from the checked-out commit, runs
`boxd init` against a new init target in the same run-local directory, captures
the single `compat_api_key=` line in a 0600 temporary file, immediately masks it,
exports it only in the current shell, and deletes the file. It then generates
the final config from the verified template against that same SQLite/data tree,
and runs `config validate`, `runtime import`, and `doctor --json` with `.overall == true`,
verifies the loopback port is unoccupied, starts that job-owned daemon, waits
for `/health/ready`, and installs an EXIT trap to stop it. A pre-running local
endpoint is never accepted. The runner manifest is kept only in `$RUNNER_TEMP`
until conversion. The converter is:

```sh
node compat/upstash-box-0.6.3/scripts/differential-evidence.mjs \
  --run /tmp/differential-run.json \
  --matrix compat/upstash-box-0.6.3/differential/case-matrix.json \
  --output /tmp/differential-evidence.json \
  --commit "$(git rev-parse HEAD)" \
  --local-binary "$BOXD_DIFF_LOCAL_BINARY" \
  --runtime-bundle "$BOXD_DIFF_RUNTIME_BUNDLE" \
  --local-config "$BOXD_DIFF_LOCAL_CONFIG"
```

It emits strict `boxd-phase4-evidence-v1` JSON with:

- full commit, native platform/virtualization, Node/SDK toolchain;
- SHA-256 records for the pinned matrix, run manifest, current-checkout local
  binary, runtime bundle, and local config;
- 82 unique case IDs with expected/observed/status and normalized artifact hash;
- external requirements, secret-scan result, and consistent summary counts.

Input files must be unique regular files (no symlink/hardlink). Output is
created with exclusive `wx` and mode `0600`; an existing output is rejected.
Unknown fields, response/request bodies, secret-like fields or environment
secret values are rejected before writing. Counts, status/gates, exact matrix
case IDs, cleanup counts, target-origin legality, and executor reason enums are
also closed-validated. No response body, resource ID,
credential, token, or provider value is included in evidence.

Status mapping is fail-closed:

```text
pass     -> exit 0, all 82 cases pass and cleanup succeeds
failed   -> exit 1, any response mismatch, execution or cleanup failure
blocked  -> exit 2, any missing gate/external input before requests
```

The workflow validates the emitted JSON with `scripts/phase4-evidence.py` and
uploads the redacted directory with `if-no-files-found: error` regardless of
job result. A missing evidence file is an artifact error, not a pass.

## Trigger

After the protected reviewer approves the environment, run manually with an
architecture matching the online runner:

```sh
gh workflow run phase4-authenticated-differential.yml \
  --repo Payhon/boxd -f confirm_run=true -f architecture=x64
gh run list --repo Payhon/boxd --workflow phase4-authenticated-differential.yml
gh run watch --repo Payhon/boxd <run-id>
```

An exit-2 blocked run is evidence that required inputs were absent; it is not a
successful compatibility run. A full Phase 4 gate requires current-commit
evidence with 82/82 pass and completed cleanup on each required native platform.
