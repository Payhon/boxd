# Phase 4 load / recovery harness

The load validator covers 1/4/16/64 Boxes for `exec`, `SSE`, `browser`, and
`preview`, with P50/P95/P99, error rate, CPU, RSS, FD, and disk-ceiling fields.
The recovery validator covers graceful stop, SIGTERM, worker SIGKILL, daemon
restart, disk full, interrupted runtime pull, SQLite backup/restore, and the
migration journal. Both are Python-stdlib only and reject secret-like values.

Fixture mode is explicitly `blocked`: it proves only matrix and schema shape.
It emits `boxd-phase4-evidence-v1` with eight blocked cases and must never be
promoted to a recovery pass. A live input is a closed `boxd-phase4-recovery-v1`
document: it must bind the full commit plus SHA-256 values for `boxd`,
`runtime`, `db`, and `artifact`, each with a normalized relative path, and be
run with a mandatory `--artifact-root`. The harness uses `lstat`, rejects
symlinks, non-regular files, hardlinks, and root escapes, and recomputes every
SHA-256 before accepting it. Live input must identify native Linux KVM or macOS
aarch64 HVF, and provide one `pass`/`fail` result, observed text, and artifact
path/hash for each scenario. Missing bindings, `none` virtualization,
secret-like values, and fixture/mock/model wording are rejected fail-closed.
The emitted evidence is then checked with `scripts/phase4-evidence.py`.

## Live load collection

Use the hash-verified SDK collector only against an explicitly running local
boxd. API keys are environment-only and are never written to evidence:

```sh
BOXD_LOAD_MODE=live \
BOXD_BASE_URL=http://127.0.0.1:8787 \
# BOXD_API_KEY is created in the same shell from the fresh admin DB; it is not a secret input.
BOXD_API_KEY='(bootstrap helper output, shell only)' \
BOXD_BINARY=/absolute/path/to/boxd \
BOXD_RUNTIME_BUNDLE=/absolute/path/to/runtime.bundle \
BOXD_LOAD_ARTIFACT_ROOT=/absolute/path/containing/release-artifacts \
BOXD_RUNTIME=node \
BOXD_DATA_DIR=/absolute/path/to/data \
BOXD_DAEMON_PID=12345 \
BOXD_LOAD_CONFIG=/absolute/path/to/load-profile-boxd.toml \
BOXD_LOAD_PROFILE=phase4-64 \
BOXD_LOAD_SAMPLE_INTERVAL_MS=250 \
BOXD_LOAD_RESULT=/tmp/boxd-load.json \
node scripts/phase4-load-runner.mjs
python3 scripts/phase4-load-harness.py --result /tmp/boxd-load.json --artifact-root /absolute/path/containing/release-artifacts --emit-evidence /tmp/boxd-load-evidence.json
```

The runner rejects symlinks/hardlinks and records normalized artifact-relative
paths plus recomputed SHA-256 values. The harness independently reopens those
files under the mandatory artifact root and recomputes the hashes before it can
emit live evidence. `BOXD_LOAD_RESULT` must not already exist; the collector
creates it mode `0600` and never follows an existing output path. `BOXD_LOAD_PROFILE`
and `BOXD_LOAD_CONFIG` are mandatory: `phase4-64` must run with
`BOXD_RUNTIME=node` and explicitly provide at least 64 running Boxes, 262144
MiB total memory, 128 vCPUs, a per-Box default disk of at least 20 GiB, and
tenant quotas of at least 64 Boxes/1280 GiB and 64 concurrent runs. A lower profile fails before the
matrix starts; the default boxd resource configuration cannot be used to claim
a 64-Box result. Every cell
contains a closed proof transcript with actual create/operation/delete counts,
failures, monotonic timestamps, a SHA-256 of sorted created IDs (IDs are never
emitted), and a continuous resource sampler. Aggregate CPU, RSS, and open FD count
for the owned boxd process tree (including VMM workers), plus runner-owned data
disk usage, are sampled every `BOXD_LOAD_SAMPLE_INTERVAL_MS` milliseconds; the
cell records the sample count and maximum (ceiling) of each resource. The
preview cell starts a guest Node HTTP service, fetches the URL returned by the
pinned `getPublicURL(port)` contract (`{url, port, ...}`), and consumes every
non-empty response body; merely creating a preview URL is rejected. Counts,
preview fetch/byte counters, sampling
metadata and cleanup must close exactly; fixture records retain the old schema
and remain permanently `blocked`.

The protected native workflow's environment-specific `BOXD_PHASE4_CONFIG` must
also use a bounded API-key request rate/burst sufficient for the matrix (the
preflight requires at least 4096 requests/minute and a 512 request burst).
Those values remain inside the copied, SHA-256-bound config artifact; they are
not supplied through `BOXD__` environment overrides.

The protected native workflow does not run the provider template in place. It
creates a unique config under `RUNNER_TEMP`, rewrites listen/public/preview
URLs to a newly reserved loopback port, and rewrites SQLite plus every storage
directory to that run's `RUNNER_TEMP` data directory. The daemon, sampler,
artifact root, and `BOXD_BASE_URL` all use those generated paths; an occupied
endpoint or missing generated evidence fails the job.

Fresh native SQLite state is initialized with the current `boxd init` binary
before the daemon starts. The workflow captures and masks the one-time init
compatibility key in a `0600` runner-temporary file, then logs in through
`/api/admin/v1/auth/login` and creates a short-lived admin-issued key with the
compatibility load scopes `boxes_read`, `boxes_write`, and `runs_write` using
the HttpOnly session cookie plus CSRF header. The compatibility authenticator
intentionally rejects the separate `admin` AuthScope, so claiming an
`admin`-scoped compatibility key would fail closed with 401. Only that shell exports
`BOXD_API_KEY`; its EXIT trap revokes the key before stopping the daemon and
deletes the temporary record. No API-key secret is configured in the workflow.

Recovery artifacts are closed JSON `boxd-phase4-recovery-artifact-v1` records;
their bytes are hashed before parsing and scenario/status/commit/platform plus
`boxd`/`runtime`/`db` hashes are cross-checked against the live document.
Arbitrary text, altered or cross-bound artifacts, secrets, and blocked/failing
steps for a purported pass are rejected. This proves runner transcript
integrity only: JSON cannot self-authenticate, so trusted native runner/build
provenance, signatures, and the real HVF/KVM environment remain required.
Hosted Actions cannot claim native load or recovery evidence.
