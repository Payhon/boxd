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
BOXD_API_KEY='(environment only)' \
BOXD_BINARY=/absolute/path/to/boxd \
BOXD_RUNTIME_BUNDLE=/absolute/path/to/runtime.bundle \
BOXD_LOAD_ARTIFACT_ROOT=/absolute/path/containing/release-artifacts \
BOXD_RUNTIME=node \
BOXD_DATA_DIR=/absolute/path/to/data \
BOXD_DAEMON_PID=12345 \
BOXD_LOAD_RESULT=/tmp/boxd-load.json \
node scripts/phase4-load-runner.mjs
python3 scripts/phase4-load-harness.py --result /tmp/boxd-load.json --artifact-root /absolute/path/containing/release-artifacts --emit-evidence /tmp/boxd-load-evidence.json
```

The runner rejects symlinks/hardlinks and records normalized artifact-relative
paths plus recomputed SHA-256 values. The harness independently reopens those
files under the mandatory artifact root and recomputes the hashes before it can
emit live evidence. `BOXD_LOAD_RESULT` must not already exist; the collector
creates it mode `0600` and never follows an existing output path. Every cell
contains a closed proof transcript with actual create/operation/delete counts,
failures, monotonic timestamps, and a SHA-256 of sorted created IDs (IDs are
never emitted). Counts must close exactly and cleanup failure is fail-closed;
fixture records retain the old schema and remain permanently `blocked`.

Recovery artifacts are closed JSON `boxd-phase4-recovery-artifact-v1` records;
their bytes are hashed before parsing and scenario/status/commit/platform plus
`boxd`/`runtime`/`db` hashes are cross-checked against the live document.
Arbitrary text, altered or cross-bound artifacts, secrets, and blocked/failing
steps for a purported pass are rejected. This proves runner transcript
integrity only: JSON cannot self-authenticate, so trusted native runner/build
provenance, signatures, and the real HVF/KVM environment remain required.
Hosted Actions cannot claim native load or recovery evidence.
