# Pinned SDK compatibility limitations

## Nested `files.download`

`@upstash/box@0.6.3` creates only the top-level local destination directory,
skips directory entries, and writes each file directly to `dest/file.name`.
It does not create parent directories contained in `file.name`.

Consequently, this version cannot safely download a remote folder containing
subdirectories: preserving relative paths produces local `ENOENT`, while
flattening names can overwrite files with identical basenames. boxd therefore
fails such listings with HTTP 501 `feature_not_supported`. Flat, single-level
folders and the single-file binary download endpoint remain supported.

The executable regression is in `test/sdk-contract.test.mjs`; it compiles and
imports the hash-verified vendored source before reproducing the upstream
`ENOENT` behavior.

## Authenticated differential execution

The Phase 4 executor defines and validates the 78-contract/82-case matrix,
normalizers, independent credential/external-mutation/cost/budget gates, and
redacted hash-only run evidence. All 82 public cases now have executable
pinned-SDK adapters with resource cleanup. This is executor coverage, not
authenticated compatibility evidence: the current environment has no
official/local credentials, runtime, provider key, disposable Git fixture or
cost budget, so the full run remains blocked before sending requests. Phase 4
still requires a passing authenticated official/local run with successful
cleanup for every case.
