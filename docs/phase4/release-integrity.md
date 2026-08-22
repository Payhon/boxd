# Phase 4 release integrity boundary

This slice is a hermetic integrity gate, not production release evidence. It can
bind already-built payloads and reject drift in hosted CI, but it cannot replace
Developer ID signing, notarization, stapling, HVF/KVM execution, or a real
service upgrade.

## Release layout and generation

Prepare one target-specific directory containing exactly the paths declared by
`boxd-release-input-v1`. The six required roles are `boxd`, `libkrun`,
`libkrunfw`, `runtime_bundle`, `sbom`, and `licenses`. Artifact paths must be
normalized relative paths and no component may be a symlink.

The release root is a closed tree. Its only permitted files are: the six input
artifact paths; the local provenance path; files referenced by the license
index; and the generated `SHA256SUMS` and `release-manifest.json`. Directories
are allowed only as ancestors of those files. Service definitions are validated
separately and are rejected from this release root until a later manifest
version binds their hashes explicitly. Empty directories, nested tool output,
temporary files, symlinks, hardlinks, and any other file type fail closed. This
check runs before generation and during verification, so an interrupted build
cannot be resumed from a contaminated staging tree.

The provenance object must include a local relative `path` in addition to its
URI and SHA-256. The gate hashes that file from the release directory; a URI
and claimed digest alone is rejected. The SPDX 2.3 document must describe
`boxd`, `boxd-console`, `libkrun`, `libkrunfw`, and `runtime-bundle`. Its
SHA-256 package checksums must match the payload bytes; because the console is
embedded in `boxd` and has no independent artifact path, its checksum must
match the exact `boxd` payload hash as well. The license index must bind
license evidence for the same five components.

```bash
python3 scripts/phase4-release-integrity.py generate \
  --release-dir /absolute/path/to/staged-release \
  --input /absolute/path/to/boxd-release-input.json

python3 scripts/phase4-release-integrity.py verify \
  --release-dir /absolute/path/to/staged-release
```

Generation writes canonical `SHA256SUMS` and `release-manifest.json` bytes. A
second generation from unchanged inputs must be byte-identical. Verification
re-hashes every payload, checks file sizes, revalidates SPDX, provenance and
licenses, and requires `SHA256SUMS` to be the exact sorted projection. The
manifest itself is not listed in `SHA256SUMS`, avoiding a circular hash; the
manifest binds the local provenance file path and digest separately. Generated
outputs, payloads, provenance, service definitions, `SHA256SUMS`, and the
manifest must all be unique regular files: symlinks and hardlinks are rejected.
This is an integrity/closure check only; it does not claim code signing,
Developer ID identity, notarization, stapling, Linux signing, or provenance
attestation.

## Service definitions

```bash
python3 scripts/phase4-validate-services.py \
  --systemd release/services/boxd.service \
  --launchd release/services/com.payhon.boxd.plist
```

The static gate rejects relaxed paths, shell syntax, missing KVM device policy,
missing service identity, and unreviewed launchd keys. It does not install the
service and does not prove the service account, paths, entitlements, or log
directories exist on a target host.

## Evidence and blocked gates

`boxd-phase4-evidence-v1` rejects unknown fields, inconsistent summary counts,
unsafe artifact paths, unbound case artifact hashes, and false `pass` summaries
when a case, secret scan, or external requirement is blocked or failed.

The hermetic upgrade/rollback drill checks backup ordering, a forward-only
migration journal model, schema compatibility windows, content-addressed runtime
coexistence, and running-Box pinning:

```bash
python3 scripts/phase4-upgrade-rollback-drill.py \
  --commit "$(git rev-parse HEAD)" \
  --output /tmp/boxd-phase4-upgrade-evidence.json
python3 scripts/phase4-evidence.py /tmp/boxd-phase4-upgrade-evidence.json
```

Its summary remains `blocked` because a real service/database upgrade, notarized
macOS HVF execution, and Linux x86_64/aarch64 KVM execution require external
artifacts or hardware. Those gates must produce new evidence for the exact
release commit; hosted CI cannot turn these requirements into `pass`.

## Runtime SQLite migration guard

When `database.auto_migrate` is enabled, startup calls the `box-db` migration
guard while holding the existing single-instance lock. SQLite pending migration
names are read without creating tables first. A non-empty database is copied
with SQLite `VACUUM INTO` into `data_dir/migration-backups/`; the output is a
private regular file and its SHA-256 is recorded in `migration-journal.json`.
The journal is atomically replaced and records `prepared`, `failed`, or
`applied`, together with the forward-only pending/applied migration names.
An existing `prepared` or `failed` journal blocks every later startup with
`migration_recovery_required`, including when the schema itself no longer has
pending migrations; an operator must inspect or restore the bound backup rather
than silently continuing from an ambiguous partial upgrade.
Fresh empty databases explicitly record a null backup. Non-SQLite databases
continue through the ordinary forward-only SeaORM migrator and do not claim a
local backup.
