# Runtime bundle format (v1)

`boxd runtime import <path> -c <config>` and `boxd runtime pull <name> -c
<config>` both terminate in this same verifier. Import accepts a directory,
tar, or tar.zst. Pull downloads the architecture-specific channel artifact
`<bundle_registry>/box-runtime-<name>-<arch>.tar.zst` into a private,
size-limited temporary file with redirects disabled, then verifies its signed
manifest (including runtime and architecture) before publication. A registry
may update that channel artifact only to a newly signed bundle; installed
content remains addressed by its rootfs SHA-256. Non-loopback downloads require
HTTPS. The total HTTP exchange is limited to four minutes, below the service's
five-minute creation deadline. A caller deadline or shutdown cancellation stops
that caller from waiting, while the host continues tracking the single shared
per-runtime pull through completion; this prevents an abandoned blocking task
from opening a duplicate download gate. Temporary files are removed on every
completion path.

An archive is a tar or tar.zst stream terminated by the standard two zero
blocks.  It contains only regular files:

```text
manifest.json
manifest.sig
rootfs.raw
sbom.spdx.json
licenses/<relative regular files>
```

No symlink, hardlink, device, FIFO, directory archive entry, duplicate path,
absolute path, `.` or `..` component is accepted.  The importer enforces
archive, unpacked, rootfs, per-file and entry-count limits before publishing.

`manifest.json` is UTF-8 JSON and includes format version, runtime and runtime
version, arch, pinned `libkrun_version`, kernel version, agent protocol,
build-toolchain, feature set, rootfs descriptor, SBOM descriptor, and one
descriptor for every `licenses/...` file.  Descriptors contain lowercase or
uppercase hexadecimal SHA-256 and byte length.  `key_id` is ASCII
`[A-Za-z0-9._-]`, 1–128 bytes.  The required libkrun version is `1.19.4`.

`manifest.sig` is base64 Ed25519.  Its signed message is the **exact raw bytes
of `manifest.json` as stored in the bundle**, not reserialized JSON.  This
avoids parser/canonicalization ambiguity.  The key is selected by `key_id`
from the caller-provided trusted key ring; an empty ring always fails closed.
The CLI decodes `runtime.trusted_signing_keys.<key_id>` as a 32-byte base64
Ed25519 public key. `runtime.verify_signatures=false`, an empty trust ring, a
runtime-name mismatch, or an architecture mismatch is an error.

Import stages all files privately, verifies the signature and every descriptor,
fsyncs the tree, marks `rootfs.raw` read-only, and atomically renames it to
`images/<rootfs-sha256>/`.  A preexisting content-addressed directory is
re-read and fully verified; its raw manifest and signature must exactly match
the incoming identity.  Base images are rehashed before every clone.

Phase 1 does not invoke host `e2fsck`/`resize2fs` and does not claim that merely
extending a raw file grows its ext4 filesystem. Consequently the authenticated
`rootfs.raw` descriptor size must exactly equal `resources.default_disk_gib` in
bytes. Clone fails closed on any mismatch. Runtime publishers must build the
ext4 filesystem at its final configured capacity before signing the bundle.

Clone destinations are paths relative to the configured `boxes_dir` only.
Unix creation uses `openat`/`mkdirat` with `O_NOFOLLOW` and `O_EXCL`; absolute
paths, traversal, symlink parents, and preexisting leaves are rejected.

Installed resolution scans only lowercase 64-hex content-address directories
under `images/` and revalidates the raw signed manifest plus rootfs, SBOM, and
every license file before reporting readiness. A runtime/architecture pair
may have multiple signed versions. `runtime_version` must be valid SemVer at
import time. New Box creation deterministically binds the highest semantic
`runtime_version` (equal versions use the lexicographically
highest content SHA-256); the selected SHA-256, version, and architecture are
persisted with the Box. Clone, boot, and reconciliation resolve that exact SHA
and revalidate the complete bundle identity, so installing a newer runtime does
not change existing Boxes. Legacy unbound `resolve_installed` callers still
reject multiple matches rather than guessing.

Production Box creation accepts only a canonical UUIDv7 and creates
`boxes/<box-id>/data.raw` as a private APFS clonefile/Linux reflink when
available, otherwise a sparse copy of the authenticated base. The installed
base remains read-only; `data.raw` is the writable ext4 root used for all guest
writes. A failed clone removes only its newly created Box directory. Removal
uses retained directory descriptors and `openat`/`unlinkat` with no-follow
checks; missing is idempotent, while symlinks, hardlinks, or any entry other
than the single-link regular `data.raw` fail closed.

## Guest boot contract

`rootfs.raw` is an ext4 filesystem containing an executable
`/usr/local/bin/box-agent`, `/workspace`, and `/home/boxuser`. Box creation
clones this image into the Box-private writable raw disk; it does not create a
blank ext4 disk. At boot, libkrun attaches the installed immutable base first
as read-only `/dev/vda` for authenticated provenance, then the private clone as
writable `/dev/vdb`. The worker selects `/dev/vdb` as the ext4 root through
`krun_set_root_disk_remount(ctx, "/dev/vdb", "ext4", NULL)` and explicitly
executes `/usr/local/bin/box-agent`.

The agent receives a fully controlled, explicit environment including
`BOXD_PRIVATE_ROOT_DEVICE=/dev/vdb`, `BOXD_IMMUTABLE_BASE_DEVICE=/dev/vda`,
`BOXD_WORKSPACE=/workspace`, identity/handshake fields, runtime/architecture,
and validated Box environment variables. The base remains read-only; all guest
filesystem writes, including `/workspace`, land in the Box-private clone.
At startup the agent creates the pinned SDK default cwd `/workspace/home`
relative to its retained no-follow workspace descriptor, validates any
preexisting entry as a real directory, and assigns it to `boxuser` before
accepting RPCs.
