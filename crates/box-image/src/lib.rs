//! Offline runtime-bundle import, verification and disk-cloning boundary.
//!
//! This crate deliberately has no HTTP client.  Callers that want a registry
//! implement [`Downloader`]; Phase 1 only uses [`RuntimeBundleManager::import`].

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fs2::FileExt;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const FORMAT_VERSION: u32 = 1;
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LICENSE_DESCRIPTOR_BYTES: u64 = 16 * 1024 * 1024;
const MANIFEST: &str = "manifest.json";
const SIGNATURE: &str = "manifest.sig";
const ROOTFS: &str = "rootfs.raw";
const SBOM: &str = "sbom.spdx.json";
const LICENSES: &str = "licenses";
const DATA_DISK: &str = "data.raw";

/// The manifest format stored with every imported runtime bundle.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBundleManifest {
    pub format_version: u32,
    pub runtime: String,
    pub runtime_version: String,
    pub arch: String,
    pub libkrun_version: String,
    pub kernel_version: String,
    pub agent_protocol: u32,
    pub build_toolchain: String,
    #[serde(default)]
    pub features: BTreeSet<String>,
    pub rootfs: RootfsDescriptor,
    pub sbom: FileDescriptor,
    /// Every key is a relative `licenses/...` path and every value authenticates
    /// the corresponding regular file.
    pub licenses: BTreeMap<String, FileDescriptor>,
    pub signature: SignatureMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootfsDescriptor {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileDescriptor {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureMetadata {
    /// Must be `ed25519`; it is explicit to prevent algorithm confusion.
    pub algorithm: String,
    pub key_id: String,
}

/// Limits applied before any bundle material becomes visible in `images/`.
#[derive(Clone, Debug)]
pub struct ImportLimits {
    pub max_archive_bytes: u64,
    pub max_unpacked_bytes: u64,
    pub max_rootfs_bytes: u64,
    pub max_entries: usize,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 32 * 1024 * 1024 * 1024,
            max_unpacked_bytes: 64 * 1024 * 1024 * 1024,
            max_rootfs_bytes: 60 * 1024 * 1024 * 1024,
            max_entries: 64,
        }
    }
}

/// A trusted Ed25519 public-key ring.  An empty ring is intentionally not a
/// permissive mode: every signature check fails closed.
#[derive(Clone, Debug, Default)]
pub struct TrustedEd25519Keys(BTreeMap<String, Vec<u8>>);

impl TrustedEd25519Keys {
    pub fn new(keys: BTreeMap<String, Vec<u8>>) -> Self {
        Self(keys)
    }

    fn verify(
        &self,
        metadata: &SignatureMetadata,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ImageError> {
        if metadata.algorithm != "ed25519" {
            return Err(ImageError::UnsupportedSignatureAlgorithm);
        }
        let key = self
            .0
            .get(&metadata.key_id)
            .ok_or(ImageError::UntrustedSigningKey)?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(message, signature)
            .map_err(|_| ImageError::InvalidSignature)
    }
}

/// Location of an offline input.  Network download is intentionally absent.
#[derive(Clone, Debug)]
pub enum ImportSource {
    Directory(PathBuf),
    Archive(PathBuf),
}

/// An opt-in integration point for a future registry client.  The crate does
/// not provide an implementation, so a caller cannot mistake a mock pull for a
/// verified import.
pub trait Downloader: Send + Sync {
    fn download(&self, _reference: &str, _destination: &Path) -> Result<(), ImageError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedBundle {
    pub rootfs_sha256: String,
    pub path: PathBuf,
    pub already_present: bool,
    pub manifest: RuntimeBundleManifest,
}

/// An installed bundle that passed signature and complete content
/// revalidation. `rootfs_path` is absolute/canonical and must remain read-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRuntime {
    pub rootfs_path: PathBuf,
    pub rootfs_sha256: String,
    pub manifest: RuntimeBundleManifest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskIdentity {
    pub path: PathBuf,
    pub source_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoxRuntimeDisks {
    pub base_rootfs: DiskIdentity,
    pub data_disk: DiskIdentity,
    pub manifest: RuntimeBundleManifest,
    pub clone_method: CloneMethod,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotDisk {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub clone_method: CloneMethod,
}

pub struct RuntimeBundleManager {
    images_dir: PathBuf,
    staging_dir: PathBuf,
    boxes_dir: PathBuf,
    snapshots_dir: PathBuf,
    trusted_keys: TrustedEd25519Keys,
    limits: ImportLimits,
    /// Process-local cache of identities that already passed the complete
    /// signature and content scan. Clone still hashes the source immediately
    /// before copying, so this only removes a redundant directory-wide scan.
    resolved_cache: Mutex<HashMap<String, ResolvedRuntime>>,
}

impl RuntimeBundleManager {
    pub fn new(
        images_dir: impl Into<PathBuf>,
        boxes_dir: impl Into<PathBuf>,
        snapshots_dir: impl Into<PathBuf>,
        trusted_keys: TrustedEd25519Keys,
        limits: ImportLimits,
    ) -> Self {
        let images_dir = images_dir.into();
        Self {
            staging_dir: images_dir.join(".staging"),
            images_dir,
            boxes_dir: boxes_dir.into(),
            snapshots_dir: snapshots_dir.into(),
            trusted_keys,
            limits,
            resolved_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn import(&self, source: ImportSource) -> Result<ImportedBundle, ImageError> {
        self.import_with_policy(source, None, None)
    }

    /// Imports only when the authenticated manifest matches the caller's
    /// runtime/platform selection. The policy is checked before publication.
    pub fn import_with_policy(
        &self,
        source: ImportSource,
        expected_runtime: Option<&str>,
        expected_arch: Option<&str>,
    ) -> Result<ImportedBundle, ImageError> {
        fs::create_dir_all(&self.images_dir)?;
        fs::create_dir_all(&self.staging_dir)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.images_dir.join(".import.lock"))?;
        lock.lock_exclusive()?;
        let result = self.import_locked(source, expected_runtime, expected_arch);
        let _ = FileExt::unlock(&lock);
        result
    }

    /// Verifies an offline input without publishing it.  This is intentionally
    /// fail-closed: a missing trusted key is an error, not a warning.
    pub fn verify(&self, source: ImportSource) -> Result<RuntimeBundleManifest, ImageError> {
        fs::create_dir_all(&self.staging_dir)?;
        let staging = self.staging_dir.join(format!("verify-{}", unique_suffix()));
        fs::create_dir(&staging)?;
        let result = match source {
            ImportSource::Directory(path) => self.read_directory(&path, &staging),
            ImportSource::Archive(path) => self.read_archive(&path, &staging),
        }
        .and_then(|raw| self.verify_raw(&raw));
        let _ = fs::remove_dir_all(staging);
        result
    }

    pub fn resolve_installed(
        &self,
        runtime: &str,
        arch: &str,
    ) -> Result<ResolvedRuntime, ImageError> {
        if !valid_runtime(runtime) || !matches!(arch, "aarch64" | "x86_64") {
            return Err(ImageError::BundlePolicyMismatch);
        }
        let mut found = self
            .scan_installed(arch)?
            .into_iter()
            .filter(|resolved| resolved.manifest.runtime == runtime)
            .collect::<Vec<_>>();
        match found.len() {
            0 => Err(ImageError::BundleNotFound),
            1 => Ok(found.pop().expect("exactly one match")),
            _ => Err(ImageError::AmbiguousBundle),
        }
    }

    /// Selects the newest authenticated semantic version deterministically.
    /// Equal versions are ordered by content SHA-256 so every host binds the
    /// same immutable bundle without relying on directory iteration order.
    pub fn resolve_preferred(
        &self,
        runtime: &str,
        arch: &str,
    ) -> Result<ResolvedRuntime, ImageError> {
        self.resolve_preferred_with_features(runtime, arch, &BTreeSet::new())
    }

    /// Selects the newest authenticated bundle that includes every required
    /// feature. Browser boxes use this to avoid booting a generic runtime and
    /// discovering the missing Chromium dependency after disk clone.
    pub fn resolve_preferred_with_features(
        &self,
        runtime: &str,
        arch: &str,
        required_features: &BTreeSet<String>,
    ) -> Result<ResolvedRuntime, ImageError> {
        if !valid_runtime(runtime) || !matches!(arch, "aarch64" | "x86_64") {
            return Err(ImageError::BundlePolicyMismatch);
        }
        let mut found = self
            .scan_installed(arch)?
            .into_iter()
            .filter(|resolved| {
                resolved.manifest.runtime == runtime
                    && required_features.is_subset(&resolved.manifest.features)
            })
            .map(|resolved| {
                semver::Version::parse(&resolved.manifest.runtime_version)
                    .map(|version| (version, resolved.rootfs_sha256.clone(), resolved))
                    .map_err(|_| ImageError::InvalidManifest)
            })
            .collect::<Result<Vec<_>, _>>()?;
        found.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        found
            .pop()
            .map(|(_, _, resolved)| resolved)
            .ok_or(ImageError::BundleNotFound)
    }

    /// Revalidates and resolves one immutable content-addressed bundle.
    pub fn resolve_installed_by_sha(
        &self,
        sha256: &str,
        runtime: &str,
        runtime_version: &str,
        arch: &str,
    ) -> Result<ResolvedRuntime, ImageError> {
        if !valid_runtime(runtime) {
            return Err(ImageError::BundlePolicyMismatch);
        }
        let resolved = self.resolve_binding_by_sha(sha256, runtime_version, arch)?;
        if resolved.manifest.runtime != runtime {
            return Err(ImageError::BundlePolicyMismatch);
        }
        Ok(resolved)
    }

    pub fn resolve_binding_by_sha(
        &self,
        sha256: &str,
        runtime_version: &str,
        arch: &str,
    ) -> Result<ResolvedRuntime, ImageError> {
        if !valid_content_address(sha256) || !matches!(arch, "aarch64" | "x86_64") {
            return Err(ImageError::BundlePolicyMismatch);
        }
        if let Some(resolved) = self
            .resolved_cache
            .lock()
            .map_err(|_| ImageError::UnsafeInput)?
            .get(sha256)
            .cloned()
        {
            self.validate_cached_runtime(&resolved)?;
            if resolved.manifest.runtime_version != runtime_version
                || resolved.manifest.arch != arch
            {
                return Err(ImageError::BundlePolicyMismatch);
            }
            return Ok(resolved);
        }
        let resolved = self
            .scan_installed(arch)?
            .into_iter()
            .find(|resolved| resolved.rootfs_sha256 == sha256)
            .ok_or(ImageError::BundleNotFound)?;
        if resolved.manifest.runtime_version != runtime_version || resolved.manifest.arch != arch {
            return Err(ImageError::BundlePolicyMismatch);
        }
        Ok(resolved)
    }

    /// Verifies the installed content-addressed tree once and returns the
    /// requested runtime names that have no authenticated bundle for `arch`.
    /// Multiple signed versions count as available; Box-version binding is a
    /// higher-level selection concern.
    pub fn missing_from_catalog(
        &self,
        runtimes: &[&str],
        arch: &str,
    ) -> Result<Vec<String>, ImageError> {
        if !matches!(arch, "aarch64" | "x86_64") || runtimes.iter().any(|name| !valid_runtime(name))
        {
            return Err(ImageError::BundlePolicyMismatch);
        }
        let installed = self.scan_installed(arch)?;
        Ok(runtimes
            .iter()
            .filter(|runtime| {
                !installed
                    .iter()
                    .any(|resolved| resolved.manifest.runtime.as_str() == **runtime)
            })
            .map(|runtime| (*runtime).to_owned())
            .collect())
    }

    fn scan_installed(&self, arch: &str) -> Result<Vec<ResolvedRuntime>, ImageError> {
        let entries = match fs::read_dir(&self.images_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        let images = self.images_dir.canonicalize()?;
        let mut found = Vec::new();
        for entry in entries {
            let entry = entry?;
            let Some(address) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !valid_content_address(&address) {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(ImageError::UnsafeInput);
            }
            let raw = read_installed_directory(&entry.path(), &self.limits)?;
            let manifest = self.verify_raw(&raw)?;
            if raw.rootfs.sha256 != address {
                return Err(ImageError::HashCollision);
            }
            let rootfs_path = entry.path().join(ROOTFS).canonicalize()?;
            if !rootfs_path.is_absolute() || !rootfs_path.starts_with(&images) {
                return Err(ImageError::UnsafeInput);
            }
            if !fs::metadata(&rootfs_path)?.permissions().readonly() {
                return Err(ImageError::BaseImageTampered);
            }
            if manifest.arch == arch {
                let resolved = ResolvedRuntime {
                    rootfs_path,
                    rootfs_sha256: address,
                    manifest,
                };
                self.resolved_cache
                    .lock()
                    .map_err(|_| ImageError::UnsafeInput)?
                    .insert(resolved.rootfs_sha256.clone(), resolved.clone());
                found.push(resolved);
            }
        }
        Ok(found)
    }

    fn validate_cached_runtime(&self, resolved: &ResolvedRuntime) -> Result<(), ImageError> {
        let images = self.images_dir.canonicalize()?;
        let expected = images
            .join(&resolved.rootfs_sha256)
            .join(ROOTFS)
            .canonicalize()?;
        if resolved.rootfs_path != expected
            || !expected.starts_with(&images)
            || resolved.manifest.rootfs.sha256 != resolved.rootfs_sha256
        {
            return Err(ImageError::BaseImageTampered);
        }
        let metadata = fs::symlink_metadata(&expected)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != resolved.manifest.rootfs.size_bytes
            || !metadata.permissions().readonly()
        {
            return Err(ImageError::BaseImageTampered);
        }
        Ok(())
    }

    pub fn ready_for(&self, runtime: &str, arch: &str) -> Result<bool, ImageError> {
        match self.resolve_preferred(runtime, arch) {
            Ok(_) => Ok(true),
            Err(ImageError::BundleNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Clones the selected base image into the Box-private writable root disk.
    /// The authenticated installed base remains separate and read-only.
    pub fn clone_runtime_for_box(
        &self,
        box_id: &str,
        runtime: &str,
        arch: &str,
    ) -> Result<BoxRuntimeDisks, ImageError> {
        let resolved = self.resolve_installed(runtime, arch)?;
        let size = resolved.manifest.rootfs.size_bytes;
        self.clone_resolved_for_box(box_id, resolved, size)
    }

    pub fn clone_runtime_for_box_sized(
        &self,
        box_id: &str,
        runtime: &str,
        arch: &str,
        disk_size_bytes: u64,
    ) -> Result<BoxRuntimeDisks, ImageError> {
        validate_box_id(box_id)?;
        let resolved = self.resolve_installed(runtime, arch)?;
        self.clone_resolved_for_box(box_id, resolved, disk_size_bytes)
    }

    pub fn clone_runtime_for_box_binding_sized(
        &self,
        box_id: &str,
        sha256: &str,
        runtime_version: &str,
        arch: &str,
        disk_size_bytes: u64,
    ) -> Result<BoxRuntimeDisks, ImageError> {
        validate_box_id(box_id)?;
        let resolved = self.resolve_binding_by_sha(sha256, runtime_version, arch)?;
        self.clone_resolved_for_box(box_id, resolved, disk_size_bytes)
    }

    fn clone_resolved_for_box(
        &self,
        box_id: &str,
        resolved: ResolvedRuntime,
        disk_size_bytes: u64,
    ) -> Result<BoxRuntimeDisks, ImageError> {
        validate_box_id(box_id)?;
        if disk_size_bytes != resolved.manifest.rootfs.size_bytes {
            return Err(ImageError::DiskSizeMismatch);
        }
        let boxes = ensure_directory_no_follow(&self.boxes_dir)?;
        let box_directory = create_box_directory(&boxes, box_id)?;
        let result = (|| {
            let mut source = open_regular_no_follow(&resolved.rootfs_path)?;
            let hashed = hash_file(&mut source, self.limits.max_rootfs_bytes)?;
            if hashed.sha256 != resolved.rootfs_sha256 {
                return Err(ImageError::BaseImageTampered);
            }
            let clone_method = clone_private_file(&mut source, &box_directory, DATA_DISK)?;
            let data_disk = self.boxes_dir.join(box_id).join(DATA_DISK).canonicalize()?;
            Ok(BoxRuntimeDisks {
                base_rootfs: DiskIdentity {
                    path: resolved.rootfs_path,
                    source_sha256: resolved.rootfs_sha256.clone(),
                },
                data_disk: DiskIdentity {
                    path: data_disk,
                    source_sha256: resolved.rootfs_sha256,
                },
                manifest: resolved.manifest,
                clone_method,
            })
        })();
        if result.is_err() {
            cleanup_new_box_directory(&boxes, &box_directory, box_id);
        }
        result
    }

    pub fn remove_box_disk(&self, box_id: &str) -> Result<(), ImageError> {
        validate_box_id(box_id)?;
        let boxes = match open_directory_no_follow(&self.boxes_dir) {
            Ok(value) => value,
            Err(ImageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        remove_box_directory(&boxes, box_id)
    }

    pub fn create_snapshot_disk(
        &self,
        box_id: &str,
        snapshot_id: &str,
    ) -> Result<SnapshotDisk, ImageError> {
        validate_box_id(box_id)?;
        validate_box_id(snapshot_id)?;
        let boxes = open_directory_no_follow(&self.boxes_dir)?;
        let mut source = open_private_data_file(&boxes, box_id)?;
        let source_hash = hash_file(&mut source, self.limits.max_rootfs_bytes)?;
        let snapshots = ensure_directory_no_follow(&self.snapshots_dir)?;
        let snapshot_directory = create_box_directory(&snapshots, snapshot_id)?;
        let result = (|| {
            let clone_method = clone_private_file(&mut source, &snapshot_directory, DATA_DISK)?;
            let path = self
                .snapshots_dir
                .join(snapshot_id)
                .join(DATA_DISK)
                .canonicalize()?;
            let mut cloned = open_regular_no_follow(&path)?;
            let cloned_hash = hash_file(&mut cloned, self.limits.max_rootfs_bytes)?;
            if cloned_hash.sha256 != source_hash.sha256
                || cloned_hash.size_bytes != source_hash.size_bytes
            {
                return Err(ImageError::HashCollision);
            }
            Ok(SnapshotDisk {
                relative_path: format!("{snapshot_id}/{DATA_DISK}"),
                size_bytes: cloned_hash.size_bytes,
                sha256: cloned_hash.sha256,
                clone_method,
            })
        })();
        if result.is_err() {
            cleanup_new_box_directory(&snapshots, &snapshot_directory, snapshot_id);
        }
        result
    }

    pub fn clone_snapshot_for_box(
        &self,
        snapshot_id: &str,
        box_id: &str,
        expected_sha256: &str,
    ) -> Result<CloneMethod, ImageError> {
        validate_box_id(snapshot_id)?;
        validate_box_id(box_id)?;
        validate_sha256(expected_sha256)?;
        let snapshots = open_directory_no_follow(&self.snapshots_dir)?;
        let mut source = open_private_data_file(&snapshots, snapshot_id)?;
        let source_hash = hash_file(&mut source, self.limits.max_rootfs_bytes)?;
        if source_hash.sha256 != expected_sha256 {
            return Err(ImageError::BaseImageTampered);
        }
        let boxes = ensure_directory_no_follow(&self.boxes_dir)?;
        let box_directory = create_box_directory(&boxes, box_id)?;
        let result = clone_private_file(&mut source, &box_directory, DATA_DISK);
        if result.is_err() {
            cleanup_new_box_directory(&boxes, &box_directory, box_id);
        }
        result
    }

    pub fn remove_snapshot_disk(&self, snapshot_id: &str) -> Result<(), ImageError> {
        validate_box_id(snapshot_id)?;
        let snapshots = match open_directory_no_follow(&self.snapshots_dir) {
            Ok(value) => value,
            Err(ImageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        remove_box_directory(&snapshots, snapshot_id)
    }

    /// Inspects a Box-private disk through retained directory descriptors. A
    /// missing UUID directory is not ready; any symlink, hardlink, or unexpected
    /// entry fails closed instead of being treated as a missing disk.
    pub fn private_disk_ready(&self, box_id: &str) -> Result<bool, ImageError> {
        validate_box_id(box_id)?;
        let boxes = match open_directory_no_follow(&self.boxes_dir) {
            Ok(value) => value,
            Err(ImageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        inspect_box_directory(&boxes, box_id)
    }

    pub fn clone_base_image(
        &self,
        rootfs_sha256: &str,
        relative_destination: impl AsRef<Path>,
    ) -> Result<CloneMethod, ImageError> {
        validate_sha256(rootfs_sha256)?;
        validate_relative_destination(relative_destination.as_ref())?;
        let base = self.images_dir.join(rootfs_sha256).join(ROOTFS);
        if !matches!(fs::symlink_metadata(&base), Ok(meta) if meta.file_type().is_file() && !meta.file_type().is_symlink())
        {
            return Err(ImageError::BundleNotFound);
        }
        let hashed = sha256_file(&base, self.limits.max_rootfs_bytes)?;
        if hashed.sha256 != rootfs_sha256 {
            return Err(ImageError::BaseImageTampered);
        }
        fs::create_dir_all(&self.boxes_dir)?;
        let root = open_directory_no_follow(&self.boxes_dir)?;
        let mut destination = create_relative_file_no_follow(&root, relative_destination.as_ref())?;
        let mut input = File::open(base)?;
        io::copy(&mut input, &mut destination)?;
        destination.sync_all()?;
        Ok(CloneMethod::Copied)
    }

    fn import_locked(
        &self,
        source: ImportSource,
        expected_runtime: Option<&str>,
        expected_arch: Option<&str>,
    ) -> Result<ImportedBundle, ImageError> {
        let nonce = format!("{}-{}", std::process::id(), unique_suffix());
        let staging = self.staging_dir.join(nonce);
        fs::create_dir(&staging)?;
        let result = match source {
            ImportSource::Directory(path) => self.read_directory(&path, &staging),
            ImportSource::Archive(path) => self.read_archive(&path, &staging),
        }
        .and_then(|raw| self.finish_import(raw, &staging, expected_runtime, expected_arch));
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    fn read_directory(&self, directory: &Path, staging: &Path) -> Result<RawBundle, ImageError> {
        let meta = fs::symlink_metadata(directory)?;
        if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
            return Err(ImageError::UnsafeInput);
        }
        let directory = directory.canonicalize()?;
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
                return Err(ImageError::UnsafeInput);
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let valid_entry = if name == LICENSES {
                file_type.is_dir()
            } else {
                file_type.is_file() && allowed_name(&name)
            };
            if !valid_entry || !names.insert(name.clone()) {
                return Err(ImageError::UnsafeInput);
            }
        }
        if !names.contains(MANIFEST)
            || !names.contains(SIGNATURE)
            || !names.contains(ROOTFS)
            || !names.contains(SBOM)
            || !names.contains(LICENSES)
        {
            return Err(ImageError::InvalidManifest);
        }
        let manifest = read_regular_no_follow(&directory.join(MANIFEST), MAX_METADATA_BYTES)?;
        let signature = read_regular_no_follow(&directory.join(SIGNATURE), MAX_METADATA_BYTES)?;
        let rootfs = open_regular_no_follow(&directory.join(ROOTFS))?;
        let copied = copy_rootfs(rootfs, staging.join(ROOTFS), &self.limits)?;
        let sbom = copy_limited_file(
            open_regular_no_follow(&directory.join(SBOM))?,
            staging.join(SBOM),
            MAX_METADATA_BYTES,
        )?;
        let licenses = copy_license_tree(
            &directory.join(LICENSES),
            &staging.join(LICENSES),
            &self.limits,
        )?;
        Ok(RawBundle {
            manifest,
            signature,
            rootfs: copied,
            sbom,
            licenses,
        })
    }

    fn read_archive(&self, archive: &Path, staging: &Path) -> Result<RawBundle, ImageError> {
        let meta = fs::metadata(archive)?;
        if !meta.is_file() || meta.len() > self.limits.max_archive_bytes {
            return Err(ImageError::ArchiveLimit);
        }
        let input: Box<dyn Read> = if archive.extension().is_some_and(|ext| ext == "zst") {
            Box::new(zstd::stream::read::Decoder::new(File::open(archive)?)?)
        } else {
            Box::new(File::open(archive)?)
        };
        read_tar(BufReader::new(input), staging, &self.limits)
    }

    fn finish_import(
        &self,
        raw: RawBundle,
        staging: &Path,
        expected_runtime: Option<&str>,
        expected_arch: Option<&str>,
    ) -> Result<ImportedBundle, ImageError> {
        let manifest = self.verify_raw(&raw)?;
        if expected_runtime.is_some_and(|value| manifest.runtime != value)
            || expected_arch.is_some_and(|value| manifest.arch != value)
        {
            return Err(ImageError::BundlePolicyMismatch);
        }
        let destination = self.images_dir.join(&raw.rootfs.sha256);
        if destination.exists() {
            let verification_staging = self
                .staging_dir
                .join(format!("existing-{}", unique_suffix()));
            fs::create_dir(&verification_staging)?;
            let existing = self
                .read_directory(&destination, &verification_staging)
                .and_then(|bundle| {
                    let existing_manifest = self.verify_raw(&bundle)?;
                    if bundle.manifest != raw.manifest
                        || bundle.signature != raw.signature
                        || existing_manifest != manifest
                    {
                        return Err(ImageError::HashCollision);
                    }
                    Ok(bundle)
                });
            let _ = fs::remove_dir_all(&verification_staging);
            let existing = existing?;
            if existing.rootfs.sha256 != raw.rootfs.sha256 {
                return Err(ImageError::HashCollision);
            }
            return Ok(ImportedBundle {
                rootfs_sha256: raw.rootfs.sha256,
                path: destination,
                already_present: true,
                manifest,
            });
        }
        fs::write(staging.join(MANIFEST), &raw.manifest)?;
        fs::write(staging.join(SIGNATURE), &raw.signature)?;
        make_read_only(&staging.join(ROOTFS))?;
        sync_tree(staging)?;
        fs::rename(staging, &destination)?;
        sync_dir(&self.images_dir)?;
        Ok(ImportedBundle {
            rootfs_sha256: raw.rootfs.sha256,
            path: destination,
            already_present: false,
            manifest,
        })
    }

    fn verify_raw(&self, raw: &RawBundle) -> Result<RuntimeBundleManifest, ImageError> {
        let manifest: RuntimeBundleManifest =
            serde_json::from_slice(&raw.manifest).map_err(|_| ImageError::InvalidManifest)?;
        validate_manifest(&manifest, &self.limits)?;
        let signature = BASE64
            .decode(
                raw.signature
                    .iter()
                    .copied()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| ImageError::InvalidSignature)?;
        self.trusted_keys
            .verify(&manifest.signature, &raw.manifest, &signature)?;
        if manifest.rootfs.sha256 != raw.rootfs.sha256
            || manifest.rootfs.size_bytes != raw.rootfs.size_bytes
            || manifest.sbom.sha256 != raw.sbom.sha256
            || manifest.sbom.size_bytes != raw.sbom.size_bytes
            || manifest.licenses != to_descriptors(&raw.licenses)
        {
            return Err(ImageError::RootfsHashMismatch);
        }
        Ok(manifest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloneMethod {
    CopyOnWrite,
    Copied,
}

#[derive(Debug, Error)]
pub enum ImageError {
    #[error("runtime bundle input is unsafe")]
    UnsafeInput,
    #[error("runtime bundle archive exceeds configured limits")]
    ArchiveLimit,
    #[error("runtime bundle manifest is invalid")]
    InvalidManifest,
    #[error("runtime bundle signature is invalid")]
    InvalidSignature,
    #[error("runtime bundle signature algorithm is unsupported")]
    UnsupportedSignatureAlgorithm,
    #[error("runtime bundle signing key is not trusted")]
    UntrustedSigningKey,
    #[error("rootfs checksum or size does not match manifest")]
    RootfsHashMismatch,
    #[error("existing image path has unexpected content")]
    HashCollision,
    #[error("invalid sha256 image identifier")]
    InvalidSha256,
    #[error("runtime bundle was not found")]
    BundleNotFound,
    #[error("multiple installed bundles match the selected runtime and architecture")]
    AmbiguousBundle,
    #[error("box id must be a canonical UUIDv7 string")]
    InvalidBoxId,
    #[error("box directory contains an unsafe or unexpected entry")]
    UnsafeBoxDirectory,
    #[error("destination already exists")]
    DestinationExists,
    #[error(
        "configured private disk size must exactly match the authenticated rootfs filesystem image"
    )]
    DiskSizeMismatch,
    #[error("destination path is invalid")]
    InvalidDestination,
    #[error("base image content no longer matches its content address")]
    BaseImageTampered,
    #[error("runtime bundle does not match the selected runtime or host architecture")]
    BundlePolicyMismatch,
    #[error("I/O failure while handling runtime bundle")]
    Io(#[from] io::Error),
}

struct RawBundle {
    manifest: Vec<u8>,
    signature: Vec<u8>,
    rootfs: HashedFile,
    sbom: HashedFile,
    licenses: BTreeMap<String, HashedFile>,
}
struct HashedFile {
    sha256: String,
    size_bytes: u64,
}

fn validate_manifest(
    manifest: &RuntimeBundleManifest,
    limits: &ImportLimits,
) -> Result<(), ImageError> {
    if manifest.format_version != FORMAT_VERSION
        || !valid_runtime(&manifest.runtime)
        || !matches!(manifest.arch.as_str(), "aarch64" | "x86_64")
        || manifest.libkrun_version != "1.19.4"
        || !valid_key_id(&manifest.signature.key_id)
        || semver::Version::parse(&manifest.runtime_version).is_err()
        || manifest.kernel_version.is_empty()
        || manifest.agent_protocol == 0
        || manifest.build_toolchain.is_empty()
        || manifest.rootfs.size_bytes > limits.max_rootfs_bytes
        || manifest.sbom.size_bytes > MAX_METADATA_BYTES
        || manifest.licenses.is_empty()
    {
        return Err(ImageError::InvalidManifest);
    }
    validate_sha256(&manifest.rootfs.sha256)?;
    validate_descriptor(&manifest.sbom, MAX_METADATA_BYTES)?;
    if manifest.licenses.len() > limits.max_entries {
        return Err(ImageError::InvalidManifest);
    }
    for (path, descriptor) in &manifest.licenses {
        if !path.starts_with("licenses/") || !safe_archive_path(path) {
            return Err(ImageError::InvalidManifest);
        }
        validate_descriptor(descriptor, MAX_LICENSE_DESCRIPTOR_BYTES)?;
    }
    Ok(())
}
fn validate_descriptor(value: &FileDescriptor, max_size: u64) -> Result<(), ImageError> {
    if value.size_bytes > max_size {
        return Err(ImageError::InvalidManifest);
    }
    validate_sha256(&value.sha256)
}
fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
fn valid_runtime(runtime: &str) -> bool {
    matches!(
        runtime,
        "node"
            | "python"
            | "golang"
            | "ruby"
            | "rust"
            | "node-alpine"
            | "python-alpine"
            | "golang-alpine"
            | "ruby-alpine"
            | "rust-alpine"
    )
}
fn validate_sha256(value: &str) -> Result<(), ImageError> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ImageError::InvalidSha256)
    }
}
fn valid_content_address(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn validate_box_id(value: &str) -> Result<(), ImageError> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| ImageError::InvalidBoxId)?;
    if id.get_version_num() != 7 || id.to_string() != value {
        return Err(ImageError::InvalidBoxId);
    }
    Ok(())
}
fn allowed_name(name: &str) -> bool {
    matches!(name, MANIFEST | SIGNATURE | ROOTFS | SBOM)
}

fn copy_rootfs(
    mut input: impl Read,
    destination: PathBuf,
    limits: &ImportLimits,
) -> Result<HashedFile, ImageError> {
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 1024 * 128];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(ImageError::ArchiveLimit)?;
        if total > limits.max_rootfs_bytes {
            return Err(ImageError::ArchiveLimit);
        }
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    output.sync_all()?;
    Ok(HashedFile {
        sha256: hex::encode(hash.finalize()),
        size_bytes: total,
    })
}
fn hash_bytes(bytes: &[u8]) -> HashedFile {
    HashedFile {
        sha256: hex::encode(Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
    }
}
fn to_descriptors(values: &BTreeMap<String, HashedFile>) -> BTreeMap<String, FileDescriptor> {
    values
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                FileDescriptor {
                    sha256: value.sha256.clone(),
                    size_bytes: value.size_bytes,
                },
            )
        })
        .collect()
}
fn copy_limited_file(
    mut input: impl Read,
    destination: PathBuf,
    limit: u64,
) -> Result<HashedFile, ImageError> {
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(ImageError::ArchiveLimit)?;
        if total > limit {
            return Err(ImageError::ArchiveLimit);
        }
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    output.sync_all()?;
    Ok(HashedFile {
        sha256: hex::encode(hash.finalize()),
        size_bytes: total,
    })
}
fn read_regular_no_follow(path: &Path, limit: u64) -> Result<Vec<u8>, ImageError> {
    let mut file = open_regular_no_follow(path)?;
    if file.metadata()?.len() > limit {
        return Err(ImageError::ArchiveLimit);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn open_regular_no_follow(path: &Path) -> Result<File, ImageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ImageError::UnsafeInput);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(ImageError::UnsafeInput);
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        Ok(File::open(path)?)
    }
}

fn read_installed_directory(
    directory: &Path,
    limits: &ImportLimits,
) -> Result<RawBundle, ImageError> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
            return Err(ImageError::UnsafeInput);
        }
        let name = entry
            .file_name()
            .to_str()
            .ok_or(ImageError::UnsafeInput)?
            .to_owned();
        let valid = if name == LICENSES {
            file_type.is_dir()
        } else {
            file_type.is_file() && allowed_name(&name)
        };
        if !valid || !names.insert(name) {
            return Err(ImageError::UnsafeInput);
        }
    }
    let required = BTreeSet::from([
        MANIFEST.to_owned(),
        SIGNATURE.to_owned(),
        ROOTFS.to_owned(),
        SBOM.to_owned(),
        LICENSES.to_owned(),
    ]);
    if names != required {
        return Err(ImageError::InvalidManifest);
    }
    Ok(RawBundle {
        manifest: read_regular_no_follow(&directory.join(MANIFEST), MAX_METADATA_BYTES)?,
        signature: read_regular_no_follow(&directory.join(SIGNATURE), MAX_METADATA_BYTES)?,
        rootfs: hash_open_file(
            open_regular_no_follow(&directory.join(ROOTFS))?,
            limits.max_rootfs_bytes,
        )?,
        sbom: hash_open_file(
            open_regular_no_follow(&directory.join(SBOM))?,
            MAX_METADATA_BYTES,
        )?,
        licenses: hash_license_tree(&directory.join(LICENSES), limits)?,
    })
}

fn hash_license_tree(
    source: &Path,
    limits: &ImportLimits,
) -> Result<BTreeMap<String, HashedFile>, ImageError> {
    if !matches!(fs::symlink_metadata(source), Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink())
    {
        return Err(ImageError::UnsafeInput);
    }
    let mut result = BTreeMap::new();
    fn walk(
        path: &Path,
        root: &Path,
        result: &mut BTreeMap<String, HashedFile>,
        limits: &ImportLimits,
    ) -> Result<(), ImageError> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(ImageError::UnsafeInput);
            }
            if file_type.is_dir() {
                walk(&entry.path(), root, result, limits)?;
                continue;
            }
            if !file_type.is_file() || result.len() >= limits.max_entries {
                return Err(ImageError::UnsafeInput);
            }
            let key = Path::new(LICENSES)
                .join(
                    entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|_| ImageError::UnsafeInput)?,
                )
                .to_str()
                .ok_or(ImageError::UnsafeInput)?
                .to_owned();
            if !safe_archive_path(&key) || result.contains_key(&key) {
                return Err(ImageError::UnsafeInput);
            }
            result.insert(
                key,
                hash_open_file(
                    open_regular_no_follow(&entry.path())?,
                    MAX_LICENSE_DESCRIPTOR_BYTES,
                )?,
            );
        }
        Ok(())
    }
    walk(source, source, &mut result, limits)?;
    if result.is_empty() {
        return Err(ImageError::InvalidManifest);
    }
    Ok(result)
}
fn copy_license_tree(
    source: &Path,
    destination: &Path,
    limits: &ImportLimits,
) -> Result<BTreeMap<String, HashedFile>, ImageError> {
    if !matches!(fs::symlink_metadata(source), Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink())
    {
        return Err(ImageError::UnsafeInput);
    }
    let mut result = BTreeMap::new();
    fn walk(
        src: &Path,
        dst: &Path,
        root: &Path,
        result: &mut BTreeMap<String, HashedFile>,
        limits: &ImportLimits,
    ) -> Result<(), ImageError> {
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let path = entry.path();
            if ty.is_symlink() {
                return Err(ImageError::UnsafeInput);
            }
            if ty.is_dir() {
                walk(&path, &dst.join(entry.file_name()), root, result, limits)?;
                continue;
            }
            if !ty.is_file() || result.len() >= limits.max_entries {
                return Err(ImageError::UnsafeInput);
            }
            let key = Path::new(LICENSES)
                .join(
                    path.strip_prefix(root)
                        .map_err(|_| ImageError::UnsafeInput)?,
                )
                .to_string_lossy()
                .into_owned();
            if !safe_archive_path(&key) {
                return Err(ImageError::UnsafeInput);
            }
            fs::create_dir_all(dst)?;
            let hashed = copy_limited_file(
                open_regular_no_follow(&path)?,
                dst.join(entry.file_name()),
                MAX_LICENSE_DESCRIPTOR_BYTES,
            )?;
            if result.insert(key, hashed).is_some() {
                return Err(ImageError::UnsafeInput);
            }
        }
        Ok(())
    }
    walk(source, destination, source, &mut result, limits)?;
    if result.is_empty() {
        return Err(ImageError::InvalidManifest);
    }
    Ok(result)
}
fn make_read_only(path: &Path) -> Result<(), ImageError> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}
#[cfg(unix)]
fn open_directory_no_follow(path: &Path) -> Result<File, ImageError> {
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            io::{AsRawFd, FromRawFd},
        },
    };
    let path = path.canonicalize()?;
    if !path.is_absolute() {
        return Err(ImageError::InvalidDestination);
    }
    let mut directory = OpenOptions::new().read(true).open("/")?;
    for component in path.components() {
        let Component::Normal(component) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(ImageError::InvalidDestination);
        };
        let component =
            CString::new(component.as_bytes()).map_err(|_| ImageError::InvalidDestination)?;
        // SAFETY: the current directory FD and CString are live; O_NOFOLLOW
        // rejects every symlink component.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(ImageError::Io(io::Error::last_os_error()));
        }
        // SAFETY: successful openat returned a fresh owned descriptor.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}
#[cfg(not(unix))]
fn open_directory_no_follow(path: &Path) -> Result<File, ImageError> {
    Ok(File::open(path)?)
}

#[cfg(unix)]
fn ensure_directory_no_follow(path: &Path) -> Result<File, ImageError> {
    fs::create_dir_all(path)?;
    open_directory_no_follow(path)
}

#[cfg(not(unix))]
fn ensure_directory_no_follow(path: &Path) -> Result<File, ImageError> {
    fs::create_dir_all(path)?;
    open_directory_no_follow(path)
}
#[cfg(unix)]
fn create_relative_file_no_follow(root: &File, relative: &Path) -> Result<File, ImageError> {
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            io::{AsRawFd, FromRawFd},
        },
    };
    validate_relative_destination(relative)?;
    let parts: Vec<_> = relative.components().collect();
    if parts.is_empty() {
        return Err(ImageError::InvalidDestination);
    }
    let mut dirfd = root.as_raw_fd();
    let mut owned = Vec::new();
    for component in &parts[..parts.len() - 1] {
        let name = match component {
            Component::Normal(name) => {
                CString::new(name.as_bytes()).map_err(|_| ImageError::InvalidDestination)?
            }
            _ => return Err(ImageError::InvalidDestination),
        };
        let mkdir = unsafe { libc::mkdirat(dirfd, name.as_ptr(), 0o700) };
        if mkdir != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
            return Err(ImageError::Io(io::Error::last_os_error()));
        }
        let next = unsafe {
            libc::openat(
                dirfd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(ImageError::InvalidDestination);
        }
        owned.push(unsafe { File::from_raw_fd(next) });
        dirfd = owned.last().expect("just pushed").as_raw_fd();
    }
    let leaf = match parts.last().expect("checked nonempty") {
        Component::Normal(name) => {
            CString::new(name.as_bytes()).map_err(|_| ImageError::InvalidDestination)?
        }
        _ => return Err(ImageError::InvalidDestination),
    };
    let fd = unsafe {
        libc::openat(
            dirfd,
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return match io::Error::last_os_error().kind() {
            io::ErrorKind::AlreadyExists => Err(ImageError::DestinationExists),
            _ => Err(ImageError::InvalidDestination),
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(not(unix))]
fn create_relative_file_no_follow(_root: &File, _relative: &Path) -> Result<File, ImageError> {
    Err(ImageError::InvalidDestination)
}

fn validate_relative_destination(relative: &Path) -> Result<(), ImageError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ImageError::InvalidDestination);
    }
    Ok(())
}

#[cfg(unix)]
fn create_box_directory(boxes: &File, box_id: &str) -> Result<File, ImageError> {
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd},
    };
    let name = CString::new(box_id).map_err(|_| ImageError::InvalidBoxId)?;
    // SAFETY: boxes is a retained directory FD and name is NUL-terminated.
    if unsafe { libc::mkdirat(boxes.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return match io::Error::last_os_error().kind() {
            io::ErrorKind::AlreadyExists => Err(ImageError::DestinationExists),
            _ => Err(ImageError::Io(io::Error::last_os_error())),
        };
    }
    // SAFETY: the just-created directory is opened without following links.
    let fd = unsafe {
        libc::openat(
            boxes.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ImageError::InvalidDestination);
    }
    // SAFETY: successful openat returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn create_box_directory(_boxes: &File, _box_id: &str) -> Result<File, ImageError> {
    Err(ImageError::InvalidDestination)
}

#[cfg(unix)]
fn clone_private_file(
    source: &mut File,
    destination_directory: &File,
    name: &str,
) -> Result<CloneMethod, ImageError> {
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd},
    };
    let name = CString::new(name).map_err(|_| ImageError::InvalidDestination)?;
    source.seek(SeekFrom::Start(0))?;

    #[cfg(target_os = "macos")]
    {
        // SAFETY: source/destination FDs remain live and clonefileat creates
        // the validated leaf exclusively within the retained directory.
        if unsafe {
            libc::fclonefileat(
                source.as_raw_fd(),
                destination_directory.as_raw_fd(),
                name.as_ptr(),
                0,
            )
        } == 0
        {
            make_private_clone_writable(destination_directory, &name)?;
            return Ok(CloneMethod::CopyOnWrite);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            return Err(ImageError::DestinationExists);
        }
        if !matches!(
            error.raw_os_error(),
            Some(code) if code == libc::ENOTSUP || code == libc::EXDEV || code == libc::EINVAL
        ) {
            return Err(ImageError::Io(error));
        }
    }

    // SAFETY: destination is created exclusively beneath the retained Box FD.
    let fd = unsafe {
        libc::openat(
            destination_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return match io::Error::last_os_error().kind() {
            io::ErrorKind::AlreadyExists => Err(ImageError::DestinationExists),
            _ => Err(ImageError::Io(io::Error::last_os_error())),
        };
    }
    // SAFETY: successful openat returned a fresh owned descriptor.
    let mut destination = unsafe { File::from_raw_fd(fd) };

    #[cfg(target_os = "linux")]
    {
        // SAFETY: FICLONE receives live regular-file descriptors.
        if unsafe { libc::ioctl(destination.as_raw_fd(), libc::FICLONE, source.as_raw_fd()) } == 0 {
            destination.sync_all()?;
            return Ok(CloneMethod::CopyOnWrite);
        }
        destination.set_len(0)?;
        destination.seek(SeekFrom::Start(0))?;
        source.seek(SeekFrom::Start(0))?;
    }

    sparse_copy(source, &mut destination)?;
    destination.sync_all()?;
    Ok(CloneMethod::Copied)
}

#[cfg(unix)]
fn make_private_clone_writable(
    destination_directory: &File,
    name: &std::ffi::CStr,
) -> Result<(), ImageError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: the clone was created exclusively below this retained dirfd;
    // O_NOFOLLOW prevents a substituted final-component symlink.
    let fd = unsafe {
        libc::openat(
            destination_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    // SAFETY: successful openat returned a fresh descriptor owned here.
    let file = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn clone_private_file(
    _source: &mut File,
    _destination_directory: &File,
    _name: &str,
) -> Result<CloneMethod, ImageError> {
    Err(ImageError::InvalidDestination)
}

fn sparse_copy(source: &mut File, destination: &mut File) -> Result<(), ImageError> {
    source.seek(SeekFrom::Start(0))?;
    let mut length = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or(ImageError::ArchiveLimit)?;
        if buffer[..count].iter().all(|byte| *byte == 0) {
            destination.seek(SeekFrom::Current(count as i64))?;
        } else {
            destination.write_all(&buffer[..count])?;
        }
    }
    destination.set_len(length)?;
    Ok(())
}

#[cfg(unix)]
fn cleanup_new_box_directory(boxes: &File, box_directory: &File, box_id: &str) {
    use std::{ffi::CString, os::fd::AsRawFd};
    let data = CString::new(DATA_DISK).expect("constant has no NUL");
    let box_id = CString::new(box_id).expect("validated UUID has no NUL");
    // SAFETY: only the known leaf and retained newly-created directory are used.
    unsafe {
        libc::unlinkat(box_directory.as_raw_fd(), data.as_ptr(), 0);
        libc::unlinkat(boxes.as_raw_fd(), box_id.as_ptr(), libc::AT_REMOVEDIR);
    }
}

#[cfg(not(unix))]
fn cleanup_new_box_directory(_boxes: &File, _box_directory: &File, _box_id: &str) {}

#[cfg(unix)]
fn inspect_box_directory(boxes: &File, box_id: &str) -> Result<bool, ImageError> {
    use std::{
        ffi::{CStr, CString},
        os::fd::{AsRawFd, FromRawFd},
    };
    let name = CString::new(box_id).map_err(|_| ImageError::InvalidBoxId)?;
    // SAFETY: boxes/name are live; O_NOFOLLOW rejects a UUID-named symlink.
    let fd = unsafe {
        libc::openat(
            boxes.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(ImageError::UnsafeBoxDirectory)
        };
    }
    // SAFETY: successful openat returned a fresh descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    // SAFETY: fdopendir consumes the duplicated directory descriptor.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not consume on failure.
        unsafe { libc::close(duplicate) };
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    let mut has_data = false;
    loop {
        // SAFETY: stream remains live until closedir below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated for the returned live dirent.
        let entry_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(entry_name, b"." | b"..") {
            continue;
        }
        if entry_name != DATA_DISK.as_bytes() || has_data {
            // SAFETY: stream is live and closed exactly once.
            unsafe { libc::closedir(stream) };
            return Err(ImageError::UnsafeBoxDirectory);
        }
        has_data = true;
    }
    // SAFETY: stream is live and closed exactly once.
    unsafe { libc::closedir(stream) };
    if !has_data {
        return Err(ImageError::UnsafeBoxDirectory);
    }
    let data = CString::new(DATA_DISK).expect("constant has no NUL");
    // SAFETY: zeroed stat is valid output storage and the leaf is not followed.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            data.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
    {
        return Err(ImageError::UnsafeBoxDirectory);
    }
    Ok(true)
}

#[cfg(not(unix))]
fn inspect_box_directory(_boxes: &File, _box_id: &str) -> Result<bool, ImageError> {
    Err(ImageError::InvalidDestination)
}

#[cfg(unix)]
fn open_private_data_file(root: &File, id: &str) -> Result<File, ImageError> {
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd},
    };
    let id = CString::new(id).map_err(|_| ImageError::InvalidBoxId)?;
    // SAFETY: root is a retained directory capability and O_NOFOLLOW rejects aliases.
    let directory_fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            id.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if directory_fd < 0 {
        return Err(ImageError::UnsafeBoxDirectory);
    }
    // SAFETY: successful openat returned a fresh owned descriptor.
    let directory = unsafe { File::from_raw_fd(directory_fd) };
    let name = CString::new(DATA_DISK).expect("constant has no NUL");
    // SAFETY: the retained directory and constant leaf are valid for openat.
    let file_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if file_fd < 0 {
        return Err(ImageError::UnsafeBoxDirectory);
    }
    // SAFETY: successful openat returned a fresh owned descriptor.
    let file = unsafe { File::from_raw_fd(file_fd) };
    let metadata = file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(ImageError::UnsafeBoxDirectory);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_data_file(_root: &File, _id: &str) -> Result<File, ImageError> {
    Err(ImageError::InvalidDestination)
}

#[cfg(unix)]
fn remove_box_directory(boxes: &File, box_id: &str) -> Result<(), ImageError> {
    use std::{
        ffi::{CStr, CString},
        os::fd::{AsRawFd, FromRawFd},
    };
    let name = CString::new(box_id).map_err(|_| ImageError::InvalidBoxId)?;
    // SAFETY: boxes/name are live; O_NOFOLLOW rejects a UUID-named symlink.
    let fd = unsafe {
        libc::openat(
            boxes.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(ImageError::UnsafeBoxDirectory)
        };
    }
    // SAFETY: successful openat returned a fresh descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    // SAFETY: fdopendir consumes the duplicated directory descriptor.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not consume on failure.
        unsafe { libc::close(duplicate) };
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    let mut has_data = false;
    loop {
        // SAFETY: stream remains live until closedir below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated for the returned live dirent.
        let entry_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(entry_name, b"." | b"..") {
            continue;
        }
        if entry_name != DATA_DISK.as_bytes() || has_data {
            // SAFETY: stream is live and closed exactly once.
            unsafe { libc::closedir(stream) };
            return Err(ImageError::UnsafeBoxDirectory);
        }
        has_data = true;
    }
    // SAFETY: stream is live and closed exactly once.
    unsafe { libc::closedir(stream) };
    if has_data {
        let data = CString::new(DATA_DISK).expect("constant has no NUL");
        // SAFETY: zeroed `stat` is valid output storage; fstatat does not retain
        // it and AT_SYMLINK_NOFOLLOW inspects rather than follows the leaf.
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                data.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_nlink != 1
        {
            return Err(ImageError::UnsafeBoxDirectory);
        }
        // SAFETY: directory/data identify the validated regular single-link file.
        if unsafe { libc::unlinkat(directory.as_raw_fd(), data.as_ptr(), 0) } != 0 {
            return Err(ImageError::Io(io::Error::last_os_error()));
        }
    }
    // SAFETY: name identifies the retained, now-empty directory below boxes.
    if unsafe { libc::unlinkat(boxes.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(ImageError::UnsafeBoxDirectory);
    }
    Ok(())
}

#[cfg(not(unix))]
fn remove_box_directory(_boxes: &File, _box_id: &str) -> Result<(), ImageError> {
    Err(ImageError::InvalidDestination)
}

fn hash_file(input: &mut File, limit: u64) -> Result<HashedFile, ImageError> {
    input.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(ImageError::ArchiveLimit)?;
        if total > limit {
            return Err(ImageError::ArchiveLimit);
        }
        hash.update(&buffer[..count]);
    }
    input.seek(SeekFrom::Start(0))?;
    Ok(HashedFile {
        sha256: hex::encode(hash.finalize()),
        size_bytes: total,
    })
}

fn hash_open_file(mut input: File, limit: u64) -> Result<HashedFile, ImageError> {
    hash_file(&mut input, limit)
}

fn sha256_file(path: &Path, limit: u64) -> Result<HashedFile, ImageError> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 1024 * 128];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(ImageError::ArchiveLimit)?;
        if total > limit {
            return Err(ImageError::ArchiveLimit);
        }
        hash.update(&buffer[..count]);
    }
    Ok(HashedFile {
        sha256: hex::encode(hash.finalize()),
        size_bytes: total,
    })
}
fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

fn read_tar(
    mut reader: impl Read,
    staging: &Path,
    limits: &ImportLimits,
) -> Result<RawBundle, ImageError> {
    let mut manifest = None;
    let mut signature = None;
    let mut rootfs = None;
    let mut sbom = None;
    let mut licenses = BTreeMap::new();
    let mut total = 0_u64;
    let mut entries = 0_usize;
    loop {
        let mut header = [0_u8; 512];
        if !read_exact_or_eof(&mut reader, &mut header)? {
            break;
        }
        if header.iter().all(|b| *b == 0) {
            let mut second = [0_u8; 512];
            if !read_exact_or_eof(&mut reader, &mut second)? || !second.iter().all(|b| *b == 0) {
                return Err(ImageError::UnsafeInput);
            }
            break;
        }
        entries += 1;
        if entries > limits.max_entries {
            return Err(ImageError::ArchiveLimit);
        }
        let name = tar_name(&header)?;
        let size = tar_number(&header[124..136])?;
        let kind = header[156];
        if kind != 0 && kind != b'0' {
            return Err(ImageError::UnsafeInput);
        }
        let is_license = name.starts_with("licenses/") && safe_archive_path(&name);
        if !(allowed_name(&name) || is_license) || !safe_archive_path(&name) {
            return Err(ImageError::UnsafeInput);
        }
        total = total.checked_add(size).ok_or(ImageError::ArchiveLimit)?;
        if total > limits.max_unpacked_bytes {
            return Err(ImageError::ArchiveLimit);
        }
        if name == MANIFEST || name == SIGNATURE || name == SBOM {
            if size > MAX_METADATA_BYTES {
                return Err(ImageError::ArchiveLimit);
            }
            let mut bytes = vec![0; size as usize];
            reader.read_exact(&mut bytes)?;
            if name == MANIFEST {
                if manifest.replace(bytes).is_some() {
                    return Err(ImageError::UnsafeInput);
                }
            } else if name == SIGNATURE {
                if signature.replace(bytes).is_some() {
                    return Err(ImageError::UnsafeInput);
                }
            } else if name == SBOM {
                let target = staging.join(SBOM);
                fs::write(&target, &bytes)?;
                if sbom.replace(hash_bytes(&bytes)).is_some() {
                    return Err(ImageError::UnsafeInput);
                }
            } else {
                unreachable!("only known metadata names reach this branch")
            }
        } else if name == ROOTFS {
            if rootfs.is_some() {
                return Err(ImageError::UnsafeInput);
            }
            let mut limited = (&mut reader).take(size);
            let copied = copy_rootfs(&mut limited, staging.join(ROOTFS), limits)?;
            if limited.limit() != 0 {
                return Err(ImageError::UnsafeInput);
            }
            rootfs = Some(copied);
        } else {
            if size > MAX_LICENSE_DESCRIPTOR_BYTES || licenses.contains_key(&name) {
                return Err(ImageError::ArchiveLimit);
            }
            let target = staging.join(&name);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut limited = (&mut reader).take(size);
            let copied = copy_limited_file(&mut limited, target, MAX_LICENSE_DESCRIPTOR_BYTES)?;
            if limited.limit() != 0 {
                return Err(ImageError::UnsafeInput);
            }
            licenses.insert(name, copied);
        }
        let padding = (512 - size % 512) % 512;
        let mut padding_bytes = vec![0_u8; padding as usize];
        reader.read_exact(&mut padding_bytes)?;
    }
    Ok(RawBundle {
        manifest: manifest.ok_or(ImageError::InvalidManifest)?,
        signature: signature.ok_or(ImageError::InvalidSignature)?,
        rootfs: rootfs.ok_or(ImageError::InvalidManifest)?,
        sbom: sbom.ok_or(ImageError::InvalidManifest)?,
        licenses,
    })
}
fn read_exact_or_eof(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<bool> {
    let mut read = 0;
    while read < buffer.len() {
        let n = reader.read(&mut buffer[read..])?;
        if n == 0 {
            if read == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated tar",
            ));
        }
        read += n;
    }
    Ok(true)
}
fn tar_name(header: &[u8; 512]) -> Result<String, ImageError> {
    let bytes = &header[..100];
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| ImageError::UnsafeInput)
}
fn tar_number(bytes: &[u8]) -> Result<u64, ImageError> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        // GNU base-256 uses the high bit as the representation marker and the
        // next bit as the signed value bit. Phase 1 accepts only the canonical
        // fixed-width nonnegative form (0x80 followed by the magnitude), and
        // rejects negative, alternate marker, or u64-overflow encodings.
        if bytes[0] != 0x80 {
            return Err(ImageError::UnsafeInput);
        }
        return bytes[1..].iter().try_fold(0_u64, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(u64::from(*byte)))
                .ok_or(ImageError::UnsafeInput)
        });
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ImageError::UnsafeInput)?
        .trim_matches(char::from(0))
        .trim();
    u64::from_str_radix(if text.is_empty() { "0" } else { text }, 8)
        .map_err(|_| ImageError::UnsafeInput)
}
fn safe_archive_path(name: &str) -> bool {
    !name.is_empty()
        && Path::new(name)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

fn sync_tree(path: &Path) -> Result<(), ImageError> {
    for name in [ROOTFS, MANIFEST, SIGNATURE, SBOM] {
        let file = File::open(path.join(name))?;
        file.sync_all()?;
    }
    fn sync_licenses(path: &Path) -> Result<(), ImageError> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                sync_licenses(&entry.path())?;
            } else {
                File::open(entry.path())?.sync_all()?;
            }
        }
        sync_dir(path)
    }
    sync_licenses(&path.join(LICENSES))?;
    sync_dir(path)
}
#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), ImageError> {
    File::open(path)?.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<(), ImageError> {
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{sync::Arc, thread};
    use tempfile::TempDir;

    #[test]
    fn tar_numbers_accept_canonical_twenty_gib_base256_and_reject_unsafe_forms() {
        let mut encoded = [0_u8; 12];
        encoded[0] = 0x80;
        encoded[4..].copy_from_slice(&(20_u64 * 1024 * 1024 * 1024).to_be_bytes());
        assert_eq!(tar_number(&encoded).unwrap(), 20_u64 * 1024 * 1024 * 1024);

        let mut negative = encoded;
        negative[0] = 0xc0;
        assert!(matches!(
            tar_number(&negative),
            Err(ImageError::UnsafeInput)
        ));
        let overflow = [0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            tar_number(&overflow),
            Err(ImageError::UnsafeInput)
        ));
    }

    fn bundle(dir: &Path, rootfs: &[u8]) -> (TrustedEd25519Keys, Vec<u8>) {
        bundle_with_key_id(dir, rootfs, "test")
    }

    fn bundle_with_key_id(
        dir: &Path,
        rootfs: &[u8],
        key_id: &str,
    ) -> (TrustedEd25519Keys, Vec<u8>) {
        bundle_with_version(dir, rootfs, key_id, "22.0.0")
    }

    fn bundle_with_version(
        dir: &Path,
        rootfs: &[u8],
        key_id: &str,
        runtime_version: &str,
    ) -> (TrustedEd25519Keys, Vec<u8>) {
        bundle_with_version_features(dir, rootfs, key_id, runtime_version, BTreeSet::new())
    }

    fn bundle_with_version_features(
        dir: &Path,
        rootfs: &[u8],
        key_id: &str,
        runtime_version: &str,
        features: BTreeSet<String>,
    ) -> (TrustedEd25519Keys, Vec<u8>) {
        fs::write(dir.join(ROOTFS), rootfs).unwrap();
        fs::write(dir.join(SBOM), b"{}").unwrap();
        fs::create_dir(dir.join(LICENSES)).unwrap();
        fs::write(dir.join(LICENSES).join("NOTICE"), b"notice").unwrap();
        let key = Ed25519KeyPair::from_pkcs8(
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let sha = hex::encode(Sha256::digest(rootfs));
        let manifest = serde_json::to_vec(&RuntimeBundleManifest {
            format_version: 1,
            runtime: "node".into(),
            runtime_version: runtime_version.into(),
            arch: "aarch64".into(),
            libkrun_version: "1.19.4".into(),
            kernel_version: "6.1".into(),
            agent_protocol: 1,
            build_toolchain: "test".into(),
            features,
            rootfs: RootfsDescriptor {
                sha256: sha,
                size_bytes: rootfs.len() as u64,
            },
            sbom: FileDescriptor {
                sha256: hex::encode(Sha256::digest(b"{}")),
                size_bytes: 2,
            },
            licenses: BTreeMap::from([(
                "licenses/NOTICE".into(),
                FileDescriptor {
                    sha256: hex::encode(Sha256::digest(b"notice")),
                    size_bytes: 6,
                },
            )]),
            signature: SignatureMetadata {
                algorithm: "ed25519".into(),
                key_id: key_id.into(),
            },
        })
        .unwrap();
        fs::write(dir.join(MANIFEST), &manifest).unwrap();
        fs::write(
            dir.join(SIGNATURE),
            BASE64.encode(key.sign(&manifest).as_ref()),
        )
        .unwrap();
        let mut keys = BTreeMap::new();
        keys.insert(key_id.into(), key.public_key().as_ref().to_vec());
        (TrustedEd25519Keys::new(keys), manifest)
    }
    fn manager(tmp: &TempDir, keys: TrustedEd25519Keys) -> RuntimeBundleManager {
        RuntimeBundleManager::new(
            tmp.path().join("images"),
            tmp.path().join("boxes"),
            tmp.path().join("snapshots"),
            keys,
            ImportLimits::default(),
        )
    }

    #[test]
    fn signed_license_aggregates_have_a_bounded_browser_bundle_allowance() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (_, manifest_bytes) = bundle(&source, b"rootfs");
        let mut manifest: RuntimeBundleManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        manifest
            .licenses
            .get_mut("licenses/NOTICE")
            .unwrap()
            .size_bytes = 7 * 1024 * 1024;
        validate_manifest(&manifest, &ImportLimits::default()).unwrap();
        manifest
            .licenses
            .get_mut("licenses/NOTICE")
            .unwrap()
            .size_bytes = MAX_LICENSE_DESCRIPTOR_BYTES + 1;
        assert!(matches!(
            validate_manifest(&manifest, &ImportLimits::default()),
            Err(ImageError::InvalidManifest)
        ));
    }

    #[test]
    fn imports_idempotently_and_clone_does_not_mutate_base() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (keys, _) = bundle(&source, b"base image");
        let manager = manager(&tmp, keys);
        let first = manager
            .import(ImportSource::Directory(source.clone()))
            .unwrap();
        let second = manager.import(ImportSource::Directory(source)).unwrap();
        assert!(!first.already_present);
        assert!(second.already_present);
        let disk = Path::new("a.raw");
        manager
            .clone_base_image(&first.rootfs_sha256, disk)
            .unwrap();
        fs::write(tmp.path().join("boxes").join(disk), b"changed disk").unwrap();
        assert_eq!(fs::read(first.path.join(ROOTFS)).unwrap(), b"base image");
    }

    #[test]
    fn rejects_tamper_and_missing_trust() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (keys, manifest) = bundle(&source, b"safe");
        fs::write(source.join(ROOTFS), b"tampered").unwrap();
        assert!(matches!(
            manager(&tmp, keys).import(ImportSource::Directory(source.clone())),
            Err(ImageError::RootfsHashMismatch)
        ));
        fs::write(source.join(ROOTFS), b"safe").unwrap();
        fs::write(source.join(MANIFEST), manifest).unwrap();
        assert!(matches!(
            manager(&tmp, TrustedEd25519Keys::default()).import(ImportSource::Directory(source)),
            Err(ImageError::UntrustedSigningKey)
        ));
    }

    #[test]
    fn policy_mismatch_is_rejected_before_publication() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (keys, _) = bundle(&source, b"safe");
        let manager = manager(&tmp, keys);
        assert!(matches!(
            manager.import_with_policy(
                ImportSource::Directory(source),
                Some("python"),
                Some("aarch64")
            ),
            Err(ImageError::BundlePolicyMismatch)
        ));
        assert_eq!(
            fs::read_dir(tmp.path().join("images"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
                .count(),
            0
        );
    }

    #[test]
    fn concurrent_imports_publish_one_content_address() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (keys, _) = bundle(&source, b"same");
        let manager = Arc::new(manager(&tmp, keys));
        let one = manager.clone();
        let source_one = source.clone();
        let handle =
            thread::spawn(move || one.import(ImportSource::Directory(source_one)).unwrap());
        let two = manager.import(ImportSource::Directory(source)).unwrap();
        let one = handle.join().unwrap();
        assert_ne!(one.already_present, two.already_present);
        assert_eq!(one.rootfs_sha256, two.rootfs_sha256);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_input() {
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (keys, _) = bundle(&source, b"safe");
        fs::remove_file(source.join(ROOTFS)).unwrap();
        symlink("/etc/passwd", source.join(ROOTFS)).unwrap();
        assert!(matches!(
            manager(&tmp, keys).import(ImportSource::Directory(source)),
            Err(ImageError::UnsafeInput)
        ));
    }

    #[test]
    fn clone_rejects_escape_and_detects_tampered_published_base() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (keys, _) = bundle(&source, b"safe base");
        let manager = manager(&tmp, keys);
        let imported = manager.import(ImportSource::Directory(source)).unwrap();
        assert!(matches!(
            manager.clone_base_image(&imported.rootfs_sha256, Path::new("../escape.raw")),
            Err(ImageError::InvalidDestination)
        ));
        fs::set_permissions(
            imported.path.join(ROOTFS),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(imported.path.join(ROOTFS), b"tampered").unwrap();
        assert!(matches!(
            manager.clone_base_image(&imported.rootfs_sha256, Path::new("safe.raw")),
            Err(ImageError::BaseImageTampered)
        ));
    }

    #[test]
    fn resolves_revalidates_and_clones_uuid_v7_private_root() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (keys, _) = bundle(&source, b"ext4 private root fixture");
        let manager = manager(&tmp, keys);
        let imported = manager.import(ImportSource::Directory(source)).unwrap();

        let resolved = manager.resolve_installed("node", "aarch64").unwrap();
        assert!(resolved.rootfs_path.is_absolute());
        assert_eq!(resolved.rootfs_sha256, imported.rootfs_sha256);
        assert!(manager.ready_for("node", "aarch64").unwrap());
        assert!(!manager.ready_for("python", "aarch64").unwrap());

        let box_id = "01890f3e-7b2a-7cc1-8000-000000000001";
        let disks = manager
            .clone_runtime_for_box(box_id, "node", "aarch64")
            .unwrap();
        assert_eq!(disks.base_rootfs.path, resolved.rootfs_path);
        assert_eq!(
            fs::read(&disks.data_disk.path).unwrap(),
            b"ext4 private root fixture"
        );
        assert_eq!(
            fs::metadata(&disks.data_disk.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(matches!(
            manager.clone_runtime_for_box(box_id, "node", "aarch64"),
            Err(ImageError::DestinationExists)
        ));
        let sized_id = "01890f3e-7b2a-7cc1-8000-000000000002";
        let sized = manager
            .clone_runtime_for_box_sized(
                sized_id,
                "node",
                "aarch64",
                b"ext4 private root fixture".len() as u64,
            )
            .unwrap();
        assert_eq!(
            fs::metadata(sized.data_disk.path).unwrap().len(),
            b"ext4 private root fixture".len() as u64
        );
        let mismatched_id = "01890f3e-7b2a-7cc1-8000-000000000003";
        assert!(matches!(
            manager.clone_runtime_for_box_sized(mismatched_id, "node", "aarch64", 4096),
            Err(ImageError::DiskSizeMismatch)
        ));
        assert!(!manager.boxes_dir.join(mismatched_id).exists());
        assert!(matches!(
            manager.clone_runtime_for_box(
                "550e8400-e29b-41d4-a716-446655440000",
                "node",
                "aarch64"
            ),
            Err(ImageError::InvalidBoxId)
        ));
        manager.remove_box_disk(box_id).unwrap();
        manager.remove_box_disk(box_id).unwrap();
    }

    #[test]
    fn snapshot_disk_is_hashed_cloned_restored_and_deleted_by_descriptor() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir(&source).unwrap();
        let (keys, manifest) =
            bundle_with_key_id(&source, b"ext4 private root fixture", "snapshot-key");
        let manifest: RuntimeBundleManifest = serde_json::from_slice(&manifest).unwrap();
        let manager = manager(&tmp, keys);
        manager.import(ImportSource::Directory(source)).unwrap();
        let box_id = "01890f3e-7b2a-7cc1-8000-000000000011";
        let snapshot_id = "01890f3e-7b2a-7cc1-8000-000000000012";
        let restored_id = "01890f3e-7b2a-7cc1-8000-000000000013";
        manager
            .clone_runtime_for_box(box_id, "node", "aarch64")
            .unwrap();
        let snapshot = manager.create_snapshot_disk(box_id, snapshot_id).unwrap();
        assert_eq!(snapshot.sha256, manifest.rootfs.sha256);
        assert_eq!(snapshot.size_bytes, manifest.rootfs.size_bytes);
        assert_eq!(snapshot.relative_path, format!("{snapshot_id}/{DATA_DISK}"));
        manager.remove_box_disk(box_id).unwrap();
        manager
            .clone_snapshot_for_box(snapshot_id, restored_id, &snapshot.sha256)
            .unwrap();
        assert_eq!(
            fs::read(tmp.path().join("boxes").join(restored_id).join(DATA_DISK)).unwrap(),
            b"ext4 private root fixture"
        );
        manager.remove_snapshot_disk(snapshot_id).unwrap();
        manager.remove_snapshot_disk(snapshot_id).unwrap();
    }

    #[test]
    fn resolve_rejects_tampered_metadata_and_ambiguous_matches() {
        let tmp = TempDir::new().unwrap();
        let first = tmp.path().join("first");
        fs::create_dir(&first).unwrap();
        let (keys, _) = bundle(&first, b"one");
        let tamper_manager = manager(&tmp, keys.clone());
        let imported = tamper_manager
            .import(ImportSource::Directory(first))
            .unwrap();
        fs::write(imported.path.join(SBOM), b"tampered").unwrap();
        assert!(matches!(
            tamper_manager.resolve_installed("node", "aarch64"),
            Err(ImageError::RootfsHashMismatch)
        ));

        let tmp = TempDir::new().unwrap();
        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let (first_keys, _) = bundle_with_key_id(&first, b"one", "first");
        let (second_keys, _) = bundle_with_key_id(&second, b"two", "second");
        let mut trusted = first_keys.0;
        trusted.extend(second_keys.0);
        let manager = manager(&tmp, TrustedEd25519Keys::new(trusted));
        manager.import(ImportSource::Directory(first)).unwrap();
        manager.import(ImportSource::Directory(second)).unwrap();
        assert!(matches!(
            manager.resolve_installed("node", "aarch64"),
            Err(ImageError::AmbiguousBundle)
        ));
        assert!(
            manager
                .missing_from_catalog(&["node"], "aarch64")
                .unwrap()
                .is_empty(),
            "a single catalog scan reports availability even while selection requires a pinned version"
        );
    }

    #[test]
    fn preferred_binding_uses_highest_semver_and_sha_resolution_revalidates_identity() {
        let tmp = TempDir::new().unwrap();
        let old = tmp.path().join("old");
        let new = tmp.path().join("new");
        fs::create_dir(&old).unwrap();
        fs::create_dir(&new).unwrap();
        let (old_keys, _) = bundle_with_version(&old, b"old", "old", "21.9.0");
        let (new_keys, _) = bundle_with_version(&new, b"new", "new", "22.1.0");
        let mut trusted = old_keys.0;
        trusted.extend(new_keys.0);
        let manager = manager(&tmp, TrustedEd25519Keys::new(trusted));
        let old = manager.import(ImportSource::Directory(old)).unwrap();
        let new = manager.import(ImportSource::Directory(new)).unwrap();

        let preferred = manager.resolve_preferred("node", "aarch64").unwrap();
        assert_eq!(preferred.rootfs_sha256, new.rootfs_sha256);
        let pinned_old = manager
            .resolve_installed_by_sha(&old.rootfs_sha256, "node", "21.9.0", "aarch64")
            .unwrap();
        assert_eq!(pinned_old.rootfs_sha256, old.rootfs_sha256);
        let disks = manager
            .clone_runtime_for_box_binding_sized(
                "01890f3e-7b2a-7cc1-8000-000000000009",
                &old.rootfs_sha256,
                "21.9.0",
                "aarch64",
                3,
            )
            .unwrap();
        assert_eq!(disks.base_rootfs.source_sha256, old.rootfs_sha256);
        assert!(matches!(
            manager.resolve_installed_by_sha(&old.rootfs_sha256, "node", "22.1.0", "aarch64"),
            Err(ImageError::BundlePolicyMismatch)
        ));
    }

    #[test]
    fn browser_binding_requires_authenticated_browser_feature() {
        let tmp = TempDir::new().unwrap();
        let generic = tmp.path().join("generic");
        let browser = tmp.path().join("browser");
        fs::create_dir(&generic).unwrap();
        fs::create_dir(&browser).unwrap();
        let (generic_keys, _) = bundle_with_version(&generic, b"generic", "generic", "23.0.0");
        let (browser_keys, _) = bundle_with_version_features(
            &browser,
            b"browser",
            "browser",
            "22.0.0",
            BTreeSet::from(["browser-cdp-v1".into()]),
        );
        let mut trusted = generic_keys.0;
        trusted.extend(browser_keys.0);
        let manager = manager(&tmp, TrustedEd25519Keys::new(trusted));
        let generic = manager.import(ImportSource::Directory(generic)).unwrap();
        let browser = manager.import(ImportSource::Directory(browser)).unwrap();
        assert_eq!(
            manager
                .resolve_preferred("node", "aarch64")
                .unwrap()
                .rootfs_sha256,
            generic.rootfs_sha256
        );
        assert_eq!(
            manager
                .resolve_preferred_with_features(
                    "node",
                    "aarch64",
                    &BTreeSet::from(["browser-cdp-v1".into()]),
                )
                .unwrap()
                .rootfs_sha256,
            browser.rootfs_sha256
        );
    }

    #[cfg(unix)]
    #[test]
    fn removal_rejects_symlink_hardlink_and_extra_entries() {
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let boxes = tmp.path().join("boxes");
        fs::create_dir(&boxes).unwrap();
        let manager = RuntimeBundleManager::new(
            tmp.path().join("images"),
            &boxes,
            tmp.path().join("snapshots"),
            TrustedEd25519Keys::default(),
            ImportLimits::default(),
        );
        let id = "01890f3e-7b2a-7cc1-8000-000000000001";
        symlink(tmp.path(), boxes.join(id)).unwrap();
        assert!(matches!(
            manager.private_disk_ready(id),
            Err(ImageError::UnsafeBoxDirectory)
        ));
        assert!(matches!(
            manager.remove_box_disk(id),
            Err(ImageError::UnsafeBoxDirectory)
        ));
        fs::remove_file(boxes.join(id)).unwrap();

        fs::create_dir(boxes.join(id)).unwrap();
        fs::write(boxes.join(id).join(DATA_DISK), b"disk").unwrap();
        fs::hard_link(
            boxes.join(id).join(DATA_DISK),
            tmp.path().join("disk-alias"),
        )
        .unwrap();
        assert!(matches!(
            manager.private_disk_ready(id),
            Err(ImageError::UnsafeBoxDirectory)
        ));
        assert!(matches!(
            manager.remove_box_disk(id),
            Err(ImageError::UnsafeBoxDirectory)
        ));
        fs::remove_file(tmp.path().join("disk-alias")).unwrap();
        assert!(manager.private_disk_ready(id).unwrap());
        fs::write(boxes.join(id).join("unexpected"), b"x").unwrap();
        assert!(matches!(
            manager.private_disk_ready(id),
            Err(ImageError::UnsafeBoxDirectory)
        ));
        assert!(matches!(
            manager.remove_box_disk(id),
            Err(ImageError::UnsafeBoxDirectory)
        ));
        assert!(
            !manager
                .private_disk_ready("01890f3e-7b2a-7cc1-8000-000000000002")
                .unwrap()
        );
    }

    #[test]
    fn failed_private_clone_cleans_new_box_directory() {
        let tmp = TempDir::new().unwrap();
        let manager = manager(&tmp, TrustedEd25519Keys::default());
        let id = "01890f3e-7b2a-7cc1-8000-000000000001";
        let resolved = ResolvedRuntime {
            rootfs_path: tmp.path().join("missing.raw"),
            rootfs_sha256: "0".repeat(64),
            manifest: RuntimeBundleManifest {
                format_version: 1,
                runtime: "node".into(),
                runtime_version: "22.0.0".into(),
                arch: "aarch64".into(),
                libkrun_version: "1.19.4".into(),
                kernel_version: "6.1".into(),
                agent_protocol: 1,
                build_toolchain: "test".into(),
                features: BTreeSet::new(),
                rootfs: RootfsDescriptor {
                    sha256: "0".repeat(64),
                    size_bytes: 0,
                },
                sbom: FileDescriptor {
                    sha256: "0".repeat(64),
                    size_bytes: 0,
                },
                licenses: BTreeMap::new(),
                signature: SignatureMetadata {
                    algorithm: "ed25519".into(),
                    key_id: "test".into(),
                },
            },
        };
        assert!(manager.clone_resolved_for_box(id, resolved, 0).is_err());
        assert!(!tmp.path().join("boxes").join(id).exists());
    }

    #[test]
    fn tar_rejects_traversal_and_hardlink_headers_before_extracting() {
        fn header(name: &str, kind: u8) -> [u8; 512] {
            let mut header = [0_u8; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[124..135].copy_from_slice(b"00000000000");
            header[156] = kind;
            header
        }
        let tmp = TempDir::new().unwrap();
        let limits = ImportLimits::default();
        assert!(matches!(
            read_tar(
                header("../rootfs.raw", b'0').to_vec().as_slice(),
                tmp.path(),
                &limits
            ),
            Err(ImageError::UnsafeInput)
        ));
        assert!(matches!(
            read_tar(
                header(ROOTFS, b'1').to_vec().as_slice(),
                tmp.path(),
                &limits
            ),
            Err(ImageError::UnsafeInput)
        ));
    }
}
