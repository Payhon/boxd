//! Compile-time verified runtime assets for a platform-specific release.
//!
//! Development builds may omit the asset and remain usable for non-runtime
//! commands, but `serve` and runtime readiness must fail before listening.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

pub const LIBKRUN_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/embedded-libkrun.bin"));
pub const LIBKRUN_LICENSE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/embedded-libkrun-license.txt"));
pub const LIBKRUN_SHA256: &str =
    include_str!(concat!(env!("OUT_DIR"), "/embedded-libkrun-sha256.txt"));
pub const LIBKRUNFW_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/embedded-libkrunfw.bin"));
pub const LIBKRUNFW_LICENSE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/embedded-libkrunfw-license.txt"));
pub const LIBKRUNFW_SHA256: &str =
    include_str!(concat!(env!("OUT_DIR"), "/embedded-libkrunfw-sha256.txt"));

pub fn is_present() -> bool {
    !LIBKRUN_BYTES.is_empty()
        && !LIBKRUN_LICENSE.is_empty()
        && LIBKRUN_SHA256.len() == 64
        && !LIBKRUNFW_BYTES.is_empty()
        && !LIBKRUNFW_LICENSE.is_empty()
        && LIBKRUNFW_SHA256.len() == 64
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledAssets {
    pub directory: PathBuf,
    pub libkrun: PathBuf,
    pub libkrunfw: PathBuf,
}

/// Publishes the compile-time verified pair into a private content-addressed
/// directory. Existing files are accepted only after re-hashing, so a modified
/// data directory can never silently replace the release artifact.
pub fn install(data_dir: &Path) -> Result<InstalledAssets, String> {
    if !is_present() {
        return Err(
            "this boxd build has no embedded libkrun/libkrunfw release assets; refusing to serve"
                .into(),
        );
    }
    let parent = data_dir.join("embedded");
    fs::create_dir_all(&parent)
        .map_err(|error| format!("cannot create embedded runtime directory: {error}"))?;
    reject_symlink(&parent)?;
    let directory = parent.join(format!("{}-{}", LIBKRUN_SHA256, LIBKRUNFW_SHA256));
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create embedded runtime identity directory: {error}"))?;
    reject_symlink(&directory)?;
    let libkrun = directory.join(libkrun_filename());
    let libkrunfw = directory.join(libkrunfw_filename());
    publish(&libkrun, LIBKRUN_BYTES, LIBKRUN_SHA256)?;
    publish(&libkrunfw, LIBKRUNFW_BYTES, LIBKRUNFW_SHA256)?;
    publish(
        &directory.join("LICENSE.libkrun"),
        LIBKRUN_LICENSE,
        &hash_bytes(LIBKRUN_LICENSE),
    )?;
    publish(
        &directory.join("LICENSE.libkrunfw"),
        LIBKRUNFW_LICENSE,
        &hash_bytes(LIBKRUNFW_LICENSE),
    )?;
    let directory = directory
        .canonicalize()
        .map_err(|error| format!("cannot resolve embedded runtime directory: {error}"))?;
    Ok(InstalledAssets {
        libkrun: directory.join(libkrun_filename()),
        libkrunfw: directory.join(libkrunfw_filename()),
        directory,
    })
}

fn publish(path: &Path, bytes: &[u8], expected: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "embedded runtime target is not a regular file: {}",
                    path.display()
                ));
            }
            return verify(path, expected);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect embedded runtime target: {error}")),
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("cannot create embedded runtime staging file: {error}"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot publish embedded runtime bytes: {error}"))?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify(path, expected)?;
            }
            Err(error) => {
                return Err(format!(
                    "cannot atomically publish embedded runtime: {error}"
                ));
            }
        }
        fs::remove_file(&temporary)
            .map_err(|error| format!("cannot remove embedded runtime staging link: {error}"))?;
        verify(path, expected)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn verify(path: &Path, expected: &str) -> Result<(), String> {
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open embedded runtime artifact: {error}"))?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)
        .map_err(|error| format!("cannot hash embedded runtime artifact: {error}"))?;
    if format!("{:x}", hash.finalize()) != expected {
        return Err(format!(
            "embedded runtime artifact checksum mismatch: {}",
            path.display()
        ));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect embedded runtime directory: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "embedded runtime directory is unsafe: {}",
            path.display()
        ));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(target_os = "macos")]
const fn libkrun_filename() -> &'static str {
    "libkrun.1.dylib"
}
#[cfg(target_os = "macos")]
const fn libkrunfw_filename() -> &'static str {
    "libkrunfw.5.dylib"
}
#[cfg(target_os = "linux")]
const fn libkrun_filename() -> &'static str {
    "libkrun.so.1"
}
#[cfg(target_os = "linux")]
const fn libkrunfw_filename() -> &'static str {
    "libkrunfw.so.5"
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn libkrun_filename() -> &'static str {
    "libkrun.unsupported"
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn libkrunfw_filename() -> &'static str {
    "libkrunfw.unsupported"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_is_complete_or_deliberately_absent() {
        assert_eq!(LIBKRUN_BYTES.is_empty(), LIBKRUN_LICENSE.is_empty());
        assert_eq!(LIBKRUN_BYTES.is_empty(), LIBKRUN_SHA256.is_empty());
        assert_eq!(LIBKRUNFW_BYTES.is_empty(), LIBKRUNFW_LICENSE.is_empty());
        assert_eq!(LIBKRUNFW_BYTES.is_empty(), LIBKRUNFW_SHA256.is_empty());
        assert_eq!(LIBKRUN_BYTES.is_empty(), LIBKRUNFW_BYTES.is_empty());
        assert!(
            !is_present()
                || (LIBKRUN_SHA256.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && LIBKRUNFW_SHA256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()))
        );
    }
}
