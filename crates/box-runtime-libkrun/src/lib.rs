//! The only crate permitted to use libkrun FFI. `start_enter` is deliberately
//! private to the worker entry point: it consumes the context and may call `exit`.
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use box_egress::{
    CustomNetworkPolicy, GUEST_MAC, HttpInterceptionConfig, ProxyLimits, spawn_custom_proxy,
    spawn_custom_proxy_with_http_interception, spawn_restricted_proxy,
    spawn_restricted_proxy_with_http_interception,
};
use box_egress_http::{
    AttachHeaderRule, AttachHeaderRules, HostPattern, PerBoxCertificateAuthority,
    SecretHeaderValue, SecretPrivateKeyDer,
};
use box_runtime::{
    DriverCapabilities, FirmwareIdentity, LibraryIdentity, MAX_WORKER_SPEC_BYTES, NetworkMode,
    Result as RuntimeResult, RuntimeError, WorkerSpec,
};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, c_char},
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    os::unix::fs::MetadataExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

pub const LIBKRUN_TAG: &str = "v1.19.4";
pub const LIBKRUN_COMMIT: &str = "728df8125077d0db44265f6e997c72b81b65c015";
pub const LIBKRUN_HEADER_SHA256: &str =
    "0ce40e378736b6ac409aa7f7db37f9ecc02069cff0d83b2148423dacb970ae96";
pub const FEATURE_NET: u64 = 0;
pub const FEATURE_BLK: u64 = 1;
pub const WORKER_SPEC_READ_TIMEOUT: Duration = Duration::from_secs(5);
const IMMUTABLE_BASE_DEVICE: &str = "/dev/vda";
const PRIVATE_ROOT_DEVICE: &str = "/dev/vdb";
const GUEST_AGENT_PATH: &str = "/usr/local/bin/box-agent";
const PREPARED_RUNTIME_ENV: &str = "BOXD_PRIVATE_RUNTIME_DIR";
const NET_FLAG_DHCP_CLIENT: u32 = 1 << 1;
#[cfg(target_os = "macos")]
const PRIVATE_LIBKRUN_NAME: &str = "libkrun.private.dylib";
#[cfg(not(target_os = "macos"))]
const PRIVATE_LIBKRUN_NAME: &str = "libkrun.private.so";
#[cfg(target_os = "macos")]
const FIRMWARE_SONAME: &str = "libkrunfw.5.dylib";
#[cfg(target_os = "linux")]
const FIRMWARE_SONAME: &str = "libkrunfw.so.5";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const FIRMWARE_SONAME: &str = "unsupported";
const REQUIRED_ABI_SYMBOLS: &[&[u8]] = &[
    b"krun_create_ctx\0",
    b"krun_free_ctx\0",
    b"krun_set_vm_config\0",
    b"krun_add_disk\0",
    b"krun_set_root_disk_remount\0",
    b"krun_set_exec\0",
    b"krun_add_vsock_port2\0",
    b"krun_set_console_output\0",
    b"krun_add_net_unixstream\0",
    b"krun_has_feature\0",
    b"krun_start_enter\0",
];

fn require_abi_symbols(mut contains: impl FnMut(&[u8]) -> bool) -> RuntimeResult<()> {
    for symbol in REQUIRED_ABI_SYMBOLS {
        if !contains(symbol) {
            let name = std::str::from_utf8(&symbol[..symbol.len() - 1]).unwrap_or("invalid-symbol");
            return Err(RuntimeError(format!(
                "missing required libkrun symbol: {name}"
            )));
        }
    }
    Ok(())
}

trait ExactLibraryIdentity {
    fn exact_v1_19_4(&self) -> bool;
}

impl ExactLibraryIdentity for LibraryIdentity {
    fn exact_v1_19_4(&self) -> bool {
        self.tag == LIBKRUN_TAG
            && self.commit == LIBKRUN_COMMIT
            && self.header_sha256 == LIBKRUN_HEADER_SHA256
            && self.artifact_sha256.len() == 64
            && self
                .artifact_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}
pub fn verify_library(path: &Path, identity: &LibraryIdentity) -> RuntimeResult<()> {
    let mut file = open_path_no_symlinks(path, false, "libkrun library")?;
    verify_library_file(&mut file, identity)
}

fn verify_library_file(file: &mut File, identity: &LibraryIdentity) -> RuntimeResult<()> {
    if !identity.exact_v1_19_4() {
        return Err(RuntimeError(
            "libkrun manifest does not prove v1.19.4".into(),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| RuntimeError(format!("cannot seek libkrun artifact: {error}")))?;
    let mut hash = Sha256::new();
    std::io::copy(file, &mut hash)
        .map_err(|error| RuntimeError(format!("cannot hash libkrun artifact: {error}")))?;
    let actual = format!("{:x}", hash.finalize());
    if actual != identity.artifact_sha256 {
        return Err(RuntimeError("libkrun artifact checksum mismatch".into()));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| RuntimeError(format!("cannot rewind libkrun artifact: {error}")))?;
    Ok(())
}

fn verify_firmware_file(file: &mut File, identity: &FirmwareIdentity) -> RuntimeResult<()> {
    if identity.version != "5"
        || identity.soname != FIRMWARE_SONAME
        || identity.artifact_sha256.len() != 64
        || !identity
            .artifact_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RuntimeError(
            "libkrun firmware manifest does not prove pinned ABI 5".into(),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| RuntimeError(format!("cannot seek libkrun firmware: {error}")))?;
    let mut hash = Sha256::new();
    std::io::copy(file, &mut hash)
        .map_err(|error| RuntimeError(format!("cannot hash libkrun firmware: {error}")))?;
    if format!("{:x}", hash.finalize()) != identity.artifact_sha256 {
        return Err(RuntimeError("libkrun firmware checksum mismatch".into()));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| RuntimeError(format!("cannot rewind libkrun firmware: {error}")))?;
    Ok(())
}

fn open_path_no_symlinks(path: &Path, writable: bool, label: &str) -> RuntimeResult<File> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(RuntimeError(format!("{label} must be absolute")));
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .open("/")
        .map_err(|error| RuntimeError(format!("cannot open filesystem root: {error}")))?;
    let components: Vec<_> = path.components().collect();
    let normal: Vec<_> = components
        .iter()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(*value),
            Component::RootDir => None,
            _ => None,
        })
        .collect();
    if normal.len() + 1 != components.len() || normal.is_empty() {
        return Err(RuntimeError(format!("{label} has unsafe path components")));
    }
    for component in &normal[..normal.len() - 1] {
        let component = CString::new(component.as_encoded_bytes())
            .map_err(|_| RuntimeError(format!("{label} contains NUL")))?;
        // SAFETY: both directory FD and NUL-terminated component are live;
        // flags prohibit symlink traversal and return a new owned descriptor.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(RuntimeError(format!(
                "cannot securely walk {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: successful openat returned a fresh descriptor now owned here.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let leaf = CString::new(normal.last().expect("nonempty").as_encoded_bytes())
        .map_err(|_| RuntimeError(format!("{label} contains NUL")))?;
    let access = if writable {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    // SAFETY: the pinned directory and leaf CString remain live for openat.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(RuntimeError(format!(
            "cannot securely open {label}: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful openat returned a fresh descriptor now owned here.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError(format!("cannot inspect {label}: {error}")))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(RuntimeError(format!(
            "{label} must be a regular file with one link"
        )));
    }
    Ok(file)
}

fn open_directory_no_symlinks(path: &Path, label: &str) -> RuntimeResult<File> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(RuntimeError(format!("{label} must be absolute")));
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .open("/")
        .map_err(|error| RuntimeError(format!("cannot open filesystem root: {error}")))?;
    for component in path.components() {
        let Component::Normal(component) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(RuntimeError(format!("{label} has unsafe components")));
        };
        let component = CString::new(component.as_encoded_bytes())
            .map_err(|_| RuntimeError(format!("{label} contains NUL")))?;
        // SAFETY: both directory FD and component CString are valid and live.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(RuntimeError(format!(
                "cannot securely walk {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: successful openat returned a fresh descriptor now owned here.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

fn verify_private_directory_owner(directory: &File, label: &str) -> RuntimeResult<()> {
    let metadata = directory
        .metadata()
        .map_err(|error| RuntimeError(format!("cannot inspect {label}: {error}")))?;
    // SAFETY: geteuid has no arguments or preconditions.
    let owner = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o777 != 0o700 {
        return Err(RuntimeError(format!(
            "{label} must be a mode-0700 directory owned by the worker uid"
        )));
    }
    Ok(())
}

fn verify_private_file_owner(file: &File, label: &str) -> RuntimeResult<()> {
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError(format!("cannot inspect {label}: {error}")))?;
    // SAFETY: geteuid has no arguments or preconditions.
    let owner = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o277 != 0
    {
        return Err(RuntimeError(format!(
            "{label} must be a single-link, owner-only non-writable file"
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_macos_code_signature(path: &Path, label: &str) -> RuntimeResult<()> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .arg("--verify")
        .arg("--strict")
        .arg("--verbose=2")
        .arg(path)
        .output()
        .map_err(|error| RuntimeError(format!("cannot execute codesign for {label}: {error}")))?;
    if !output.status.success() {
        return Err(RuntimeError(format!(
            "invalid code signature for {label} (codesign status {})",
            output.status
        )));
    }
    Ok(())
}

#[cfg(any(not(target_os = "macos"), test))]
fn snapshot_verified_library(spec: &WorkerSpec) -> RuntimeResult<File> {
    let name = CString::new(format!(
        ".boxd-libkrun-{}-{}",
        std::process::id(),
        &spec.boot_nonce[..16]
    ))
    .expect("validated nonce yields a valid file name");
    snapshot_library(
        &spec.libkrun_library,
        &spec.libkrun_identity,
        &spec.workdir,
        &name,
    )
}

#[cfg(any(not(target_os = "macos"), test))]
fn snapshot_library(
    path: &Path,
    identity: &LibraryIdentity,
    snapshot_directory: &Path,
    name: &CString,
) -> RuntimeResult<File> {
    let mut source = open_path_no_symlinks(path, false, "libkrun library")?;
    let directory = open_directory_no_symlinks(snapshot_directory, "libkrun snapshot directory")?;
    // SAFETY: directory/name are valid and mode is supplied for O_CREAT.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o500,
        )
    };
    if fd < 0 {
        return Err(RuntimeError(format!(
            "cannot create private libkrun snapshot: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful openat returned a fresh descriptor now owned here.
    let mut snapshot = unsafe { File::from_raw_fd(fd) };
    // SAFETY: the directory and filename still designate the just-created file.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(RuntimeError(format!(
            "cannot unlink private libkrun snapshot: {}",
            std::io::Error::last_os_error()
        )));
    }
    std::io::copy(&mut source, &mut snapshot)
        .map_err(|error| RuntimeError(format!("cannot snapshot libkrun artifact: {error}")))?;
    snapshot
        .sync_all()
        .map_err(|error| RuntimeError(format!("cannot sync libkrun snapshot: {error}")))?;
    verify_library_file(&mut snapshot, identity)?;
    let metadata = snapshot
        .metadata()
        .map_err(|error| RuntimeError(format!("cannot inspect libkrun snapshot: {error}")))?;
    if metadata.nlink() != 0 {
        return Err(RuntimeError(
            "private libkrun snapshot unexpectedly remains linked".into(),
        ));
    }
    Ok(snapshot)
}

#[cfg(any(not(target_os = "macos"), test))]
fn snapshot_firmware(
    path: &Path,
    identity: &FirmwareIdentity,
    snapshot_directory: &Path,
    name: &CString,
) -> RuntimeResult<File> {
    let mut source = open_path_no_symlinks(path, false, "libkrun firmware")?;
    let directory = open_directory_no_symlinks(snapshot_directory, "firmware snapshot directory")?;
    // SAFETY: directory/name are valid and mode is supplied for O_CREAT.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o500,
        )
    };
    if fd < 0 {
        return Err(RuntimeError(format!(
            "cannot create private firmware snapshot: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful openat returned a fresh descriptor now owned here.
    let mut snapshot = unsafe { File::from_raw_fd(fd) };
    // SAFETY: directory/name still identify the just-created private file.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(RuntimeError(
            "cannot unlink private firmware snapshot".into(),
        ));
    }
    std::io::copy(&mut source, &mut snapshot)
        .map_err(|error| RuntimeError(format!("cannot snapshot libkrun firmware: {error}")))?;
    snapshot
        .sync_all()
        .map_err(|error| RuntimeError(format!("cannot sync firmware snapshot: {error}")))?;
    verify_firmware_file(&mut snapshot, identity)?;
    if snapshot
        .metadata()
        .map_err(|error| RuntimeError(format!("cannot inspect firmware snapshot: {error}")))?
        .nlink()
        != 0
    {
        return Err(RuntimeError(
            "private firmware snapshot unexpectedly remains linked".into(),
        ));
    }
    Ok(snapshot)
}

/// Loads checksum-pinned artifacts and probes the actual required v1.19.4
/// ABI/capabilities. macOS retains signed linked copies for the entire dynamic
/// library lifetime; Linux uses unlinked fixed-FD snapshots.
pub fn probe_library(
    path: &Path,
    identity: &LibraryIdentity,
    firmware_path: &Path,
    firmware_identity: &FirmwareIdentity,
) -> RuntimeResult<DriverCapabilities> {
    #[cfg(target_os = "macos")]
    {
        probe_library_macos(path, identity, firmware_path, firmware_identity)
    }
    #[cfg(not(target_os = "macos"))]
    {
        probe_library_unlinked(path, identity, firmware_path, firmware_identity)
    }
}

#[cfg(not(target_os = "macos"))]
fn probe_library_unlinked(
    path: &Path,
    identity: &LibraryIdentity,
    firmware_path: &Path,
    firmware_identity: &FirmwareIdentity,
) -> RuntimeResult<DriverCapabilities> {
    let snapshot_directory = std::env::temp_dir()
        .canonicalize()
        .map_err(|error| RuntimeError(format!("cannot resolve probe directory: {error}")))?;
    let name = CString::new(format!(
        ".boxd-libkrun-probe-{}-{}",
        std::process::id(),
        unique_snapshot_suffix()
    ))
    .expect("numeric probe name contains no NUL");
    let snapshot = snapshot_library(path, identity, &snapshot_directory, &name)?;
    let firmware_name = CString::new(format!(
        ".boxd-libkrunfw-probe-{}-{}",
        std::process::id(),
        unique_snapshot_suffix()
    ))
    .expect("numeric firmware probe name contains no NUL");
    let firmware = snapshot_firmware(
        firmware_path,
        firmware_identity,
        &snapshot_directory,
        &firmware_name,
    )?;
    let firmware_path = PathBuf::from(descriptor_path(&firmware));
    // SAFETY: the firmware descriptor is checksum-pinned and retained through
    // symbol resolution; the symbol type is the official ABI 5 signature.
    let firmware_library = unsafe { libloading::Library::new(&firmware_path) }
        .map_err(|error| RuntimeError(format!("cannot load pinned libkrun firmware: {error}")))?;
    // SAFETY: presence/type are from the official ABI 5 public firmware API.
    unsafe {
        firmware_library
            .get::<unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut c_char>(
                b"krunfw_get_kernel\0",
            )
            .map_err(|error| RuntimeError(format!("invalid libkrun firmware ABI: {error}")))?;
    }
    let snapshot_path = PathBuf::from(descriptor_path(&snapshot));
    // SAFETY: `snapshot` is an unlinked, checksum-verified v1.19.4 artifact
    // retained until after the loaded library and all resolved symbols drop.
    let api = unsafe { ffi::DynamicKrun::load(&snapshot_path) }?;
    let capabilities = probe_api(&api)?;
    drop(firmware_library);
    Ok(capabilities)
}

#[cfg(target_os = "macos")]
struct MacosLinkedRuntime {
    parent: File,
    directory: File,
    directory_name: CString,
    path: PathBuf,
}

#[cfg(target_os = "macos")]
impl Drop for MacosLinkedRuntime {
    fn drop(&mut self) {
        cleanup_private_runtime(&self.parent, &self.directory, &self.directory_name);
    }
}

#[cfg(target_os = "macos")]
fn random_private_directory_name() -> RuntimeResult<CString> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|error| {
            RuntimeError(format!("cannot obtain private probe randomness: {error}"))
        })?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    CString::new(format!(".boxd-libkrun-probe-{suffix}"))
        .map_err(|_| RuntimeError("private probe name contains NUL".into()))
}

#[cfg(target_os = "macos")]
fn prepare_macos_linked_probe_runtime(
    library_path: &Path,
    library_identity: &LibraryIdentity,
    firmware_path: &Path,
    firmware_identity: &FirmwareIdentity,
) -> RuntimeResult<MacosLinkedRuntime> {
    let parent_path = std::env::temp_dir()
        .canonicalize()
        .map_err(|error| RuntimeError(format!("cannot resolve probe directory: {error}")))?;
    let parent = open_directory_no_symlinks(&parent_path, "probe parent directory")?;
    let directory_name = random_private_directory_name()?;
    // SAFETY: parent/name are retained and mode is supplied to mkdirat.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), directory_name.as_ptr(), 0o700) } != 0 {
        return Err(RuntimeError(format!(
            "cannot create private linked probe directory: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the atomically created directory is opened without following links.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            directory_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        // SAFETY: remove only the exact name just created below retained parent.
        unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                directory_name.as_ptr(),
                libc::AT_REMOVEDIR,
            );
        }
        return Err(RuntimeError(
            "cannot open private linked probe directory".into(),
        ));
    }
    // SAFETY: successful openat returned a fresh descriptor now owned here.
    let directory = unsafe { File::from_raw_fd(fd) };
    let name = directory_name
        .to_str()
        .map_err(|_| RuntimeError("private probe directory name is not UTF-8".into()))?;
    let path = parent_path.join(name);
    let runtime = MacosLinkedRuntime {
        parent,
        directory,
        directory_name,
        path,
    };
    if let Err(error) =
        verify_private_directory_owner(&runtime.directory, "private linked probe directory")
    {
        drop(runtime);
        return Err(error);
    }
    let result = (|| {
        copy_verified_file(
            library_path,
            &runtime.directory,
            PRIVATE_LIBKRUN_NAME,
            |file| verify_library_file(file, library_identity),
        )?;
        copy_verified_file(firmware_path, &runtime.directory, FIRMWARE_SONAME, |file| {
            verify_firmware_file(file, firmware_identity)
        })?;
        Ok(())
    })();
    if let Err(error) = result {
        drop(runtime);
        return Err(error);
    }
    Ok(runtime)
}

#[cfg(target_os = "macos")]
fn verify_macos_linked_artifacts(
    runtime: &MacosLinkedRuntime,
    identity: &LibraryIdentity,
    firmware_identity: &FirmwareIdentity,
) -> RuntimeResult<(PathBuf, PathBuf)> {
    verify_private_directory_owner(&runtime.directory, "private linked runtime directory")?;
    let library_path = runtime.path.join(PRIVATE_LIBKRUN_NAME);
    let firmware_path = runtime.path.join(FIRMWARE_SONAME);
    let mut library = open_path_no_symlinks(&library_path, false, "linked libkrun probe")?;
    verify_private_file_owner(&library, "linked libkrun probe")?;
    verify_library_file(&mut library, identity)?;
    let mut firmware = open_path_no_symlinks(&firmware_path, false, "linked firmware probe")?;
    verify_private_file_owner(&firmware, "linked firmware probe")?;
    verify_firmware_file(&mut firmware, firmware_identity)?;
    verify_macos_code_signature(&library_path, "pinned libkrun")?;
    verify_macos_code_signature(&firmware_path, "pinned libkrun firmware")?;
    // Re-hash after codesign verification and immediately before dlopen.
    verify_library_file(&mut library, identity)?;
    verify_firmware_file(&mut firmware, firmware_identity)?;
    Ok((library_path, firmware_path))
}

#[cfg(target_os = "macos")]
fn probe_library_macos(
    path: &Path,
    identity: &LibraryIdentity,
    firmware_path: &Path,
    firmware_identity: &FirmwareIdentity,
) -> RuntimeResult<DriverCapabilities> {
    let runtime =
        prepare_macos_linked_probe_runtime(path, identity, firmware_path, firmware_identity)?;
    let (library_path, firmware_path) =
        verify_macos_linked_artifacts(&runtime, identity, firmware_identity)?;
    // SAFETY: this checksum-pinned, signed linked file remains present through
    // `firmware_library` drop and is owner-confined by the retained 0700 dirfd.
    let firmware_library = unsafe { libloading::Library::new(&firmware_path) }
        .map_err(|error| RuntimeError(format!("cannot load pinned libkrun firmware: {error}")))?;
    // SAFETY: presence/type are from the official ABI 5 public firmware API.
    unsafe {
        firmware_library
            .get::<unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut c_char>(
                b"krunfw_get_kernel\0",
            )
            .map_err(|error| RuntimeError(format!("invalid libkrun firmware ABI: {error}")))?;
    }
    // SAFETY: the checksum-pinned signed linked file remains present until
    // `api` drops, after which `runtime` removes fixed children via dirfd.
    let api = unsafe { ffi::DynamicKrun::load(&library_path) }?;
    let capabilities = probe_api(&api)?;
    drop(api);
    drop(firmware_library);
    drop(runtime);
    Ok(capabilities)
}

#[cfg(not(target_os = "macos"))]
fn unique_snapshot_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn private_runtime_name(spec: &WorkerSpec) -> CString {
    CString::new(format!(
        ".boxd-runtime-{}-{}",
        std::process::id(),
        &spec.boot_nonce[..16]
    ))
    .expect("validated nonce yields a valid private directory name")
}

fn prepare_private_runtime(spec: &WorkerSpec) -> RuntimeResult<PathBuf> {
    let workdir = open_directory_no_symlinks(&spec.workdir, "worker directory")?;
    let name = private_runtime_name(spec);
    // SAFETY: workdir/name are live and mode is supplied to mkdirat.
    if unsafe { libc::mkdirat(workdir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(RuntimeError(format!(
            "cannot create private runtime directory: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the just-created directory is opened without following links.
    let fd = unsafe {
        libc::openat(
            workdir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        // SAFETY: name is the just-created directory below retained workdir.
        unsafe {
            libc::unlinkat(workdir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
        }
        return Err(RuntimeError("cannot open private runtime directory".into()));
    }
    // SAFETY: successful openat returned a fresh descriptor now owned here.
    let directory = unsafe { File::from_raw_fd(fd) };
    verify_private_directory_owner(&directory, "private runtime directory")?;
    let result = (|| {
        copy_verified_file(
            &spec.libkrun_library,
            &directory,
            PRIVATE_LIBKRUN_NAME,
            |file| verify_library_file(file, &spec.libkrun_identity),
        )?;
        copy_verified_file(
            &spec.libkrun_firmware,
            &directory,
            FIRMWARE_SONAME,
            |file| verify_firmware_file(file, &spec.libkrun_firmware_identity),
        )?;
        spec.workdir
            .join(name.to_str().expect("private name is UTF-8"))
            .canonicalize()
            .map_err(|error| RuntimeError(format!("cannot resolve private runtime: {error}")))
    })();
    if result.is_err() {
        cleanup_private_runtime(&workdir, &directory, &name);
    }
    result
}

fn copy_verified_file(
    source_path: &Path,
    directory: &File,
    name: &str,
    verify: impl FnOnce(&mut File) -> RuntimeResult<()>,
) -> RuntimeResult<()> {
    let mut source = open_path_no_symlinks(source_path, false, name)?;
    let name = CString::new(name).expect("fixed runtime file name has no NUL");
    // SAFETY: directory/name are live and mode is supplied for O_CREAT.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o500,
        )
    };
    if fd < 0 {
        return Err(RuntimeError(format!(
            "cannot create private runtime file {name:?}: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful openat returned a fresh descriptor now owned here.
    let mut destination = unsafe { File::from_raw_fd(fd) };
    std::io::copy(&mut source, &mut destination)
        .map_err(|error| RuntimeError(format!("cannot copy private runtime file: {error}")))?;
    destination
        .sync_all()
        .map_err(|error| RuntimeError(format!("cannot sync private runtime file: {error}")))?;
    verify(&mut destination)?;
    verify_private_file_owner(&destination, "private runtime artifact")
}

fn prepared_runtime_directory(spec: &WorkerSpec) -> RuntimeResult<PathBuf> {
    let provided = std::env::var_os(PREPARED_RUNTIME_ENV)
        .ok_or_else(|| RuntimeError("worker runtime was not privately prepared".into()))?;
    let expected = spec
        .workdir
        .join(
            private_runtime_name(spec)
                .to_str()
                .expect("private name is UTF-8"),
        )
        .canonicalize()
        .map_err(|error| RuntimeError(format!("cannot resolve prepared runtime: {error}")))?;
    if provided != expected.as_os_str() {
        return Err(RuntimeError("prepared runtime identity mismatch".into()));
    }
    let directory = open_directory_no_symlinks(&expected, "prepared runtime directory")?;
    verify_private_directory_owner(&directory, "prepared runtime directory")?;
    Ok(expected)
}

fn cleanup_private_runtime(parent: &File, directory: &File, directory_name: &CString) {
    for name in [PRIVATE_LIBKRUN_NAME, FIRMWARE_SONAME] {
        let name = CString::new(name).expect("fixed runtime file name has no NUL");
        // SAFETY: only fixed children of the retained private directory are removed.
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
        }
    }
    // SAFETY: directory_name is the retained private directory below parent.
    unsafe {
        libc::unlinkat(
            parent.as_raw_fd(),
            directory_name.as_ptr(),
            libc::AT_REMOVEDIR,
        );
    }
}

fn cleanup_prepared_runtime(spec: &WorkerSpec, directory: &File) {
    if let Ok(parent) = open_directory_no_symlinks(&spec.workdir, "worker directory") {
        cleanup_private_runtime(&parent, directory, &private_runtime_name(spec));
    }
}

fn cleanup_prepared_runtime_path(spec: &WorkerSpec, path: &Path) {
    if let Ok(directory) = open_directory_no_symlinks(path, "prepared runtime directory") {
        cleanup_prepared_runtime(spec, &directory);
    }
}

struct PrivateRuntimeGuard<'a> {
    spec: &'a WorkerSpec,
    directory: &'a File,
    armed: bool,
}

#[cfg(unix)]
fn install_pipe_read_end_as_stdin(read_fd: libc::c_int) -> RuntimeResult<()> {
    if read_fd == 0 {
        return Ok(());
    }
    // SAFETY: read_fd is the live pipe read end and FD0 is the worker's owned
    // spec input. dup2 atomically installs a second reference at FD0.
    if unsafe { libc::dup2(read_fd, 0) } < 0 {
        // SAFETY: this branch still owns the live read end.
        unsafe { libc::close(read_fd) };
        return Err(RuntimeError("cannot install prepared worker pipe".into()));
    }
    // SAFETY: FD0 now owns the pipe reference; the original is redundant.
    unsafe { libc::close(read_fd) };
    Ok(())
}

impl PrivateRuntimeGuard<'_> {
    fn cleanup(&mut self) {
        if self.armed {
            cleanup_prepared_runtime(self.spec, self.directory);
            self.armed = false;
        }
    }
}

impl Drop for PrivateRuntimeGuard<'_> {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(unix)]
fn reexec_with_private_runtime(spec: &WorkerSpec, directory: &Path) -> RuntimeResult<()> {
    use std::os::unix::process::CommandExt;
    let wire = spec.to_wire()?;
    let mut pipe = [-1; 2];
    // SAFETY: pipe points to storage for two descriptors.
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return Err(RuntimeError(format!(
            "cannot create prepared worker pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the worker is single-threaded before the fork. The child invokes
    // only async-signal-safe syscalls and `_exit` before the parent execs.
    let writer = unsafe { libc::fork() };
    if writer < 0 {
        // SAFETY: both descriptors were created above and remain owned here.
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(RuntimeError("cannot fork prepared wire writer".into()));
    }
    if writer == 0 {
        // SAFETY: child owns its descriptor copies and writes the immutable wire.
        unsafe {
            libc::close(pipe[0]);
            let mut offset = 0_usize;
            while offset < wire.len() {
                let written =
                    libc::write(pipe[1], wire[offset..].as_ptr().cast(), wire.len() - offset);
                if written <= 0 {
                    libc::_exit(70);
                }
                offset += written as usize;
            }
            libc::close(pipe[1]);
            libc::_exit(0);
        }
    }
    // SAFETY: parent retains read end as FD0 and closes both redundant copies.
    unsafe {
        libc::close(pipe[1]);
    }
    install_pipe_read_end_as_stdin(pipe[0])?;
    let executable = std::env::current_exe()
        .map_err(|error| RuntimeError(format!("cannot resolve worker executable: {error}")))?;
    let mut command = std::process::Command::new(executable);
    command
        .arg("__vmm-worker")
        .arg("--spec-fd")
        .arg("0")
        .env_clear()
        .env(PREPARED_RUNTIME_ENV, directory)
        .env("BOXD_WIRE_WRITER_PID", writer.to_string())
        .current_dir(directory);
    #[cfg(target_os = "macos")]
    command.env("DYLD_LIBRARY_PATH", directory);
    #[cfg(target_os = "linux")]
    command.env("LD_LIBRARY_PATH", directory);
    let error = command.exec();
    // Re-exec failed: close the pipe so a blocked writer gets EPIPE, then reap
    // that exact child before returning to the supervisor.
    // SAFETY: FD0 is the installed pipe read end and `writer` is the recorded child.
    unsafe {
        libc::close(0);
        libc::waitpid(writer, std::ptr::null_mut(), 0);
    }
    cleanup_prepared_runtime_path(spec, directory);
    Err(RuntimeError(format!(
        "cannot re-exec privately prepared worker: {error}"
    )))
}

fn same_open_file(left: &File, right: &File) -> RuntimeResult<bool> {
    let left = left
        .metadata()
        .map_err(|error| RuntimeError(error.to_string()))?;
    let right = right
        .metadata()
        .map_err(|error| RuntimeError(error.to_string()))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn descriptor_path(file: &File) -> String {
    format!("/dev/fd/{}", file.as_raw_fd())
}

trait IsolationOps {
    fn set_nofile(&self, value: u64) -> RuntimeResult<()>;
    fn set_nproc(&self, value: u64) -> RuntimeResult<()>;
    fn no_new_privileges(&self) -> RuntimeResult<()>;
    fn close_extra_fds(&self, preserve: &[std::os::fd::RawFd]) -> RuntimeResult<()>;
}

struct RealIsolation;

impl IsolationOps for RealIsolation {
    fn set_nofile(&self, value: u64) -> RuntimeResult<()> {
        set_limit(libc::RLIMIT_NOFILE, value, "RLIMIT_NOFILE")
    }

    fn set_nproc(&self, value: u64) -> RuntimeResult<()> {
        set_limit(libc::RLIMIT_NPROC, value, "RLIMIT_NPROC")
    }

    #[cfg(target_os = "linux")]
    fn no_new_privileges(&self) -> RuntimeResult<()> {
        // SAFETY: PR_SET_NO_NEW_PRIVS takes scalar arguments and mutates only
        // the calling process security state.
        let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if result != 0 {
            return Err(RuntimeError(format!(
                "cannot enable no_new_privileges: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn no_new_privileges(&self) -> RuntimeResult<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn close_extra_fds(&self, preserve: &[std::os::fd::RawFd]) -> RuntimeResult<()> {
        let mut preserve = preserve
            .iter()
            .copied()
            .filter(|fd| *fd >= 3)
            .collect::<Vec<_>>();
        preserve.sort_unstable();
        preserve.dedup();
        let mut first = 3_u32;
        for fd in preserve {
            let fd = u32::try_from(fd)
                .map_err(|_| RuntimeError("invalid preserved worker descriptor".into()))?;
            if first < fd {
                // SAFETY: the scalar range deliberately excludes each
                // validated descriptor in the explicit allowlist.
                let result = unsafe { libc::syscall(libc::SYS_close_range, first, fd - 1, 0_u32) };
                if result != 0 {
                    return Err(RuntimeError(format!(
                        "cannot close inherited worker descriptors: {}",
                        std::io::Error::last_os_error()
                    )));
                }
            }
            first = fd
                .checked_add(1)
                .ok_or_else(|| RuntimeError("invalid preserved worker descriptor".into()))?;
        }
        // SAFETY: all explicit allowlist gaps were handled above; the final
        // scalar range closes every larger inherited descriptor.
        let result = unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0_u32) };
        if result != 0 {
            return Err(RuntimeError(format!(
                "cannot close inherited worker descriptors: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn close_extra_fds(&self, preserve: &[std::os::fd::RawFd]) -> RuntimeResult<()> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` points to initialized writable storage for one
        // `rlimit`; `getrlimit` does not retain the pointer.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return Err(RuntimeError(format!(
                "cannot determine worker descriptor limit: {}",
                std::io::Error::last_os_error()
            )));
        }

        let upper_bound = limit.rlim_cur.min(libc::c_int::MAX as libc::rlim_t) as libc::c_int;
        for fd in 3..upper_bound {
            if preserve.contains(&fd) {
                continue;
            }
            // SAFETY: `fd` is a scalar descriptor number. Close errors are
            // intentionally ignored because unopened descriptors yield EBADF.
            unsafe {
                libc::close(fd);
            }
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn close_extra_fds(&self, _: &[std::os::fd::RawFd]) -> RuntimeResult<()> {
        Err(RuntimeError(
            "worker FD isolation is unsupported on this host".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type RlimitResource = libc::c_int;

fn set_limit(resource: RlimitResource, value: u64, label: &str) -> RuntimeResult<()> {
    let value = libc::rlim_t::try_from(value)
        .map_err(|_| RuntimeError(format!("{label} value is too large")))?;
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `limit` is initialized and borrowed for the synchronous syscall.
    let result = unsafe { libc::setrlimit(resource, &limit) };
    if result != 0 {
        return Err(RuntimeError(format!(
            "cannot set {label}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn apply_process_isolation(
    limits: &box_runtime::ResourceLimits,
    isolation: &impl IsolationOps,
    preserve: &[std::os::fd::RawFd],
) -> RuntimeResult<()> {
    // Close against the original descriptor space before lowering NOFILE;
    // otherwise an inherited FD above the new soft limit would escape the scan.
    isolation.close_extra_fds(preserve)?;
    isolation.set_nofile(u64::from(limits.host_worker_max_open_files))?;
    isolation.set_nproc(u64::from(limits.host_worker_max_processes))?;
    isolation.no_new_privileges()
}

#[cfg(target_os = "linux")]
mod seccomp {
    use super::{RuntimeError, RuntimeResult};

    pub const POLICY_VERSION: u16 = 1;
    const AUDIT_ARCH: u32 = if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else if cfg!(target_arch = "aarch64") {
        0xc000_00b7
    } else {
        0
    };
    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;

    fn statement(code: u16, value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k: value,
        }
    }

    fn jump(code: u16, value: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt,
            jf,
            k: value,
        }
    }

    fn blocked_syscalls() -> &'static [libc::c_long] {
        &[
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_open_by_handle_at,
            libc::SYS_name_to_handle_at,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_move_mount,
            libc::SYS_mount_setattr,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_reboot,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_bpf,
            libc::SYS_userfaultfd,
            libc::SYS_perf_event_open,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
        ]
    }

    fn filter() -> RuntimeResult<Vec<libc::sock_filter>> {
        if AUDIT_ARCH == 0 {
            return Err(RuntimeError(
                "Linux seccomp policy supports only x86_64 and aarch64".into(),
            ));
        }
        let mut filter = Vec::with_capacity(5 + blocked_syscalls().len() * 2);
        // struct seccomp_data { int nr; __u32 arch; ... }
        filter.push(statement(BPF_LD_W_ABS, 4));
        filter.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH, 1, 0));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        filter.push(statement(BPF_LD_W_ABS, 0));
        for syscall in blocked_syscalls() {
            let syscall = u32::try_from(*syscall)
                .map_err(|_| RuntimeError("invalid syscall number in seccomp policy".into()))?;
            filter.push(jump(BPF_JMP_JEQ_K, syscall, 0, 1));
            filter.push(statement(
                BPF_RET_K,
                SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).expect("EPERM fits u32"),
            ));
        }
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
        Ok(filter)
    }

    fn install_filter(filter: &mut [libc::sock_filter]) -> std::io::Result<()> {
        let len = u16::try_from(filter.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "seccomp filter too large")
        })?;
        let program = libc::sock_fprog {
            len,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: `program` and its filter slice remain live for the synchronous
        // seccomp syscall. TSYNC applies the same immutable filter to every
        // existing worker thread; future threads inherit it.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC,
                &program,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    pub fn install() -> RuntimeResult<()> {
        let mut filter = filter()?;
        install_filter(&mut filter).map_err(|error| {
            RuntimeError(format!(
                "cannot install Linux worker seccomp policy v{POLICY_VERSION}: {error}"
            ))
        })
    }

    pub fn probe() -> RuntimeResult<()> {
        let mut filter = filter()?;
        // The child executes only async-signal-safe syscalls after fork. The
        // filter is fully allocated beforehand, avoiding allocator use in the
        // forked side of a potentially multi-threaded doctor process.
        // SAFETY: fork creates a separate child; both branches use only their
        // own address space and the parent waits for exactly that PID.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(RuntimeError(format!(
                "cannot fork Linux seccomp probe: {}",
                std::io::Error::last_os_error()
            )));
        }
        if child == 0 {
            // SAFETY: the probe child mutates only its own irreversible
            // privilege state, matching the production worker precondition.
            let no_new_privileges =
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 };
            let installed = no_new_privileges && install_filter(&mut filter).is_ok();
            // SAFETY: this deliberately invokes a blocked syscall to verify
            // that the kernel returns EPERM, without affecting another process.
            let blocked = unsafe {
                libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                ) == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
            };
            // SAFETY: `_exit` is async-signal-safe and avoids running inherited
            // Rust destructors in the post-fork child.
            unsafe { libc::_exit(i32::from(!(installed && blocked))) }
        }
        let mut status = 0;
        // SAFETY: `child` is the positive PID returned above and `status` is
        // valid writable storage for this synchronous wait.
        if unsafe { libc::waitpid(child, &mut status, 0) } != child
            || !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
        {
            return Err(RuntimeError(format!(
                "Linux worker seccomp policy v{POLICY_VERSION} enforcement probe failed"
            )));
        }
        Ok(())
    }
}

/// Reports whether the production Linux worker seccomp policy can be installed
/// and really denies a representative dangerous syscall.
pub fn probe_linux_worker_seccomp() -> RuntimeResult<()> {
    #[cfg(target_os = "linux")]
    {
        seccomp::probe()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn install_linux_worker_seccomp() -> RuntimeResult<()> {
    seccomp::install()
}

#[cfg(not(target_os = "linux"))]
fn install_linux_worker_seccomp() -> RuntimeResult<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
mod cgroup {
    use super::{RuntimeError, RuntimeResult};
    use box_runtime::{ResourceLimits, WorkerSpec};
    use std::{
        collections::BTreeSet,
        fs, io,
        path::{Component, Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    const MOUNT: &str = "/sys/fs/cgroup";
    const NAMESPACE: &str = "boxd";
    const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];
    const VMM_MEMORY_OVERHEAD_BYTES: u64 = 256 * 1024 * 1024;
    const CPU_PERIOD_US: u64 = 100_000;

    trait CgroupFs {
        fn read(&self, path: &Path) -> io::Result<String>;
        fn create_dir(&self, path: &Path) -> io::Result<()>;
        fn write(&self, path: &Path, value: &str) -> io::Result<()>;
        fn remove_dir(&self, path: &Path) -> io::Result<()>;
        fn ensure_directory(&self, path: &Path) -> io::Result<()>;
    }

    struct RealCgroupFs;

    impl CgroupFs for RealCgroupFs {
        fn read(&self, path: &Path) -> io::Result<String> {
            fs::read_to_string(path)
        }

        fn create_dir(&self, path: &Path) -> io::Result<()> {
            fs::create_dir(path)
        }

        fn write(&self, path: &Path, value: &str) -> io::Result<()> {
            fs::write(path, value)
        }

        fn remove_dir(&self, path: &Path) -> io::Result<()> {
            fs::remove_dir(path)
        }

        fn ensure_directory(&self, path: &Path) -> io::Result<()> {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cgroup path is not a real directory",
                ));
            }
            Ok(())
        }
    }

    fn io_error(action: &str, path: &Path, error: io::Error) -> RuntimeError {
        RuntimeError(format!("{action} {}: {error}", path.display()))
    }

    fn own_cgroup_parent(root: &Path, membership: &str) -> RuntimeResult<PathBuf> {
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| RuntimeError("cannot determine unified cgroup membership".into()))?;
        let mut result = root.to_path_buf();
        for component in Path::new(relative).components() {
            match component {
                Component::RootDir => {}
                Component::Normal(value) => result.push(value),
                _ => {
                    return Err(RuntimeError(
                        "unified cgroup membership contains an unsafe component".into(),
                    ));
                }
            }
        }
        Ok(result)
    }

    fn require_controllers(value: &str, path: &Path) -> RuntimeResult<()> {
        let present = value.split_ascii_whitespace().collect::<BTreeSet<_>>();
        let missing = REQUIRED_CONTROLLERS
            .iter()
            .copied()
            .filter(|controller| !present.contains(controller))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError(format!(
                "{} is missing required cgroup v2 controller(s): {}",
                path.display(),
                missing.join(", ")
            )))
        }
    }

    fn prepare_namespace(
        fs: &impl CgroupFs,
        root: &Path,
        membership: &str,
    ) -> RuntimeResult<PathBuf> {
        fs.ensure_directory(root)
            .map_err(|error| io_error("invalid cgroup v2 mount", root, error))?;
        let parent = own_cgroup_parent(root, membership)?;
        fs.ensure_directory(&parent)
            .map_err(|error| io_error("invalid delegated cgroup", &parent, error))?;
        let parent_controllers = parent.join("cgroup.controllers");
        require_controllers(
            &fs.read(&parent_controllers)
                .map_err(|error| io_error("cannot read", &parent_controllers, error))?,
            &parent_controllers,
        )?;
        let subtree = parent.join("cgroup.subtree_control");
        require_controllers(
            &fs.read(&subtree).map_err(|error| {
                io_error("cannot read delegated controllers from", &subtree, error)
            })?,
            &subtree,
        )?;

        let namespace = parent.join(NAMESPACE);
        match fs.create_dir(&namespace) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error("cannot create", &namespace, error)),
        }
        fs.ensure_directory(&namespace)
            .map_err(|error| io_error("invalid worker cgroup namespace", &namespace, error))?;
        let namespace_controllers = namespace.join("cgroup.controllers");
        require_controllers(
            &fs.read(&namespace_controllers)
                .map_err(|error| io_error("cannot read", &namespace_controllers, error))?,
            &namespace_controllers,
        )?;
        let namespace_subtree = namespace.join("cgroup.subtree_control");
        fs.write(&namespace_subtree, "+cpu +memory +pids")
            .map_err(|error| {
                io_error(
                    "cannot enable worker controllers in",
                    &namespace_subtree,
                    error,
                )
            })?;
        Ok(namespace)
    }

    fn create_leaf(fs: &impl CgroupFs, namespace: &Path, name: &str) -> RuntimeResult<PathBuf> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(RuntimeError("invalid cgroup leaf name".into()));
        }
        let leaf = namespace.join(name);
        fs.create_dir(&leaf)
            .map_err(|error| io_error("cannot create worker cgroup", &leaf, error))?;
        fs.ensure_directory(&leaf)
            .map_err(|error| io_error("invalid worker cgroup", &leaf, error))?;
        Ok(leaf)
    }

    fn write_limit(fs: &impl CgroupFs, leaf: &Path, file: &str, value: &str) -> RuntimeResult<()> {
        let path = leaf.join(file);
        fs.write(&path, value)
            .map_err(|error| io_error("cannot write", &path, error))
    }

    fn configure_leaf(
        fs: &impl CgroupFs,
        leaf: &Path,
        limits: &ResourceLimits,
        pid: u32,
    ) -> RuntimeResult<()> {
        let guest_bytes = u64::from(limits.memory_mib)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| RuntimeError("worker memory limit overflow".into()))?;
        let memory_max = guest_bytes
            .checked_add(VMM_MEMORY_OVERHEAD_BYTES)
            .ok_or_else(|| RuntimeError("worker memory limit overflow".into()))?;
        let cpu_quota = u64::from(limits.vcpus)
            .checked_mul(CPU_PERIOD_US)
            .ok_or_else(|| RuntimeError("worker CPU limit overflow".into()))?;
        write_limit(fs, leaf, "memory.max", &memory_max.to_string())?;
        write_limit(
            fs,
            leaf,
            "pids.max",
            &limits.host_worker_max_processes.to_string(),
        )?;
        write_limit(fs, leaf, "cpu.max", &format!("{cpu_quota} {CPU_PERIOD_US}"))?;
        // Placement is deliberately last: a partial limit write never moves
        // the worker into an incompletely configured cgroup.
        write_limit(fs, leaf, "cgroup.procs", &pid.to_string())
    }

    fn remove_empty_leaf(fs: &impl CgroupFs, leaf: &Path) -> RuntimeResult<()> {
        match fs.remove_dir(leaf) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error("cannot remove worker cgroup", leaf, error)),
        }
    }

    pub(super) fn place(spec: &WorkerSpec) -> RuntimeResult<()> {
        let membership = fs::read_to_string("/proc/self/cgroup")
            .map_err(|error| RuntimeError(format!("cannot read /proc/self/cgroup: {error}")))?;
        let filesystem = RealCgroupFs;
        let namespace = prepare_namespace(&filesystem, Path::new(MOUNT), &membership)?;
        let leaf = create_leaf(&filesystem, &namespace, &spec.box_id)?;
        if let Err(error) = configure_leaf(&filesystem, &leaf, &spec.limits, std::process::id()) {
            let _ = remove_empty_leaf(&filesystem, &leaf);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn probe() -> RuntimeResult<()> {
        let membership = fs::read_to_string("/proc/self/cgroup")
            .map_err(|error| RuntimeError(format!("cannot read /proc/self/cgroup: {error}")))?;
        let filesystem = RealCgroupFs;
        let namespace = prepare_namespace(&filesystem, Path::new(MOUNT), &membership)?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| RuntimeError(format!("system clock error: {error}")))?
            .as_nanos();
        let leaf = create_leaf(
            &filesystem,
            &namespace,
            &format!("doctor-{}-{nonce}", std::process::id()),
        )?;
        let result = (|| {
            write_limit(&filesystem, &leaf, "memory.max", "max")?;
            write_limit(&filesystem, &leaf, "pids.max", "max")?;
            write_limit(&filesystem, &leaf, "cpu.max", "max 100000")
        })();
        let cleanup = remove_empty_leaf(&filesystem, &leaf);
        result.and(cleanup)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            cell::RefCell,
            collections::{BTreeMap, BTreeSet},
        };

        #[derive(Default)]
        struct FakeFs {
            directories: RefCell<BTreeSet<PathBuf>>,
            files: RefCell<BTreeMap<PathBuf, String>>,
            writes: RefCell<Vec<(PathBuf, String)>>,
        }

        impl FakeFs {
            fn directory(&self, path: impl Into<PathBuf>) {
                self.directories.borrow_mut().insert(path.into());
            }

            fn file(&self, path: impl Into<PathBuf>, value: &str) {
                self.files.borrow_mut().insert(path.into(), value.into());
            }
        }

        impl CgroupFs for FakeFs {
            fn read(&self, path: &Path) -> io::Result<String> {
                self.files
                    .borrow()
                    .get(path)
                    .cloned()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
            }

            fn create_dir(&self, path: &Path) -> io::Result<()> {
                if !self.directories.borrow_mut().insert(path.to_path_buf()) {
                    return Err(io::Error::from(io::ErrorKind::AlreadyExists));
                }
                let controllers = path.join("cgroup.controllers");
                self.files
                    .borrow_mut()
                    .insert(controllers, "cpu memory pids".into());
                Ok(())
            }

            fn write(&self, path: &Path, value: &str) -> io::Result<()> {
                self.writes
                    .borrow_mut()
                    .push((path.to_path_buf(), value.into()));
                self.files
                    .borrow_mut()
                    .insert(path.to_path_buf(), value.into());
                Ok(())
            }

            fn remove_dir(&self, path: &Path) -> io::Result<()> {
                if self.directories.borrow_mut().remove(path) {
                    Ok(())
                } else {
                    Err(io::Error::from(io::ErrorKind::NotFound))
                }
            }

            fn ensure_directory(&self, path: &Path) -> io::Result<()> {
                self.directories
                    .borrow()
                    .contains(path)
                    .then_some(())
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
            }
        }

        #[test]
        fn configures_all_limits_before_atomic_process_placement() {
            let root = Path::new("/cgroup");
            let parent = root.join("delegated");
            let fs = FakeFs::default();
            fs.directory(root);
            fs.directory(&parent);
            fs.file(parent.join("cgroup.controllers"), "cpu memory pids io");
            fs.file(parent.join("cgroup.subtree_control"), "cpu memory pids");
            let namespace = prepare_namespace(&fs, root, "0::/delegated").expect("namespace");
            let leaf =
                create_leaf(&fs, &namespace, "0198c9f4-88af-7cc8-b068-d9bb50f58f2e").expect("leaf");
            let limits = ResourceLimits {
                vcpus: 1,
                memory_mib: 128,
                host_worker_max_processes: 2,
                host_worker_max_open_files: 16,
            };
            configure_leaf(&fs, &leaf, &limits, 4242).expect("configure");
            let writes = fs.writes.borrow();
            let tail = &writes[writes.len() - 4..];
            assert_eq!(tail[0], (leaf.join("memory.max"), "402653184".into()));
            assert_eq!(tail[1], (leaf.join("pids.max"), "2".into()));
            assert_eq!(tail[2], (leaf.join("cpu.max"), "100000 100000".into()));
            assert_eq!(tail[3], (leaf.join("cgroup.procs"), "4242".into()));
        }

        #[test]
        fn missing_controller_fails_closed_before_creating_namespace() {
            let root = Path::new("/cgroup");
            let fs = FakeFs::default();
            fs.directory(root);
            fs.file(root.join("cgroup.controllers"), "cpu memory");
            let error = prepare_namespace(&fs, root, "0::/").expect_err("missing pids");
            assert!(error.0.contains("missing required cgroup v2 controller"));
            assert!(!fs.directories.borrow().contains(&root.join(NAMESPACE)));
        }
    }
}

/// Probes actual cgroup v2 delegation by creating a transient empty leaf and
/// writing all three controller limit files. The current process is not moved.
pub fn probe_linux_worker_cgroup() -> RuntimeResult<()> {
    #[cfg(target_os = "linux")]
    {
        cgroup::probe()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

fn place_linux_worker_cgroup(spec: &box_runtime::WorkerSpec) -> RuntimeResult<()> {
    #[cfg(target_os = "linux")]
    {
        cgroup::place(spec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = spec;
        Ok(())
    }
}

fn verify_parent_identity(expected_parent_pid: u32) -> RuntimeResult<()> {
    // SAFETY: getppid has no pointer arguments or preconditions.
    if expected_parent_pid == 0 || unsafe { libc::getppid() } as u32 != expected_parent_pid {
        return Err(RuntimeError("worker parent identity mismatch".into()));
    }
    Ok(())
}

fn start_parent_watchdog(expected_parent_pid: u32) -> RuntimeResult<()> {
    verify_parent_identity(expected_parent_pid)?;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_PDEATHSIG takes scalar arguments for this process.
        let result = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
        // SAFETY: getppid has no pointer arguments or preconditions.
        if result != 0 || unsafe { libc::getppid() } as u32 != expected_parent_pid {
            return Err(RuntimeError(
                "cannot establish worker parent-death policy".into(),
            ));
        }
    }
    std::thread::Builder::new()
        .name("boxd-parent-watchdog".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(250));
                // SAFETY: getppid has no pointer arguments or preconditions.
                if unsafe { libc::getppid() } as u32 != expected_parent_pid {
                    // SAFETY: getpid is always valid and SIGKILL is a valid
                    // signal; this intentionally terminates an orphan worker.
                    unsafe {
                        libc::kill(libc::getpid(), libc::SIGKILL);
                    }
                    return;
                }
            }
        })
        .map_err(|error| RuntimeError(format!("cannot start parent watchdog: {error}")))?;
    Ok(())
}

/// Narrow, mockable stable ABI surface. Error values are preserved verbatim.
pub trait KrunApi {
    fn create_ctx(&self) -> i32;
    fn free_ctx(&self, ctx: u32) -> i32;
    fn set_vm_config(&self, ctx: u32, vcpus: u8, memory_mib: u32) -> i32;
    fn add_disk(&self, ctx: u32, block_id: &str, path: &str, read_only: bool)
    -> RuntimeResult<i32>;
    fn set_root_disk_remount(
        &self,
        ctx: u32,
        device: &str,
        fstype: &str,
        options: Option<&str>,
    ) -> RuntimeResult<i32>;
    fn set_exec(
        &self,
        ctx: u32,
        path: &str,
        argv: &[String],
        environment: &[String],
    ) -> RuntimeResult<i32>;
    fn add_vsock_port2(&self, ctx: u32, port: u32, path: &str, listen: bool) -> RuntimeResult<i32>;
    fn set_console_output(&self, ctx: u32, path: &str) -> RuntimeResult<i32>;
    fn add_net_unixstream(
        &self,
        ctx: u32,
        fd: i32,
        mac: &mut [u8; 6],
        features: u32,
        flags: u32,
    ) -> i32;
    fn has_feature(&self, feature: u64) -> i32;
    fn has_vsock_symbol(&self) -> bool;
}
fn probe_api(api: &impl KrunApi) -> RuntimeResult<DriverCapabilities> {
    let capabilities = DriverCapabilities {
        blk: api.has_feature(FEATURE_BLK) > 0,
        net: api.has_feature(FEATURE_NET) > 0,
        vsock: api.has_vsock_symbol(),
    };
    if !capabilities.blk || !capabilities.net || !capabilities.vsock {
        return Err(RuntimeError(
            "required libkrun BLK/NET/vsock capability unavailable".into(),
        ));
    }
    Ok(capabilities)
}
fn rc(code: i32, what: &str) -> RuntimeResult<()> {
    if code < 0 {
        Err(RuntimeError(format!(
            "{what} failed with libkrun code {code}"
        )))
    } else {
        Ok(())
    }
}
pub struct Context<'a, A: KrunApi> {
    api: &'a A,
    id: Option<u32>,
    network_guest: Option<UnixStream>,
    network_peer: Option<UnixStream>,
    base_disk: Option<File>,
    writable_disk: Option<File>,
}
impl<'a, A: KrunApi> Context<'a, A> {
    pub fn create(api: &'a A) -> RuntimeResult<Self> {
        let id = api.create_ctx();
        if id < 0 {
            return Err(RuntimeError(format!(
                "krun_create_ctx failed with libkrun code {id}"
            )));
        }
        Ok(Self {
            api,
            id: Some(id as u32),
            network_guest: None,
            network_peer: None,
            base_disk: None,
            writable_disk: None,
        })
    }
    fn id(&self) -> u32 {
        self.id.expect("context live")
    }
    pub fn configure(&mut self, s: &WorkerSpec) -> RuntimeResult<()> {
        let guest_environment = guest_environment(s)?;
        probe_api(self.api)?;
        rc(
            self.api.set_vm_config(self.id(), s.vcpus, s.memory_mib),
            "krun_set_vm_config",
        )?;
        let base_disk = open_path_no_symlinks(&s.base_root_disk, false, "base root disk")?;
        let writable_disk =
            open_path_no_symlinks(&s.writable_data_disk, true, "writable data disk")?;
        if same_open_file(&base_disk, &writable_disk)? {
            return Err(RuntimeError(
                "base and writable disks resolve to the same inode".into(),
            ));
        }
        let root_disk = descriptor_path(&base_disk);
        let data_disk = descriptor_path(&writable_disk);
        let vsock_socket = utf8_path(&s.vsock_socket)?;
        let console_path = utf8_path(&s.console_path)?;
        rc(
            self.api.add_disk(self.id(), "rootfs", &root_disk, true)?,
            "krun_add_disk(rootfs)",
        )?;
        rc(
            self.api.add_disk(self.id(), "data", &data_disk, false)?,
            "krun_add_disk(data)",
        )?;
        rc(
            self.api
                .set_root_disk_remount(self.id(), PRIVATE_ROOT_DEVICE, "ext4", None)?,
            "krun_set_root_disk_remount",
        )?;
        let argv = vec![GUEST_AGENT_PATH.to_owned()];
        rc(
            self.api
                .set_exec(self.id(), GUEST_AGENT_PATH, &argv, &guest_environment)?,
            "krun_set_exec",
        )?;
        self.base_disk = Some(base_disk);
        self.writable_disk = Some(writable_disk);
        rc(
            self.api
                .add_vsock_port2(self.id(), s.vsock_port, vsock_socket, true)?,
            "krun_add_vsock_port2",
        )?;
        rc(
            self.api.set_console_output(self.id(), console_path)?,
            "krun_set_console_output",
        )?;
        match s.network_mode {
            NetworkMode::DenyAll => self.configure_deny_all_network(),
            NetworkMode::RestrictedDefault => self.configure_restricted_network(),
            NetworkMode::Custom => self.configure_network_pair("custom", NET_FLAG_DHCP_CLIENT),
        }
    }

    fn configure_deny_all_network(&mut self) -> RuntimeResult<()> {
        self.configure_network_pair("deny-all", 0)
    }

    fn configure_restricted_network(&mut self) -> RuntimeResult<()> {
        self.configure_network_pair("restricted-default", NET_FLAG_DHCP_CLIENT)
    }

    fn configure_network_pair(&mut self, mode: &str, flags: u32) -> RuntimeResult<()> {
        let (guest, peer) = UnixStream::pair()
            .map_err(|error| RuntimeError(format!("cannot create {mode} network pair: {error}")))?;
        let mut mac = GUEST_MAC;
        rc(
            self.api
                .add_net_unixstream(self.id(), guest.as_raw_fd(), &mut mac, 0, flags),
            "krun_add_net_unixstream",
        )?;
        self.network_guest = Some(guest);
        self.network_peer = Some(peer);
        Ok(())
    }

    /// Starts a read-only sink and transfers the configured guest endpoint to
    /// libkrun. The v1.19.4 source constructs `OwnedFd::from_raw_fd` while
    /// activating this device, so Rust must disarm its owner before entering.
    fn arm_network(&mut self, spec: &WorkerSpec) -> RuntimeResult<()> {
        for (label, file) in [
            ("base root disk", self.base_disk.as_ref()),
            ("writable data disk", self.writable_disk.as_ref()),
        ] {
            let metadata = file
                .ok_or_else(|| RuntimeError(format!("{label} is not pinned")))?
                .metadata()
                .map_err(|error| RuntimeError(format!("cannot revalidate {label}: {error}")))?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(RuntimeError(format!(
                    "{label} identity changed before VM entry"
                )));
            }
        }
        let mut peer = self
            .network_peer
            .take()
            .ok_or_else(|| RuntimeError("network peer is not configured".into()))?;
        let interception = http_interception(spec)?;
        match spec.network_mode {
            NetworkMode::DenyAll => {
                std::thread::Builder::new()
                    .name("boxd-net-blackhole".into())
                    .spawn(move || {
                        let _ = std::io::copy(&mut peer, &mut std::io::sink());
                    })
                    .map_err(|error| {
                        RuntimeError(format!("cannot start deny-all network sink: {error}"))
                    })?;
            }
            NetworkMode::RestrictedDefault => {
                let resolvers = spec.dns_servers.clone();
                let result = match interception {
                    Some(interception) => spawn_restricted_proxy_with_http_interception(
                        peer,
                        resolvers,
                        spec.dns_over_https_name.clone(),
                        ProxyLimits::default(),
                        interception,
                    ),
                    None => spawn_restricted_proxy(
                        peer,
                        resolvers,
                        spec.dns_over_https_name.clone(),
                        ProxyLimits::default(),
                    ),
                };
                result.map_err(|error| {
                    RuntimeError(format!("cannot start restricted network proxy: {error}"))
                })?;
            }
            NetworkMode::Custom => {
                let policy = spec.custom_network_policy.as_ref().ok_or_else(|| {
                    RuntimeError("custom network policy is missing after validation".into())
                })?;
                let policy = CustomNetworkPolicy::from_strings(
                    policy.allowed_domains.clone(),
                    policy.allowed_cidrs.clone(),
                    policy.denied_cidrs.clone(),
                )
                .map_err(|_| RuntimeError("custom network policy failed revalidation".into()))?;
                let result = match interception {
                    Some(interception) => spawn_custom_proxy_with_http_interception(
                        peer,
                        spec.dns_servers.clone(),
                        spec.dns_over_https_name.clone(),
                        ProxyLimits::default(),
                        policy,
                        interception,
                    ),
                    None => spawn_custom_proxy(
                        peer,
                        spec.dns_servers.clone(),
                        spec.dns_over_https_name.clone(),
                        ProxyLimits::default(),
                        policy,
                    ),
                };
                result.map_err(|error| {
                    RuntimeError(format!("cannot start custom network proxy: {error}"))
                })?;
            }
        }
        let guest = self
            .network_guest
            .take()
            .ok_or_else(|| RuntimeError("network endpoint is not configured".into()))?;
        let _libkrun_owned_fd = guest.into_raw_fd();
        Ok(())
    }
}

fn http_interception(spec: &WorkerSpec) -> RuntimeResult<Option<Arc<HttpInterceptionConfig>>> {
    let Some(attach_headers) = &spec.attach_headers else {
        return Ok(None);
    };
    let mut rules = Vec::with_capacity(attach_headers.rules.len());
    for (pattern, headers) in &attach_headers.rules {
        let pattern = HostPattern::parse(pattern)
            .map_err(|_| RuntimeError("invalid attach_headers host pattern".into()))?;
        let mut values = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            let value = SecretHeaderValue::new(value.as_bytes().to_vec())
                .map_err(|_| RuntimeError("invalid attach_headers value".into()))?;
            values.push((name.as_str(), value));
        }
        rules.push(
            AttachHeaderRule::new(pattern, values)
                .map_err(|_| RuntimeError("invalid attach_headers rule".into()))?,
        );
    }
    let rules = AttachHeaderRules::new(rules)
        .map_err(|_| RuntimeError("invalid attach_headers rules".into()))?;
    let private_key = SecretPrivateKeyDer::new(attach_headers.ca_private_key_der.clone())
        .map_err(|_| RuntimeError("invalid attach_headers CA private key".into()))?;
    let authority = PerBoxCertificateAuthority::from_der(
        spec.box_id.clone(),
        attach_headers.ca_certificate_der.clone(),
        private_key,
    )
    .map_err(|_| RuntimeError("invalid attach_headers CA certificate or key".into()))?;
    Ok(Some(Arc::new(HttpInterceptionConfig::new(
        Arc::new(authority),
        rules,
    ))))
}

fn guest_environment(spec: &WorkerSpec) -> RuntimeResult<Vec<String>> {
    if spec
        .guest_environment
        .keys()
        .any(|key| key.starts_with("BOXD_"))
    {
        return Err(RuntimeError(
            "guest environment may not override reserved BOXD_ identity variables".into(),
        ));
    }
    let mut environment = vec![
        format!("BOXD_BOOT_NONCE_HEX={}", spec.boot_nonce),
        format!("BOXD_BOX_ID={}", spec.box_id),
        format!(
            "BOXD_AGENT_PROTOCOL_VERSION={}",
            spec.agent_protocol_version
        ),
        format!("BOXD_BROWSER_ENABLED={}", u8::from(spec.browser_enabled)),
        format!(
            "BOXD_NETWORK_MODE={}",
            match spec.network_mode {
                NetworkMode::DenyAll => "deny-all",
                NetworkMode::RestrictedDefault => "restricted-default",
                NetworkMode::Custom => "custom",
            }
        ),
        format!("BOXD_RUNTIME={}", spec.runtime),
        format!("BOXD_ARCH={}", spec.arch),
        format!("BOXD_IMMUTABLE_BASE_DEVICE={IMMUTABLE_BASE_DEVICE}"),
        format!("BOXD_PRIVATE_ROOT_DEVICE={PRIVATE_ROOT_DEVICE}"),
        "BOXD_WORKSPACE=/workspace".to_owned(),
        format!("BOXD_AGENT_PATH={GUEST_AGENT_PATH}"),
    ];
    if let Some(attach_headers) = &spec.attach_headers {
        let body = BASE64.encode(&attach_headers.ca_certificate_der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).map_err(|_| {
                RuntimeError("egress CA base64 encoding produced invalid UTF-8".into())
            })?);
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        environment.push(format!(
            "BOXD_EGRESS_CA_PEM_BASE64={}",
            BASE64.encode(pem.as_bytes())
        ));
    }
    environment.extend(
        spec.guest_environment
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    Ok(environment)
}

fn utf8_path(path: &Path) -> RuntimeResult<&str> {
    path.to_str()
        .ok_or_else(|| RuntimeError("libkrun path is not valid UTF-8".into()))
}
impl<A: KrunApi> Drop for Context<'_, A> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let _ = self.api.free_ctx(id);
        }
    }
}

/// Reads exactly one bounded, length-prefixed spec and closes the supplied FD.
/// The complete frame, including EOF, must arrive within the total deadline.
#[cfg(unix)]
pub fn read_spec_fd(fd: std::os::fd::RawFd) -> RuntimeResult<WorkerSpec> {
    read_spec_fd_with_timeout(fd, WORKER_SPEC_READ_TIMEOUT)
}

#[cfg(unix)]
pub fn read_spec_fd_with_timeout(
    fd: std::os::fd::RawFd,
    read_timeout: Duration,
) -> RuntimeResult<WorkerSpec> {
    use std::os::fd::FromRawFd;
    // SAFETY: the hidden worker command accepts an owned descriptor. This
    // function is its sole consumer and intentionally closes it on return.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let deadline = Instant::now() + read_timeout;
    let mut prefix = [0; 4];
    read_exact_deadline(&mut file, &mut prefix, deadline)?;
    let n = u32::from_be_bytes(prefix) as usize;
    if n > MAX_WORKER_SPEC_BYTES {
        return Err(RuntimeError("worker spec exceeds limit".into()));
    }
    let mut body = vec![0; n];
    read_exact_deadline(&mut file, &mut body, deadline)?;
    wait_readable(file_fd(&file), deadline)?;
    let mut trailing = [0_u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(RuntimeError("trailing bytes after worker spec".into())),
        Err(error) if error.kind() == ErrorKind::Interrupted => {
            return Err(RuntimeError("worker spec EOF read interrupted".into()));
        }
        Err(error) => {
            return Err(RuntimeError(format!(
                "worker spec EOF read failed: {error}"
            )));
        }
    }
    let mut wire = prefix.to_vec();
    wire.append(&mut body);
    WorkerSpec::from_wire(&wire)
}

#[cfg(unix)]
fn file_fd(file: &File) -> std::os::fd::RawFd {
    use std::os::fd::AsRawFd;
    file.as_raw_fd()
}

#[cfg(unix)]
fn read_exact_deadline(
    file: &mut File,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> RuntimeResult<()> {
    while !buffer.is_empty() {
        wait_readable(file_fd(file), deadline)?;
        match file.read(buffer) {
            Ok(0) => return Err(RuntimeError("unexpected EOF in worker spec".into())),
            Ok(count) => buffer = &mut buffer[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(RuntimeError(format!("worker spec read failed: {error}"))),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn wait_readable(fd: std::os::fd::RawFd, deadline: Instant) -> RuntimeResult<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(RuntimeError("worker spec read timed out".into()));
        }
        let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: `descriptor` points to one initialized pollfd for the full
        // call, and the descriptor remains owned by the live File caller.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready > 0 {
            return Ok(());
        }
        if ready == 0 {
            return Err(RuntimeError("worker spec read timed out".into()));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(RuntimeError(format!("worker spec poll failed: {error}")));
        }
    }
}

mod ffi {
    use super::*;
    pub struct DynamicKrun {
        _library: libloading::Library,
        create: unsafe extern "C" fn() -> i32,
        free: unsafe extern "C" fn(u32) -> i32,
        vm: unsafe extern "C" fn(u32, u8, u32) -> i32,
        disk: unsafe extern "C" fn(u32, *const c_char, *const c_char, bool) -> i32,
        root_remount: unsafe extern "C" fn(u32, *const c_char, *const c_char, *const c_char) -> i32,
        exec: unsafe extern "C" fn(
            u32,
            *const c_char,
            *const *const c_char,
            *const *const c_char,
        ) -> i32,
        vsock: unsafe extern "C" fn(u32, u32, *const c_char, bool) -> i32,
        console: unsafe extern "C" fn(u32, *const c_char) -> i32,
        net: unsafe extern "C" fn(u32, *const c_char, i32, *mut u8, u32, u32) -> i32,
        feature: unsafe extern "C" fn(u64) -> i32,
        start: unsafe extern "C" fn(u32) -> i32,
    }
    impl DynamicKrun {
        /// # Safety
        ///
        /// `path` must identify the checksum-verified v1.19.4 artifact. The
        /// loaded library is retained for at least as long as every symbol.
        pub unsafe fn load(path: &Path) -> RuntimeResult<Self> {
            // SAFETY: the caller verifies artifact identity before loading;
            // `_library` below keeps all resolved symbols alive.
            let lib = unsafe { libloading::Library::new(path) }
                .map_err(|e| RuntimeError(e.to_string()))?;
            require_abi_symbols(|name| {
                // SAFETY: this preflight only checks symbol presence. The
                // typed resolutions below establish the pinned ABI types.
                unsafe { lib.get::<*mut std::ffi::c_void>(name) }.is_ok()
            })?;
            macro_rules! sym {
                ($name:literal,$ty:ty) => {
                    // SAFETY: symbol names and signatures are copied from the
                    // pinned libkrun v1.19.4 public C header.
                    *unsafe { lib.get::<$ty>($name) }.map_err(|e| RuntimeError(e.to_string()))?
                };
            }
            Ok(Self {
                create: sym!(b"krun_create_ctx\0", unsafe extern "C" fn() -> i32),
                free: sym!(b"krun_free_ctx\0", unsafe extern "C" fn(u32) -> i32),
                vm: sym!(
                    b"krun_set_vm_config\0",
                    unsafe extern "C" fn(u32, u8, u32) -> i32
                ),
                disk: sym!(
                    b"krun_add_disk\0",
                    unsafe extern "C" fn(u32, *const c_char, *const c_char, bool) -> i32
                ),
                root_remount: sym!(
                    b"krun_set_root_disk_remount\0",
                    unsafe extern "C" fn(u32, *const c_char, *const c_char, *const c_char) -> i32
                ),
                exec: sym!(
                    b"krun_set_exec\0",
                    unsafe extern "C" fn(
                        u32,
                        *const c_char,
                        *const *const c_char,
                        *const *const c_char,
                    ) -> i32
                ),
                vsock: sym!(
                    b"krun_add_vsock_port2\0",
                    unsafe extern "C" fn(u32, u32, *const c_char, bool) -> i32
                ),
                console: sym!(
                    b"krun_set_console_output\0",
                    unsafe extern "C" fn(u32, *const c_char) -> i32
                ),
                net: sym!(
                    b"krun_add_net_unixstream\0",
                    unsafe extern "C" fn(u32, *const c_char, i32, *mut u8, u32, u32) -> i32
                ),
                feature: sym!(b"krun_has_feature\0", unsafe extern "C" fn(u64) -> i32),
                start: sym!(b"krun_start_enter\0", unsafe extern "C" fn(u32) -> i32),
                _library: lib,
            })
        }
        pub(super) unsafe fn start_enter(&self, ctx: u32) -> i32 {
            // SAFETY: `ctx` is a live, configured context transferred from
            // Context; this worker is allowed to be consumed/exited by libkrun.
            unsafe { (self.start)(ctx) }
        }
    }
    impl KrunApi for DynamicKrun {
        // SAFETY for the calls below: every function pointer was resolved with
        // the exact v1.19.4 header signature, the library is retained by self,
        // context IDs originate from create_ctx, and CString arguments remain
        // alive for the duration of each synchronous C call.
        fn create_ctx(&self) -> i32 {
            unsafe { (self.create)() }
        }
        fn free_ctx(&self, c: u32) -> i32 {
            unsafe { (self.free)(c) }
        }
        fn set_vm_config(&self, c: u32, v: u8, m: u32) -> i32 {
            unsafe { (self.vm)(c, v, m) }
        }
        fn add_disk(&self, c: u32, b: &str, p: &str, r: bool) -> RuntimeResult<i32> {
            let b = c_string(b, "block id")?;
            let p = c_string(p, "disk path")?;
            Ok(unsafe { (self.disk)(c, b.as_ptr(), p.as_ptr(), r) })
        }
        fn set_root_disk_remount(
            &self,
            c: u32,
            device: &str,
            fstype: &str,
            options: Option<&str>,
        ) -> RuntimeResult<i32> {
            let device = c_string(device, "root device")?;
            let fstype = c_string(fstype, "root filesystem type")?;
            let options = options
                .map(|value| c_string(value, "root mount options"))
                .transpose()?;
            Ok(unsafe {
                (self.root_remount)(
                    c,
                    device.as_ptr(),
                    fstype.as_ptr(),
                    options
                        .as_ref()
                        .map_or(std::ptr::null(), |value| value.as_ptr()),
                )
            })
        }
        fn set_exec(
            &self,
            c: u32,
            path: &str,
            argv: &[String],
            environment: &[String],
        ) -> RuntimeResult<i32> {
            let path = c_string(path, "guest executable")?;
            let argv = c_string_array(argv, "guest argv")?;
            let environment = c_string_array(environment, "guest environment")?;
            let argv_pointers = null_terminated_pointers(&argv);
            let environment_pointers = null_terminated_pointers(&environment);
            Ok(unsafe {
                (self.exec)(
                    c,
                    path.as_ptr(),
                    argv_pointers.as_ptr(),
                    environment_pointers.as_ptr(),
                )
            })
        }
        fn add_vsock_port2(&self, c: u32, p: u32, s: &str, l: bool) -> RuntimeResult<i32> {
            let s = c_string(s, "vsock path")?;
            Ok(unsafe { (self.vsock)(c, p, s.as_ptr(), l) })
        }
        fn set_console_output(&self, c: u32, p: &str) -> RuntimeResult<i32> {
            let p = c_string(p, "console path")?;
            Ok(unsafe { (self.console)(c, p.as_ptr()) })
        }
        fn add_net_unixstream(
            &self,
            c: u32,
            fd: i32,
            mac: &mut [u8; 6],
            features: u32,
            flags: u32,
        ) -> i32 {
            unsafe { (self.net)(c, std::ptr::null(), fd, mac.as_mut_ptr(), features, flags) }
        }
        fn has_feature(&self, f: u64) -> i32 {
            unsafe { (self.feature)(f) }
        }
        fn has_vsock_symbol(&self) -> bool {
            true
        }
    }
}

fn c_string(value: &str, field: &str) -> RuntimeResult<CString> {
    CString::new(value).map_err(|_| RuntimeError(format!("{field} contains an interior NUL byte")))
}

fn c_string_array(values: &[String], field: &str) -> RuntimeResult<Vec<CString>> {
    values.iter().map(|value| c_string(value, field)).collect()
}

fn null_terminated_pointers(values: &[CString]) -> Vec<*const c_char> {
    let mut pointers = values
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    pointers.push(std::ptr::null());
    pointers
}

/// Worker-only entry point. It is intentionally the only caller of start_enter.
#[cfg(unix)]
pub fn worker_entry(spec_fd: std::os::fd::RawFd) -> RuntimeResult<()> {
    let spec = read_spec_fd(spec_fd)?;
    if std::env::var_os(PREPARED_RUNTIME_ENV).is_none() {
        verify_parent_identity(spec.expected_parent_pid)?;
        let directory = prepare_private_runtime(&spec)?;
        if let Err(error) = verify_parent_identity(spec.expected_parent_pid) {
            cleanup_prepared_runtime_path(&spec, &directory);
            return Err(error);
        }
        return reexec_with_private_runtime(&spec, &directory);
    }
    let private_directory_path = prepared_runtime_directory(&spec)?;
    // The wire writer closes its pipe before EOF; reap it before the VMM starts.
    let writer_pid = std::env::var("BOXD_WIRE_WRITER_PID")
        .ok()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| RuntimeError("prepared wire writer identity is missing".into()))?;
    let mut writer_status = 0;
    // SAFETY: the re-exec stage waits only for the explicitly recorded writer,
    // never an unrelated child that may be added later.
    if unsafe { libc::waitpid(writer_pid, &mut writer_status, 0) } < 0
        || !libc::WIFEXITED(writer_status)
        || libc::WEXITSTATUS(writer_status) != 0
    {
        cleanup_prepared_runtime_path(&spec, &private_directory_path);
        return Err(RuntimeError("prepared wire writer failed".into()));
    }
    let private_directory =
        open_directory_no_symlinks(&private_directory_path, "prepared runtime directory")?;
    verify_private_directory_owner(&private_directory, "prepared runtime directory")?;
    let mut private_runtime = PrivateRuntimeGuard {
        spec: &spec,
        directory: &private_directory,
        armed: true,
    };
    start_parent_watchdog(spec.expected_parent_pid)?;
    let mut private_spec = spec.clone();
    private_spec.libkrun_library = private_directory_path.join(PRIVATE_LIBKRUN_NAME);
    private_spec.libkrun_firmware = private_directory_path.join(FIRMWARE_SONAME);
    let mut firmware = open_path_no_symlinks(
        &private_spec.libkrun_firmware,
        false,
        "prepared libkrun firmware",
    )?;
    verify_private_file_owner(&firmware, "prepared libkrun firmware")?;
    verify_firmware_file(&mut firmware, &private_spec.libkrun_firmware_identity)?;
    #[cfg(target_os = "macos")]
    verify_macos_code_signature(&private_spec.libkrun_firmware, "pinned libkrun firmware")?;
    #[cfg(target_os = "macos")]
    verify_firmware_file(&mut firmware, &private_spec.libkrun_firmware_identity)?;
    #[cfg(not(target_os = "macos"))]
    let library = snapshot_verified_library(&private_spec)?;
    #[cfg(not(target_os = "macos"))]
    let library_path = PathBuf::from(descriptor_path(&library));
    #[cfg(target_os = "macos")]
    let library_path = private_spec.libkrun_library.clone();
    #[cfg(target_os = "macos")]
    {
        let mut library = open_path_no_symlinks(&library_path, false, "prepared libkrun library")?;
        verify_private_file_owner(&library, "prepared libkrun library")?;
        verify_library_file(&mut library, &private_spec.libkrun_identity)?;
        verify_macos_code_signature(&library_path, "pinned libkrun")?;
        verify_library_file(&mut library, &private_spec.libkrun_identity)?;
    }
    #[cfg(target_os = "macos")]
    let preserved_fds = vec![private_directory.as_raw_fd(), firmware.as_raw_fd()];
    #[cfg(not(target_os = "macos"))]
    let preserved_fds = vec![
        private_directory.as_raw_fd(),
        firmware.as_raw_fd(),
        library.as_raw_fd(),
    ];
    if let Err(error) = apply_process_isolation(&spec.limits, &RealIsolation, &preserved_fds) {
        cleanup_prepared_runtime_path(&spec, &private_directory_path);
        return Err(error);
    }
    if let Err(error) = place_linux_worker_cgroup(&spec) {
        cleanup_prepared_runtime_path(&spec, &private_directory_path);
        return Err(error);
    }
    // SAFETY: snapshot_verified_library copied and verified the artifact into
    // an unlinked private file on Linux. macOS instead uses the verified,
    // signed linked file retained by `private_runtime` because system policy
    // rejects signed dylibs loaded through an unlinked `/dev/fd` path.
    let api = unsafe { ffi::DynamicKrun::load(&library_path) }?;
    let context = Context::create(&api);
    // krun_create_ctx initializes v1.19.4's LazyLock and resolves the firmware
    // by its fixed name through the stage-2 private loader directory. Both
    // artifacts can now be unlinked without changing the loaded objects.
    #[cfg(not(target_os = "macos"))]
    private_runtime.cleanup();
    let mut ctx = context?;
    ctx.configure(&spec)?;
    install_linux_worker_seccomp()?;
    ctx.arm_network(&spec)?;
    let id = ctx.id.take().expect("live context");
    // SAFETY: the context is fully configured, its network descriptor has
    // been transferred exactly once, and this disposable worker may be exited.
    let code = unsafe { api.start_enter(id) };
    drop(ctx);
    drop(api);
    drop(firmware);
    private_runtime.cleanup();
    rc(code, "krun_start_enter")
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LibkrunAdapterBoundary;

#[cfg(test)]
mod tests {
    use super::*;
    use box_runtime::WORKER_SPEC_VERSION;
    use std::cell::RefCell;
    struct Fake {
        calls: RefCell<Vec<String>>,
        guest_env: RefCell<Vec<String>>,
        guest_exec: RefCell<Option<String>>,
        guest_argv: RefCell<Vec<String>>,
        missing_feature: Option<u64>,
        vsock_available: bool,
        fail: Option<&'static str>,
        network_flags: RefCell<Vec<u32>>,
    }
    impl Fake {
        fn call(&self, n: &str) -> i32 {
            self.calls.borrow_mut().push(n.into());
            if self.fail == Some(n) { -9 } else { 0 }
        }
    }
    impl KrunApi for Fake {
        fn create_ctx(&self) -> i32 {
            self.call("create");
            7
        }
        fn free_ctx(&self, _: u32) -> i32 {
            self.call("free")
        }
        fn set_vm_config(&self, _: u32, _: u8, _: u32) -> i32 {
            self.call("vm")
        }
        fn add_disk(&self, _: u32, b: &str, _: &str, _: bool) -> RuntimeResult<i32> {
            Ok(self.call(b))
        }
        fn set_root_disk_remount(
            &self,
            _: u32,
            device: &str,
            fstype: &str,
            options: Option<&str>,
        ) -> RuntimeResult<i32> {
            assert_eq!((device, fstype, options), ("/dev/vdb", "ext4", None));
            Ok(self.call("root-remount"))
        }
        fn set_exec(
            &self,
            _: u32,
            path: &str,
            argv: &[String],
            environment: &[String],
        ) -> RuntimeResult<i32> {
            *self.guest_exec.borrow_mut() = Some(path.to_owned());
            *self.guest_argv.borrow_mut() = argv.to_vec();
            *self.guest_env.borrow_mut() = environment.to_vec();
            Ok(self.call("exec"))
        }
        fn add_vsock_port2(&self, _: u32, _: u32, _: &str, _: bool) -> RuntimeResult<i32> {
            Ok(self.call("vsock"))
        }
        fn set_console_output(&self, _: u32, _: &str) -> RuntimeResult<i32> {
            Ok(self.call("console"))
        }
        fn add_net_unixstream(&self, _: u32, _: i32, _: &mut [u8; 6], _: u32, flags: u32) -> i32 {
            self.network_flags.borrow_mut().push(flags);
            self.call("net")
        }
        fn has_feature(&self, feature: u64) -> i32 {
            i32::from(self.missing_feature != Some(feature))
        }
        fn has_vsock_symbol(&self) -> bool {
            self.vsock_available
        }
    }
    #[test]
    fn failure_frees_once() {
        let f = Fake {
            calls: RefCell::new(vec![]),
            guest_env: RefCell::new(vec![]),
            guest_exec: RefCell::new(None),
            guest_argv: RefCell::new(vec![]),
            missing_feature: None,
            vsock_available: true,
            fail: Some("vm"),
            network_flags: RefCell::new(vec![]),
        };
        let mut c = Context::create(&f).unwrap();
        let s = WorkerSpec {
            version: WORKER_SPEC_VERSION,
            box_id: String::new(),
            expected_parent_pid: 0,
            agent_protocol_version: 1,
            browser_enabled: false,
            runtime: "node".into(),
            arch: "aarch64".into(),
            data_root: Default::default(),
            base_root_disk: Default::default(),
            writable_data_disk: Default::default(),
            vcpus: 1,
            memory_mib: 128,
            console_path: Default::default(),
            vsock_socket: Default::default(),
            vsock_port: 18080,
            boot_nonce: "0123456789abcdef".repeat(4),
            workdir: Default::default(),
            guest_environment: Default::default(),
            limits: box_runtime::ResourceLimits {
                vcpus: 1,
                memory_mib: 128,
                host_worker_max_processes: 1,
                host_worker_max_open_files: 1,
            },
            libkrun_library: Default::default(),
            libkrun_identity: LibraryIdentity {
                tag: LIBKRUN_TAG.into(),
                commit: LIBKRUN_COMMIT.into(),
                header_sha256: LIBKRUN_HEADER_SHA256.into(),
                artifact_sha256: "0".repeat(64),
            },
            libkrun_firmware: Default::default(),
            libkrun_firmware_identity: FirmwareIdentity {
                version: "5".into(),
                soname: FIRMWARE_SONAME.into(),
                artifact_sha256: "0".repeat(64),
            },
            network_mode: NetworkMode::DenyAll,
            custom_network_policy: None,
            attach_headers: None,
            dns_servers: vec![],
            dns_over_https_name: None,
        };
        assert!(c.configure(&s).is_err());
        drop(c);
        assert_eq!(&*f.calls.borrow(), &["create", "vm", "free"]);
    }

    #[test]
    fn deny_all_network_is_explicitly_configured_before_start() {
        let f = Fake {
            calls: RefCell::new(vec![]),
            guest_env: RefCell::new(vec![]),
            guest_exec: RefCell::new(None),
            guest_argv: RefCell::new(vec![]),
            missing_feature: None,
            vsock_available: true,
            fail: None,
            network_flags: RefCell::new(vec![]),
        };
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        for name in ["base.raw", "data.raw"] {
            std::fs::write(root.join(name), []).unwrap();
        }
        let mut c = Context::create(&f).unwrap();
        let s = WorkerSpec {
            version: WORKER_SPEC_VERSION,
            box_id: "01890f3e-7b2a-7cc1-8000-000000000001".into(),
            expected_parent_pid: 0,
            agent_protocol_version: 1,
            browser_enabled: true,
            runtime: "node".into(),
            arch: "aarch64".into(),
            data_root: root.clone(),
            base_root_disk: root.join("base.raw"),
            writable_data_disk: root.join("data.raw"),
            vcpus: 1,
            memory_mib: 128,
            console_path: Default::default(),
            vsock_socket: Default::default(),
            vsock_port: 18080,
            boot_nonce: "0123456789abcdef".repeat(4),
            workdir: Default::default(),
            guest_environment: [
                ("LANG".into(), "C.UTF-8".into()),
                ("TOKEN".into(), "guest-secret".into()),
            ]
            .into(),
            limits: box_runtime::ResourceLimits {
                vcpus: 1,
                memory_mib: 128,
                host_worker_max_processes: 2,
                host_worker_max_open_files: 16,
            },
            libkrun_library: Default::default(),
            libkrun_identity: LibraryIdentity {
                tag: LIBKRUN_TAG.into(),
                commit: LIBKRUN_COMMIT.into(),
                header_sha256: LIBKRUN_HEADER_SHA256.into(),
                artifact_sha256: "0".repeat(64),
            },
            libkrun_firmware: Default::default(),
            libkrun_firmware_identity: FirmwareIdentity {
                version: "5".into(),
                soname: FIRMWARE_SONAME.into(),
                artifact_sha256: "0".repeat(64),
            },
            network_mode: NetworkMode::DenyAll,
            custom_network_policy: None,
            attach_headers: None,
            dns_servers: vec![],
            dns_over_https_name: None,
        };
        c.configure(&s).unwrap();
        assert_eq!(
            &*f.calls.borrow(),
            &[
                "create",
                "vm",
                "rootfs",
                "data",
                "root-remount",
                "exec",
                "vsock",
                "console",
                "net"
            ]
        );
        assert_eq!(
            f.guest_exec.borrow().as_deref(),
            Some("/usr/local/bin/box-agent")
        );
        assert_eq!(&*f.guest_argv.borrow(), &["/usr/local/bin/box-agent"]);
        assert_eq!(
            &*f.guest_env.borrow(),
            &[
                format!("BOXD_BOOT_NONCE_HEX={}", "0123456789abcdef".repeat(4)),
                "BOXD_BOX_ID=01890f3e-7b2a-7cc1-8000-000000000001".to_owned(),
                "BOXD_AGENT_PROTOCOL_VERSION=1".to_owned(),
                "BOXD_BROWSER_ENABLED=1".to_owned(),
                "BOXD_NETWORK_MODE=deny-all".to_owned(),
                "BOXD_RUNTIME=node".to_owned(),
                "BOXD_ARCH=aarch64".to_owned(),
                "BOXD_IMMUTABLE_BASE_DEVICE=/dev/vda".to_owned(),
                "BOXD_PRIVATE_ROOT_DEVICE=/dev/vdb".to_owned(),
                "BOXD_WORKSPACE=/workspace".to_owned(),
                "BOXD_AGENT_PATH=/usr/local/bin/box-agent".to_owned(),
                "LANG=C.UTF-8".to_owned(),
                "TOKEN=guest-secret".to_owned(),
            ]
        );
        assert!(c.network_guest.is_some());
        assert!(c.network_peer.is_some());
        std::fs::hard_link(root.join("base.raw"), root.join("late-alias.raw")).unwrap();
        assert!(c.arm_network(&s).is_err());
    }

    #[test]
    fn restricted_network_enables_libkrun_embedded_dhcp_client() {
        let f = Fake {
            calls: RefCell::new(vec![]),
            guest_env: RefCell::new(vec![]),
            guest_exec: RefCell::new(None),
            guest_argv: RefCell::new(vec![]),
            missing_feature: None,
            vsock_available: true,
            fail: None,
            network_flags: RefCell::new(vec![]),
        };
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        for name in ["base.raw", "data.raw"] {
            std::fs::write(root.join(name), []).unwrap();
        }
        let mut c = Context::create(&f).unwrap();
        let mut s = WorkerSpec {
            version: WORKER_SPEC_VERSION,
            box_id: "01890f3e-7b2a-7cc1-8000-000000000001".into(),
            expected_parent_pid: 0,
            agent_protocol_version: 1,
            browser_enabled: false,
            runtime: "node".into(),
            arch: "aarch64".into(),
            data_root: root.clone(),
            base_root_disk: root.join("base.raw"),
            writable_data_disk: root.join("data.raw"),
            vcpus: 1,
            memory_mib: 128,
            console_path: Default::default(),
            vsock_socket: Default::default(),
            vsock_port: 18080,
            boot_nonce: "0123456789abcdef".repeat(4),
            workdir: Default::default(),
            guest_environment: Default::default(),
            limits: box_runtime::ResourceLimits {
                vcpus: 1,
                memory_mib: 128,
                host_worker_max_processes: 2,
                host_worker_max_open_files: 16,
            },
            libkrun_library: Default::default(),
            libkrun_identity: LibraryIdentity {
                tag: LIBKRUN_TAG.into(),
                commit: LIBKRUN_COMMIT.into(),
                header_sha256: LIBKRUN_HEADER_SHA256.into(),
                artifact_sha256: "0".repeat(64),
            },
            libkrun_firmware: Default::default(),
            libkrun_firmware_identity: FirmwareIdentity {
                version: "5".into(),
                soname: FIRMWARE_SONAME.into(),
                artifact_sha256: "0".repeat(64),
            },
            network_mode: NetworkMode::RestrictedDefault,
            custom_network_policy: None,
            attach_headers: None,
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
            dns_over_https_name: None,
        };
        c.configure(&s).unwrap();
        assert_eq!(&*f.network_flags.borrow(), &[NET_FLAG_DHCP_CLIENT]);
        assert!(
            f.guest_env
                .borrow()
                .iter()
                .any(|value| value == "BOXD_NETWORK_MODE=restricted-default")
        );
        s.network_mode = NetworkMode::Custom;
        s.custom_network_policy = Some(box_runtime::CustomNetworkPolicySpec {
            allowed_domains: vec!["api.example.com".into()],
            allowed_cidrs: vec![],
            denied_cidrs: vec!["10.0.0.0/8".into()],
        });
        let mut custom = Context::create(&f).unwrap();
        custom.configure(&s).unwrap();
        assert_eq!(f.network_flags.borrow().last(), Some(&NET_FLAG_DHCP_CLIENT));
    }

    #[test]
    fn attach_headers_builds_redacted_host_interception_and_exports_only_the_ca() {
        let authority =
            PerBoxCertificateAuthority::generate("01890f3e-7b2a-7cc1-8000-000000000001").unwrap();
        let certificate = authority.certificate_der().as_ref().to_vec();
        let private_key = authority.private_key_der().expose_secret().to_vec();
        let header_secret = "phase4-header-secret";
        let spec = WorkerSpec {
            version: WORKER_SPEC_VERSION,
            box_id: "01890f3e-7b2a-7cc1-8000-000000000001".into(),
            expected_parent_pid: 0,
            agent_protocol_version: 1,
            browser_enabled: false,
            runtime: "node".into(),
            arch: "aarch64".into(),
            data_root: Default::default(),
            base_root_disk: Default::default(),
            writable_data_disk: Default::default(),
            vcpus: 1,
            memory_mib: 128,
            console_path: Default::default(),
            vsock_socket: Default::default(),
            vsock_port: 18_080,
            boot_nonce: "0123456789abcdef".repeat(4),
            workdir: Default::default(),
            guest_environment: Default::default(),
            limits: box_runtime::ResourceLimits {
                vcpus: 1,
                memory_mib: 128,
                host_worker_max_processes: 2,
                host_worker_max_open_files: 16,
            },
            libkrun_library: Default::default(),
            libkrun_identity: LibraryIdentity {
                tag: LIBKRUN_TAG.into(),
                commit: LIBKRUN_COMMIT.into(),
                header_sha256: LIBKRUN_HEADER_SHA256.into(),
                artifact_sha256: "0".repeat(64),
            },
            libkrun_firmware: Default::default(),
            libkrun_firmware_identity: FirmwareIdentity {
                version: "5".into(),
                soname: FIRMWARE_SONAME.into(),
                artifact_sha256: "0".repeat(64),
            },
            network_mode: NetworkMode::RestrictedDefault,
            custom_network_policy: None,
            attach_headers: Some(box_runtime::AttachHeadersSpec {
                rules: [(
                    "api.example.com".into(),
                    [("authorization".into(), header_secret.into())].into(),
                )]
                .into(),
                ca_certificate_der: certificate,
                ca_private_key_der: private_key.clone(),
            }),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
            dns_over_https_name: None,
        };

        let interception = http_interception(&spec).unwrap().unwrap();
        assert_eq!(
            format!("{interception:?}"),
            "HttpInterceptionConfig([REDACTED])"
        );
        let environment = guest_environment(&spec).unwrap();
        assert!(
            environment
                .iter()
                .any(|entry| entry.starts_with("BOXD_EGRESS_CA_PEM_BASE64="))
        );
        let joined_environment = environment.join("\n");
        assert!(!joined_environment.contains(header_secret));
        assert!(!joined_environment.contains(&BASE64.encode(&private_key)));
        assert!(!format!("{spec:?}").contains(header_secret));
    }

    #[test]
    fn reserved_guest_identity_cannot_be_overridden_before_ffi() {
        let f = Fake {
            calls: RefCell::new(vec![]),
            guest_env: RefCell::new(vec![]),
            guest_exec: RefCell::new(None),
            guest_argv: RefCell::new(vec![]),
            missing_feature: None,
            vsock_available: true,
            fail: None,
            network_flags: RefCell::new(vec![]),
        };
        let mut c = Context::create(&f).unwrap();
        let mut s = WorkerSpec {
            version: WORKER_SPEC_VERSION,
            box_id: "01890f3e-7b2a-7cc1-8000-000000000001".into(),
            expected_parent_pid: 0,
            agent_protocol_version: 1,
            browser_enabled: false,
            runtime: "node".into(),
            arch: "aarch64".into(),
            data_root: Default::default(),
            base_root_disk: Default::default(),
            writable_data_disk: Default::default(),
            vcpus: 1,
            memory_mib: 128,
            console_path: Default::default(),
            vsock_socket: Default::default(),
            vsock_port: 18080,
            boot_nonce: "0123456789abcdef".repeat(4),
            workdir: Default::default(),
            guest_environment: Default::default(),
            limits: box_runtime::ResourceLimits {
                vcpus: 1,
                memory_mib: 128,
                host_worker_max_processes: 2,
                host_worker_max_open_files: 16,
            },
            libkrun_library: Default::default(),
            libkrun_identity: LibraryIdentity {
                tag: LIBKRUN_TAG.into(),
                commit: LIBKRUN_COMMIT.into(),
                header_sha256: LIBKRUN_HEADER_SHA256.into(),
                artifact_sha256: "0".repeat(64),
            },
            libkrun_firmware: Default::default(),
            libkrun_firmware_identity: FirmwareIdentity {
                version: "5".into(),
                soname: FIRMWARE_SONAME.into(),
                artifact_sha256: "0".repeat(64),
            },
            network_mode: NetworkMode::DenyAll,
            custom_network_policy: None,
            attach_headers: None,
            dns_servers: vec![],
            dns_over_https_name: None,
        };
        s.guest_environment
            .insert("BOXD_BOOT_NONCE_HEX".into(), "override".into());
        assert!(c.configure(&s).is_err());
        assert_eq!(&*f.calls.borrow(), &["create"]);
        assert!(f.guest_env.borrow().is_empty());
        assert!(f.guest_exec.borrow().is_none());
    }

    #[test]
    fn interior_nul_is_an_explicit_error() {
        let error = c_string("bad\0path", "disk path").unwrap_err();
        assert!(error.0.contains("interior NUL"));
    }

    #[derive(Default)]
    struct FakeIsolation {
        calls: RefCell<Vec<String>>,
    }

    impl IsolationOps for FakeIsolation {
        fn set_nofile(&self, value: u64) -> RuntimeResult<()> {
            self.calls.borrow_mut().push(format!("nofile={value}"));
            Ok(())
        }

        fn set_nproc(&self, value: u64) -> RuntimeResult<()> {
            self.calls.borrow_mut().push(format!("nproc={value}"));
            Ok(())
        }

        fn no_new_privileges(&self) -> RuntimeResult<()> {
            self.calls.borrow_mut().push("no-new-privileges".into());
            Ok(())
        }

        fn close_extra_fds(&self, preserve: &[std::os::fd::RawFd]) -> RuntimeResult<()> {
            self.calls
                .borrow_mut()
                .push(format!("close-extra-fds={preserve:?}"));
            Ok(())
        }
    }

    #[test]
    fn process_limits_and_fd_policy_are_not_ignored() {
        let isolation = FakeIsolation::default();
        apply_process_isolation(
            &box_runtime::ResourceLimits {
                vcpus: 2,
                memory_mib: 512,
                host_worker_max_processes: 73,
                host_worker_max_open_files: 129,
            },
            &isolation,
            &[7, 11],
        )
        .unwrap();
        assert_eq!(
            &*isolation.calls.borrow(),
            &[
                "close-extra-fds=[7, 11]",
                "nofile=129",
                "nproc=73",
                "no-new-privileges"
            ]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn real_fd_isolation_preserves_only_the_explicit_allowlist() {
        let preserved = tempfile::tempfile().unwrap();
        let discarded = tempfile::tempfile().unwrap();
        // SAFETY: the child performs only direct descriptor syscalls and exits
        // without running inherited Rust destructors; the parent waits for the
        // exact child and retains its own independent descriptors.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let result = RealIsolation.close_extra_fds(&[preserved.as_raw_fd()]);
            let preserved_open = unsafe { libc::fcntl(preserved.as_raw_fd(), libc::F_GETFD) } >= 0;
            let discarded_closed = unsafe { libc::fcntl(discarded.as_raw_fd(), libc::F_GETFD) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
            unsafe {
                libc::_exit(i32::from(
                    !(result.is_ok() && preserved_open && discarded_closed),
                ))
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn secure_open_rejects_symlink_and_hardlink_aliases() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let original = root.join("disk.raw");
        let hardlink = root.join("hardlink.raw");
        let symlink_path = root.join("symlink.raw");
        std::fs::write(&original, b"disk").unwrap();
        std::fs::hard_link(&original, &hardlink).unwrap();
        assert!(open_path_no_symlinks(&original, false, "disk").is_err());
        std::fs::remove_file(&hardlink).unwrap();
        symlink(&original, &symlink_path).unwrap();
        assert!(open_path_no_symlinks(&symlink_path, false, "disk").is_err());
    }

    #[test]
    fn dev_fd_path_reopens_the_pinned_inode() {
        use std::io::{Seek, Write};
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let path = root.join("disk.raw");
        std::fs::write(&path, b"before").unwrap();
        let pinned = open_path_no_symlinks(&path, true, "disk").unwrap();
        let mut reopened = OpenOptions::new()
            .read(true)
            .write(true)
            .open(descriptor_path(&pinned))
            .unwrap();
        assert!(same_open_file(&pinned, &reopened).unwrap());
        reopened.seek(SeekFrom::Start(0)).unwrap();
        reopened.write_all(b"after!").unwrap();
        reopened.sync_all().unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"after!");
    }

    #[test]
    fn verified_library_snapshot_is_unlinked_and_immutable_from_source_swaps() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let library_path = root.join("libkrun.dylib");
        let workdir = root.join("work");
        std::fs::create_dir(&workdir).unwrap();
        std::fs::write(&library_path, b"verified-libkrun").unwrap();
        std::fs::write(root.join(FIRMWARE_SONAME), b"verified-firmware").unwrap();
        for disk in ["base.raw", "data.raw"] {
            std::fs::write(root.join(disk), []).unwrap();
        }
        let spec = WorkerSpec {
            version: WORKER_SPEC_VERSION,
            box_id: "01890f3e-7b2a-7cc1-8000-000000000001".into(),
            expected_parent_pid: std::process::id(),
            agent_protocol_version: 1,
            browser_enabled: false,
            runtime: "node".into(),
            arch: "aarch64".into(),
            data_root: root.clone(),
            base_root_disk: root.join("base.raw"),
            writable_data_disk: root.join("data.raw"),
            vcpus: 1,
            memory_mib: 128,
            console_path: root.join("console.log"),
            vsock_socket: root.join("agent.sock"),
            vsock_port: 18_080,
            boot_nonce: "0123456789abcdef".repeat(4),
            workdir,
            guest_environment: Default::default(),
            limits: box_runtime::ResourceLimits {
                vcpus: 1,
                memory_mib: 128,
                host_worker_max_processes: 2,
                host_worker_max_open_files: 16,
            },
            libkrun_library: library_path.clone(),
            libkrun_identity: LibraryIdentity {
                tag: LIBKRUN_TAG.into(),
                commit: LIBKRUN_COMMIT.into(),
                header_sha256: LIBKRUN_HEADER_SHA256.into(),
                artifact_sha256: format!("{:x}", Sha256::digest(b"verified-libkrun")),
            },
            libkrun_firmware: root.join(FIRMWARE_SONAME),
            libkrun_firmware_identity: FirmwareIdentity {
                version: "5".into(),
                soname: FIRMWARE_SONAME.into(),
                artifact_sha256: format!("{:x}", Sha256::digest(b"verified-firmware")),
            },
            network_mode: NetworkMode::DenyAll,
            custom_network_policy: None,
            attach_headers: None,
            dns_servers: vec![],
            dns_over_https_name: None,
        };
        let mut snapshot = snapshot_verified_library(&spec).unwrap();
        assert_eq!(snapshot.metadata().unwrap().nlink(), 0);
        let private = prepare_private_runtime(&spec).unwrap();
        assert_eq!(
            std::fs::read(private.join(PRIVATE_LIBKRUN_NAME)).unwrap(),
            b"verified-libkrun"
        );
        assert_eq!(
            std::fs::read(private.join(FIRMWARE_SONAME)).unwrap(),
            b"verified-firmware"
        );
        let private_directory =
            open_directory_no_symlinks(&private, "prepared runtime directory").unwrap();
        cleanup_prepared_runtime(&spec, &private_directory);
        assert!(!private.exists());
        std::fs::write(library_path, b"swapped-source").unwrap();
        snapshot.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        snapshot.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"verified-libkrun");
    }

    #[test]
    fn firmware_requires_exact_soname_and_checksum() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(FIRMWARE_SONAME);
        std::fs::write(&path, b"firmware-v5").unwrap();
        let mut file = File::open(&path).unwrap();
        let mut identity = FirmwareIdentity {
            version: "5".into(),
            soname: FIRMWARE_SONAME.into(),
            artifact_sha256: format!("{:x}", Sha256::digest(b"firmware-v5")),
        };
        assert!(verify_firmware_file(&mut file, &identity).is_ok());
        identity.artifact_sha256 = "0".repeat(64);
        assert!(verify_firmware_file(&mut file, &identity).is_err());
        identity.artifact_sha256 = format!("{:x}", Sha256::digest(b"firmware-v5"));
        identity.soname = "wrong".into();
        assert!(verify_firmware_file(&mut file, &identity).is_err());
    }

    #[test]
    fn firmware_probe_snapshot_is_unlinked_and_source_swap_safe() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let path = root.join(FIRMWARE_SONAME);
        std::fs::write(&path, b"firmware-v5").unwrap();
        let identity = FirmwareIdentity {
            version: "5".into(),
            soname: FIRMWARE_SONAME.into(),
            artifact_sha256: format!("{:x}", Sha256::digest(b"firmware-v5")),
        };
        let name = CString::new("firmware-snapshot").unwrap();
        let mut snapshot = snapshot_firmware(&path, &identity, &root, &name).unwrap();
        assert_eq!(snapshot.metadata().unwrap().nlink(), 0);
        std::fs::write(path, b"swapped-source").unwrap();
        snapshot.seek(SeekFrom::Start(0)).unwrap();
        let mut contents = Vec::new();
        snapshot.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"firmware-v5");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_linked_probe_is_retained_until_guard_drop_and_detects_tamper() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let library_path = root.join("libkrun.dylib");
        let firmware_path = root.join(FIRMWARE_SONAME);
        std::fs::write(&library_path, b"signed-library-fixture").unwrap();
        std::fs::write(&firmware_path, b"signed-firmware-fixture").unwrap();
        let identity = LibraryIdentity {
            tag: LIBKRUN_TAG.into(),
            commit: LIBKRUN_COMMIT.into(),
            header_sha256: LIBKRUN_HEADER_SHA256.into(),
            artifact_sha256: format!("{:x}", Sha256::digest(b"signed-library-fixture")),
        };
        let firmware_identity = FirmwareIdentity {
            version: "5".into(),
            soname: FIRMWARE_SONAME.into(),
            artifact_sha256: format!("{:x}", Sha256::digest(b"signed-firmware-fixture")),
        };
        let runtime = prepare_macos_linked_probe_runtime(
            &library_path,
            &identity,
            &firmware_path,
            &firmware_identity,
        )
        .unwrap();
        let private_path = runtime.path.clone();
        assert_eq!(
            std::fs::metadata(&private_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(private_path.join(PRIVATE_LIBKRUN_NAME).is_file());
        let private_library = private_path.join(PRIVATE_LIBKRUN_NAME);
        std::fs::set_permissions(&private_library, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&private_library, b"tampered").unwrap();
        let error = verify_macos_linked_artifacts(&runtime, &identity, &firmware_identity)
            .expect_err("tampered linked copy must fail before dlopen");
        assert!(error.0.contains("owner-only") || error.0.contains("checksum mismatch"));
        drop(runtime);
        assert!(!private_path.exists());
    }

    #[test]
    fn missing_deny_all_network_symbol_fails_preflight() {
        let error = require_abi_symbols(|symbol| symbol != b"krun_add_net_unixstream\0")
            .expect_err("missing network ABI must fail closed");
        assert!(error.0.contains("krun_add_net_unixstream"));
    }

    #[test]
    fn root_remount_and_exec_symbols_are_required() {
        for required in [
            b"krun_set_root_disk_remount\0".as_slice(),
            b"krun_set_exec\0",
        ] {
            let error = require_abi_symbols(|symbol| symbol != required)
                .expect_err("missing boot ABI must fail closed");
            assert!(
                error
                    .0
                    .contains(std::str::from_utf8(&required[..required.len() - 1]).unwrap())
            );
        }
    }

    #[test]
    fn capability_probe_fails_closed() {
        let fake = Fake {
            calls: RefCell::new(vec![]),
            guest_env: RefCell::new(vec![]),
            guest_exec: RefCell::new(None),
            guest_argv: RefCell::new(vec![]),
            missing_feature: Some(FEATURE_BLK),
            vsock_available: true,
            fail: None,
            network_flags: RefCell::new(vec![]),
        };
        assert!(probe_api(&fake).is_err());

        let fake = Fake {
            missing_feature: None,
            vsock_available: false,
            ..fake
        };
        assert!(probe_api(&fake).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_worker_seccomp_gate_is_executable_and_enforced() {
        probe_linux_worker_seccomp().expect("kernel must enforce the versioned policy");
    }

    #[cfg(unix)]
    #[test]
    fn pipe_rejects_trailing_bytes() {
        use std::{io::Write, os::fd::IntoRawFd, os::unix::net::UnixStream};
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&0_u32.to_be_bytes()).unwrap();
        writer.write_all(b"x").unwrap();
        drop(writer);
        let error =
            read_spec_fd_with_timeout(reader.into_raw_fd(), Duration::from_secs(1)).unwrap_err();
        assert!(error.0.contains("trailing bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn pipe_read_has_a_total_deadline_and_owns_fd() {
        use std::{os::fd::IntoRawFd, os::unix::net::UnixStream};
        let (reader, _writer) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let error =
            read_spec_fd_with_timeout(reader.into_raw_fd(), Duration::from_millis(20)).unwrap_err();
        assert!(error.0.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_pipe_preserves_a_read_end_that_reuses_fd_zero() {
        // SAFETY: the child performs only scalar libc FD operations and _exit;
        // the parent waits for exactly the child it created.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::close(0) };
            let mut pipe = [-1; 2];
            if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 || pipe[0] != 0 {
                unsafe { libc::_exit(10) };
            }
            let byte = [0x5a_u8];
            if unsafe { libc::write(pipe[1], byte.as_ptr().cast(), 1) } != 1 {
                unsafe { libc::_exit(11) };
            }
            unsafe { libc::close(pipe[1]) };
            if install_pipe_read_end_as_stdin(pipe[0]).is_err() {
                unsafe { libc::_exit(12) };
            }
            let mut observed = [0_u8];
            let read = unsafe { libc::read(0, observed.as_mut_ptr().cast(), 1) };
            unsafe { libc::_exit(i32::from(read != 1 || observed != byte)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
