//! Control-plane runtime abstractions. This crate never starts a VMM in-process.
use async_trait::async_trait;
use box_egress::{AddressClass, classify_address};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::OpenOptions,
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::{Mutex, watch},
    time::{sleep, timeout},
};

pub const WORKER_SPEC_VERSION: u16 = 3;
pub const MAX_WORKER_SPEC_BYTES: usize = 64 * 1024;
pub const AGENT_VSOCK_PORT: u32 = 18_080;
pub const DEFAULT_WORKER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_GUEST_ENVIRONMENT_VARIABLES: usize = 128;
const MAX_GUEST_ENVIRONMENT_NAME_BYTES: usize = 255;
const MAX_GUEST_ENVIRONMENT_VALUE_BYTES: usize = 16 * 1024;
const MAX_GUEST_ENVIRONMENT_TOTAL_BYTES: usize = 48 * 1024;
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(20);
const FORCE_REAP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError(pub String);
impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RuntimeError {}
pub type Result<T> = std::result::Result<T, RuntimeError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryIdentity {
    pub tag: String,
    pub commit: String,
    pub header_sha256: String,
    pub artifact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareIdentity {
    pub version: String,
    pub soname: String,
    pub artifact_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverCapabilities {
    pub blk: bool,
    pub net: bool,
    pub vsock: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub host_worker_max_processes: u32,
    pub host_worker_max_open_files: u32,
}
impl ResourceLimits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=64).contains(&self.vcpus)
            || !(128..=1_048_576).contains(&self.memory_mib)
            || self.host_worker_max_processes < 2
            || self.host_worker_max_open_files < 16
        {
            return Err(RuntimeError(
                "resource limits outside supported bounds".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// Installs an isolated virtio-net backend so libkrun cannot enable TSI.
    DenyAll,
    /// Installs the bounded packet proxy. Only configured numeric DNS
    /// resolvers and public IPv4 TCP destinations on ports 80/443 are valid.
    RestrictedDefault,
}

/// Versioned, potentially secret-bearing input sent over an inherited pipe,
/// never argv or the host worker environment.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSpec {
    pub version: u16,
    pub box_id: String,
    pub expected_parent_pid: u32,
    pub agent_protocol_version: u32,
    /// Enables the guest-only Chromium adapter for browser boxes.
    pub browser_enabled: bool,
    pub runtime: String,
    pub arch: String,
    pub data_root: PathBuf,
    pub base_root_disk: PathBuf,
    pub writable_data_disk: PathBuf,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub console_path: PathBuf,
    pub vsock_socket: PathBuf,
    pub vsock_port: u32,
    pub boot_nonce: String,
    pub workdir: PathBuf,
    /// Guest-only environment forwarded with `krun_set_env`; never inherited
    /// by the host worker process.
    pub guest_environment: BTreeMap<String, String>,
    pub limits: ResourceLimits,
    /// Verified, data-root-confined artifact selected by the control plane.
    pub libkrun_library: PathBuf,
    pub libkrun_identity: LibraryIdentity,
    pub libkrun_firmware: PathBuf,
    pub libkrun_firmware_identity: FirmwareIdentity,
    pub network_mode: NetworkMode,
    /// Numeric upstream resolvers. Hostname resolvers would introduce an
    /// implicit host lookup before the egress policy can classify an address.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Optional HTTPS DNS authority. Its TLS connection is pinned to
    /// `dns_servers`, so the worker never performs an implicit host lookup.
    #[serde(default)]
    pub dns_over_https_name: Option<String>,
}
impl std::fmt::Debug for WorkerSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerSpec")
            .field("version", &self.version)
            .field("box_id", &self.box_id)
            .field("runtime", &self.runtime)
            .field("arch", &self.arch)
            .field("browser_enabled", &self.browser_enabled)
            .field("boot_nonce", &"[REDACTED]")
            .field(
                "guest_environment_keys",
                &self.guest_environment.keys().collect::<Vec<_>>(),
            )
            .field("vcpus", &self.vcpus)
            .field("memory_mib", &self.memory_mib)
            .field("network_mode", &self.network_mode)
            .field("dns_server_count", &self.dns_servers.len())
            .field(
                "dns_over_https",
                &self.dns_over_https_name.as_ref().map(|_| "configured"),
            )
            .finish_non_exhaustive()
    }
}
impl WorkerSpec {
    pub fn validate(&self) -> Result<()> {
        if self.version != WORKER_SPEC_VERSION {
            return Err(RuntimeError("unsupported worker spec version".into()));
        }
        let box_id = uuid::Uuid::parse_str(&self.box_id)
            .map_err(|_| RuntimeError("box id must be UUIDv7".into()))?;
        if box_id.get_version_num() != 7
            || self.boot_nonce.len() != 64
            || !self.boot_nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RuntimeError("invalid worker identity or nonce".into()));
        }
        if self.agent_protocol_version != 1
            || !matches!(self.arch.as_str(), "aarch64" | "x86_64")
            || !matches!(
                self.runtime.as_str(),
                "node"
                    | "node-alpine"
                    | "python"
                    | "python-alpine"
                    | "golang"
                    | "golang-alpine"
                    | "ruby"
                    | "ruby-alpine"
                    | "rust"
                    | "rust-alpine"
            )
        {
            return Err(RuntimeError(
                "unsupported guest protocol, runtime, or architecture".into(),
            ));
        }
        if self.vsock_port != AGENT_VSOCK_PORT {
            return Err(RuntimeError(
                "only agent vsock port 18080 is allowed".into(),
            ));
        }
        match self.network_mode {
            NetworkMode::DenyAll
                if !self.dns_servers.is_empty() || self.dns_over_https_name.is_some() =>
            {
                return Err(RuntimeError(
                    "deny-all worker spec must not contain DNS configuration".into(),
                ));
            }
            NetworkMode::DenyAll => {}
            NetworkMode::RestrictedDefault => {
                if !(1..=3).contains(&self.dns_servers.len()) {
                    return Err(RuntimeError(
                        "restricted-default requires one to three DNS resolvers".into(),
                    ));
                }
                let unique = self.dns_servers.iter().copied().collect::<BTreeSet<_>>();
                if unique.len() != self.dns_servers.len()
                    || unique.iter().any(|address| {
                        classify_address(IpAddr::V4(*address)) != AddressClass::PublicUnicast
                    })
                {
                    return Err(RuntimeError(
                        "DNS resolvers must be unique public IPv4 addresses".into(),
                    ));
                }
                if self
                    .dns_over_https_name
                    .as_deref()
                    .is_some_and(|name| !valid_dns_authority(name))
                {
                    return Err(RuntimeError(
                        "DNS-over-HTTPS authority must be a canonical ASCII hostname".into(),
                    ));
                }
            }
        }
        self.limits.validate()?;
        if self.vcpus != self.limits.vcpus || self.memory_mib != self.limits.memory_mib {
            return Err(RuntimeError("resource values do not match limits".into()));
        }
        validate_guest_environment(&self.guest_environment)?;
        let root = canonical(&self.data_root)?;
        if self.data_root != root {
            return Err(RuntimeError(
                "data root must be an absolute canonical directory without symlinks".into(),
            ));
        }
        for path in [
            &self.base_root_disk,
            &self.writable_data_disk,
            &self.workdir,
            &self.libkrun_library,
            &self.libkrun_firmware,
        ] {
            ensure_existing_under(&root, path)?;
        }
        ensure_output_under(&root, &self.console_path)?;
        ensure_private_vsock_output(&self.vsock_socket, &self.box_id)?;
        if self.base_root_disk == self.writable_data_disk {
            return Err(RuntimeError("base and writable disks must differ".into()));
        }
        ensure_unique_regular_file(&self.base_root_disk, "base root disk")?;
        ensure_unique_regular_file(&self.writable_data_disk, "writable data disk")?;
        ensure_unique_regular_file(&self.libkrun_library, "libkrun library")?;
        ensure_unique_regular_file(&self.libkrun_firmware, "libkrun firmware")?;
        if same_file(&self.libkrun_library, &self.libkrun_firmware)? {
            return Err(RuntimeError(
                "libkrun library and firmware must be distinct files".into(),
            ));
        }
        if self.libkrun_firmware_identity.version != "5"
            || self.libkrun_firmware_identity.soname != expected_firmware_soname()
            || self.libkrun_firmware_identity.artifact_sha256.len() != 64
            || !self
                .libkrun_firmware_identity
                .artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(RuntimeError("invalid libkrun firmware identity".into()));
        }
        if same_file(&self.base_root_disk, &self.writable_data_disk)? {
            return Err(RuntimeError(
                "base and writable disks resolve to the same inode".into(),
            ));
        }
        for disk in [&self.base_root_disk, &self.writable_data_disk] {
            if disk.extension().and_then(|x| x.to_str()) != Some("raw") {
                return Err(RuntimeError("only raw disks are permitted".into()));
            }
        }
        for path in [
            &self.data_root,
            &self.base_root_disk,
            &self.writable_data_disk,
            &self.console_path,
            &self.vsock_socket,
            &self.workdir,
            &self.libkrun_library,
            &self.libkrun_firmware,
        ] {
            let value = path
                .to_str()
                .ok_or_else(|| RuntimeError("worker paths must be valid UTF-8".into()))?;
            if value.contains('\0') {
                return Err(RuntimeError("worker paths must not contain NUL".into()));
            }
        }
        Ok(())
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let json = serde_json::to_vec(self).map_err(|e| RuntimeError(e.to_string()))?;
        if json.len() > MAX_WORKER_SPEC_BYTES {
            return Err(RuntimeError("worker spec exceeds limit".into()));
        }
        let mut out = (json.len() as u32).to_be_bytes().to_vec();
        out.extend(json);
        Ok(out)
    }
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(RuntimeError("truncated worker spec".into()));
        }
        let n = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes")) as usize;
        if n > MAX_WORKER_SPEC_BYTES || bytes.len() != n + 4 {
            return Err(RuntimeError("invalid worker spec length".into()));
        }
        let spec: Self = serde_json::from_slice(&bytes[4..])
            .map_err(|e| RuntimeError(format!("invalid worker spec: {e}")))?;
        spec.validate()?;
        Ok(spec)
    }
}

fn valid_dns_authority(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(target_os = "macos")]
fn expected_firmware_soname() -> &'static str {
    "libkrunfw.5.dylib"
}

#[cfg(target_os = "linux")]
fn expected_firmware_soname() -> &'static str {
    "libkrunfw.so.5"
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn expected_firmware_soname() -> &'static str {
    "unsupported"
}

fn validate_guest_environment(environment: &BTreeMap<String, String>) -> Result<()> {
    if environment.len() > MAX_GUEST_ENVIRONMENT_VARIABLES {
        return Err(RuntimeError(
            "guest environment has too many variables".into(),
        ));
    }

    let mut total_bytes = 0_usize;
    for (name, value) in environment {
        let valid_name = !name.is_empty()
            && name.len() <= MAX_GUEST_ENVIRONMENT_NAME_BYTES
            && name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            });
        if !valid_name {
            return Err(RuntimeError(
                "guest environment name is not a POSIX variable name".into(),
            ));
        }
        if name.starts_with("BOXD_") {
            return Err(RuntimeError(
                "guest environment may not override reserved BOXD_ identity variables".into(),
            ));
        }
        if value.contains('\0') {
            return Err(RuntimeError(
                "guest environment value contains an interior NUL byte".into(),
            ));
        }
        if value.len() > MAX_GUEST_ENVIRONMENT_VALUE_BYTES {
            return Err(RuntimeError(
                "guest environment value exceeds the per-variable limit".into(),
            ));
        }
        total_bytes = total_bytes
            .checked_add(name.len() + 1 + value.len())
            .ok_or_else(|| RuntimeError("guest environment size overflow".into()))?;
        if total_bytes > MAX_GUEST_ENVIRONMENT_TOTAL_BYTES {
            return Err(RuntimeError(
                "guest environment exceeds the total byte limit".into(),
            ));
        }
    }
    Ok(())
}
fn canonical(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path)
        .map_err(|_| RuntimeError(format!("path cannot be canonicalized: {}", path.display())))
}
fn ensure_existing_under(root: &Path, path: &Path) -> Result<()> {
    let p = canonical(path)?;
    if p != path || !p.starts_with(root) {
        return Err(RuntimeError("worker path escapes data root".into()));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_unique_regular_file(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| RuntimeError(format!("cannot inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1
    {
        return Err(RuntimeError(format!(
            "{label} must be a regular, non-symlink file with one link"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_unique_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| RuntimeError(format!("cannot inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(RuntimeError(format!(
            "{label} must be a regular, non-symlink file"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let left = std::fs::metadata(left).map_err(|error| RuntimeError(error.to_string()))?;
    let right = std::fs::metadata(right).map_err(|error| RuntimeError(error.to_string()))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn same_file(left: &Path, right: &Path) -> Result<bool> {
    Ok(canonical(left)? == canonical(right)?)
}

fn ensure_output_under(root: &Path, path: &Path) -> Result<()> {
    if path.exists() {
        return ensure_existing_under(root, path);
    }
    let parent = path
        .parent()
        .ok_or_else(|| RuntimeError("worker output has no parent".into()))?;
    let parent = canonical(parent)?;
    if !parent.starts_with(root) {
        return Err(RuntimeError("worker path escapes data root".into()));
    }
    let name = path
        .file_name()
        .ok_or_else(|| RuntimeError("worker output has no file name".into()))?;
    if name == "." || name == ".." {
        return Err(RuntimeError("invalid worker output name".into()));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_vsock_output(path: &Path, box_id: &str) -> Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

    if path.exists() {
        return Err(RuntimeError(
            "worker vsock output must not already exist".into(),
        ));
    }
    if path.as_os_str().as_bytes().len() > 103 {
        return Err(RuntimeError(
            "worker vsock path exceeds the portable Unix-socket limit".into(),
        ));
    }
    let expected_name = format!("{box_id}.sock");
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(RuntimeError(
            "worker vsock name does not match the box identity".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| RuntimeError("worker vsock output has no parent".into()))?;
    let canonical_parent = canonical(parent)?;
    if parent != canonical_parent {
        return Err(RuntimeError(
            "worker vsock parent must be an absolute canonical directory".into(),
        ));
    }
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| RuntimeError(format!("cannot inspect worker vsock parent: {error}")))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(RuntimeError(
            "worker vsock parent must be a current-user-owned 0700 directory".into(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_vsock_output(_: &Path, _: &str) -> Result<()> {
    Err(RuntimeError(
        "worker vsock output is only supported on Unix hosts".into(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    pub worker: WorkerSpec,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSandbox {
    pub id: String,
    pub worker: WorkerSpec,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub started_at: SystemTime,
    /// Monotonic marker assigned by this control-plane process. It prevents an
    /// old watcher from overwriting a newer launch for the same Box.
    pub launch_id: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningSandbox {
    pub id: String,
    pub pid: u32,
    pub started_at: SystemTime,
    pub launch_id: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerExit {
    pub identity: ProcessIdentity,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub observed_at: SystemTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeState {
    Prepared,
    Running(RunningSandbox),
    Exited(WorkerExit),
    Error(String),
    Missing,
}

#[async_trait]
pub trait SandboxDriver: Send + Sync {
    async fn capabilities(&self) -> DriverCapabilities;
    async fn prepare(&self, spec: &SandboxSpec) -> Result<PreparedSandbox>;
    async fn start(&self, prepared: &PreparedSandbox) -> Result<RunningSandbox>;
    async fn request_shutdown(&self, id: &str, grace: Duration) -> Result<()>;
    async fn force_stop(&self, id: &str) -> Result<()>;
    async fn inspect(&self, id: &str) -> Result<RuntimeState>;
    async fn cleanup(&self, id: &str) -> Result<()>;
}

/// Injectable boundary around `boxd __vmm-worker --spec-fd`; production launchers
/// must pass a pipe FD and must not serialize a spec in argv/environment.
#[async_trait]
pub trait WorkerLauncher: Send + Sync {
    async fn spawn(&self, spec_wire: Vec<u8>) -> Result<WorkerProcess>;
}
pub struct WorkerProcess {
    pub identity: ProcessIdentity,
    child: Child,
}

impl WorkerProcess {
    pub fn from_child(child: Child, started_at: SystemTime, launch_id: u64) -> Result<Self> {
        let pid = child
            .id()
            .ok_or_else(|| RuntimeError("spawned worker has no process id".into()))?;
        Ok(Self {
            identity: ProcessIdentity {
                pid,
                started_at,
                launch_id,
            },
            child,
        })
    }
}

/// Production launcher for the single-binary worker model. The child receives
/// exactly three fixed argv values and an empty host environment. The
/// versioned spec is written to child stdin (FD 0), then the pipe is closed.
#[derive(Debug)]
pub struct CurrentExeWorkerLauncher {
    executable: PathBuf,
    write_timeout: Duration,
    next_launch_id: AtomicU64,
}

impl CurrentExeWorkerLauncher {
    pub fn new() -> Result<Self> {
        let executable = std::env::current_exe()
            .map_err(|error| RuntimeError(format!("cannot resolve current executable: {error}")))?;
        Ok(Self::with_executable(executable))
    }

    pub fn with_executable(executable: PathBuf) -> Self {
        Self {
            executable,
            write_timeout: DEFAULT_WORKER_WRITE_TIMEOUT,
            next_launch_id: AtomicU64::new(1),
        }
    }

    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }
}

#[async_trait]
impl WorkerLauncher for CurrentExeWorkerLauncher {
    async fn spawn(&self, spec_wire: Vec<u8>) -> Result<WorkerProcess> {
        let mut spec = WorkerSpec::from_wire(&spec_wire)?;
        spec.expected_parent_pid = std::process::id();
        let spec_wire = spec.to_wire()?;
        let mut command = Command::new(&self.executable);
        let worker_log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(spec.workdir.join("worker.log"))
            .map_err(|error| RuntimeError(format!("cannot create VMM worker log: {error}")))?;
        command
            .arg("__vmm-worker")
            .arg("--spec-fd")
            .arg("0")
            .current_dir(&spec.workdir)
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::from(worker_log))
            .kill_on_drop(true);
        // A terminal-generated SIGINT targets the foreground process group.
        // Keep VMM workers in their own group so the control plane can first
        // quiesce the guest, flush its filesystem and request an orderly stop.
        // The parent still owns and explicitly signals the child by PID.
        command.process_group(0);
        let started_at = SystemTime::now();
        let mut child = command
            .spawn()
            .map_err(|error| RuntimeError(format!("cannot spawn VMM worker: {error}")))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| RuntimeError("worker stdin pipe unavailable".into()))?;
        let write = async {
            stdin.write_all(&spec_wire).await?;
            stdin.shutdown().await
        };
        match timeout(self.write_timeout, write).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                terminate_failed_spawn(&mut child).await?;
                return Err(RuntimeError(format!(
                    "worker spec pipe write failed: {error}"
                )));
            }
            Err(_) => {
                terminate_failed_spawn(&mut child).await?;
                return Err(RuntimeError("worker spec pipe write timed out".into()));
            }
        }
        drop(stdin);
        let launch_id = self.next_launch_id.fetch_add(1, Ordering::SeqCst);
        WorkerProcess::from_child(child, started_at, launch_id)
    }
}

async fn terminate_failed_spawn(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .map_err(|error| RuntimeError(format!("cannot inspect failed worker spawn: {error}")))?
        .is_some()
    {
        return Ok(());
    }
    let kill_error = child.start_kill().err();
    timeout(FORCE_REAP_TIMEOUT, child.wait())
        .await
        .map_err(|_| {
            RuntimeError(match kill_error {
                Some(error) => {
                    format!("failed worker spawn could not be killed or reaped: {error}")
                }
                None => "failed worker spawn could not be reaped".into(),
            })
        })?
        .map_err(|error| RuntimeError(format!("cannot reap failed worker spawn: {error}")))?;
    Ok(())
}

#[derive(Clone)]
struct ProcessRecord {
    identity: ProcessIdentity,
    child: Arc<Mutex<Child>>,
    exit: watch::Receiver<Option<WorkerExit>>,
}

struct SupervisorInner {
    states: Mutex<BTreeMap<String, RuntimeState>>,
    processes: Mutex<BTreeMap<String, ProcessRecord>>,
    locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    leased_ports: Mutex<BTreeSet<u16>>,
}

pub struct Supervisor<L> {
    launcher: Arc<L>,
    inner: Arc<SupervisorInner>,
}

impl<L> Clone for Supervisor<L> {
    fn clone(&self) -> Self {
        Self {
            launcher: Arc::clone(&self.launcher),
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<L: WorkerLauncher> Supervisor<L> {
    pub fn new(launcher: L) -> Self {
        Self {
            launcher: Arc::new(launcher),
            inner: Arc::new(SupervisorInner {
                states: Mutex::new(BTreeMap::new()),
                processes: Mutex::new(BTreeMap::new()),
                locks: Mutex::new(BTreeMap::new()),
                leased_ports: Mutex::new(BTreeSet::new()),
            }),
        }
    }
    async fn box_lock(&self, id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.inner.locks.lock().await;
        locks
            .entry(id.into())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn prepare(&self, spec: &SandboxSpec) -> Result<PreparedSandbox> {
        spec.worker.validate()?;
        let id = spec.worker.box_id.clone();
        let lock = self.box_lock(&id).await;
        let _guard = lock.lock().await;
        if self.inner.processes.lock().await.contains_key(&id) {
            return Err(RuntimeError(
                "worker already exists; cleanup is required".into(),
            ));
        }
        self.inner
            .states
            .lock()
            .await
            .insert(id.clone(), RuntimeState::Prepared);
        Ok(PreparedSandbox {
            id,
            worker: spec.worker.clone(),
        })
    }

    pub async fn start(&self, prepared: PreparedSandbox) -> Result<RunningSandbox> {
        let lock = self.box_lock(&prepared.id).await;
        let _guard = lock.lock().await;
        if self.inner.processes.lock().await.contains_key(&prepared.id) {
            return Err(RuntimeError(
                "worker already exists; cleanup is required".into(),
            ));
        }
        let wire = prepared.worker.to_wire()?;
        let process = self.launcher.spawn(wire).await?;
        let identity = process.identity.clone();
        let running = RunningSandbox {
            id: prepared.id.clone(),
            pid: identity.pid,
            started_at: identity.started_at,
            launch_id: identity.launch_id,
        };
        let child = Arc::new(Mutex::new(process.child));
        let (exit_tx, exit_rx) = watch::channel(None);
        self.inner.processes.lock().await.insert(
            prepared.id.clone(),
            ProcessRecord {
                identity: identity.clone(),
                child: Arc::clone(&child),
                exit: exit_rx,
            },
        );
        self.inner
            .states
            .lock()
            .await
            .insert(prepared.id.clone(), RuntimeState::Running(running.clone()));
        tokio::spawn(watch_worker(
            Arc::downgrade(&self.inner),
            prepared.id,
            identity,
            child,
            exit_tx,
        ));
        Ok(running)
    }

    pub async fn inspect(&self, id: &str) -> Result<RuntimeState> {
        let state = self
            .inner
            .states
            .lock()
            .await
            .get(id)
            .cloned()
            .unwrap_or(RuntimeState::Missing);
        if let RuntimeState::Running(running) = &state {
            let record = self.inner.processes.lock().await.get(id).cloned();
            let Some(record) = record else {
                return Ok(RuntimeState::Error(
                    "running state has no parent-owned worker handle".into(),
                ));
            };
            if record.identity.pid != running.pid
                || record.identity.launch_id != running.launch_id
                || record.identity.started_at != running.started_at
            {
                return Ok(RuntimeState::Error(
                    "worker process identity mismatch".into(),
                ));
            }
            if let Some(exit) = record.exit.borrow().clone() {
                return Ok(RuntimeState::Exited(exit));
            }
        }
        Ok(state)
    }

    pub async fn request_shutdown(&self, id: &str, grace: Duration) -> Result<()> {
        self.stop_locked(id, grace, true).await
    }

    pub async fn force_stop(&self, id: &str) -> Result<()> {
        self.stop_locked(id, Duration::ZERO, false).await
    }

    async fn stop_locked(&self, id: &str, grace: Duration, graceful: bool) -> Result<()> {
        let lock = self.box_lock(id).await;
        let _guard = lock.lock().await;
        let Some(record) = self.inner.processes.lock().await.get(id).cloned() else {
            return Ok(());
        };
        if record.exit.borrow().is_some() {
            return Ok(());
        }
        if graceful {
            send_terminate(&record).await?;
            if wait_for_exit(record.exit.clone(), grace).await.is_ok() {
                return Ok(());
            }
        }
        force_kill(&record).await?;
        wait_for_exit(record.exit, FORCE_REAP_TIMEOUT).await
    }

    pub async fn cleanup(&self, id: &str) -> Result<()> {
        self.force_stop(id).await?;
        let lock = self.box_lock(id).await;
        let _guard = lock.lock().await;
        self.inner.processes.lock().await.remove(id);
        self.inner
            .states
            .lock()
            .await
            .insert(id.into(), RuntimeState::Missing);
        Ok(())
    }

    pub async fn reconcile_missing(&self, id: &str) {
        let lock = self.box_lock(id).await;
        let _guard = lock.lock().await;
        if !self.inner.processes.lock().await.contains_key(id) {
            self.inner.states.lock().await.insert(
                id.into(),
                RuntimeState::Error("worker parent handle missing during reconciliation".into()),
            );
        }
    }
    pub async fn lease_port(&self, port: u16) -> Result<()> {
        let mut ports = self.inner.leased_ports.lock().await;
        if !ports.insert(port) {
            return Err(RuntimeError("port lease already held".into()));
        }
        Ok(())
    }
    pub async fn release_port(&self, port: u16) {
        self.inner.leased_ports.lock().await.remove(&port);
    }
}

async fn watch_worker(
    inner: Weak<SupervisorInner>,
    id: String,
    identity: ProcessIdentity,
    child: Arc<Mutex<Child>>,
    exit_tx: watch::Sender<Option<WorkerExit>>,
) {
    loop {
        let status = {
            let mut child = child.lock().await;
            child.try_wait()
        };
        match status {
            Ok(Some(status)) => {
                let exit = WorkerExit {
                    identity: identity.clone(),
                    exit_code: status.code(),
                    success: status.success(),
                    observed_at: SystemTime::now(),
                };
                let cgroup_cleanup = cleanup_linux_worker_cgroup(&id);
                let _ = exit_tx.send(Some(exit.clone()));
                if let Some(inner) = inner.upgrade() {
                    let state = match cgroup_cleanup {
                        Ok(()) => RuntimeState::Exited(exit),
                        Err(error) => RuntimeState::Error(format!(
                            "worker exited but its cgroup could not be removed: {error}"
                        )),
                    };
                    record_state_if_current(&inner, &id, &identity, state).await;
                }
                return;
            }
            Ok(None) => sleep(WORKER_POLL_INTERVAL).await,
            Err(error) => {
                if let Some(inner) = inner.upgrade() {
                    record_state_if_current(
                        &inner,
                        &id,
                        &identity,
                        RuntimeState::Error(format!("cannot inspect worker handle: {error}")),
                    )
                    .await;
                }
                return;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn cleanup_linux_worker_cgroup(id: &str) -> Result<()> {
    let membership = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| RuntimeError(format!("cannot read /proc/self/cgroup: {error}")))?;
    cleanup_linux_worker_cgroup_at(Path::new("/sys/fs/cgroup"), &membership, id)
}

#[cfg(not(target_os = "linux"))]
fn cleanup_linux_worker_cgroup(_: &str) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_linux_worker_cgroup_at(root: &Path, membership: &str, id: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(id)
        .map_err(|_| RuntimeError("worker cgroup id is not a UUIDv7".into()))?;
    if parsed.get_version_num() != 7 {
        return Err(RuntimeError("worker cgroup id is not a UUIDv7".into()));
    }
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| RuntimeError("cannot determine unified cgroup membership".into()))?;
    let mut leaf = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(value) => leaf.push(value),
            _ => {
                return Err(RuntimeError(
                    "unified cgroup membership contains an unsafe component".into(),
                ));
            }
        }
    }
    leaf.push("boxd");
    leaf.push(id);
    let metadata = match std::fs::symlink_metadata(&leaf) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(RuntimeError(format!(
                "cannot inspect worker cgroup {}: {error}",
                leaf.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError(format!(
            "worker cgroup {} is not a real directory",
            leaf.display()
        )));
    }
    std::fs::remove_dir(&leaf).map_err(|error| {
        RuntimeError(format!(
            "cannot remove worker cgroup {}: {error}",
            leaf.display()
        ))
    })
}

async fn record_state_if_current(
    inner: &SupervisorInner,
    id: &str,
    identity: &ProcessIdentity,
    state: RuntimeState,
) -> bool {
    // Keep the process-generation guard held through the state write. Cleanup
    // and a subsequent start cannot interleave between comparison and commit.
    let processes = inner.processes.lock().await;
    let current = processes.get(id).is_some_and(|record| {
        record.identity.launch_id == identity.launch_id
            && record.identity.pid == identity.pid
            && record.identity.started_at == identity.started_at
    });
    if current {
        inner.states.lock().await.insert(id.into(), state);
    }
    current
}

#[cfg(unix)]
async fn send_terminate(record: &ProcessRecord) -> Result<()> {
    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    let mut child = record.child.lock().await;
    if child
        .try_wait()
        .map_err(|error| RuntimeError(format!("cannot inspect worker before TERM: {error}")))?
        .is_some()
    {
        return Ok(());
    }
    kill(Pid::from_raw(record.identity.pid as i32), Signal::SIGTERM)
        .map_err(|error| RuntimeError(format!("cannot send TERM to worker: {error}")))
}

#[cfg(not(unix))]
async fn send_terminate(_record: &ProcessRecord) -> Result<()> {
    Err(RuntimeError("libkrun worker requires a Unix host".into()))
}

async fn force_kill(record: &ProcessRecord) -> Result<()> {
    let mut child = record.child.lock().await;
    if child
        .try_wait()
        .map_err(|error| RuntimeError(format!("cannot inspect worker before KILL: {error}")))?
        .is_none()
    {
        child
            .start_kill()
            .map_err(|error| RuntimeError(format!("cannot KILL worker: {error}")))?;
    }
    Ok(())
}

async fn wait_for_exit(
    mut exit: watch::Receiver<Option<WorkerExit>>,
    duration: Duration,
) -> Result<()> {
    if exit.borrow().is_some() {
        return Ok(());
    }
    timeout(duration, async {
        loop {
            exit.changed()
                .await
                .map_err(|_| RuntimeError("worker exit watcher closed".into()))?;
            if exit.borrow().is_some() {
                return Ok(());
            }
        }
    })
    .await
    .map_err(|_| RuntimeError("worker did not exit before deadline".into()))?
}

#[derive(Clone)]
pub struct LibkrunDriver {
    supervisor: Supervisor<CurrentExeWorkerLauncher>,
    capabilities: DriverCapabilities,
}

impl LibkrunDriver {
    pub fn new(launcher: CurrentExeWorkerLauncher, capabilities: DriverCapabilities) -> Self {
        Self {
            supervisor: Supervisor::new(launcher),
            capabilities,
        }
    }

    pub fn current_exe(capabilities: DriverCapabilities) -> Result<Self> {
        Ok(Self::new(CurrentExeWorkerLauncher::new()?, capabilities))
    }
}

#[async_trait]
impl SandboxDriver for LibkrunDriver {
    async fn capabilities(&self) -> DriverCapabilities {
        self.capabilities
    }

    async fn prepare(&self, spec: &SandboxSpec) -> Result<PreparedSandbox> {
        self.supervisor.prepare(spec).await
    }

    async fn start(&self, prepared: &PreparedSandbox) -> Result<RunningSandbox> {
        self.supervisor.start(prepared.clone()).await
    }

    async fn request_shutdown(&self, id: &str, grace: Duration) -> Result<()> {
        self.supervisor.request_shutdown(id, grace).await
    }

    async fn force_stop(&self, id: &str) -> Result<()> {
        self.supervisor.force_stop(id).await
    }

    async fn inspect(&self, id: &str) -> Result<RuntimeState> {
        self.supervisor.inspect(id).await
    }

    async fn cleanup(&self, id: &str) -> Result<()> {
        self.supervisor.cleanup(id).await
    }
}

/// Marker for the runtime port boundary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeBoundary;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };
    const BOX_ID: &str = "01890f3e-7b2a-7cc1-8000-000000000001";
    fn spec() -> (tempfile::TempDir, WorkerSpec) {
        let d = tempfile::Builder::new()
            .prefix(".boxd-runtime-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = fs::canonicalize(d.path()).unwrap();
        for n in [
            "base.raw",
            "data.raw",
            "console.log",
            "libkrun.so",
            expected_firmware_soname(),
            "work",
        ] {
            let p = root.join(n);
            if n == "work" {
                fs::create_dir(&p).unwrap()
            } else {
                fs::write(p, []).unwrap()
            }
        }
        let socket_root = root.join("socket-root");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&socket_root)
            .unwrap();
        let s = WorkerSpec {
            version: WORKER_SPEC_VERSION,
            box_id: BOX_ID.into(),
            expected_parent_pid: 0,
            agent_protocol_version: 1,
            browser_enabled: false,
            runtime: "node".into(),
            arch: "aarch64".into(),
            data_root: root.clone(),
            base_root_disk: root.join("base.raw"),
            writable_data_disk: root.join("data.raw"),
            vcpus: 2,
            memory_mib: 512,
            console_path: root.join("console.log"),
            vsock_socket: socket_root.join(format!("{BOX_ID}.sock")),
            vsock_port: 18080,
            boot_nonce: "0123456789abcdef".repeat(4),
            workdir: root.join("work"),
            guest_environment: BTreeMap::new(),
            limits: ResourceLimits {
                vcpus: 2,
                memory_mib: 512,
                host_worker_max_processes: 64,
                host_worker_max_open_files: 256,
            },
            libkrun_library: root.join("libkrun.so"),
            libkrun_identity: LibraryIdentity {
                tag: "v1.19.4".into(),
                commit: "728df8125077d0db44265f6e997c72b81b65c015".into(),
                header_sha256: "0ce40e378736b6ac409aa7f7db37f9ecc02069cff0d83b2148423dacb970ae96"
                    .into(),
                artifact_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            },
            libkrun_firmware: root.join(expected_firmware_soname()),
            libkrun_firmware_identity: FirmwareIdentity {
                version: "5".into(),
                soname: expected_firmware_soname().into(),
                artifact_sha256: "0".repeat(64),
            },
            network_mode: NetworkMode::DenyAll,
            dns_servers: vec![],
            dns_over_https_name: None,
        };
        (d, s)
    }
    #[test]
    fn spec_wire_is_strict() {
        let (_d, s) = spec();
        let wire = s.to_wire().unwrap();
        assert_eq!(WorkerSpec::from_wire(&wire).unwrap(), s);
        assert!(WorkerSpec::from_wire(&[0, 1, 0, 1]).is_err());
    }
    #[test]
    fn rejects_escape_and_wrong_version() {
        let (_d, mut s) = spec();
        s.version = WORKER_SPEC_VERSION + 1;
        assert!(s.validate().is_err());
        s.version = WORKER_SPEC_VERSION;
        s.console_path = PathBuf::from("/tmp/out");
        assert!(s.validate().is_err());
    }

    #[test]
    fn vsock_output_requires_private_short_identity_bound_directory() {
        let (_d, mut s) = spec();
        let socket_root = s.vsock_socket.parent().unwrap().to_path_buf();
        s.vsock_socket = socket_root.join("wrong.sock");
        assert!(s.validate().is_err());

        s.vsock_socket = socket_root.join(format!("{BOX_ID}.sock"));
        fs::set_permissions(&socket_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(s.validate().is_err());
        fs::set_permissions(&socket_root, fs::Permissions::from_mode(0o700)).unwrap();

        let long_root = s.data_root.join("x".repeat(96));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&long_root)
            .unwrap();
        s.vsock_socket = long_root.join(format!("{BOX_ID}.sock"));
        assert!(s.validate().is_err());
    }

    #[test]
    fn validates_network_wire_policy() {
        let (_directory, mut spec) = spec();
        spec.dns_servers = vec![Ipv4Addr::new(1, 1, 1, 1)];
        assert!(spec.validate().is_err(), "deny-all must carry no resolver");

        spec.network_mode = NetworkMode::RestrictedDefault;
        assert!(spec.validate().is_ok());
        spec.dns_servers.push(Ipv4Addr::new(1, 1, 1, 1));
        assert!(spec.validate().is_err(), "duplicate resolver must fail");
        spec.dns_servers = vec![Ipv4Addr::new(169, 254, 169, 254)];
        assert!(spec.validate().is_err(), "metadata resolver must fail");
        spec.dns_servers.clear();
        assert!(spec.validate().is_err(), "resolver list must be non-empty");
    }

    #[test]
    fn rejects_nul_before_process_or_ffi_boundary() {
        let (_d, mut s) = spec();
        s.guest_environment
            .insert("TOKEN".into(), "secret\0attack".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn guest_environment_is_general_bounded_and_reserves_identity() {
        let (_d, mut s) = spec();
        s.guest_environment
            .insert("TOKEN".into(), "guest-secret".into());
        s.guest_environment.insert(
            "npm_config_registry".into(),
            "https://registry.invalid".into(),
        );
        assert!(s.validate().is_ok());

        s.guest_environment
            .insert("BOXD_BOX_ID".into(), "attacker-controlled".into());
        assert!(s.validate().is_err());
        s.guest_environment.remove("BOXD_BOX_ID");

        s.guest_environment
            .insert("INVALID-NAME".into(), "x".into());
        assert!(s.validate().is_err());
        s.guest_environment.remove("INVALID-NAME");

        s.guest_environment
            .insert("TOO_LARGE".into(), "x".repeat(16 * 1024 + 1));
        assert!(s.validate().is_err());
    }

    #[test]
    fn worker_debug_redacts_boot_nonce_and_environment_values() {
        let (_directory, mut spec) = spec();
        spec.boot_nonce = "super-secret-nonce".into();
        spec.guest_environment
            .insert("TOKEN".into(), "super-secret-value".into());
        let debug = format!("{spec:?}");
        assert!(debug.contains("TOKEN"));
        assert!(!debug.contains("super-secret-nonce"));
        assert!(!debug.contains("super-secret-value"));
    }

    #[test]
    fn boot_nonce_is_exactly_thirty_two_hex_bytes() {
        let (_d, mut s) = spec();
        assert!(s.validate().is_ok());
        s.boot_nonce = "0".repeat(63);
        assert!(s.validate().is_err());
        s.boot_nonce = "g".repeat(64);
        assert!(s.validate().is_err());
    }

    #[test]
    fn box_identity_is_strict_uuid_v7() {
        let (_d, mut s) = spec();
        s.box_id = "550e8400-e29b-41d4-a716-446655440000".into();
        assert!(s.validate().is_err());
        s.box_id = "not-a-uuid".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn firmware_identity_is_exact_and_hash_pinned() {
        let (_d, mut s) = spec();
        assert!(s.validate().is_ok());
        s.libkrun_firmware_identity.soname = "libkrunfw-uncontrolled".into();
        assert!(s.validate().is_err());
        s.libkrun_firmware_identity.soname = expected_firmware_soname().into();
        s.libkrun_firmware_identity.artifact_sha256 = "A".repeat(64);
        assert!(s.validate().is_err());
    }

    #[test]
    fn worker_spec_rejects_hardlinked_sensitive_files() {
        let (_d, s) = spec();
        fs::hard_link(
            &s.base_root_disk,
            s.data_root.join("unexpected-root-alias.raw"),
        )
        .unwrap();
        assert!(s.validate().is_err());
    }

    fn helper_script(directory: &Path, body: &str) -> PathBuf {
        let path = directory.join("worker-helper.sh");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    async fn wait_until_exited(
        supervisor: &Supervisor<CurrentExeWorkerLauncher>,
        id: &str,
    ) -> WorkerExit {
        timeout(Duration::from_secs(10), async {
            loop {
                if let RuntimeState::Exited(exit) = supervisor.inspect(id).await.unwrap() {
                    return exit;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("worker exit timeout")
    }

    #[tokio::test]
    async fn production_launcher_keeps_wire_out_of_argv_and_environment() {
        let (_guard, s) = spec();
        let helper = helper_script(
            &s.workdir,
            "/usr/bin/printf '%s\\n' \"$@\" > argv.txt\n/usr/bin/env > env.txt\n/bin/cat > wire.bin\nexit 0",
        );
        let wire = s.to_wire().unwrap();
        let launcher = CurrentExeWorkerLauncher::with_executable(helper);
        let mut process = launcher.spawn(wire.clone()).await.unwrap();
        let status = process.child.wait().await.unwrap();
        assert!(status.success());
        let argv = fs::read_to_string(s.workdir.join("argv.txt")).unwrap();
        let environment = fs::read_to_string(s.workdir.join("env.txt")).unwrap();
        assert_eq!(argv, "__vmm-worker\n--spec-fd\n0\n");
        assert!(!argv.contains(&s.boot_nonce));
        assert!(!environment.contains(&s.boot_nonce));
        let child_wire = fs::read(s.workdir.join("wire.bin")).unwrap();
        let child_spec = WorkerSpec::from_wire(&child_wire).unwrap();
        assert_eq!(child_spec.expected_parent_pid, std::process::id());
        let mut expected = WorkerSpec::from_wire(&wire).unwrap();
        expected.expected_parent_pid = std::process::id();
        assert_eq!(child_spec, expected);
    }

    #[tokio::test]
    async fn production_worker_has_an_independent_process_group() {
        let (_guard, s) = spec();
        let helper = helper_script(&s.workdir, "/bin/cat >/dev/null\nexec /bin/sleep 30");
        let launcher = CurrentExeWorkerLauncher::with_executable(helper);
        let mut process = launcher.spawn(s.to_wire().unwrap()).await.unwrap();
        let pid = process.child.id().unwrap() as i32;
        // SAFETY: pid identifies the live child retained in `process`; these
        // syscalls only inspect process-group identifiers.
        let child_group = unsafe { nix::libc::getpgid(pid) };
        // SAFETY: getpgrp has no arguments and only reads caller process state.
        let parent_group = unsafe { nix::libc::getpgrp() };
        assert_eq!(child_group, pid);
        assert_ne!(child_group, parent_group);
        terminate_failed_spawn(&mut process.child).await.unwrap();
    }

    #[tokio::test]
    async fn supervisor_records_exit_without_bare_pid_inspection() {
        let (_guard, s) = spec();
        let helper = helper_script(&s.workdir, "/bin/cat >/dev/null\nexit 23");
        let supervisor = Supervisor::new(CurrentExeWorkerLauncher::with_executable(helper));
        let prepared = supervisor
            .prepare(&SandboxSpec { worker: s })
            .await
            .unwrap();
        let running = supervisor.start(prepared).await.unwrap();
        assert!(running.launch_id > 0);
        let exit = wait_until_exited(&supervisor, BOX_ID).await;
        assert_eq!(exit.exit_code, Some(23));
        assert!(!exit.success);
    }

    #[tokio::test]
    async fn shutdown_escalates_reaps_and_cleanup_is_idempotent() {
        let (_guard, s) = spec();
        let helper = helper_script(
            &s.workdir,
            "/bin/cat >/dev/null\ntrap '' TERM\nexec /bin/sleep 30",
        );
        let supervisor = Supervisor::new(CurrentExeWorkerLauncher::with_executable(helper));
        let prepared = supervisor
            .prepare(&SandboxSpec { worker: s })
            .await
            .unwrap();
        supervisor.start(prepared).await.unwrap();
        supervisor
            .request_shutdown(BOX_ID, Duration::from_millis(50))
            .await
            .unwrap();
        let exit = wait_until_exited(&supervisor, BOX_ID).await;
        assert_eq!(exit.exit_code, None);
        let record = supervisor
            .inner
            .processes
            .lock()
            .await
            .get(BOX_ID)
            .cloned()
            .unwrap();
        assert!(record.child.lock().await.try_wait().unwrap().is_some());
        supervisor.cleanup(BOX_ID).await.unwrap();
        supervisor.cleanup(BOX_ID).await.unwrap();
        assert_eq!(
            supervisor.inspect(BOX_ID).await.unwrap(),
            RuntimeState::Missing
        );
    }

    #[tokio::test]
    async fn stale_watcher_cannot_overwrite_new_generation() {
        let supervisor = Supervisor::new(CurrentExeWorkerLauncher::with_executable(PathBuf::from(
            "/bin/false",
        )));
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id().unwrap();
        let started_at = SystemTime::now();
        let current_identity = ProcessIdentity {
            pid,
            started_at,
            launch_id: 2,
        };
        let running = RunningSandbox {
            id: BOX_ID.into(),
            pid,
            started_at,
            launch_id: 2,
        };
        let (_exit_tx, exit_rx) = watch::channel(None);
        supervisor.inner.processes.lock().await.insert(
            BOX_ID.into(),
            ProcessRecord {
                identity: current_identity,
                child: Arc::new(Mutex::new(child)),
                exit: exit_rx,
            },
        );
        supervisor
            .inner
            .states
            .lock()
            .await
            .insert(BOX_ID.into(), RuntimeState::Running(running.clone()));
        let stale_identity = ProcessIdentity {
            pid,
            started_at,
            launch_id: 1,
        };
        let stale_exit = WorkerExit {
            identity: stale_identity.clone(),
            exit_code: Some(1),
            success: false,
            observed_at: SystemTime::now(),
        };
        assert!(
            !record_state_if_current(
                &supervisor.inner,
                BOX_ID,
                &stale_identity,
                RuntimeState::Exited(stale_exit),
            )
            .await
        );
        assert_eq!(
            supervisor.inner.states.lock().await.get(BOX_ID),
            Some(&RuntimeState::Running(running))
        );
        let record = supervisor
            .inner
            .processes
            .lock()
            .await
            .remove(BOX_ID)
            .unwrap();
        child = Arc::try_unwrap(record.child)
            .expect("test owns child")
            .into_inner();
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }

    #[tokio::test]
    async fn failed_spawn_termination_confirms_reaping() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        terminate_failed_spawn(&mut child).await.unwrap();
        assert!(child.try_wait().unwrap().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worker_cgroup_cleanup_is_confined_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let leaf = root.join("delegated/boxd").join(BOX_ID);
        fs::create_dir_all(&leaf).unwrap();
        cleanup_linux_worker_cgroup_at(root, "0::/delegated", BOX_ID).unwrap();
        assert!(!leaf.exists());
        cleanup_linux_worker_cgroup_at(root, "0::/delegated", BOX_ID).unwrap();
        assert!(cleanup_linux_worker_cgroup_at(root, "0::/../escape", BOX_ID).is_err());
        assert!(cleanup_linux_worker_cgroup_at(root, "0::/delegated", "not-a-uuid").is_err());
    }
}
