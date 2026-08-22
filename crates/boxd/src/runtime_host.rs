use std::{
    collections::{BTreeMap, HashMap},
    fs,
    future::Future,
    io,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use box_core::{
    Box as DomainBox, BoxId, BoxSize, NetworkPolicy, ResourceSpec, Runtime, RuntimeBundleBinding,
};
use box_image::{BoxRuntimeDisks, ImageError, RuntimeBundleManager};
use box_observability::{NoopTelemetry, Telemetry};
use box_runtime::{
    AGENT_VSOCK_PORT, DriverCapabilities, FirmwareIdentity, LibkrunDriver, LibraryIdentity,
    NetworkMode, PreparedSandbox, ResourceLimits, RuntimeState, SandboxDriver, SandboxSpec,
    WORKER_SPEC_VERSION, WorkerSpec,
};
use box_service::{
    AgentBootIdentity, AgentEndpointResolver, CreationCancellation, HostAgentEndpoint, ImageStore,
    PrivateDiskInspection, ResourceAdmission, ResourceReservation, RuntimeController,
    RuntimeInspection, VerifiedRuntimeBundle,
};
use tokio::sync::{Mutex, Notify};

use crate::{config::AppConfig, embedded_runtime::InstalledAssets};

struct RuntimeRecord {
    prepared: PreparedSandbox,
    boot_nonce: Vec<u8>,
    runtime: String,
    arch: String,
    socket: PathBuf,
}

struct SocketRoot {
    path: PathBuf,
}

impl SocketRoot {
    fn create() -> box_core::Result<Self> {
        for _ in 0..16 {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).map_err(runtime_error)?;
            let path = PathBuf::from("/tmp").join(format!(
                ".boxd-vsock-{}-{}",
                std::process::id(),
                hex::encode(random)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path: path.canonicalize().map_err(runtime_error)?,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(runtime_error(error)),
            }
        }
        Err(unavailable(
            "cannot allocate a private short Unix-socket directory",
        ))
    }

    fn socket_path(&self, id: BoxId) -> PathBuf {
        self.path.join(format!("{id}.sock"))
    }
}

impl Drop for SocketRoot {
    fn drop(&mut self) {
        // Only remove an empty directory. A live socket is evidence that the
        // runtime was not shut down cleanly and must not be recursively erased.
        let _ = fs::remove_dir(&self.path);
    }
}

const IMAGE_READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const IMAGE_CATALOG_CACHE_TTL: Duration = Duration::from_secs(30);
#[cfg(test)]
const SUPPORTED_RUNTIMES: [&str; 10] = [
    "node",
    "python",
    "golang",
    "ruby",
    "rust",
    "node-alpine",
    "python-alpine",
    "golang-alpine",
    "ruby-alpine",
    "rust-alpine",
];

#[derive(Clone, Copy)]
struct HostCapacity {
    logical_cpus: u32,
    available_memory_bytes: u64,
    available_disk_bytes: u64,
}

trait HostCapacityProbe: Send + Sync {
    fn probe(&self, data_root: &std::path::Path) -> Result<HostCapacity, String>;
}

struct SystemHostCapacityProbe;

impl HostCapacityProbe for SystemHostCapacityProbe {
    fn probe(&self, data_root: &std::path::Path) -> Result<HostCapacity, String> {
        let logical_cpus = std::thread::available_parallelism()
            .map_err(|error| format!("cannot inspect host CPUs: {error}"))?
            .get()
            .try_into()
            .unwrap_or(u32::MAX);
        let system = sysinfo::System::new_with_specifics(
            sysinfo::RefreshKind::nothing()
                .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram()),
        );
        let available_memory_bytes = system.available_memory();
        let available_disk_bytes = fs2::available_space(data_root)
            .map_err(|error| format!("cannot inspect data-dir free space: {error}"))?;
        Ok(HostCapacity {
            logical_cpus,
            available_memory_bytes,
            available_disk_bytes,
        })
    }
}

pub(crate) struct HostAdmission {
    max_running_boxes: u32,
    max_total_vcpus: u32,
    max_total_memory_mib: u64,
    minimum_free_bytes: u64,
    default_disk_bytes: u64,
    data_root: PathBuf,
    profiles: [ResourceSpec; 3],
    ledger: Arc<AdmissionLedger>,
    probe: Arc<dyn HostCapacityProbe>,
    telemetry: Arc<dyn Telemetry>,
}

struct AdmissionLedger {
    reservations: Mutex<HashMap<BoxId, (BoxSize, u64, bool)>>,
    next_generation: AtomicU64,
}

struct HostReservation {
    box_id: BoxId,
    generation: u64,
    ledger: Arc<AdmissionLedger>,
    telemetry: Arc<dyn Telemetry>,
    disk_bytes_per_box: u64,
}

#[async_trait]
impl ResourceReservation for HostReservation {
    fn box_id(&self) -> BoxId {
        self.box_id
    }

    async fn release(self: Box<Self>) -> box_core::Result<()> {
        let mut reservations = self.ledger.reservations.lock().await;
        if reservations
            .get(&self.box_id)
            .is_some_and(|(_, generation, _)| *generation == self.generation)
        {
            reservations.remove(&self.box_id);
        }
        self.telemetry.set_disk_bytes(
            u64::try_from(reservations.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(self.disk_bytes_per_box),
        );
        Ok(())
    }
}

impl HostAdmission {
    pub(crate) fn new(config: &AppConfig) -> box_core::Result<Self> {
        Self::with_probe(config, Arc::new(SystemHostCapacityProbe))
    }

    fn with_probe(config: &AppConfig, probe: Arc<dyn HostCapacityProbe>) -> box_core::Result<Self> {
        let profiles = [
            (BoxSize::Small, "small"),
            (BoxSize::Medium, "medium"),
            (BoxSize::Large, "large"),
        ]
        .into_iter()
        .map(|(size, name)| {
            let configured = config.resources.profiles.get(name).ok_or_else(|| {
                box_core::DomainError::validation(format!("resources.profiles.{name} is required"))
            })?;
            let resources = ResourceSpec {
                vcpus: u8::try_from(configured.vcpus).map_err(|_| {
                    box_core::DomainError::validation(format!(
                        "resources.profiles.{name}.vcpus does not fit the runtime ABI"
                    ))
                })?,
                memory_mib: u32::try_from(configured.memory_mib).map_err(|_| {
                    box_core::DomainError::validation(format!(
                        "resources.profiles.{name}.memory_mib does not fit the runtime ABI"
                    ))
                })?,
            };
            if resources != size.resources() {
                return Err(box_core::DomainError::validation(format!(
                    "resources.profiles.{name} must exactly match the fixed BoxSize mapping"
                )));
            }
            Ok((size, resources))
        })
        .map(|result| result.map(|(_, resources)| resources))
        .collect::<box_core::Result<Vec<_>>>()?
        .try_into()
        .expect("exactly three fixed profiles");
        let gib = 1024_u64 * 1024 * 1024;
        let minimum_free_bytes = config
            .storage
            .minimum_free_gib
            .checked_mul(gib)
            .ok_or_else(|| box_core::DomainError::validation("minimum free space overflow"))?;
        let default_disk_bytes = config
            .resources
            .default_disk_gib
            .checked_mul(gib)
            .ok_or_else(|| box_core::DomainError::validation("default disk size overflow"))?;
        let data_root = config
            .storage
            .data_dir
            .canonicalize()
            .map_err(runtime_error)?;
        Ok(Self {
            max_running_boxes: config.resources.max_running_boxes,
            max_total_vcpus: config.resources.max_total_vcpus,
            max_total_memory_mib: config.resources.max_total_memory_mib,
            minimum_free_bytes,
            default_disk_bytes,
            data_root,
            profiles,
            ledger: Arc::new(AdmissionLedger {
                reservations: Mutex::new(HashMap::new()),
                next_generation: AtomicU64::new(1),
            }),
            probe,
            telemetry: Arc::new(NoopTelemetry),
        })
    }

    pub(crate) fn with_telemetry(mut self, telemetry: Arc<dyn Telemetry>) -> Self {
        self.telemetry = telemetry;
        self
    }

    async fn reserve_inner(
        &self,
        box_id: BoxId,
        size: BoxSize,
        requires_new_disk: bool,
    ) -> box_core::Result<Box<dyn ResourceReservation>> {
        let mut reservations = self.ledger.reservations.lock().await;
        if let Some((current, generation, _)) = reservations.get(&box_id) {
            if *current == size {
                return Ok(Box::new(HostReservation {
                    box_id,
                    generation: *generation,
                    ledger: Arc::clone(&self.ledger),
                    telemetry: Arc::clone(&self.telemetry),
                    disk_bytes_per_box: self.default_disk_bytes,
                }));
            }
            return Err(box_core::DomainError::state_conflict(
                "box already has a different resource reservation",
            ));
        }
        let resources = self.profile(size);
        let requested_vcpus = u32::from(resources.vcpus);
        let requested_memory_mib = u64::from(resources.memory_mib);
        let (used_vcpus, used_memory_mib) =
            reservations
                .values()
                .fold((0_u32, 0_u64), |(vcpus, memory), (reserved_size, _, _)| {
                    let reserved = self.profile(*reserved_size);
                    (
                        vcpus.saturating_add(u32::from(reserved.vcpus)),
                        memory.saturating_add(u64::from(reserved.memory_mib)),
                    )
                });
        if reservations.len() >= self.max_running_boxes as usize
            || used_vcpus.saturating_add(requested_vcpus) > self.max_total_vcpus
            || used_memory_mib.saturating_add(requested_memory_mib) > self.max_total_memory_mib
        {
            return Err(capacity("configured runtime capacity is exhausted"));
        }
        let probe = Arc::clone(&self.probe);
        let data_root = self.data_root.clone();
        let host = tokio::task::spawn_blocking(move || probe.probe(&data_root))
            .await
            .map_err(runtime_error)?
            .map_err(runtime_error)?;
        let physical_vcpus = used_vcpus.saturating_add(requested_vcpus);
        let physical_memory_bytes = used_memory_mib
            .saturating_add(requested_memory_mib)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| capacity("reserved memory size overflow"))?;
        let required_disk_bytes = if requires_new_disk {
            let pending_disks = reservations
                .values()
                .filter(|(_, _, pending_disk)| *pending_disk)
                .count();
            let reserved_disks = u64::try_from(pending_disks)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            reserved_disks
                .checked_mul(self.default_disk_bytes)
                .and_then(|bytes| bytes.checked_add(self.minimum_free_bytes))
                .ok_or_else(|| capacity("required disk size overflow"))?
        } else {
            // Restore reconstructs the CPU/memory admission ledger for an
            // already-persisted private disk. available_space already excludes
            // that disk, so charging default_disk_bytes again would reject a
            // safe daemon restart near the minimum-free threshold.
            self.minimum_free_bytes
        };
        if physical_vcpus > host.logical_cpus
            || physical_memory_bytes > host.available_memory_bytes
            || required_disk_bytes > host.available_disk_bytes
        {
            return Err(capacity(
                "host CPU, available memory, or data-dir space is insufficient",
            ));
        }
        let generation = self.ledger.next_generation.fetch_add(1, Ordering::SeqCst);
        reservations.insert(box_id, (size, generation, requires_new_disk));
        self.telemetry.set_disk_bytes(
            u64::try_from(reservations.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(self.default_disk_bytes),
        );
        Ok(Box::new(HostReservation {
            box_id,
            generation,
            ledger: Arc::clone(&self.ledger),
            telemetry: Arc::clone(&self.telemetry),
            disk_bytes_per_box: self.default_disk_bytes,
        }))
    }

    fn profile(&self, size: BoxSize) -> ResourceSpec {
        self.profiles[match size {
            BoxSize::Small => 0,
            BoxSize::Medium => 1,
            BoxSize::Large => 2,
        }]
    }
}

#[async_trait]
impl ResourceAdmission for HostAdmission {
    async fn reserve(
        &self,
        box_id: BoxId,
        size: BoxSize,
    ) -> box_core::Result<Box<dyn ResourceReservation>> {
        self.reserve_inner(box_id, size, true).await
    }

    async fn restore(
        &self,
        box_id: BoxId,
        size: BoxSize,
    ) -> box_core::Result<Box<dyn ResourceReservation>> {
        self.reserve_inner(box_id, size, false).await
    }

    async fn commit_disk(&self, box_id: BoxId) -> box_core::Result<()> {
        let mut reservations = self.ledger.reservations.lock().await;
        let (_, _, pending_disk) = reservations
            .get_mut(&box_id)
            .ok_or_else(|| runtime_error("resource reservation disappeared before disk commit"))?;
        *pending_disk = false;
        Ok(())
    }

    async fn release_box(&self, box_id: BoxId) -> box_core::Result<()> {
        let mut reservations = self.ledger.reservations.lock().await;
        reservations.remove(&box_id);
        self.telemetry.set_disk_bytes(
            u64::try_from(reservations.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(self.default_disk_bytes),
        );
        Ok(())
    }
}

pub struct RuntimeHost {
    manager: Arc<RuntimeBundleManager>,
    driver: Arc<LibkrunDriver>,
    assets: InstalledAssets,
    data_root: PathBuf,
    boxes_dir: PathBuf,
    run_dir: PathBuf,
    records: Mutex<HashMap<BoxId, RuntimeRecord>>,
    auto_pull: bool,
    bundle_registry: String,
    pull_inflight: Arc<Mutex<HashMap<String, Arc<SharedPull>>>>,
    binding_inflight: Arc<Mutex<HashMap<String, Arc<SharedBinding>>>>,
    clone_inflight: Arc<Mutex<HashMap<BoxId, Arc<CloneOperation>>>>,
    /// A successful clone already rehashes the authenticated base immediately
    /// before the copy. Reuse that exact identity during prepare instead of
    /// performing a third full 20 GiB scan on the create critical path.
    verified_clones: Arc<Mutex<HashMap<BoxId, BoxRuntimeDisks>>>,
    image_catalog: Arc<Mutex<CatalogState>>,
    default_disk_bytes: u64,
    dns_servers: Vec<std::net::Ipv4Addr>,
    dns_over_https_name: Option<String>,
    socket_root: SocketRoot,
    telemetry: Arc<dyn Telemetry>,
}

struct SharedPull {
    result: Mutex<Option<box_core::Result<()>>>,
    completed: Notify,
}

struct SharedBinding {
    result: Mutex<Option<box_core::Result<VerifiedRuntimeBundle>>>,
    completed: Notify,
}

impl SharedBinding {
    fn pending() -> Self {
        Self {
            result: Mutex::new(None),
            completed: Notify::new(),
        }
    }
}

impl SharedPull {
    fn pending() -> Self {
        Self {
            result: Mutex::new(None),
            completed: Notify::new(),
        }
    }
}

struct CatalogState {
    cached: Option<(tokio::time::Instant, box_core::Result<()>)>,
    inflight: Option<Arc<SharedPull>>,
}

struct CloneOperation {
    state: Mutex<CloneState>,
    completed: Notify,
}

struct CloneState {
    result: Option<box_core::Result<()>>,
    abandoned: bool,
    claimed: bool,
}

impl CloneOperation {
    fn pending() -> Self {
        Self {
            state: Mutex::new(CloneState {
                result: None,
                abandoned: false,
                claimed: false,
            }),
            completed: Notify::new(),
        }
    }
}

enum CatalogLookup {
    Cached(box_core::Result<()>),
    Pending(Arc<SharedPull>),
}

async fn catalog_operation<Action, ActionFuture>(
    state: &Arc<Mutex<CatalogState>>,
    action: Action,
) -> CatalogLookup
where
    Action: FnOnce() -> ActionFuture + Send + 'static,
    ActionFuture: Future<Output = box_core::Result<()>> + Send + 'static,
{
    let mut catalog = state.lock().await;
    if let Some((verified_at, result)) = &catalog.cached
        && verified_at.elapsed() < IMAGE_CATALOG_CACHE_TTL
    {
        return CatalogLookup::Cached(result.clone());
    }
    if let Some(operation) = &catalog.inflight {
        return CatalogLookup::Pending(Arc::clone(operation));
    }
    let operation = Arc::new(SharedPull::pending());
    catalog.inflight = Some(Arc::clone(&operation));
    drop(catalog);
    let catalog_state = Arc::clone(state);
    let scan = Arc::clone(&operation);
    tokio::spawn(async move {
        let result = tokio::spawn(action())
            .await
            .map_err(runtime_error)
            .and_then(std::convert::identity);
        *scan.result.lock().await = Some(result.clone());
        scan.completed.notify_waiters();
        let mut catalog = catalog_state.lock().await;
        catalog.cached = Some((tokio::time::Instant::now(), result));
        if catalog
            .inflight
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &scan))
        {
            catalog.inflight = None;
        }
    });
    CatalogLookup::Pending(operation)
}

impl RuntimeHost {
    pub fn new(
        config: &AppConfig,
        manager: Arc<RuntimeBundleManager>,
        assets: InstalledAssets,
        capabilities: DriverCapabilities,
    ) -> box_core::Result<Self> {
        fs::create_dir_all(config.storage.data_dir.join("run")).map_err(runtime_error)?;
        let data_root = config
            .storage
            .data_dir
            .canonicalize()
            .map_err(runtime_error)?;
        let boxes_dir = config
            .storage
            .boxes_dir
            .canonicalize()
            .map_err(runtime_error)?;
        let run_dir = config
            .storage
            .data_dir
            .join("run")
            .canonicalize()
            .map_err(runtime_error)?;
        if !boxes_dir.starts_with(&data_root) || !run_dir.starts_with(&data_root) {
            return Err(unavailable(
                "runtime directories escape the configured data root",
            ));
        }
        let driver = LibkrunDriver::current_exe(capabilities).map_err(runtime_error)?;
        let socket_root = SocketRoot::create()?;
        Ok(Self {
            manager,
            driver: Arc::new(driver),
            assets,
            data_root,
            boxes_dir,
            run_dir,
            records: Mutex::new(HashMap::new()),
            auto_pull: config.runtime.auto_pull,
            bundle_registry: config.runtime.bundle_registry.clone(),
            pull_inflight: Arc::new(Mutex::new(HashMap::new())),
            binding_inflight: Arc::new(Mutex::new(HashMap::new())),
            clone_inflight: Arc::new(Mutex::new(HashMap::new())),
            verified_clones: Arc::new(Mutex::new(HashMap::new())),
            image_catalog: Arc::new(Mutex::new(CatalogState {
                cached: None,
                inflight: None,
            })),
            default_disk_bytes: config
                .resources
                .default_disk_gib
                .checked_mul(1024 * 1024 * 1024)
                .ok_or_else(|| box_core::DomainError::validation("default disk size overflow"))?,
            dns_servers: config
                .network
                .dns_servers
                .iter()
                .map(|address| address.parse().map_err(runtime_error))
                .collect::<box_core::Result<_>>()?,
            dns_over_https_name: (!config.network.dns_over_https_name.is_empty())
                .then(|| config.network.dns_over_https_name.clone()),
            socket_root,
            telemetry: Arc::new(NoopTelemetry),
        })
    }

    pub fn with_telemetry(mut self, telemetry: Arc<dyn Telemetry>) -> Self {
        self.telemetry = telemetry;
        self
    }

    fn runtime_name(runtime: Runtime) -> &'static str {
        match runtime {
            Runtime::Node => "node",
            Runtime::Python => "python",
            Runtime::Golang => "golang",
            Runtime::Ruby => "ruby",
            Runtime::Rust => "rust",
            Runtime::NodeAlpine => "node-alpine",
            Runtime::PythonAlpine => "python-alpine",
            Runtime::GolangAlpine => "golang-alpine",
            Runtime::RubyAlpine => "ruby-alpine",
            Runtime::RustAlpine => "rust-alpine",
        }
    }

    fn identity(&self) -> LibraryIdentity {
        LibraryIdentity {
            tag: box_runtime_libkrun::LIBKRUN_TAG.into(),
            commit: box_runtime_libkrun::LIBKRUN_COMMIT.into(),
            header_sha256: box_runtime_libkrun::LIBKRUN_HEADER_SHA256.into(),
            artifact_sha256: crate::embedded_runtime::LIBKRUN_SHA256.into(),
        }
    }

    fn firmware_identity(&self) -> FirmwareIdentity {
        FirmwareIdentity {
            version: "5".into(),
            soname: firmware_soname().into(),
            artifact_sha256: crate::embedded_runtime::LIBKRUNFW_SHA256.into(),
        }
    }

    fn run_path(&self, id: BoxId) -> PathBuf {
        self.run_dir.join(id.to_string())
    }

    fn remove_run_path(&self, id: BoxId) -> box_core::Result<()> {
        let directory = self.run_path(id);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(runtime_error(error)),
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(unavailable("runtime work directory is unsafe"));
        }
        for entry in fs::read_dir(&directory).map_err(runtime_error)? {
            let entry = entry.map_err(runtime_error)?;
            let name = entry.file_name();
            let name_text = name.to_string_lossy();
            if name_text.starts_with(".boxd-runtime-") {
                remove_private_runtime_directory(&entry.path())?;
                continue;
            }
            if name != "console.log" && name != "worker.log" && name != "agent.sock" {
                return Err(unavailable(format!(
                    "runtime work directory contains unexpected entry: {}",
                    name.to_string_lossy()
                )));
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(runtime_error)?;
            if metadata.file_type().is_dir() {
                return Err(unavailable(
                    "runtime work entry is unexpectedly a directory",
                ));
            }
            fs::remove_file(entry.path()).map_err(runtime_error)?;
        }
        fs::remove_dir(&directory).map_err(runtime_error)
    }

    fn remove_socket_path(&self, id: BoxId) -> box_core::Result<()> {
        let path = self.socket_root.socket_path(id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => Err(unavailable(
                "runtime agent socket path is unexpectedly a directory",
            )),
            Ok(_) => fs::remove_file(path).map_err(runtime_error),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(runtime_error(error)),
        }
    }

    fn log_worker_diagnostic(&self, id: BoxId) {
        for (name, label) in [
            ("worker.log", "VMM worker diagnostic"),
            ("console.log", "guest console diagnostic"),
        ] {
            let path = self.run_path(id).join(name);
            let Ok(bytes) = fs::read(path) else {
                continue;
            };
            let start = bytes.len().saturating_sub(64 * 1024);
            let diagnostic = String::from_utf8_lossy(&bytes[start..]);
            if !diagnostic.trim().is_empty() {
                tracing::error!(box_id = %id, diagnostic = %diagnostic.trim(), "{label}");
            }
        }
    }

    async fn ensure_runtime(
        &self,
        runtime: &str,
        deadline: tokio::time::Instant,
        cancellation: CreationCancellation,
    ) -> box_core::Result<()> {
        if cancellation.is_cancelled() {
            return Err(unavailable("box creation was cancelled during shutdown"));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(unavailable(
                "box creation exceeded the five minute deadline",
            ));
        }
        let ready = tokio::select! {
            result = self.runtime_is_ready(runtime) => result?,
            () = tokio::time::sleep_until(deadline) => {
                return Err(unavailable("box creation exceeded the five minute deadline"));
            }
            () = cancellation.cancelled() => {
                return Err(unavailable("box creation was cancelled during shutdown"));
            }
        };
        if ready {
            return Ok(());
        }
        require_auto_pull(self.auto_pull, runtime)?;
        let manager = Arc::clone(&self.manager);
        let registry = self.bundle_registry.clone();
        let run_dir = self.run_dir.clone();
        let runtime_owned = runtime.to_owned();
        let arch = std::env::consts::ARCH.to_owned();
        let telemetry = Arc::clone(&self.telemetry);
        run_once_per_key(
            &self.pull_inflight,
            runtime.to_owned(),
            deadline,
            cancellation,
            move || async move {
                let started = std::time::Instant::now();
                let ready_manager = Arc::clone(&manager);
                let ready_runtime = runtime_owned.clone();
                let ready_arch = arch.clone();
                let ready = tokio::task::spawn_blocking(move || {
                    ready_manager.ready_for(&ready_runtime, &ready_arch)
                })
                .await
                .map_err(runtime_error)?
                .map_err(runtime_error)?;
                if ready {
                    return Ok(());
                }
                let outcome = tokio::task::spawn_blocking(move || {
                    crate::runtime_image::pull_verified(
                        &registry,
                        &run_dir,
                        &manager,
                        &runtime_owned,
                        &arch,
                    )
                })
                .await
                .map_err(runtime_error)?
                .map(drop)
                .map_err(runtime_error);
                telemetry.record_runtime_pull(started.elapsed(), outcome.is_ok());
                outcome
            },
        )
        .await
    }

    async fn runtime_is_ready(&self, runtime: &str) -> box_core::Result<bool> {
        let manager = Arc::clone(&self.manager);
        let runtime = runtime.to_owned();
        tokio::task::spawn_blocking(move || manager.ready_for(&runtime, std::env::consts::ARCH))
            .await
            .map_err(runtime_error)?
            .map_err(runtime_error)
    }
}

fn require_auto_pull(enabled: bool, runtime: &str) -> box_core::Result<()> {
    enabled.then_some(()).ok_or_else(|| {
        unavailable(format!(
            "runtime '{runtime}' is not installed and runtime.auto_pull is disabled"
        ))
    })
}

fn scan_image_catalog(manager: &RuntimeBundleManager) -> box_core::Result<()> {
    let missing = manager
        // Phase 1 readiness requires the default runtime to be immediately
        // usable. Other advertised runtimes are pulled on demand by create.
        .missing_from_catalog(&["node"], std::env::consts::ARCH)
        .map_err(runtime_error)?;
    if missing.is_empty() {
        Ok(())
    } else {
        Err(unavailable(format!(
            "runtime bundles are unavailable for architecture {}: {}",
            std::env::consts::ARCH,
            missing.join(", ")
        )))
    }
}

async fn run_once_per_key<Key, Action, ActionFuture>(
    inflight: &Arc<Mutex<HashMap<Key, Arc<SharedPull>>>>,
    key: Key,
    deadline: tokio::time::Instant,
    cancellation: CreationCancellation,
    action: Action,
) -> box_core::Result<()>
where
    Key: Clone + Eq + std::hash::Hash + Send + 'static,
    Action: FnOnce() -> ActionFuture + Send + 'static,
    ActionFuture: Future<Output = box_core::Result<()>> + Send + 'static,
{
    let (pull, start) = {
        let mut operations = inflight.lock().await;
        match operations.get(&key) {
            Some(operation) => (Arc::clone(operation), false),
            None => {
                let operation = Arc::new(SharedPull::pending());
                operations.insert(key.clone(), Arc::clone(&operation));
                (operation, true)
            }
        }
    };

    if start {
        let operation = Arc::clone(&pull);
        let operations = Arc::clone(inflight);
        let key = key.clone();
        tokio::spawn(async move {
            let result = tokio::spawn(action())
                .await
                .map_err(runtime_error)
                .and_then(std::convert::identity);
            *operation.result.lock().await = Some(result);
            operation.completed.notify_waiters();
            let mut operations = operations.lock().await;
            if operations
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &operation))
            {
                operations.remove(&key);
            }
        });
    }

    wait_for_operation(&pull, deadline, &cancellation).await
}

async fn wait_for_operation(
    operation: &SharedPull,
    deadline: tokio::time::Instant,
    cancellation: &CreationCancellation,
) -> box_core::Result<()> {
    loop {
        let completed = operation.completed.notified();
        if let Some(result) = operation.result.lock().await.clone() {
            return result;
        }
        tokio::select! {
            () = completed => {}
            () = tokio::time::sleep_until(deadline) => {
                return Err(unavailable("box creation exceeded the five minute deadline"));
            }
            () = cancellation.cancelled() => {
                return Err(unavailable("box creation was cancelled during shutdown"));
            }
        }
    }
}

async fn wait_for_completion(operation: &SharedPull) -> box_core::Result<()> {
    loop {
        let completed = operation.completed.notified();
        if let Some(result) = operation.result.lock().await.clone() {
            return result;
        }
        completed.await;
    }
}

async fn wait_for_binding(
    operation: &SharedBinding,
    deadline: tokio::time::Instant,
    cancellation: &CreationCancellation,
) -> box_core::Result<VerifiedRuntimeBundle> {
    loop {
        let completed = operation.completed.notified();
        if let Some(result) = operation.result.lock().await.clone() {
            return result;
        }
        tokio::select! {
            () = completed => {}
            () = tokio::time::sleep_until(deadline) => {
                return Err(unavailable("box creation exceeded the five minute deadline"));
            }
            () = cancellation.cancelled() => {
                return Err(unavailable("box creation was cancelled during shutdown"));
            }
        }
    }
}

async fn wait_for_clone(
    operation: &CloneOperation,
    deadline: tokio::time::Instant,
    cancellation: &CreationCancellation,
) -> box_core::Result<()> {
    loop {
        let completed = operation.completed.notified();
        {
            let mut state = operation.state.lock().await;
            if let Some(result) = state.result.clone() {
                state.claimed = true;
                return result;
            }
        }
        tokio::select! {
            () = completed => {}
            () = tokio::time::sleep_until(deadline) => {
                let mut state = operation.state.lock().await;
                if let Some(result) = state.result.clone() {
                    state.claimed = true;
                    return result;
                }
                state.abandoned = true;
                return Err(unavailable("box creation exceeded the five minute deadline"));
            }
            () = cancellation.cancelled() => {
                let mut state = operation.state.lock().await;
                if let Some(result) = state.result.clone() {
                    state.claimed = true;
                    return result;
                }
                state.abandoned = true;
                return Err(unavailable("box creation was cancelled during shutdown"));
            }
        }
    }
}

async fn wait_for_clone_completion(operation: &CloneOperation) -> box_core::Result<()> {
    loop {
        let completed = operation.completed.notified();
        if let Some(result) = operation.state.lock().await.result.clone() {
            return result;
        }
        completed.await;
    }
}

fn remove_private_runtime_directory(path: &std::path::Path) -> box_core::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(runtime_error)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(unavailable("private runtime staging entry is unsafe"));
    }
    for entry in fs::read_dir(path).map_err(runtime_error)? {
        let entry = entry.map_err(runtime_error)?;
        let name = entry.file_name();
        let allowed = name == "libkrun.private.dylib"
            || name == "libkrun.private.so"
            || name == "libkrunfw.5.dylib"
            || name == "libkrunfw.so.5";
        let metadata = fs::symlink_metadata(entry.path()).map_err(runtime_error)?;
        #[cfg(unix)]
        let unique_regular = {
            use std::os::unix::fs::MetadataExt;
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1
        };
        #[cfg(not(unix))]
        let unique_regular = metadata.file_type().is_file() && !metadata.file_type().is_symlink();
        if !allowed || !unique_regular {
            return Err(unavailable(
                "private runtime staging directory contains an unsafe entry",
            ));
        }
        fs::remove_file(entry.path()).map_err(runtime_error)?;
    }
    fs::remove_dir(path).map_err(runtime_error)
}

#[async_trait]
impl ImageStore for RuntimeHost {
    async fn ready(&self) -> box_core::Result<()> {
        let manager = Arc::clone(&self.manager);
        let operation = match catalog_operation(&self.image_catalog, move || async move {
            tokio::task::spawn_blocking(move || scan_image_catalog(&manager))
                .await
                .map_err(runtime_error)?
        })
        .await
        {
            CatalogLookup::Cached(result) => return result,
            CatalogLookup::Pending(operation) => operation,
        };
        tokio::time::timeout(IMAGE_READINESS_TIMEOUT, wait_for_completion(&operation))
            .await
            .map_err(|_| unavailable("runtime image readiness inspection timed out"))?
    }

    async fn inspect_box_disk(&self, box_id: BoxId) -> box_core::Result<PrivateDiskInspection> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || manager.private_disk_ready(&box_id.to_string()))
            .await
            .map_err(runtime_error)?
            .map_err(runtime_error)
            .map(|ready| {
                if ready {
                    PrivateDiskInspection::Ready
                } else {
                    PrivateDiskInspection::Missing
                }
            })
    }

    async fn resolve_and_bind(
        &self,
        runtime: Runtime,
        browser: bool,
        deadline: tokio::time::Instant,
        cancellation: CreationCancellation,
    ) -> box_core::Result<VerifiedRuntimeBundle> {
        let runtime = Self::runtime_name(runtime).to_owned();
        self.ensure_runtime(&runtime, deadline, cancellation.clone())
            .await?;
        let operation_key = format!("{runtime}#browser={browser}");
        let (operation, start) = {
            let mut operations = self.binding_inflight.lock().await;
            match operations.get(&operation_key) {
                Some(operation) => (Arc::clone(operation), false),
                None => {
                    let operation = Arc::new(SharedBinding::pending());
                    operations.insert(operation_key.clone(), Arc::clone(&operation));
                    (operation, true)
                }
            }
        };
        if start {
            let manager = Arc::clone(&self.manager);
            let tracked = Arc::clone(&operation);
            let operations = Arc::clone(&self.binding_inflight);
            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    let required = if browser {
                        ["browser-cdp-v1".to_owned()].into_iter().collect()
                    } else {
                        std::collections::BTreeSet::new()
                    };
                    manager.resolve_preferred_with_features(
                        &runtime,
                        std::env::consts::ARCH,
                        &required,
                    )
                })
                .await
                .map_err(runtime_error)
                .and_then(|resolved| resolved.map_err(runtime_error))
                .and_then(|resolved| {
                    let manifest_path = resolved
                        .rootfs_path
                        .parent()
                        .ok_or_else(|| unavailable("runtime bundle has no parent directory"))?
                        .join("manifest.json");
                    let manifest_json =
                        fs::read_to_string(&manifest_path).map_err(runtime_error)?;
                    let canonical_path = resolved
                        .rootfs_path
                        .to_str()
                        .ok_or_else(|| unavailable("runtime bundle path is not UTF-8"))?
                        .to_owned();
                    Ok(VerifiedRuntimeBundle {
                        binding: RuntimeBundleBinding::new(
                            resolved.rootfs_sha256,
                            resolved.manifest.runtime_version,
                            resolved.manifest.arch,
                        )?,
                        manifest_json,
                        canonical_path,
                    })
                });
                *tracked.result.lock().await = Some(result);
                tracked.completed.notify_waiters();
                let mut operations = operations.lock().await;
                if operations
                    .get(&operation_key)
                    .is_some_and(|current| Arc::ptr_eq(current, &tracked))
                {
                    operations.remove(&operation_key);
                }
            });
        }
        wait_for_binding(&operation, deadline, &cancellation).await
    }

    async fn verify_binding(
        &self,
        runtime: Runtime,
        binding: &RuntimeBundleBinding,
    ) -> box_core::Result<VerifiedRuntimeBundle> {
        let manager = Arc::clone(&self.manager);
        let runtime = Self::runtime_name(runtime).to_owned();
        let binding = binding.clone();
        tokio::task::spawn_blocking(move || {
            let resolved = manager
                .resolve_installed_by_sha(
                    &binding.sha256,
                    &runtime,
                    &binding.runtime_version,
                    &binding.arch,
                )
                .map_err(runtime_error)?;
            let manifest_path = resolved
                .rootfs_path
                .parent()
                .ok_or_else(|| unavailable("runtime bundle has no parent directory"))?
                .join("manifest.json");
            Ok(VerifiedRuntimeBundle {
                binding,
                manifest_json: fs::read_to_string(manifest_path).map_err(runtime_error)?,
                canonical_path: resolved
                    .rootfs_path
                    .to_str()
                    .ok_or_else(|| unavailable("runtime bundle path is not UTF-8"))?
                    .to_owned(),
            })
        })
        .await
        .map_err(runtime_error)?
    }

    async fn clone_for_box(
        &self,
        box_id: BoxId,
        binding: &RuntimeBundleBinding,
        deadline: tokio::time::Instant,
        cancellation: CreationCancellation,
    ) -> box_core::Result<()> {
        let manager = Arc::clone(&self.manager);
        let binding = binding.clone();
        let disk_size_bytes = self.default_disk_bytes;
        if binding.arch != std::env::consts::ARCH {
            return Err(box_core::DomainError::validation(
                "runtime bundle binding architecture does not match this host",
            ));
        }
        let (operation, start) = {
            let mut operations = self.clone_inflight.lock().await;
            match operations.get(&box_id) {
                Some(operation) => (Arc::clone(operation), false),
                None => {
                    let operation = Arc::new(CloneOperation::pending());
                    operations.insert(box_id, Arc::clone(&operation));
                    (operation, true)
                }
            }
        };
        if start {
            let tracked = Arc::clone(&operation);
            let operations = Arc::clone(&self.clone_inflight);
            let verified_clones = Arc::clone(&self.verified_clones);
            let cleanup_manager = Arc::clone(&manager);
            let abandonment = Arc::clone(&operation);
            let abandonment_operations = Arc::clone(&self.clone_inflight);
            let abandonment_manager = Arc::clone(&manager);
            let abandonment_verified_clones = Arc::clone(&self.verified_clones);
            let abandonment_cancellation = cancellation.clone();
            let abandonment_deadline = deadline
                .checked_sub(Duration::from_millis(100))
                .unwrap_or(deadline);
            tokio::spawn(async move {
                tokio::select! {
                    () = tokio::time::sleep_until(abandonment_deadline) => {}
                    () = abandonment_cancellation.cancelled() => {}
                }
                let mut state = abandonment.state.lock().await;
                if state.claimed {
                    return;
                }
                state.abandoned = true;
                let published = state.result.as_ref().is_some_and(Result::is_ok);
                let finished = state.result.is_some();
                drop(state);
                if published {
                    abandonment_verified_clones.lock().await.remove(&box_id);
                    let cleanup = tokio::task::spawn_blocking(move || {
                        abandonment_manager.remove_box_disk(&box_id.to_string())
                    })
                    .await
                    .map_err(runtime_error)
                    .and_then(|result| result.map_err(runtime_error))
                    .and_then(|()| {
                        Err(unavailable(
                            "private disk clone was abandoned before creation settlement",
                        ))
                    });
                    abandonment.state.lock().await.result = Some(cleanup);
                    abandonment.completed.notify_waiters();
                }
                if finished {
                    let mut operations = abandonment_operations.lock().await;
                    if operations
                        .get(&box_id)
                        .is_some_and(|current| Arc::ptr_eq(current, &abandonment))
                    {
                        operations.remove(&box_id);
                    }
                }
            });
            tokio::spawn(async move {
                let clone_result = tokio::task::spawn_blocking(move || {
                    manager.clone_runtime_for_box_binding_sized(
                        &box_id.to_string(),
                        &binding.sha256,
                        &binding.runtime_version,
                        &binding.arch,
                        disk_size_bytes,
                    )
                })
                .await
                .map_err(runtime_error)
                .and_then(|result| result.map_err(image_error));

                if let Ok(disks) = &clone_result {
                    verified_clones.lock().await.insert(box_id, disks.clone());
                }
                let result = clone_result.map(drop);

                let mut state = tracked.state.lock().await;
                if !state.abandoned || result.is_err() {
                    state.result = Some(result);
                    drop(state);
                    tracked.completed.notify_waiters();
                } else {
                    drop(state);
                    verified_clones.lock().await.remove(&box_id);
                    let cleanup_result = tokio::task::spawn_blocking(move || {
                        cleanup_manager.remove_box_disk(&box_id.to_string())
                    })
                    .await
                    .map_err(runtime_error)
                    .and_then(|cleanup| cleanup.map_err(runtime_error))
                    .and_then(|()| {
                        Err(unavailable(
                            "private disk clone completed after its caller abandoned creation",
                        ))
                    });
                    tracked.state.lock().await.result = Some(cleanup_result);
                    tracked.completed.notify_waiters();
                }
                let state = tracked.state.lock().await;
                let terminal_without_claim =
                    state.abandoned || state.result.as_ref().is_some_and(Result::is_err);
                drop(state);
                if terminal_without_claim {
                    let mut operations = operations.lock().await;
                    if operations
                        .get(&box_id)
                        .is_some_and(|current| Arc::ptr_eq(current, &tracked))
                    {
                        operations.remove(&box_id);
                    }
                }
            });
        }
        let result = wait_for_clone(&operation, deadline, &cancellation).await;
        if operation.state.lock().await.claimed {
            let mut operations = self.clone_inflight.lock().await;
            if operations
                .get(&box_id)
                .is_some_and(|current| Arc::ptr_eq(current, &operation))
            {
                operations.remove(&box_id);
            }
        }
        result
    }

    async fn remove_box_disk(&self, box_id: BoxId) -> box_core::Result<()> {
        let clone = self.clone_inflight.lock().await.get(&box_id).cloned();
        if let Some(operation) = clone {
            // Ignore the clone outcome: removal is the authoritative cleanup,
            // but it must not race the still-owned blocking operation.
            let _ = wait_for_clone_completion(&operation).await;
        }
        let manager = Arc::clone(&self.manager);
        let result =
            tokio::task::spawn_blocking(move || manager.remove_box_disk(&box_id.to_string()))
                .await
                .map_err(runtime_error)?
                .map_err(runtime_error);
        if result.is_ok() {
            self.verified_clones.lock().await.remove(&box_id);
        }
        result
    }

    async fn create_snapshot_disk(
        &self,
        box_id: BoxId,
        snapshot_id: box_core::SnapshotId,
    ) -> box_core::Result<box_service::SnapshotDiskRecord> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            manager.create_snapshot_disk(&box_id.to_string(), &snapshot_id.to_string())
        })
        .await
        .map_err(runtime_error)?
        .map_err(runtime_error)
        .map(|record| box_service::SnapshotDiskRecord {
            relative_path: record.relative_path,
            size_bytes: record.size_bytes,
            sha256: record.sha256,
        })
    }

    async fn clone_snapshot_for_box(
        &self,
        snapshot_id: box_core::SnapshotId,
        box_id: BoxId,
        expected_sha256: &str,
    ) -> box_core::Result<()> {
        let manager = Arc::clone(&self.manager);
        let checksum = expected_sha256.to_owned();
        tokio::task::spawn_blocking(move || {
            manager.clone_snapshot_for_box(&snapshot_id.to_string(), &box_id.to_string(), &checksum)
        })
        .await
        .map_err(runtime_error)?
        .map(|_| ())
        .map_err(runtime_error)
    }

    async fn remove_snapshot_disk(
        &self,
        snapshot_id: box_core::SnapshotId,
    ) -> box_core::Result<()> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || manager.remove_snapshot_disk(&snapshot_id.to_string()))
            .await
            .map_err(runtime_error)?
            .map_err(runtime_error)
    }
}

#[async_trait]
impl RuntimeController for RuntimeHost {
    async fn ready(&self) -> box_core::Result<()> {
        let capabilities = self.driver.capabilities().await;
        if !(capabilities.blk && capabilities.net && capabilities.vsock) {
            return Err(unavailable("libkrun runtime capabilities are incomplete"));
        }
        tokio::time::timeout(
            Duration::from_secs(15),
            tokio::task::spawn_blocking(crate::doctor::platform_readiness),
        )
        .await
        .map_err(|_| unavailable("platform readiness probe timed out"))?
        .map_err(runtime_error)?
        .map_err(unavailable)
    }

    async fn prepare(
        &self,
        value: &DomainBox,
        environment: &BTreeMap<String, String>,
        network_secrets: &box_service::RuntimeNetworkSecrets,
    ) -> box_core::Result<()> {
        let resources = value.spec.size.resources();
        async {
            let run = self.run_path(value.id);
            if run.exists() {
                self.remove_run_path(value.id)?;
            }
            fs::create_dir(&run).map_err(runtime_error)?;
            let run = run.canonicalize().map_err(runtime_error)?;
            let runtime = Self::runtime_name(value.spec.runtime).to_owned();
            let binding = value
                .runtime_bundle
                .clone()
                .ok_or_else(|| unavailable("runtime bundle is not bound"))?;
            if binding.arch != std::env::consts::ARCH {
                return Err(box_core::DomainError::validation(
                    "persisted runtime bundle binding architecture does not match this host",
                ));
            }
            let cached = self.verified_clones.lock().await.get(&value.id).cloned();
            let (base_root_disk, writable) = if let Some(disks) = cached {
                if disks.base_rootfs.source_sha256 != binding.sha256
                    || disks.data_disk.source_sha256 != binding.sha256
                    || disks.manifest.runtime != runtime
                    || disks.manifest.runtime_version != binding.runtime_version
                    || disks.manifest.arch != binding.arch
                {
                    return Err(unavailable(
                        "verified private-disk identity does not match the persisted runtime binding",
                    ));
                }
                let base = disks
                    .base_rootfs
                    .path
                    .canonicalize()
                    .map_err(runtime_error)?;
                let writable = disks
                    .data_disk
                    .path
                    .canonicalize()
                    .map_err(runtime_error)?;
                if base != disks.base_rootfs.path
                    || writable != disks.data_disk.path
                    || !writable.starts_with(&self.boxes_dir)
                {
                    return Err(unavailable("verified runtime disk paths changed after clone"));
                }
                (base, writable)
            } else {
                // A process restart has no process-local clone identity. In
                // that recovery path, retain the full authenticated scan.
                let manager = Arc::clone(&self.manager);
                let binding_for_scan = binding.clone();
                let runtime_for_scan = runtime.clone();
                let base = tokio::task::spawn_blocking(move || {
                    manager.resolve_installed_by_sha(
                        &binding_for_scan.sha256,
                        &runtime_for_scan,
                        &binding_for_scan.runtime_version,
                        &binding_for_scan.arch,
                    )
                })
                .await
                .map_err(runtime_error)?
                .map_err(runtime_error)?;
                let writable = self
                    .boxes_dir
                    .join(value.id.to_string())
                    .join("data.raw")
                    .canonicalize()
                    .map_err(runtime_error)?;
                (base.rootfs_path, writable)
            };
            let mut nonce = [0_u8; 32];
            getrandom::fill(&mut nonce).map_err(runtime_error)?;
            self.remove_socket_path(value.id)?;
            let socket = self.socket_root.socket_path(value.id);
            let needs_network_tls = !network_secrets.attach_headers.is_empty()
                || matches!(
                    &value.spec.network_policy,
                    NetworkPolicy::Custom(policy) if !policy.allowed_domains().is_empty()
                );
            let spec = WorkerSpec {
                version: WORKER_SPEC_VERSION,
                box_id: value.id.to_string(),
                expected_parent_pid: 0,
                agent_protocol_version: 1,
                browser_enabled: value.spec.browser,
                runtime: Self::runtime_name(value.spec.runtime).into(),
                arch: std::env::consts::ARCH.into(),
                data_root: self.data_root.clone(),
                base_root_disk,
                writable_data_disk: writable,
                vcpus: resources.vcpus,
                memory_mib: resources.memory_mib,
                console_path: run.join("console.log"),
                vsock_socket: socket.clone(),
                vsock_port: AGENT_VSOCK_PORT,
                boot_nonce: hex::encode(nonce),
                workdir: run,
                guest_environment: environment.clone(),
                limits: ResourceLimits {
                    vcpus: resources.vcpus,
                    memory_mib: resources.memory_mib,
                    host_worker_max_processes: 256,
                    host_worker_max_open_files: 1024,
                },
                libkrun_library: self.assets.libkrun.clone(),
                libkrun_identity: self.identity(),
                libkrun_firmware: self.assets.libkrunfw.clone(),
                libkrun_firmware_identity: self.firmware_identity(),
                network_mode: match &value.spec.network_policy {
                    NetworkPolicy::DenyAll => NetworkMode::DenyAll,
                    NetworkPolicy::RestrictedDefault => NetworkMode::RestrictedDefault,
                    NetworkPolicy::Custom(_) => NetworkMode::Custom,
                },
                custom_network_policy: match &value.spec.network_policy {
                    NetworkPolicy::Custom(policy) => Some(box_runtime::CustomNetworkPolicySpec {
                        allowed_domains: policy.allowed_domains().iter().map(|value| value.as_str().to_owned()).collect(),
                        allowed_cidrs: policy.allowed_cidrs().iter().map(ToString::to_string).collect(),
                        denied_cidrs: policy.denied_cidrs().iter().map(ToString::to_string).collect(),
                    }),
                    NetworkPolicy::DenyAll | NetworkPolicy::RestrictedDefault => None,
                },
                attach_headers: match (
                    needs_network_tls,
                    network_secrets.ca_private_key_der.as_ref(),
                    network_secrets.ca_certificate_der.is_empty(),
                    network_secrets.attach_headers.is_empty(),
                ) {
                    (false, _, _, _) => None,
                    (true, Some(private_key), false, _) => Some(box_runtime::AttachHeadersSpec {
                        rules: network_secrets.attach_headers.clone(),
                        ca_certificate_der: network_secrets.ca_certificate_der.clone(),
                        ca_private_key_der: private_key.expose_secret().to_vec(),
                    }),
                    _ => {
                        return Err(unavailable(
                            "runtime network TLS secret material is incomplete",
                        ));
                    }
                },
                dns_servers: match &value.spec.network_policy {
                    NetworkPolicy::RestrictedDefault | NetworkPolicy::Custom(_) => self.dns_servers.clone(),
                    NetworkPolicy::DenyAll => vec![],
                },
                dns_over_https_name: match &value.spec.network_policy {
                    NetworkPolicy::RestrictedDefault | NetworkPolicy::Custom(_) => self.dns_over_https_name.clone(),
                    NetworkPolicy::DenyAll => None,
                },
            };
            let prepared = self
                .driver
                .prepare(&SandboxSpec { worker: spec })
                .await
                .map_err(runtime_error)?;
            self.records.lock().await.insert(
                value.id,
                RuntimeRecord {
                    prepared,
                    boot_nonce: nonce.to_vec(),
                    runtime: Self::runtime_name(value.spec.runtime).into(),
                    arch: std::env::consts::ARCH.into(),
                    socket,
                },
            );
            Ok(())
        }
        .await
    }

    async fn start(&self, box_id: BoxId) -> box_core::Result<()> {
        let prepared = self
            .records
            .lock()
            .await
            .get(&box_id)
            .map(|record| record.prepared.clone())
            .ok_or_else(|| unavailable("box runtime was not prepared"))?;
        self.driver
            .start(&prepared)
            .await
            .map(drop)
            .map_err(runtime_error)
    }

    async fn stop(&self, box_id: BoxId, grace: Duration) -> box_core::Result<()> {
        if self.records.lock().await.contains_key(&box_id) {
            self.driver
                .request_shutdown(&box_id.to_string(), grace)
                .await
                .map_err(runtime_error)?;
            self.driver
                .cleanup(&box_id.to_string())
                .await
                .map_err(runtime_error)?;
            self.records.lock().await.remove(&box_id);
        }
        self.remove_socket_path(box_id)
    }

    async fn delete(&self, box_id: BoxId) -> box_core::Result<()> {
        if self.records.lock().await.contains_key(&box_id) {
            match self.driver.inspect(&box_id.to_string()).await {
                Ok(state) => tracing::debug!(box_id = %box_id, ?state, "VMM state before cleanup"),
                Err(error) => {
                    tracing::debug!(box_id = %box_id, %error, "cannot inspect VMM before cleanup")
                }
            }
        }
        self.log_worker_diagnostic(box_id);
        if self.records.lock().await.contains_key(&box_id) {
            self.driver
                .force_stop(&box_id.to_string())
                .await
                .map_err(runtime_error)?;
            self.driver
                .cleanup(&box_id.to_string())
                .await
                .map_err(runtime_error)?;
            self.records.lock().await.remove(&box_id);
        }
        self.remove_socket_path(box_id)?;
        self.remove_run_path(box_id)
    }

    async fn inspect(&self, box_id: BoxId) -> box_core::Result<RuntimeInspection> {
        if !self.records.lock().await.contains_key(&box_id) {
            return Ok(RuntimeInspection::Missing);
        }
        let state = self
            .driver
            .inspect(&box_id.to_string())
            .await
            .map_err(runtime_error)?;
        Ok(match state {
            RuntimeState::Missing => RuntimeInspection::Missing,
            RuntimeState::Prepared => RuntimeInspection::Prepared,
            RuntimeState::Running(value) => {
                let nonce = self
                    .records
                    .lock()
                    .await
                    .get(&box_id)
                    .map(|record| record.boot_nonce.clone())
                    .ok_or_else(|| unavailable("runtime identity disappeared"))?;
                RuntimeInspection::Running {
                    worker_pid: value.pid,
                    worker_started_at_millis: system_millis(value.started_at)?,
                    launch_id: value.launch_id,
                    boot_nonce: nonce,
                }
            }
            RuntimeState::Exited(exit) => RuntimeInspection::Exited {
                exit_code: exit.exit_code,
                success: exit.success,
            },
            RuntimeState::Error(message) => RuntimeInspection::Error { message },
        })
    }
}

#[async_trait]
impl AgentEndpointResolver for RuntimeHost {
    async fn ready(&self) -> box_core::Result<()> {
        RuntimeController::ready(self).await
    }

    async fn endpoint(&self, box_id: BoxId) -> box_core::Result<HostAgentEndpoint> {
        self.records
            .lock()
            .await
            .get(&box_id)
            .map(|record| HostAgentEndpoint::UnixVhostVsockBridge(record.socket.clone()))
            .ok_or_else(|| unavailable("agent endpoint is unavailable"))
    }

    async fn boot_identity(&self, box_id: BoxId) -> box_core::Result<AgentBootIdentity> {
        self.records
            .lock()
            .await
            .get(&box_id)
            .map(|record| AgentBootIdentity {
                nonce: record.boot_nonce.clone(),
                runtime: record.runtime.clone(),
                arch: record.arch.clone(),
            })
            .ok_or_else(|| unavailable("agent boot identity is unavailable"))
    }
}

fn system_millis(value: SystemTime) -> box_core::Result<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(runtime_error)
}

fn runtime_error(error: impl std::fmt::Display) -> box_core::DomainError {
    unavailable(format!("runtime unavailable: {error}"))
}

fn image_error(error: ImageError) -> box_core::DomainError {
    match error {
        ImageError::DiskSizeMismatch => box_core::DomainError::validation(
            "resources.default_disk_gib must exactly match the signed runtime rootfs image size; Phase 1 does not grow ext4 filesystems",
        ),
        other => runtime_error(other),
    }
}

fn unavailable(message: impl Into<String>) -> box_core::DomainError {
    box_core::DomainError {
        kind: box_core::DomainErrorKind::Unavailable,
        code: "runtime_unavailable",
        message: message.into(),
    }
}

fn capacity(message: impl Into<String>) -> box_core::DomainError {
    box_core::DomainError {
        kind: box_core::DomainErrorKind::Capacity,
        code: "capacity_exceeded",
        message: message.into(),
    }
}

#[cfg(target_os = "macos")]
const fn firmware_soname() -> &'static str {
    "libkrunfw.5.dylib"
}
#[cfg(target_os = "linux")]
const fn firmware_soname() -> &'static str {
    "libkrunfw.so.5"
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn firmware_soname() -> &'static str {
    "unsupported"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct FixedCapacity(HostCapacity);
    impl HostCapacityProbe for FixedCapacity {
        fn probe(&self, _: &std::path::Path) -> Result<HostCapacity, String> {
            Ok(self.0)
        }
    }

    fn admission(
        directory: &tempfile::TempDir,
        max_running: u32,
        capacity: HostCapacity,
    ) -> HostAdmission {
        let mut config = AppConfig::default();
        config.storage.data_dir = directory.path().to_path_buf();
        config.resources.max_running_boxes = max_running;
        HostAdmission::with_probe(&config, Arc::new(FixedCapacity(capacity))).unwrap()
    }

    #[test]
    fn runtime_names_match_public_contract() {
        let mapped = [
            Runtime::Node,
            Runtime::Python,
            Runtime::Golang,
            Runtime::Ruby,
            Runtime::Rust,
            Runtime::NodeAlpine,
            Runtime::PythonAlpine,
            Runtime::GolangAlpine,
            Runtime::RubyAlpine,
            Runtime::RustAlpine,
        ]
        .map(RuntimeHost::runtime_name);
        assert_eq!(mapped, SUPPORTED_RUNTIMES);
    }

    #[test]
    fn agent_socket_uses_a_private_short_root_independent_of_data_dir() {
        let root = SocketRoot::create().unwrap();
        let socket = root.socket_path(BoxId::new());
        assert!(socket.as_os_str().as_bytes().len() <= 103);
        let metadata = fs::metadata(&root.path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[tokio::test]
    async fn host_admission_is_atomic_idempotent_and_releases() {
        let directory = tempfile::tempdir().unwrap();
        let admission = Arc::new(admission(
            &directory,
            1,
            HostCapacity {
                logical_cpus: 8,
                available_memory_bytes: 32 * 1024 * 1024 * 1024,
                available_disk_bytes: 64 * 1024 * 1024 * 1024,
            },
        ));
        let first = BoxId::new();
        let second = BoxId::new();
        let one = {
            let admission = Arc::clone(&admission);
            tokio::spawn(async move { admission.reserve(first, BoxSize::Small).await })
        };
        let two = {
            let admission = Arc::clone(&admission);
            tokio::spawn(async move { admission.reserve(second, BoxSize::Small).await })
        };
        let results = [one.await.unwrap(), two.await.unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let error = results
            .iter()
            .find_map(|result| result.as_ref().err())
            .expect("one capacity error");
        assert_eq!(error.kind, box_core::DomainErrorKind::Capacity);
        assert_eq!(error.code, "capacity_exceeded");

        let token = results.into_iter().find_map(Result::ok).unwrap();
        let duplicate = admission
            .restore(token.box_id(), BoxSize::Small)
            .await
            .unwrap();
        token.release().await.unwrap();
        duplicate.release().await.unwrap();
        admission
            .reserve(BoxId::new(), BoxSize::Small)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn restart_restore_does_not_charge_an_existing_private_disk_twice() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.storage.data_dir = directory.path().to_path_buf();
        config.resources.max_running_boxes = 4;
        let gib = 1024_u64 * 1024 * 1024;
        let available = config.storage.minimum_free_gib * gib + 1;
        let admission = HostAdmission::with_probe(
            &config,
            Arc::new(FixedCapacity(HostCapacity {
                logical_cpus: 16,
                available_memory_bytes: 64 * gib,
                available_disk_bytes: available,
            })),
        )
        .unwrap();
        let restored = admission.restore(BoxId::new(), BoxSize::Small).await;
        assert!(restored.is_ok());
        let fresh = admission.reserve(BoxId::new(), BoxSize::Small).await;
        assert_eq!(fresh.err().unwrap().code, "capacity_exceeded");
    }

    #[tokio::test]
    async fn disk_ledger_charges_only_unmaterialized_concurrent_creates() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.storage.data_dir = directory.path().to_path_buf();
        config.resources.max_running_boxes = 4;
        let gib = 1024_u64 * 1024 * 1024;
        let available = (config.storage.minimum_free_gib + config.resources.default_disk_gib) * gib;
        let admission = HostAdmission::with_probe(
            &config,
            Arc::new(FixedCapacity(HostCapacity {
                logical_cpus: 16,
                available_memory_bytes: 64 * gib,
                available_disk_bytes: available,
            })),
        )
        .unwrap();
        let first = BoxId::new();
        admission.reserve(first, BoxSize::Small).await.unwrap();
        assert_eq!(
            admission
                .reserve(BoxId::new(), BoxSize::Small)
                .await
                .err()
                .unwrap()
                .code,
            "capacity_exceeded"
        );
        admission.commit_disk(first).await.unwrap();
        admission
            .reserve(BoxId::new(), BoxSize::Small)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stale_opaque_token_cannot_release_new_generation() {
        let directory = tempfile::tempdir().unwrap();
        let admission = admission(
            &directory,
            2,
            HostCapacity {
                logical_cpus: 16,
                available_memory_bytes: 64 * 1024 * 1024 * 1024,
                available_disk_bytes: 128 * 1024 * 1024 * 1024,
            },
        );
        let id = BoxId::new();
        let stale = admission.reserve(id, BoxSize::Small).await.unwrap();
        admission.release_box(id).await.unwrap();
        let current = admission.reserve(id, BoxSize::Small).await.unwrap();
        stale.release().await.unwrap();
        assert!(admission.ledger.reservations.lock().await.contains_key(&id));
        current.release().await.unwrap();
        assert!(!admission.ledger.reservations.lock().await.contains_key(&id));
    }

    #[tokio::test]
    async fn host_admission_checks_physical_cpu_memory_and_disk() {
        let directory = tempfile::tempdir().unwrap();
        for capacity_value in [
            HostCapacity {
                logical_cpus: 1,
                available_memory_bytes: u64::MAX,
                available_disk_bytes: u64::MAX,
            },
            HostCapacity {
                logical_cpus: u32::MAX,
                available_memory_bytes: 1024,
                available_disk_bytes: u64::MAX,
            },
            HostCapacity {
                logical_cpus: u32::MAX,
                available_memory_bytes: u64::MAX,
                available_disk_bytes: 1024,
            },
        ] {
            let admission = admission(&directory, 4, capacity_value);
            let error = admission
                .reserve(BoxId::new(), BoxSize::Small)
                .await
                .err()
                .expect("physical capacity");
            assert_eq!(error.kind, box_core::DomainErrorKind::Capacity);
        }
    }

    #[tokio::test]
    async fn host_admission_ledger_prevents_physical_memory_oversubscription() {
        let directory = tempfile::tempdir().unwrap();
        let admission = admission(
            &directory,
            4,
            HostCapacity {
                logical_cpus: 16,
                available_memory_bytes: 6 * 1024 * 1024 * 1024,
                available_disk_bytes: 128 * 1024 * 1024 * 1024,
            },
        );
        admission
            .reserve(BoxId::new(), BoxSize::Small)
            .await
            .unwrap();
        let error = admission
            .reserve(BoxId::new(), BoxSize::Small)
            .await
            .err()
            .expect("two 4 GiB reservations exceed 6 GiB available");
        assert_eq!(error.kind, box_core::DomainErrorKind::Capacity);
        assert_eq!(admission.ledger.reservations.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn concurrent_auto_pull_gate_runs_download_only_once() {
        let operations = Arc::new(Mutex::new(HashMap::new()));
        let downloads = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let operations = Arc::clone(&operations);
            let downloads = Arc::clone(&downloads);
            tasks.push(tokio::spawn(async move {
                run_once_per_key(
                    &operations,
                    "node".to_owned(),
                    tokio::time::Instant::now() + Duration::from_secs(1),
                    CreationCancellation::default(),
                    move || async move {
                        downloads.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok(())
                    },
                )
                .await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn caller_timeout_keeps_shared_pull_tracked_until_completion() {
        let operations = Arc::new(Mutex::new(HashMap::new()));
        let downloads = Arc::new(AtomicUsize::new(0));
        let first_downloads = Arc::clone(&downloads);
        let first = run_once_per_key(
            &operations,
            "node".to_owned(),
            tokio::time::Instant::now() + Duration::from_millis(10),
            CreationCancellation::default(),
            move || async move {
                first_downloads.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            },
        );
        tokio::pin!(first);
        assert!(first.await.is_err());
        assert_eq!(operations.lock().await.len(), 1);

        let duplicate_downloads = Arc::clone(&downloads);
        let duplicate = run_once_per_key(
            &operations,
            "node".to_owned(),
            tokio::time::Instant::now() + Duration::from_secs(1),
            CreationCancellation::default(),
            move || async move {
                duplicate_downloads.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        tokio::pin!(duplicate);
        duplicate.await.unwrap();
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn clone_deadline_marks_operation_abandoned_for_background_cleanup() {
        let operation = Arc::new(CloneOperation::pending());
        let error = wait_for_clone(
            &operation,
            tokio::time::Instant::now() + Duration::from_millis(10),
            &CreationCancellation::default(),
        )
        .await
        .expect_err("clone caller deadline");
        assert!(error.message.contains("deadline"));
        assert!(operation.state.lock().await.abandoned);
    }

    #[tokio::test]
    async fn readiness_catalog_scan_is_shared_and_cached() {
        let state = Arc::new(Mutex::new(CatalogState {
            cached: None,
            inflight: None,
        }));
        let scans = Arc::new(AtomicUsize::new(0));
        let mut callers = Vec::new();
        for _ in 0..8 {
            let state = Arc::clone(&state);
            let scans = Arc::clone(&scans);
            callers.push(tokio::spawn(async move {
                match catalog_operation(&state, move || async move {
                    scans.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok(())
                })
                .await
                {
                    CatalogLookup::Cached(result) => result,
                    CatalogLookup::Pending(operation) => wait_for_completion(&operation).await,
                }
            }));
        }
        for caller in callers {
            caller.await.unwrap().unwrap();
        }
        assert_eq!(scans.load(Ordering::SeqCst), 1);

        let cached_scans = Arc::clone(&scans);
        let cached = catalog_operation(&state, move || async move {
            cached_scans.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(matches!(cached, CatalogLookup::Cached(Ok(()))));
        assert_eq!(scans.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn readiness_catalog_panic_completes_inflight_with_error() {
        let state = Arc::new(Mutex::new(CatalogState {
            cached: None,
            inflight: None,
        }));
        let operation =
            match catalog_operation(&state, || async move { panic!("injected catalog panic") })
                .await
            {
                CatalogLookup::Pending(operation) => operation,
                CatalogLookup::Cached(_) => panic!("fresh catalog cannot be cached"),
            };
        assert!(wait_for_completion(&operation).await.is_err());
        tokio::task::yield_now().await;
        assert!(state.lock().await.inflight.is_none());
    }

    #[test]
    fn disabled_auto_pull_never_downloads() {
        let error = require_auto_pull(false, "node").expect_err("disabled auto pull");
        assert_eq!(error.kind, box_core::DomainErrorKind::Unavailable);
        assert!(error.message.contains("auto_pull is disabled"));
    }

    #[test]
    fn cleanup_refuses_unexpected_entries() {
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().join(".boxd-runtime-1-aabb");
        fs::create_dir(&private).unwrap();
        fs::write(private.join("libkrun.private.dylib"), b"lib").unwrap();
        fs::write(private.join("libkrunfw.5.dylib"), b"fw").unwrap();
        remove_private_runtime_directory(&private).unwrap();
        assert!(!private.exists());

        let unsafe_private = temp.path().join(".boxd-runtime-2-aabb");
        fs::create_dir(&unsafe_private).unwrap();
        fs::write(unsafe_private.join("unexpected"), b"x").unwrap();
        assert!(remove_private_runtime_directory(&unsafe_private).is_err());
        assert!(unsafe_private.join("unexpected").exists());
    }
}
