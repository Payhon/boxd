//! Infrastructure-independent domain types and ports for boxd.
//!
//! This crate deliberately contains neither HTTP DTOs nor database/runtime-driver
//! types. Compatibility translation belongs at the API boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, DomainError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainErrorKind {
    Validation,
    NotFound,
    Ownership,
    StateConflict,
    VersionConflict,
    FeatureNotSupported,
    Capacity,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainError {
    pub kind: DomainErrorKind,
    pub code: &'static str,
    pub message: String,
}

impl DomainError {
    pub fn validation(message: impl Into<String>) -> Self {
        Self {
            kind: DomainErrorKind::Validation,
            code: "validation_error",
            message: message.into(),
        }
    }
    pub fn feature_not_supported(feature: &'static str) -> Self {
        Self {
            kind: DomainErrorKind::FeatureNotSupported,
            code: "feature_not_supported",
            message: format!("{feature} is not supported"),
        }
    }
    pub fn state_conflict(message: impl Into<String>) -> Self {
        Self {
            kind: DomainErrorKind::StateConflict,
            code: "state_conflict",
            message: message.into(),
        }
    }
    pub fn version_conflict() -> Self {
        Self {
            kind: DomainErrorKind::VersionConflict,
            code: "version_conflict",
            message: "optimistic lock conflict".into(),
        }
    }
    pub fn ownership() -> Self {
        Self {
            kind: DomainErrorKind::Ownership,
            code: "tenant_forbidden",
            message: "resource does not belong to this account or tenant".into(),
        }
    }
}
impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for DomainError {}

macro_rules! strong_id {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl $name {
            /// New internally-created IDs are UUIDv7. Parsing accepts any non-nil UUID
            /// so opaque IDs already emitted by the compatibility contract remain readable.
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
            pub fn parse(value: &str) -> Result<Self> {
                let id =
                    Uuid::parse_str(value).map_err(|_| DomainError::validation("invalid UUID"))?;
                if id.is_nil() {
                    return Err(DomainError::validation("UUID must not be nil"));
                }
                Ok(Self(id))
            }
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }
        impl TryFrom<&str> for $name {
            type Error = DomainError;
            fn try_from(value: &str) -> Result<Self> {
                Self::parse(value)
            }
        }
    };
}
strong_id!(AccountId);
strong_id!(TenantId);
strong_id!(BoxId);
strong_id!(SnapshotId);
strong_id!(PreviewId);
strong_id!(RunId);
strong_id!(OperationId);
strong_id!(NodeId);

/// UTC Unix epoch milliseconds. API adapters may use `from_unix_seconds` for
/// compatibility fields that are expressed in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UtcEpochMillis(i64);
impl UtcEpochMillis {
    pub const fn from_millis(value: i64) -> Self {
        Self(value)
    }
    pub const fn from_unix_seconds(value: i64) -> Self {
        Self(value.saturating_mul(1_000))
    }
    pub const fn as_millis(self) -> i64 {
        self.0
    }
    pub const fn as_unix_seconds(self) -> i64 {
        self.0.div_euclid(1_000)
    }
}

/// A reference to encrypted secret material owned by `box-secrets`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretRef(String);
impl SecretRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 {
            return Err(DomainError::validation("invalid secret reference"));
        }
        Ok(Self(value))
    }
}
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretRef([REDACTED])")
    }
}
impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountContext {
    pub account_id: AccountId,
    pub tenant_id: TenantId,
}
impl AccountContext {
    pub fn owns(self, account_id: AccountId, tenant_id: TenantId) -> bool {
        self.account_id == account_id && self.tenant_id == tenant_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScope {
    BoxesRead,
    BoxesWrite,
    RunsWrite,
    SecretsRead,
    Admin,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedContext {
    pub account: AccountContext,
    pub scopes: BTreeSet<AuthScope>,
}
impl AuthorizedContext {
    pub fn allows(&self, scope: AuthScope) -> bool {
        self.scopes.contains(&AuthScope::Admin) || self.scopes.contains(&scope)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxStatus {
    Creating,
    Idle,
    Running,
    Paused,
    Error,
    Deleted,
}
impl BoxStatus {
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Creating, Self::Idle | Self::Error)
                | (Self::Idle, Self::Running | Self::Paused | Self::Deleted)
                | (Self::Running, Self::Idle)
                | (Self::Paused, Self::Idle | Self::Deleted)
                | (Self::Error, Self::Deleted)
        )
    }
    pub fn transition(self, next: Self, keep_alive: bool) -> Result<Self> {
        if self == Self::Idle && next == Self::Paused && keep_alive {
            return Err(DomainError::state_conflict(
                "keep_alive boxes cannot be paused",
            ));
        }
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(DomainError::state_conflict(format!(
                "cannot transition from {self:?} to {next:?}"
            )))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    Node,
    Python,
    Golang,
    Ruby,
    Rust,
    NodeAlpine,
    PythonAlpine,
    GolangAlpine,
    RubyAlpine,
    RustAlpine,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxSize {
    Small,
    Medium,
    Large,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub vcpus: u8,
    pub memory_mib: u32,
}
impl BoxSize {
    pub const fn resources(self) -> ResourceSpec {
        match self {
            Self::Small => ResourceSpec {
                vcpus: 2,
                memory_mib: 4096,
            },
            Self::Medium => ResourceSpec {
                vcpus: 4,
                memory_mib: 8192,
            },
            Self::Large => ResourceSpec {
                vcpus: 8,
                memory_mib: 16384,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label(String);
impl Label {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 20
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
        {
            return Err(DomainError::validation(
                "labels must be 1..=20 ASCII alphanumeric or ._-:",
            ));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub const DEFAULT_EPHEMERAL_TTL_SECONDS: u32 = 259_200;
pub const MAX_EPHEMERAL_TTL_SECONDS: u32 = 259_200;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralSpec {
    pub ttl_seconds: u32,
}
impl EphemeralSpec {
    pub fn new(ttl_seconds: Option<u32>) -> Result<Self> {
        let ttl_seconds = ttl_seconds.unwrap_or(DEFAULT_EPHEMERAL_TTL_SECONDS);
        if ttl_seconds == 0 || ttl_seconds > MAX_EPHEMERAL_TTL_SECONDS {
            return Err(DomainError::validation(
                "ephemeral ttl must be between 1 and 259200 seconds",
            ));
        }
        Ok(Self { ttl_seconds })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    DenyAll,
    RestrictedDefault,
    Custom,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBundleBinding {
    pub sha256: String,
    pub runtime_version: String,
    pub arch: String,
}

impl RuntimeBundleBinding {
    pub fn new(
        sha256: impl Into<String>,
        runtime_version: impl Into<String>,
        arch: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            sha256: sha256.into(),
            runtime_version: runtime_version.into(),
            arch: arch.into(),
        };
        if value.sha256.len() != 64
            || !value.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.runtime_version.is_empty()
            || value.runtime_version.len() > 128
            || !matches!(value.arch.as_str(), "aarch64" | "x86_64")
        {
            return Err(DomainError::validation("invalid runtime bundle binding"));
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxCreateSpec {
    pub name: Option<String>,
    pub labels: Vec<Label>,
    pub runtime: Runtime,
    pub size: BoxSize,
    pub browser: bool,
    pub keep_alive: bool,
    pub ephemeral: Option<EphemeralSpec>,
    pub attach_headers_requested: bool,
    pub network_policy: NetworkPolicy,
}
impl BoxCreateSpec {
    pub fn validate(&self) -> Result<()> {
        if self.labels.len() > 5 {
            return Err(DomainError::validation("at most five labels are allowed"));
        }
        if self.attach_headers_requested {
            return Err(DomainError::feature_not_supported("attach_headers"));
        }
        if self.network_policy == NetworkPolicy::Custom {
            return Err(DomainError::feature_not_supported("custom network_policy"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Box {
    pub id: BoxId,
    pub account_id: AccountId,
    pub tenant_id: TenantId,
    pub node_id: Option<NodeId>,
    pub status: BoxStatus,
    pub version: u64,
    pub spec: BoxCreateSpec,
    /// Immutable once selected. A newly persisted `creating` box is deliberately
    /// unbound so the HTTP create request never waits for an image pull.
    pub runtime_bundle: Option<RuntimeBundleBinding>,
    /// Immutable source for snapshot restores. Persisting it on the creating
    /// box lets crash recovery clone the same snapshot instead of silently
    /// falling back to the runtime base image.
    pub source_snapshot_id: Option<SnapshotId>,
    pub created_at: UtcEpochMillis,
    pub updated_at: UtcEpochMillis,
}
impl Box {
    pub fn new(owner: AccountContext, spec: BoxCreateSpec, now: UtcEpochMillis) -> Result<Self> {
        spec.validate()?;
        Ok(Self {
            id: BoxId::new(),
            account_id: owner.account_id,
            tenant_id: owner.tenant_id,
            node_id: None,
            status: BoxStatus::Creating,
            version: 0,
            spec,
            runtime_bundle: None,
            source_snapshot_id: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn bind_runtime(
        &mut self,
        binding: RuntimeBundleBinding,
        now: UtcEpochMillis,
    ) -> Result<()> {
        if let Some(current) = &self.runtime_bundle {
            return if current == &binding {
                Ok(())
            } else {
                Err(DomainError::state_conflict(
                    "runtime bundle binding is immutable",
                ))
            };
        }
        if self.status != BoxStatus::Creating {
            return Err(DomainError::state_conflict(
                "runtime bundle can only be bound while creating",
            ));
        }
        self.runtime_bundle = Some(binding);
        self.version = self
            .version
            .checked_add(1)
            .ok_or_else(DomainError::version_conflict)?;
        self.updated_at = now;
        Ok(())
    }
    pub fn assert_owned_by(&self, context: AccountContext) -> Result<()> {
        if context.owns(self.account_id, self.tenant_id) {
            Ok(())
        } else {
            Err(DomainError::ownership())
        }
    }
    pub fn transition(&mut self, next: BoxStatus, now: UtcEpochMillis) -> Result<()> {
        self.status = self.status.transition(next, self.spec.keep_alive)?;
        self.version = self
            .version
            .checked_add(1)
            .ok_or_else(DomainError::version_conflict)?;
        self.updated_at = now;
        Ok(())
    }

    /// Records a control-plane recovery failure. Recovery is allowed to mark
    /// any non-deleted instance as erroneous even when the ordinary request
    /// state machine has no user-triggered transition to `error`.
    pub fn mark_recovery_error(&mut self, now: UtcEpochMillis) -> Result<()> {
        if self.status == BoxStatus::Deleted {
            return Err(DomainError::state_conflict(
                "deleted boxes cannot enter recovery error",
            ));
        }
        self.status = BoxStatus::Error;
        self.version = self
            .version
            .checked_add(1)
            .ok_or_else(DomainError::version_conflict)?;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);
impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || value.bytes().any(|b| b.is_ascii_control()) {
            return Err(DomainError::validation("invalid idempotency key"));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdempotencyKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub id: OperationId,
    pub account_id: AccountId,
    pub tenant_id: TenantId,
    pub box_id: Option<BoxId>,
    pub kind: OperationKind,
    pub status: OperationStatus,
    pub idempotency_key: IdempotencyKey,
    pub retry_count: u32,
    pub error: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    DeleteBox,
    InitCommand,
    PullRuntime,
    Snapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Creating,
    Ready,
    Error,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub account_id: AccountId,
    pub tenant_id: TenantId,
    pub box_id: BoxId,
    pub name: String,
    pub status: SnapshotStatus,
    pub disk_path: Option<String>,
    pub size_bytes: u64,
    pub checksum: Option<String>,
    pub created_at: UtcEpochMillis,
    pub updated_at: UtcEpochMillis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewAuth {
    Public,
    Bearer,
    Basic,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preview {
    pub id: PreviewId,
    pub account_id: AccountId,
    pub tenant_id: TenantId,
    pub box_id: BoxId,
    pub port: u16,
    pub auth: PreviewAuth,
    pub token_hmac: String,
    pub expires_at: UtcEpochMillis,
    pub created_at: UtcEpochMillis,
    pub updated_at: UtcEpochMillis,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnabledSkill {
    pub account_id: AccountId,
    pub tenant_id: TenantId,
    pub box_id: BoxId,
    pub skill_id: String,
    pub name: String,
    pub source_commit: String,
    pub content_sha256: String,
    pub created_at: UtcEpochMillis,
    pub updated_at: UtcEpochMillis,
}

impl EnabledSkill {
    pub fn new(
        context: AccountContext,
        box_id: BoxId,
        skill_id: String,
        source_commit: String,
        content_sha256: String,
        timestamp: UtcEpochMillis,
    ) -> Result<Self> {
        let name = validate_skill_id(&skill_id)?;
        if source_commit.len() != 40
            || !source_commit.bytes().all(|byte| byte.is_ascii_hexdigit())
            || content_sha256.len() != 64
            || !content_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DomainError::validation("invalid skill source identity"));
        }
        Ok(Self {
            account_id: context.account_id,
            tenant_id: context.tenant_id,
            box_id,
            skill_id,
            name,
            source_commit,
            content_sha256,
            created_at: timestamp,
            updated_at: timestamp,
        })
    }
}

pub fn validate_skill_id(skill_id: &str) -> Result<String> {
    if skill_id.len() > 384 || skill_id.starts_with('/') || skill_id.ends_with('/') {
        return Err(DomainError::validation("invalid skill id"));
    }
    let parts = skill_id.split('/').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 128
                || matches!(*part, "." | "..")
                || !part.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric()
                        || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
                })
        })
    {
        return Err(DomainError::validation("invalid skill id"));
    }
    Ok(parts[2].to_owned())
}

impl fmt::Debug for Preview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Preview")
            .field("id", &self.id)
            .field("account_id", &self.account_id)
            .field("tenant_id", &self.tenant_id)
            .field("box_id", &self.box_id)
            .field("port", &self.port)
            .field("auth", &self.auth)
            .field("token_hmac", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Preview {
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 || self.port == 18_080 {
            return Err(DomainError::validation("invalid or reserved preview port"));
        }
        if self.token_hmac.len() != 64
            || !self.token_hmac.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DomainError::validation("invalid preview token digest"));
        }
        if self.expires_at <= self.created_at {
            return Err(DomainError::validation("invalid preview expiry"));
        }
        Ok(())
    }
}

impl Snapshot {
    pub fn new(
        context: AccountContext,
        box_id: BoxId,
        name: String,
        timestamp: UtcEpochMillis,
    ) -> Result<Self> {
        if name.is_empty() || name.len() > 255 || name.as_bytes().contains(&0) {
            return Err(DomainError::validation("invalid snapshot name"));
        }
        Ok(Self {
            id: SnapshotId::new(),
            account_id: context.account_id,
            tenant_id: context.tenant_id,
            box_id,
            name,
            status: SnapshotStatus::Creating,
            disk_path: None,
            size_bytes: 0,
            checksum: None,
            created_at: timestamp,
            updated_at: timestamp,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    Agent,
    Shell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl RunStatus {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunEventType {
    RunStart,
    Text,
    Thinking,
    Tool,
    ToolResult,
    Stderr,
    Stats,
    Done,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub id: RunId,
    pub account_id: AccountId,
    pub tenant_id: TenantId,
    pub box_id: BoxId,
    pub kind: RunKind,
    pub status: RunStatus,
    pub prompt: Option<String>,
    pub model: Option<String>,
    pub output: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub cost_microusd: u64,
    pub duration_millis: u64,
    pub cpu_ns: Option<u64>,
    pub compute_cost_microusd: u64,
    pub memory_peak_bytes: Option<u64>,
    pub error_message: Option<String>,
    pub session_id: Option<String>,
    pub created_at: UtcEpochMillis,
    pub completed_at: Option<UtcEpochMillis>,
}

impl Run {
    pub fn new_agent(
        context: AccountContext,
        box_id: BoxId,
        prompt: impl Into<String>,
        model: Option<String>,
        now: UtcEpochMillis,
    ) -> Result<Self> {
        Self::new_agent_with_id(RunId::new(), context, box_id, prompt, model, now)
    }

    pub fn new_agent_with_id(
        id: RunId,
        context: AccountContext,
        box_id: BoxId,
        prompt: impl Into<String>,
        model: Option<String>,
        now: UtcEpochMillis,
    ) -> Result<Self> {
        let prompt = prompt.into();
        if prompt.is_empty() || prompt.len() > 1024 * 1024 || prompt.as_bytes().contains(&0) {
            return Err(DomainError::validation("invalid run prompt"));
        }
        if model.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 255 || value.as_bytes().contains(&0)
        }) {
            return Err(DomainError::validation("invalid run model"));
        }
        Ok(Self {
            id,
            account_id: context.account_id,
            tenant_id: context.tenant_id,
            box_id,
            kind: RunKind::Agent,
            status: RunStatus::Running,
            prompt: Some(prompt),
            model,
            output: None,
            input_tokens: 0,
            output_tokens: 0,
            cached_input_tokens: 0,
            cost_microusd: 0,
            duration_millis: 0,
            cpu_ns: None,
            compute_cost_microusd: 0,
            memory_peak_bytes: None,
            error_message: None,
            session_id: None,
            created_at: now,
            completed_at: None,
        })
    }

    pub fn new_shell_with_id(
        id: RunId,
        context: AccountContext,
        box_id: BoxId,
        now: UtcEpochMillis,
    ) -> Self {
        Self {
            id,
            account_id: context.account_id,
            tenant_id: context.tenant_id,
            box_id,
            kind: RunKind::Shell,
            status: RunStatus::Running,
            prompt: None,
            model: None,
            output: None,
            input_tokens: 0,
            output_tokens: 0,
            cached_input_tokens: 0,
            cost_microusd: 0,
            duration_millis: 0,
            cpu_ns: None,
            compute_cost_microusd: 0,
            memory_peak_bytes: None,
            error_message: None,
            session_id: None,
            created_at: now,
            completed_at: None,
        }
    }

    pub fn assert_owned_by(&self, context: AccountContext) -> Result<()> {
        if self.account_id == context.account_id && self.tenant_id == context.tenant_id {
            Ok(())
        } else {
            Err(DomainError::ownership())
        }
    }

    pub fn settle(
        &mut self,
        status: RunStatus,
        output: Option<String>,
        error_message: Option<String>,
        now: UtcEpochMillis,
    ) -> Result<()> {
        if self.status.is_terminal() {
            return if self.status == status
                && self.output == output
                && self.error_message == error_message
            {
                Ok(())
            } else {
                Err(DomainError::state_conflict("run is already terminal"))
            };
        }
        if !status.is_terminal() {
            return Err(DomainError::state_conflict(
                "run settlement requires a terminal status",
            ));
        }
        if output
            .as_ref()
            .is_some_and(|value| value.len() > 16 * 1024 * 1024)
            || error_message
                .as_ref()
                .is_some_and(|value| value.len() > 1024 * 1024)
        {
            return Err(DomainError::validation("run settlement exceeds size limit"));
        }
        self.status = status;
        self.output = output;
        self.error_message = error_message;
        self.completed_at = Some(now);
        self.duration_millis = now
            .as_millis()
            .saturating_sub(self.created_at.as_millis())
            .try_into()
            .unwrap_or(0);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunEvent {
    pub run_id: RunId,
    pub account_id: AccountId,
    pub tenant_id: TenantId,
    pub sequence: u64,
    pub event_type: RunEventType,
    /// Canonical JSON payload. Persistence adapters must parse and re-serialize
    /// before storing untrusted input.
    pub payload_json: String,
    pub created_at: UtcEpochMillis,
}

impl RunEvent {
    pub fn validate(&self) -> Result<()> {
        if self.payload_json.is_empty() || self.payload_json.len() > 1024 * 1024 {
            return Err(DomainError::validation("invalid run event payload"));
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BoxLeaseToken(String);
impl BoxLeaseToken {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 {
            return Err(DomainError::validation("invalid box lease token"));
        }
        Ok(Self(value))
    }

    /// Exposes the token only to persistence and lease-comparison adapters.
    /// User-facing output must continue to use the redacted `Debug`/`Display`
    /// implementations.
    pub fn expose_for_storage(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for BoxLeaseToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoxLeaseToken([REDACTED])")
    }
}
impl fmt::Display for BoxLeaseToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeRef(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRef(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortBridge {
    pub host_port: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxSpec {
    pub box_id: BoxId,
    pub runtime: Runtime,
    pub resources: ResourceSpec,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub environment: BTreeMap<String, String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecStream {
    pub run_id: RunId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadFileRequest {
    pub path: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteFileRequest {
    pub path: String,
    pub contents: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    /// Guest filesystem mtime as Unix epoch milliseconds.
    pub modified_at_unix_millis: i64,
}

#[allow(async_fn_in_trait)]
pub trait Transaction: Send {
    async fn commit(self: std::boxed::Box<Self>) -> Result<()>;
    async fn rollback(self: std::boxed::Box<Self>) -> Result<()>;
}
#[allow(async_fn_in_trait)]
pub trait UnitOfWork: Send + Sync {
    type ActiveTransaction: Transaction;

    async fn begin(&self, context: AccountContext) -> Result<Self::ActiveTransaction>;
}
#[allow(async_fn_in_trait)]
pub trait BoxRepository: Send + Sync {
    async fn create(&self, context: AccountContext, value: &Box) -> Result<()>;
    async fn find(&self, context: AccountContext, id: BoxId) -> Result<Option<Box>>;
    async fn list(&self, context: AccountContext) -> Result<Vec<Box>>;
    /// Administrative enumeration used by startup reconciliation and expiry sweeps.
    async fn list_all(&self) -> Result<Vec<Box>>;
    async fn save(&self, context: AccountContext, value: &Box, expected_version: u64)
    -> Result<()>;
    async fn delete_idempotently(
        &self,
        context: AccountContext,
        id: BoxId,
        key: &IdempotencyKey,
    ) -> Result<OperationId>;
    async fn acquire_lease(
        &self,
        context: AccountContext,
        id: BoxId,
        token: &BoxLeaseToken,
        ttl: Duration,
    ) -> Result<bool>;
    /// Atomically extends a lease only when account, tenant, box, and token all match.
    async fn renew_lease(
        &self,
        context: AccountContext,
        id: BoxId,
        token: &BoxLeaseToken,
        ttl: Duration,
    ) -> Result<bool>;
    /// Atomically releases a lease only when account, tenant, box, and token all match.
    async fn release_lease(
        &self,
        context: AccountContext,
        id: BoxId,
        token: &BoxLeaseToken,
    ) -> Result<bool>;
}
#[allow(async_fn_in_trait)]
pub trait OperationRepository: Send + Sync {
    async fn find_by_idempotency_key(
        &self,
        context: AccountContext,
        kind: OperationKind,
        key: &IdempotencyKey,
    ) -> Result<Option<Operation>>;
    async fn create(&self, context: AccountContext, operation: &Operation) -> Result<()>;
    async fn save(&self, context: AccountContext, operation: &Operation) -> Result<()>;
}
#[allow(async_fn_in_trait)]
pub trait RunRepository: Send + Sync {
    async fn create_run(&self, context: AccountContext, run: &Run) -> Result<()>;
    async fn find_run(&self, context: AccountContext, id: RunId) -> Result<Option<Run>>;
    async fn list_runs(&self, context: AccountContext, box_id: BoxId) -> Result<Vec<Run>>;
    async fn append_run_event(&self, context: AccountContext, event: &RunEvent) -> Result<()>;
    async fn replay_run_events(
        &self,
        context: AccountContext,
        run_id: RunId,
        after_sequence: Option<u64>,
    ) -> Result<Vec<RunEvent>>;
    async fn save_run(&self, context: AccountContext, run: &Run) -> Result<()>;
}
#[allow(async_fn_in_trait)]
pub trait SnapshotRepository: Send + Sync {
    async fn create_snapshot(&self, context: AccountContext, snapshot: &Snapshot) -> Result<()>;
    async fn find_snapshot(
        &self,
        context: AccountContext,
        id: SnapshotId,
    ) -> Result<Option<Snapshot>>;
    async fn list_snapshots(
        &self,
        context: AccountContext,
        box_id: Option<BoxId>,
    ) -> Result<Vec<Snapshot>>;
    async fn save_snapshot(&self, context: AccountContext, snapshot: &Snapshot) -> Result<()>;
}
#[allow(async_fn_in_trait)]
pub trait PreviewRepository: Send + Sync {
    async fn create_preview(&self, context: AccountContext, preview: &Preview) -> Result<()>;
    async fn find_preview_by_token_hmac(&self, token_hmac: &str) -> Result<Option<Preview>>;
    async fn list_previews(&self, context: AccountContext, box_id: BoxId) -> Result<Vec<Preview>>;
    async fn delete_preview(
        &self,
        context: AccountContext,
        box_id: BoxId,
        port: u16,
    ) -> Result<bool>;
    async fn delete_expired_previews(&self, at: UtcEpochMillis) -> Result<u64>;
}
#[allow(async_fn_in_trait)]
pub trait SkillRepository: Send + Sync {
    async fn upsert_skill(&self, context: AccountContext, skill: &EnabledSkill) -> Result<()>;
    async fn list_skills(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> Result<Vec<EnabledSkill>>;
    async fn delete_skill(
        &self,
        context: AccountContext,
        box_id: BoxId,
        skill_id: &str,
    ) -> Result<bool>;
}
#[allow(async_fn_in_trait)]
pub trait SandboxRuntime: Send + Sync {
    async fn create(&self, spec: SandboxSpec) -> Result<RuntimeRef>;
    async fn start(&self, id: &RuntimeRef) -> Result<()>;
    async fn stop(&self, id: &RuntimeRef, grace: Duration) -> Result<()>;
    async fn delete(&self, id: &RuntimeRef) -> Result<()>;
    async fn exec(&self, id: &RuntimeRef, req: ExecRequest) -> Result<ExecStream>;
    async fn expose_port(&self, id: &RuntimeRef, port: u16) -> Result<PortBridge>;
    async fn snapshot(&self, id: &RuntimeRef) -> Result<SnapshotRef>;
}
#[allow(async_fn_in_trait)]
pub trait AgentClient: Send + Sync {
    async fn exec(
        &self,
        context: AccountContext,
        box_id: BoxId,
        request: ExecRequest,
    ) -> Result<ExecStream>;
    async fn read_file(
        &self,
        context: AccountContext,
        box_id: BoxId,
        request: ReadFileRequest,
    ) -> Result<Vec<u8>>;
    async fn write_file(
        &self,
        context: AccountContext,
        box_id: BoxId,
        request: WriteFileRequest,
    ) -> Result<()>;
    async fn list_files(
        &self,
        context: AccountContext,
        box_id: BoxId,
        folder: String,
    ) -> Result<Vec<FileEntry>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_are_serde_round_trip_and_internal_ids_are_v7() {
        let id = BoxId::new();
        assert_eq!(id.as_uuid().get_version_num(), 7);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<BoxId>(&json).unwrap(), id);
        let existing_v4 = BoxId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(existing_v4.as_uuid().get_version_num(), 4);
        assert!(BoxId::parse("00000000-0000-0000-0000-000000000000").is_err());
        assert!(BoxId::parse("not-a-uuid").is_err());
    }
    #[test]
    fn status_matrix_and_keep_alive_conflict() {
        for from in [
            BoxStatus::Creating,
            BoxStatus::Idle,
            BoxStatus::Running,
            BoxStatus::Paused,
            BoxStatus::Error,
            BoxStatus::Deleted,
        ] {
            for to in [
                BoxStatus::Creating,
                BoxStatus::Idle,
                BoxStatus::Running,
                BoxStatus::Paused,
                BoxStatus::Error,
                BoxStatus::Deleted,
            ] {
                assert_eq!(
                    from.transition(to, false).is_ok(),
                    from.can_transition_to(to)
                );
            }
        }
        assert_eq!(
            BoxStatus::Idle
                .transition(BoxStatus::Paused, true)
                .unwrap_err()
                .code,
            "state_conflict"
        );
        assert!(
            BoxStatus::Deleted
                .transition(BoxStatus::Idle, false)
                .is_err()
        );
    }
    #[test]
    fn create_rules_validate_labels_runtime_size_ttl_and_features() {
        assert!(Label::new("a._-:Z9").is_ok());
        assert!(Label::new("bad label").is_err());
        assert!(Label::new("x".repeat(21)).is_err());
        assert_eq!(
            BoxSize::Medium.resources(),
            ResourceSpec {
                vcpus: 4,
                memory_mib: 8192
            }
        );
        assert_eq!(EphemeralSpec::new(None).unwrap().ttl_seconds, 259_200);
        assert!(EphemeralSpec::new(Some(259_201)).is_err());
        let mut spec = BoxCreateSpec {
            name: None,
            labels: vec![],
            runtime: Runtime::RustAlpine,
            size: BoxSize::Small,
            browser: false,
            keep_alive: false,
            ephemeral: None,
            attach_headers_requested: true,
            network_policy: NetworkPolicy::DenyAll,
        };
        assert_eq!(spec.validate().unwrap_err().code, "feature_not_supported");
        spec.attach_headers_requested = false;
        spec.network_policy = NetworkPolicy::Custom;
        assert_eq!(spec.validate().unwrap_err().code, "feature_not_supported");
    }

    #[test]
    fn skill_identity_is_canonical_and_pinned_to_source_content() {
        assert_eq!(
            validate_skill_id("upstash/context7/context7-cli").unwrap(),
            "context7-cli"
        );
        for invalid in [
            "owner/repo",
            "/owner/repo/skill",
            "owner/repo/../skill",
            "owner/repo/-skill",
            "owner//skill",
        ] {
            assert!(validate_skill_id(invalid).is_err(), "accepted {invalid}");
        }
        let context = AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        };
        let skill = EnabledSkill::new(
            context,
            BoxId::new(),
            "upstash/context7/context7-cli".into(),
            "a".repeat(40),
            "b".repeat(64),
            UtcEpochMillis::from_millis(7),
        )
        .unwrap();
        assert_eq!(skill.name, "context7-cli");
        assert!(
            EnabledSkill::new(
                context,
                BoxId::new(),
                "upstash/context7/context7-cli".into(),
                "short".into(),
                "b".repeat(64),
                UtcEpochMillis::from_millis(7),
            )
            .is_err()
        );
    }
    #[test]
    fn ownership_and_secret_references_do_not_leak() {
        let owner = AccountId::new();
        let context = AccountContext {
            account_id: owner,
            tenant_id: TenantId::new(),
        };
        let spec = BoxCreateSpec {
            name: None,
            labels: vec![],
            runtime: Runtime::Node,
            size: BoxSize::Small,
            browser: false,
            keep_alive: false,
            ephemeral: None,
            attach_headers_requested: false,
            network_policy: NetworkPolicy::DenyAll,
        };
        let value = Box::new(context, spec, UtcEpochMillis::from_millis(1)).unwrap();
        assert!(value.runtime_bundle.is_none());
        assert!(value.assert_owned_by(context).is_ok());
        assert_eq!(
            value
                .assert_owned_by(AccountContext {
                    account_id: AccountId::new(),
                    tenant_id: context.tenant_id
                })
                .unwrap_err()
                .code,
            "tenant_forbidden"
        );
        assert_eq!(
            value
                .assert_owned_by(AccountContext {
                    account_id: owner,
                    tenant_id: TenantId::new()
                })
                .unwrap_err()
                .code,
            "tenant_forbidden"
        );
        let secret = SecretRef::new("actual-secret-value").unwrap();
        assert!(!format!("{secret:?}").contains("actual-secret-value"));
        assert!(!format!("{secret}").contains("actual-secret-value"));
    }

    #[test]
    fn runtime_bundle_binding_is_once_only_and_immutable() {
        let context = AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        };
        let mut value = Box::new(
            context,
            BoxCreateSpec {
                name: None,
                labels: vec![],
                runtime: Runtime::Node,
                size: BoxSize::Small,
                browser: false,
                keep_alive: false,
                ephemeral: None,
                attach_headers_requested: false,
                network_policy: NetworkPolicy::DenyAll,
            },
            UtcEpochMillis::from_millis(1),
        )
        .unwrap();
        let binding = RuntimeBundleBinding::new("0".repeat(64), "22.0.0", "aarch64").unwrap();
        value
            .bind_runtime(binding.clone(), UtcEpochMillis::from_millis(2))
            .unwrap();
        assert_eq!(value.runtime_bundle.as_ref(), Some(&binding));
        value
            .bind_runtime(binding, UtcEpochMillis::from_millis(3))
            .unwrap();
        assert!(
            value
                .bind_runtime(
                    RuntimeBundleBinding::new("1".repeat(64), "23.0.0", "aarch64").unwrap(),
                    UtcEpochMillis::from_millis(4),
                )
                .is_err()
        );
    }

    #[test]
    fn run_state_is_tenant_scoped_and_terminal_once() {
        let context = AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        };
        let mut run = Run::new_agent(
            context,
            BoxId::new(),
            "inspect the workspace",
            Some("openai/gpt-5".into()),
            UtcEpochMillis::from_millis(1_000),
        )
        .unwrap();
        assert!(run.assert_owned_by(context).is_ok());
        assert!(
            run.assert_owned_by(AccountContext {
                account_id: context.account_id,
                tenant_id: TenantId::new(),
            })
            .is_err()
        );
        run.settle(
            RunStatus::Completed,
            Some("done".into()),
            None,
            UtcEpochMillis::from_millis(1_250),
        )
        .unwrap();
        assert_eq!(run.duration_millis, 250);
        assert_eq!(run.completed_at, Some(UtcEpochMillis::from_millis(1_250)));
        run.settle(
            RunStatus::Completed,
            Some("done".into()),
            None,
            UtcEpochMillis::from_millis(1_300),
        )
        .unwrap();
        assert_eq!(
            run.settle(
                RunStatus::Failed,
                None,
                Some("late error".into()),
                UtcEpochMillis::from_millis(1_300),
            )
            .unwrap_err()
            .code,
            "state_conflict"
        );
    }
    struct MockRepository;
    impl BoxRepository for MockRepository {
        async fn create(&self, _: AccountContext, _: &Box) -> Result<()> {
            Ok(())
        }
        async fn find(&self, _: AccountContext, _: BoxId) -> Result<Option<Box>> {
            Ok(None)
        }
        async fn list(&self, _: AccountContext) -> Result<Vec<Box>> {
            Ok(vec![])
        }
        async fn list_all(&self) -> Result<Vec<Box>> {
            Ok(vec![])
        }
        async fn save(&self, _: AccountContext, _: &Box, _: u64) -> Result<()> {
            Ok(())
        }
        async fn delete_idempotently(
            &self,
            _: AccountContext,
            _: BoxId,
            _: &IdempotencyKey,
        ) -> Result<OperationId> {
            Ok(OperationId::new())
        }
        async fn acquire_lease(
            &self,
            _: AccountContext,
            _: BoxId,
            _: &BoxLeaseToken,
            _: Duration,
        ) -> Result<bool> {
            Ok(true)
        }
        async fn renew_lease(
            &self,
            _: AccountContext,
            _: BoxId,
            _: &BoxLeaseToken,
            _: Duration,
        ) -> Result<bool> {
            Ok(true)
        }
        async fn release_lease(
            &self,
            _: AccountContext,
            _: BoxId,
            _: &BoxLeaseToken,
        ) -> Result<bool> {
            Ok(true)
        }
    }
    #[test]
    fn ports_are_mock_implementable() {
        fn needs_port<T: BoxRepository>(_: &T) {}
        needs_port(&MockRepository);
    }
}
