//! SeaORM persistence adapters. Every tenant-owned query is explicitly scoped
//! by both `account_id` and `tenant_id`; missing rows are intentionally not
//! distinguishable from rows owned by another tenant.

use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    ops::Deref,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use box_core::{
    AccountContext, AuthScope, AuthorizedContext, Box as DomainBox, BoxCreateSpec, BoxId,
    BoxLeaseToken, BoxRepository, DomainError, IdempotencyKey, Label, Operation, OperationId,
    OperationKind, OperationRepository, OperationStatus, Run, RunEvent, RunEventType, RunId,
    RunRepository, RunStatus, TenantId, UtcEpochMillis,
};
use box_scheduler::{
    ScheduleClaim, ScheduleId, ScheduleLeaseToken, SchedulePayload, ScheduleRunOutcome,
    ScheduleRunStatus, ScheduleStatus, ScheduledTask,
};
use hmac::{Hmac, Mac};
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveValue::Set, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect, SqlErr, TransactionTrait, entity::prelude::*,
};
use sea_orm_migration::MigratorTrait;
use sha2::Sha256;

mod auth;
pub use auth::*;
mod secrets;
pub use secrets::*;
mod account_secrets;
pub use account_secrets::*;
mod snapshots;
pub use snapshots::*;
mod previews;
pub use previews::*;
mod skills;
pub use skills::*;
mod audit;
pub use audit::*;
mod recordings;
pub use recordings::*;

fn internal(error: impl std::fmt::Display) -> DomainError {
    DomainError {
        kind: box_core::DomainErrorKind::Internal,
        code: "database_error",
        message: error.to_string(),
    }
}
fn text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("domain enums serialize")
}
fn parse<T: serde::de::DeserializeOwned>(value: &str) -> box_core::Result<T> {
    serde_json::from_str(value).map_err(internal)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn scope(context: AccountContext) -> (String, String) {
    (
        context.account_id.to_string(),
        context.tenant_id.to_string(),
    )
}
fn db_version(version: u64) -> box_core::Result<i64> {
    i64::try_from(version).map_err(|_| DomainError::version_conflict())
}

struct DatabaseHandleInner {
    connection: DatabaseConnection,
    sqlite_lock: Option<File>,
}
impl Drop for DatabaseHandleInner {
    fn drop(&mut self) {
        if let Some(file) = &self.sqlite_lock {
            let _ = fs2::FileExt::unlock(file);
        }
    }
}

/// A cloneable database handle. For file-backed SQLite, every clone retains an
/// exclusive OS file lock so only one control-plane process can be active.
#[derive(Clone)]
pub struct DatabaseHandle(Arc<DatabaseHandleInner>);
impl DatabaseHandle {
    pub fn connection(&self) -> &DatabaseConnection {
        &self.0.connection
    }
}
impl Deref for DatabaseHandle {
    type Target = DatabaseConnection;
    fn deref(&self) -> &Self::Target {
        self.connection()
    }
}

fn sqlite_path(url: &str) -> Option<PathBuf> {
    if !url.starts_with("sqlite:") || url.starts_with("sqlite::memory:") {
        return None;
    }
    let without_query = url.split('?').next().unwrap_or(url);
    let path = without_query
        .strip_prefix("sqlite://")
        .or_else(|| without_query.strip_prefix("sqlite:"))?;
    if path.is_empty() {
        return None;
    }
    let path = PathBuf::from(path);
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let parent = absolute.parent()?.canonicalize().ok()?;
    Some(parent.join(absolute.file_name()?))
}
fn acquire_sqlite_lock(url: &str) -> box_core::Result<Option<File>> {
    let Some(path) = sqlite_path(url) else {
        return Ok(None);
    };
    if path.exists()
        && std::fs::symlink_metadata(&path)
            .map_err(internal)?
            .file_type()
            .is_symlink()
    {
        return Err(DomainError::validation(
            "SQLite database path must not be a symbolic link",
        ));
    }
    let database_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(internal)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if database_file.metadata().map_err(internal)?.nlink() != 1 {
            return Err(DomainError::validation(
                "SQLite database file must not have hard-link aliases",
            ));
        }
    }
    drop(database_file);
    let canonical = path.canonicalize().map_err(internal)?;
    let lock_path = PathBuf::from(format!("{}.boxd.lock", canonical.display()));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(internal)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| DomainError {
        kind: box_core::DomainErrorKind::Unavailable,
        code: "database_instance_locked",
        message: "another boxd control-plane instance owns this SQLite database".into(),
    })?;
    Ok(Some(file))
}

/// Creates a pool for any SeaORM-supported URL. SQLite applies WAL, foreign
/// keys, and busy timeout to every newly-created pool connection.
pub async fn connect(url: &str, max_connections: u32) -> box_core::Result<DatabaseHandle> {
    let sqlite_lock = acquire_sqlite_lock(url)?;
    let mut options = ConnectOptions::new(url);
    options.max_connections(max_connections).sqlx_logging(false);
    if url.starts_with("sqlite:") {
        options.after_connect(|connection| {
            Box::pin(async move {
                connection
                    .execute_unprepared(
                        "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
                    )
                    .await?;
                Ok(())
            })
        });
    }
    let db = Database::connect(options).await.map_err(internal)?;
    Ok(DatabaseHandle(Arc::new(DatabaseHandleInner {
        connection: db,
        sqlite_lock,
    })))
}
pub async fn migrate(db: &DatabaseHandle) -> box_core::Result<()> {
    box_migration::Migrator::up(db.connection(), None)
        .await
        .map_err(internal)
}

pub async fn migrations_current(db: &DatabaseHandle) -> box_core::Result<bool> {
    box_migration::Migrator::get_pending_migrations_read_only(db.connection())
        .await
        .map(|pending| pending.is_empty())
        .map_err(internal)
}

mod boxes {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "boxes")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub node_id: Option<String>,
        pub name: Option<String>,
        pub runtime: String,
        pub runtime_bundle_sha256: Option<String>,
        pub runtime_version: Option<String>,
        pub runtime_arch: Option<String>,
        pub source_snapshot_id: Option<String>,
        pub size: String,
        pub status: String,
        pub ephemeral: bool,
        pub expires_at: Option<i64>,
        pub keep_alive: bool,
        pub browser: Option<bool>,
        pub disk_bytes: Option<i64>,
        pub model: Option<String>,
        pub agent_json: Option<String>,
        pub counters_json: Option<String>,
        pub network_policy: String,
        pub lease_token: Option<String>,
        pub lease_expires_at: Option<i64>,
        pub version: i64,
        pub created_at: i64,
        pub updated_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod accounts {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "accounts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub status: String,
        pub created_at: i64,
        pub updated_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod box_labels {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "box_labels")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: String,
        pub label: String,
        pub position: i32,
        pub created_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod runs {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "runs")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: String,
        pub schedule_id: Option<String>,
        pub r#type: String,
        pub status: String,
        pub prompt: Option<String>,
        pub model: Option<String>,
        pub output: Option<String>,
        pub error: Option<String>,
        pub token_count: Option<i64>,
        pub input_tokens: i64,
        pub output_tokens: i64,
        pub cached_input_tokens: i64,
        pub cpu_ns: Option<i64>,
        pub memory_bytes: Option<i64>,
        pub cost: Option<String>,
        pub cost_microusd: i64,
        pub compute_cost_microusd: i64,
        pub duration_ms: i64,
        pub session_id: Option<String>,
        pub created_at: i64,
        pub updated_at: i64,
        pub completed_at: Option<i64>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod run_events {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "run_events")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub run_id: String,
        pub sequence: i64,
        pub event_type: String,
        pub payload_json: String,
        pub created_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod schedules {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "schedules")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: String,
        pub cron: String,
        pub timezone: String,
        pub payload_json: String,
        pub paused: bool,
        pub next_run_at: i64,
        pub lease_token: Option<String>,
        pub lease_expires_at: Option<i64>,
        pub created_at: i64,
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod operations {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "operations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: Option<String>,
        pub kind: String,
        pub status: String,
        pub idempotency_key: String,
        pub retry_count: i64,
        pub error: Option<String>,
        pub created_at: i64,
        pub updated_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod runtime_images {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "runtime_images")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub runtime: String,
        pub arch: String,
        pub version: String,
        pub manifest_json: String,
        pub path: String,
        pub checksum: String,
        pub status: String,
        pub created_at: i64,
        pub updated_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod api_keys {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "api_keys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub prefix: String,
        pub key_hmac: String,
        pub scopes_json: String,
        pub last_used_at: Option<i64>,
        pub expires_at: Option<i64>,
        pub created_at: i64,
        pub updated_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone)]
pub struct SeaRepository {
    db: DatabaseHandle,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeImageRecord {
    pub runtime: String,
    pub arch: String,
    pub version: String,
    pub manifest_json: String,
    pub path: String,
    pub checksum: String,
    pub status: String,
}

#[derive(Clone)]
pub struct RunStore {
    db: DatabaseHandle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBoxAgentConfig {
    pub model: String,
    pub agent_json: String,
}

impl RunStore {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }

    pub async fn put_box_agent_config(
        &self,
        context: AccountContext,
        box_id: BoxId,
        model: &str,
        agent_json: &str,
    ) -> box_core::Result<()> {
        if model.is_empty() || model.len() > 255 || model.as_bytes().contains(&0) {
            return Err(DomainError::validation("invalid agent model"));
        }
        let agent_json = Self::canonical_payload(agent_json)?;
        let (account, tenant) = scope(context);
        let updated = boxes::Entity::update_many()
            .col_expr(boxes::Column::Model, Expr::value(Some(model.to_owned())))
            .col_expr(boxes::Column::AgentJson, Expr::value(Some(agent_json)))
            .filter(boxes::Column::Id.eq(box_id.to_string()))
            .filter(boxes::Column::AccountId.eq(account))
            .filter(boxes::Column::TenantId.eq(tenant))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        if updated.rows_affected == 1 {
            Ok(())
        } else {
            Err(DomainError {
                kind: box_core::DomainErrorKind::NotFound,
                code: "not_found",
                message: "box not found".into(),
            })
        }
    }

    pub async fn box_agent_config(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Option<StoredBoxAgentConfig>> {
        let (account, tenant) = scope(context);
        let model = boxes::Entity::find_by_id(box_id.to_string())
            .filter(boxes::Column::AccountId.eq(account))
            .filter(boxes::Column::TenantId.eq(tenant))
            .one(self.db.connection())
            .await
            .map_err(internal)?;
        match model.map(|value| (value.model, value.agent_json)) {
            None | Some((None, None)) => Ok(None),
            Some((Some(model), Some(agent_json))) => {
                Self::canonical_payload(&agent_json)?;
                Ok(Some(StoredBoxAgentConfig { model, agent_json }))
            }
            Some(_) => Err(DomainError::validation(
                "inconsistent persisted agent configuration",
            )),
        }
    }

    fn db_u64(value: u64, field: &str) -> box_core::Result<i64> {
        i64::try_from(value)
            .map_err(|_| DomainError::validation(format!("{field} exceeds database range")))
    }

    fn domain_u64(value: i64, field: &str) -> box_core::Result<u64> {
        u64::try_from(value)
            .map_err(|_| DomainError::validation(format!("invalid persisted {field}")))
    }

    fn model(context: AccountContext, run: &Run) -> box_core::Result<runs::ActiveModel> {
        run.assert_owned_by(context)?;
        Ok(runs::ActiveModel {
            id: Set(run.id.to_string()),
            account_id: Set(context.account_id.to_string()),
            tenant_id: Set(context.tenant_id.to_string()),
            box_id: Set(run.box_id.to_string()),
            schedule_id: Set(None),
            r#type: Set(text(&run.kind)),
            status: Set(text(&run.status)),
            prompt: Set(run.prompt.clone()),
            model: Set(run.model.clone()),
            output: Set(run.output.clone()),
            error: Set(run.error_message.clone()),
            token_count: Set(None),
            input_tokens: Set(Self::db_u64(run.input_tokens, "input_tokens")?),
            output_tokens: Set(Self::db_u64(run.output_tokens, "output_tokens")?),
            cached_input_tokens: Set(Self::db_u64(
                run.cached_input_tokens,
                "cached_input_tokens",
            )?),
            cpu_ns: Set(run
                .cpu_ns
                .map(|value| Self::db_u64(value, "cpu_ns"))
                .transpose()?),
            memory_bytes: Set(run
                .memory_peak_bytes
                .map(|value| Self::db_u64(value, "memory_peak_bytes"))
                .transpose()?),
            cost: Set(None),
            cost_microusd: Set(Self::db_u64(run.cost_microusd, "cost_microusd")?),
            compute_cost_microusd: Set(Self::db_u64(
                run.compute_cost_microusd,
                "compute_cost_microusd",
            )?),
            duration_ms: Set(Self::db_u64(run.duration_millis, "duration_ms")?),
            session_id: Set(run.session_id.clone()),
            created_at: Set(run.created_at.as_millis()),
            updated_at: Set(run.completed_at.unwrap_or(run.created_at).as_millis()),
            completed_at: Set(run.completed_at.map(UtcEpochMillis::as_millis)),
        })
    }

    fn to_run(model: runs::Model) -> box_core::Result<Run> {
        Ok(Run {
            id: RunId::parse(&model.id)?,
            account_id: box_core::AccountId::parse(&model.account_id)?,
            tenant_id: TenantId::parse(&model.tenant_id)?,
            box_id: BoxId::parse(&model.box_id)?,
            kind: parse(&model.r#type)?,
            status: parse(&model.status)?,
            prompt: model.prompt,
            model: model.model,
            output: model.output,
            input_tokens: Self::domain_u64(model.input_tokens, "input_tokens")?,
            output_tokens: Self::domain_u64(model.output_tokens, "output_tokens")?,
            cached_input_tokens: Self::domain_u64(
                model.cached_input_tokens,
                "cached_input_tokens",
            )?,
            cost_microusd: Self::domain_u64(model.cost_microusd, "cost_microusd")?,
            duration_millis: Self::domain_u64(model.duration_ms, "duration_ms")?,
            cpu_ns: model
                .cpu_ns
                .map(|value| Self::domain_u64(value, "cpu_ns"))
                .transpose()?,
            compute_cost_microusd: Self::domain_u64(
                model.compute_cost_microusd,
                "compute_cost_microusd",
            )?,
            memory_peak_bytes: model
                .memory_bytes
                .map(|value| Self::domain_u64(value, "memory_peak_bytes"))
                .transpose()?,
            error_message: model.error,
            session_id: model.session_id,
            created_at: UtcEpochMillis::from_millis(model.created_at),
            completed_at: model.completed_at.map(UtcEpochMillis::from_millis),
        })
    }

    fn canonical_payload(payload: &str) -> box_core::Result<String> {
        let value: serde_json::Value = serde_json::from_str(payload)
            .map_err(|_| DomainError::validation("run event payload must be JSON"))?;
        serde_json::to_string(&value).map_err(internal)
    }
}
impl SeaRepository {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }

    pub async fn record_runtime_image(
        &self,
        runtime: box_core::Runtime,
        binding: &box_core::RuntimeBundleBinding,
        manifest_json: &str,
        canonical_path: &str,
        status: &str,
    ) -> box_core::Result<()> {
        if !matches!(status, "ready" | "failed") {
            return Err(DomainError::validation("invalid runtime image status"));
        }
        let timestamp = now();
        let runtime_name = text(&runtime);
        serde_json::from_str::<serde_json::Value>(manifest_json).map_err(internal)?;
        if canonical_path.is_empty() {
            return Err(DomainError::validation("runtime image path is required"));
        }
        let existing = runtime_images::Entity::find()
            .filter(runtime_images::Column::Checksum.eq(&binding.sha256))
            .one(self.db.connection())
            .await
            .map_err(internal)?;
        let model = runtime_images::ActiveModel {
            id: Set(existing.as_ref().map_or_else(
                || uuid::Uuid::now_v7().to_string(),
                |value| value.id.clone(),
            )),
            runtime: Set(runtime_name),
            arch: Set(binding.arch.clone()),
            version: Set(binding.runtime_version.clone()),
            manifest_json: Set(manifest_json.to_owned()),
            path: Set(canonical_path.to_owned()),
            checksum: Set(binding.sha256.clone()),
            status: Set(status.to_owned()),
            created_at: Set(existing
                .as_ref()
                .map_or(timestamp, |value| value.created_at)),
            updated_at: Set(timestamp),
        };
        if existing.is_some() {
            model.update(self.db.connection()).await.map_err(internal)?;
        } else {
            model.insert(self.db.connection()).await.map_err(internal)?;
        }
        Ok(())
    }
    pub async fn runtime_image(
        &self,
        checksum: &str,
    ) -> box_core::Result<Option<RuntimeImageRecord>> {
        runtime_images::Entity::find()
            .filter(runtime_images::Column::Checksum.eq(checksum))
            .one(self.db.connection())
            .await
            .map_err(internal)
            .map(|value| {
                value.map(|value| RuntimeImageRecord {
                    runtime: value.runtime,
                    arch: value.arch,
                    version: value.version,
                    manifest_json: value.manifest_json,
                    path: value.path,
                    checksum: value.checksum,
                    status: value.status,
                })
            })
    }
    fn box_model(
        context: AccountContext,
        value: &DomainBox,
    ) -> box_core::Result<boxes::ActiveModel> {
        let (account_id, tenant_id) = scope(context);
        Ok(boxes::ActiveModel {
            id: Set(value.id.to_string()),
            account_id: Set(account_id),
            tenant_id: Set(tenant_id),
            node_id: Set(value.node_id.map(|v| v.to_string())),
            name: Set(value.spec.name.clone()),
            runtime: Set(text(&value.spec.runtime)),
            runtime_bundle_sha256: Set(value
                .runtime_bundle
                .as_ref()
                .map(|binding| binding.sha256.clone())),
            runtime_version: Set(value
                .runtime_bundle
                .as_ref()
                .map(|binding| binding.runtime_version.clone())),
            runtime_arch: Set(value
                .runtime_bundle
                .as_ref()
                .map(|binding| binding.arch.clone())),
            source_snapshot_id: Set(value.source_snapshot_id.map(|id| id.to_string())),
            size: Set(text(&value.spec.size)),
            status: Set(text(&value.status)),
            ephemeral: Set(value.spec.ephemeral.is_some()),
            expires_at: Set(value.spec.ephemeral.map(|spec| {
                value
                    .created_at
                    .as_millis()
                    .saturating_add(i64::from(spec.ttl_seconds) * 1_000)
            })),
            keep_alive: Set(value.spec.keep_alive),
            browser: Set(Some(value.spec.browser)),
            disk_bytes: Set(None),
            model: Set(None),
            agent_json: Set(None),
            counters_json: Set(None),
            network_policy: Set(text(&value.spec.network_policy)),
            lease_token: Set(None),
            lease_expires_at: Set(None),
            version: Set(db_version(value.version)?),
            created_at: Set(value.created_at.as_millis()),
            updated_at: Set(value.updated_at.as_millis()),
        })
    }
    fn to_box(model: boxes::Model, labels: Vec<Label>) -> box_core::Result<DomainBox> {
        let ephemeral = match (model.ephemeral, model.expires_at) {
            (false, None) => None,
            (true, Some(expires_at)) => Some({
                let ttl_millis = expires_at.saturating_sub(model.created_at);
                let ttl_seconds = u32::try_from(ttl_millis.div_euclid(1_000))
                    .map_err(|_| DomainError::validation("invalid persisted ephemeral expiry"))?;
                box_core::EphemeralSpec::new(Some(ttl_seconds))
            }?),
            _ => {
                return Err(DomainError::validation(
                    "inconsistent persisted ephemeral fields",
                ));
            }
        };
        Ok(DomainBox {
            id: BoxId::parse(&model.id)?,
            account_id: box_core::AccountId::parse(&model.account_id)?,
            tenant_id: TenantId::parse(&model.tenant_id)?,
            node_id: model
                .node_id
                .as_deref()
                .map(box_core::NodeId::parse)
                .transpose()?,
            status: parse(&model.status)?,
            version: u64::try_from(model.version)
                .map_err(|_| DomainError::validation("invalid persisted box version"))?,
            spec: BoxCreateSpec {
                name: model.name,
                labels,
                runtime: parse(&model.runtime)?,
                size: parse(&model.size)?,
                browser: model.browser.unwrap_or(false),
                keep_alive: model.keep_alive,
                ephemeral,
                attach_headers_requested: false,
                network_policy: parse(&model.network_policy)?,
            },
            runtime_bundle: match (
                model.runtime_bundle_sha256,
                model.runtime_version,
                model.runtime_arch,
            ) {
                (None, None, None) => None,
                (Some(sha256), Some(version), Some(arch)) => {
                    Some(box_core::RuntimeBundleBinding::new(sha256, version, arch)?)
                }
                _ => {
                    return Err(DomainError::validation(
                        "persisted runtime bundle binding is incomplete",
                    ));
                }
            },
            source_snapshot_id: model
                .source_snapshot_id
                .as_deref()
                .map(box_core::SnapshotId::parse)
                .transpose()?,
            created_at: UtcEpochMillis::from_millis(model.created_at),
            updated_at: UtcEpochMillis::from_millis(model.updated_at),
        })
    }
    async fn labels_for<C: ConnectionTrait>(
        db: &C,
        context: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Vec<Label>> {
        let (account, tenant) = scope(context);
        box_labels::Entity::find()
            .filter(box_labels::Column::AccountId.eq(account))
            .filter(box_labels::Column::TenantId.eq(tenant))
            .filter(box_labels::Column::BoxId.eq(box_id.to_string()))
            .order_by_asc(box_labels::Column::Position)
            .all(db)
            .await
            .map_err(internal)?
            .into_iter()
            .map(|model| Label::new(model.label))
            .collect()
    }
    async fn insert_labels<C: ConnectionTrait>(
        db: &C,
        context: AccountContext,
        value: &DomainBox,
    ) -> box_core::Result<()> {
        for (position, label) in value.spec.labels.iter().enumerate() {
            box_labels::ActiveModel {
                id: Set(uuid::Uuid::now_v7().to_string()),
                account_id: Set(context.account_id.to_string()),
                tenant_id: Set(context.tenant_id.to_string()),
                box_id: Set(value.id.to_string()),
                label: Set(label.as_str().to_owned()),
                position: Set(i32::try_from(position).map_err(internal)?),
                created_at: Set(value.created_at.as_millis()),
            }
            .insert(db)
            .await
            .map_err(internal)?;
        }
        Ok(())
    }
    fn operation_model(context: AccountContext, op: &Operation) -> operations::ActiveModel {
        let (account_id, tenant_id) = scope(context);
        operations::ActiveModel {
            id: Set(op.id.to_string()),
            account_id: Set(account_id),
            tenant_id: Set(tenant_id),
            box_id: Set(op.box_id.map(|v| v.to_string())),
            kind: Set(text(&op.kind)),
            status: Set(text(&op.status)),
            idempotency_key: Set(op.idempotency_key.as_str().to_owned()),
            retry_count: Set(i64::from(op.retry_count)),
            error: Set(op.error.clone()),
            created_at: Set(now()),
            updated_at: Set(now()),
        }
    }
    fn to_operation(m: operations::Model) -> box_core::Result<Operation> {
        Ok(Operation {
            id: OperationId::parse(&m.id)?,
            account_id: box_core::AccountId::parse(&m.account_id)?,
            tenant_id: TenantId::parse(&m.tenant_id)?,
            box_id: m.box_id.as_deref().map(BoxId::parse).transpose()?,
            kind: parse(&m.kind)?,
            status: parse(&m.status)?,
            idempotency_key: IdempotencyKey::new(m.idempotency_key)?,
            retry_count: u32::try_from(m.retry_count)
                .map_err(|_| DomainError::validation("invalid operation retry count"))?,
            error: m.error,
        })
    }
}

impl BoxRepository for SeaRepository {
    async fn create(&self, context: AccountContext, value: &DomainBox) -> box_core::Result<()> {
        if value.account_id != context.account_id || value.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        }
        value.spec.validate()?;
        let txn = self.db.begin().await.map_err(internal)?;
        Self::box_model(context, value)?
            .insert(&txn)
            .await
            .map_err(internal)?;
        Self::insert_labels(&txn, context, value).await?;
        txn.commit().await.map_err(internal)?;
        Ok(())
    }
    async fn find(
        &self,
        context: AccountContext,
        id: BoxId,
    ) -> box_core::Result<Option<DomainBox>> {
        let (a, t) = scope(context);
        let model = boxes::Entity::find_by_id(id.to_string())
            .filter(boxes::Column::AccountId.eq(a))
            .filter(boxes::Column::TenantId.eq(t))
            .one(self.db.connection())
            .await
            .map_err(internal)?;
        let Some(model) = model else { return Ok(None) };
        let labels = Self::labels_for(self.db.connection(), context, id).await?;
        Self::to_box(model, labels).map(Some)
    }
    async fn list(&self, context: AccountContext) -> box_core::Result<Vec<DomainBox>> {
        let (a, t) = scope(context);
        let models = boxes::Entity::find()
            .filter(boxes::Column::AccountId.eq(a))
            .filter(boxes::Column::TenantId.eq(t))
            .order_by_asc(boxes::Column::CreatedAt)
            .all(self.db.connection())
            .await
            .map_err(internal)?;
        let mut values = Vec::with_capacity(models.len());
        for model in models {
            let id = BoxId::parse(&model.id)?;
            let labels = Self::labels_for(self.db.connection(), context, id).await?;
            values.push(Self::to_box(model, labels)?);
        }
        Ok(values)
    }
    async fn list_all(&self) -> box_core::Result<Vec<DomainBox>> {
        let models = boxes::Entity::find()
            .order_by_asc(boxes::Column::CreatedAt)
            .all(self.db.connection())
            .await
            .map_err(internal)?;
        let mut values = Vec::with_capacity(models.len());
        for model in models {
            let context = AccountContext {
                account_id: box_core::AccountId::parse(&model.account_id)?,
                tenant_id: TenantId::parse(&model.tenant_id)?,
            };
            let id = BoxId::parse(&model.id)?;
            let labels = Self::labels_for(self.db.connection(), context, id).await?;
            values.push(Self::to_box(model, labels)?);
        }
        Ok(values)
    }
    async fn save(
        &self,
        context: AccountContext,
        value: &DomainBox,
        expected_version: u64,
    ) -> box_core::Result<()> {
        if value.account_id != context.account_id || value.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        }
        let (a, t) = scope(context);
        value.spec.validate()?;
        let version = db_version(value.version)?;
        let expected_version = db_version(expected_version)?;
        let txn = self.db.begin().await.map_err(internal)?;
        let expires_at = value.spec.ephemeral.map(|spec| {
            value
                .created_at
                .as_millis()
                .saturating_add(i64::from(spec.ttl_seconds) * 1_000)
        });
        let result = boxes::Entity::update_many()
            .col_expr(
                boxes::Column::NodeId,
                sea_orm::sea_query::Expr::value(value.node_id.map(|node| node.to_string())),
            )
            .col_expr(
                boxes::Column::Name,
                sea_orm::sea_query::Expr::value(value.spec.name.clone()),
            )
            .col_expr(
                boxes::Column::Runtime,
                sea_orm::sea_query::Expr::value(text(&value.spec.runtime)),
            )
            .col_expr(
                boxes::Column::RuntimeBundleSha256,
                sea_orm::sea_query::Expr::value(
                    value
                        .runtime_bundle
                        .as_ref()
                        .map(|binding| binding.sha256.clone()),
                ),
            )
            .col_expr(
                boxes::Column::RuntimeVersion,
                sea_orm::sea_query::Expr::value(
                    value
                        .runtime_bundle
                        .as_ref()
                        .map(|binding| binding.runtime_version.clone()),
                ),
            )
            .col_expr(
                boxes::Column::RuntimeArch,
                sea_orm::sea_query::Expr::value(
                    value
                        .runtime_bundle
                        .as_ref()
                        .map(|binding| binding.arch.clone()),
                ),
            )
            .col_expr(
                boxes::Column::SourceSnapshotId,
                sea_orm::sea_query::Expr::value(value.source_snapshot_id.map(|id| id.to_string())),
            )
            .col_expr(
                boxes::Column::Size,
                sea_orm::sea_query::Expr::value(text(&value.spec.size)),
            )
            .col_expr(
                boxes::Column::Status,
                sea_orm::sea_query::Expr::value(text(&value.status)),
            )
            .col_expr(
                boxes::Column::Ephemeral,
                sea_orm::sea_query::Expr::value(value.spec.ephemeral.is_some()),
            )
            .col_expr(
                boxes::Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(expires_at),
            )
            .col_expr(
                boxes::Column::KeepAlive,
                sea_orm::sea_query::Expr::value(value.spec.keep_alive),
            )
            .col_expr(
                boxes::Column::NetworkPolicy,
                sea_orm::sea_query::Expr::value(text(&value.spec.network_policy)),
            )
            .col_expr(
                boxes::Column::Version,
                sea_orm::sea_query::Expr::value(version),
            )
            .col_expr(
                boxes::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(value.updated_at.as_millis()),
            )
            .filter(boxes::Column::Id.eq(value.id.to_string()))
            .filter(boxes::Column::AccountId.eq(a))
            .filter(boxes::Column::TenantId.eq(t))
            .filter(boxes::Column::Version.eq(expected_version))
            .exec(&txn)
            .await
            .map_err(internal)?;
        if result.rows_affected == 1 {
            box_labels::Entity::delete_many()
                .filter(box_labels::Column::AccountId.eq(context.account_id.to_string()))
                .filter(box_labels::Column::TenantId.eq(context.tenant_id.to_string()))
                .filter(box_labels::Column::BoxId.eq(value.id.to_string()))
                .exec(&txn)
                .await
                .map_err(internal)?;
            Self::insert_labels(&txn, context, value).await?;
            txn.commit().await.map_err(internal)?;
            Ok(())
        } else {
            txn.rollback().await.map_err(internal)?;
            Err(DomainError::version_conflict())
        }
    }
    async fn delete_idempotently(
        &self,
        context: AccountContext,
        id: BoxId,
        key: &IdempotencyKey,
    ) -> box_core::Result<OperationId> {
        if let Some(op) = self
            .find_by_idempotency_key(context, OperationKind::DeleteBox, key)
            .await?
        {
            return Ok(op.id);
        }
        if self.find(context, id).await?.is_none() {
            return Err(DomainError::ownership());
        }
        let op = Operation {
            id: OperationId::new(),
            account_id: context.account_id,
            tenant_id: context.tenant_id,
            box_id: Some(id),
            kind: OperationKind::DeleteBox,
            status: OperationStatus::Pending,
            idempotency_key: key.clone(),
            retry_count: 0,
            error: None,
        };
        match OperationRepository::create(self, context, &op).await {
            Ok(()) => Ok(op.id),
            Err(error) if error.code == "database_unique_violation" => self
                .find_by_idempotency_key(context, OperationKind::DeleteBox, key)
                .await?
                .map(|v| v.id)
                .ok_or_else(DomainError::version_conflict),
            Err(error) => Err(error),
        }
    }
    async fn acquire_lease(
        &self,
        context: AccountContext,
        id: BoxId,
        token: &BoxLeaseToken,
        ttl: Duration,
    ) -> box_core::Result<bool> {
        if ttl.is_zero() {
            return Err(DomainError::validation(
                "lease TTL must be greater than zero",
            ));
        }
        let (a, t) = scope(context);
        let expiry = now().saturating_add(ttl.as_millis() as i64);
        let result = boxes::Entity::update_many()
            .col_expr(
                boxes::Column::LeaseToken,
                sea_orm::sea_query::Expr::value(Some(token.expose_for_storage().to_owned())),
            )
            .col_expr(
                boxes::Column::LeaseExpiresAt,
                sea_orm::sea_query::Expr::value(Some(expiry)),
            )
            .filter(boxes::Column::Id.eq(id.to_string()))
            .filter(boxes::Column::AccountId.eq(a))
            .filter(boxes::Column::TenantId.eq(t))
            .filter(
                sea_orm::Condition::any()
                    .add(sea_orm::sea_query::Expr::col(boxes::Column::LeaseExpiresAt).is_null())
                    .add(boxes::Column::LeaseExpiresAt.lte(now()))
                    .add(boxes::Column::LeaseToken.eq(Some(token.expose_for_storage().to_owned()))),
            )
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        Ok(result.rows_affected == 1)
    }
    async fn renew_lease(
        &self,
        context: AccountContext,
        id: BoxId,
        token: &BoxLeaseToken,
        ttl: Duration,
    ) -> box_core::Result<bool> {
        if ttl.is_zero() {
            return Err(DomainError::validation(
                "lease TTL must be greater than zero",
            ));
        }
        let (a, t) = scope(context);
        let expiry = now().saturating_add(ttl.as_millis() as i64);
        let result = boxes::Entity::update_many()
            .col_expr(
                boxes::Column::LeaseExpiresAt,
                sea_orm::sea_query::Expr::value(Some(expiry)),
            )
            .filter(boxes::Column::Id.eq(id.to_string()))
            .filter(boxes::Column::AccountId.eq(a))
            .filter(boxes::Column::TenantId.eq(t))
            .filter(boxes::Column::LeaseToken.eq(Some(token.expose_for_storage().to_owned())))
            .filter(boxes::Column::LeaseExpiresAt.gt(now()))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        Ok(result.rows_affected == 1)
    }
    async fn release_lease(
        &self,
        context: AccountContext,
        id: BoxId,
        token: &BoxLeaseToken,
    ) -> box_core::Result<bool> {
        let (a, t) = scope(context);
        let result = boxes::Entity::update_many()
            .col_expr(
                boxes::Column::LeaseToken,
                sea_orm::sea_query::Expr::value(Option::<String>::None),
            )
            .col_expr(
                boxes::Column::LeaseExpiresAt,
                sea_orm::sea_query::Expr::value(Option::<i64>::None),
            )
            .filter(boxes::Column::Id.eq(id.to_string()))
            .filter(boxes::Column::AccountId.eq(a))
            .filter(boxes::Column::TenantId.eq(t))
            .filter(boxes::Column::LeaseToken.eq(Some(token.expose_for_storage().to_owned())))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        Ok(result.rows_affected == 1)
    }
}

impl RunRepository for RunStore {
    async fn create_run(&self, context: AccountContext, run: &Run) -> box_core::Result<()> {
        Self::model(context, run)?
            .insert(self.db.connection())
            .await
            .map_err(internal)?;
        Ok(())
    }

    async fn find_run(&self, context: AccountContext, id: RunId) -> box_core::Result<Option<Run>> {
        let (account, tenant) = scope(context);
        runs::Entity::find_by_id(id.to_string())
            .filter(runs::Column::AccountId.eq(account))
            .filter(runs::Column::TenantId.eq(tenant))
            .one(self.db.connection())
            .await
            .map_err(internal)?
            .map(Self::to_run)
            .transpose()
    }

    async fn list_runs(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Vec<Run>> {
        let (account, tenant) = scope(context);
        runs::Entity::find()
            .filter(runs::Column::AccountId.eq(account))
            .filter(runs::Column::TenantId.eq(tenant))
            .filter(runs::Column::BoxId.eq(box_id.to_string()))
            .order_by_desc(runs::Column::CreatedAt)
            .order_by_desc(runs::Column::Id)
            .all(self.db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(Self::to_run)
            .collect()
    }

    async fn append_run_event(
        &self,
        context: AccountContext,
        event: &RunEvent,
    ) -> box_core::Result<()> {
        event.validate()?;
        if event.account_id != context.account_id || event.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        }
        let payload_json = Self::canonical_payload(&event.payload_json)?;
        let sequence = Self::db_u64(event.sequence, "run event sequence")?;
        let (account, tenant) = scope(context);
        let transaction = self.db.begin().await.map_err(internal)?;
        let run = runs::Entity::find_by_id(event.run_id.to_string())
            .filter(runs::Column::AccountId.eq(account.clone()))
            .filter(runs::Column::TenantId.eq(tenant.clone()))
            .one(&transaction)
            .await
            .map_err(internal)?
            .ok_or_else(|| DomainError {
                kind: box_core::DomainErrorKind::NotFound,
                code: "not_found",
                message: "run not found".into(),
            })?;
        if parse::<RunStatus>(&run.status)?.is_terminal() {
            return Err(DomainError::state_conflict(
                "cannot append an event to a terminal run",
            ));
        }
        let latest = run_events::Entity::find()
            .filter(run_events::Column::AccountId.eq(account.clone()))
            .filter(run_events::Column::TenantId.eq(tenant.clone()))
            .filter(run_events::Column::RunId.eq(event.run_id.to_string()))
            .order_by_desc(run_events::Column::Sequence)
            .one(&transaction)
            .await
            .map_err(internal)?;
        let expected = latest.map_or(0, |value| value.sequence.saturating_add(1));
        if sequence != expected {
            return Err(DomainError::state_conflict(format!(
                "run event sequence must be {expected}"
            )));
        }
        let insert = run_events::ActiveModel {
            id: Set(uuid::Uuid::now_v7().to_string()),
            account_id: Set(account),
            tenant_id: Set(tenant),
            run_id: Set(event.run_id.to_string()),
            sequence: Set(sequence),
            event_type: Set(text(&event.event_type)),
            payload_json: Set(payload_json),
            created_at: Set(event.created_at.as_millis()),
        }
        .insert(&transaction)
        .await;
        if let Err(error) = insert {
            if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
                return Err(DomainError::state_conflict(
                    "run event sequence already exists",
                ));
            }
            return Err(internal(error));
        }
        transaction.commit().await.map_err(internal)
    }

    async fn replay_run_events(
        &self,
        context: AccountContext,
        run_id: RunId,
        after_sequence: Option<u64>,
    ) -> box_core::Result<Vec<RunEvent>> {
        if self.find_run(context, run_id).await?.is_none() {
            return Ok(Vec::new());
        }
        let (account, tenant) = scope(context);
        let mut query = run_events::Entity::find()
            .filter(run_events::Column::AccountId.eq(account))
            .filter(run_events::Column::TenantId.eq(tenant))
            .filter(run_events::Column::RunId.eq(run_id.to_string()));
        if let Some(sequence) = after_sequence {
            query = query.filter(
                run_events::Column::Sequence.gt(Self::db_u64(sequence, "run event sequence")?),
            );
        }
        query
            .order_by_asc(run_events::Column::Sequence)
            .all(self.db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(|model| {
                Ok(RunEvent {
                    run_id: RunId::parse(&model.run_id)?,
                    account_id: box_core::AccountId::parse(&model.account_id)?,
                    tenant_id: TenantId::parse(&model.tenant_id)?,
                    sequence: Self::domain_u64(model.sequence, "run event sequence")?,
                    event_type: parse::<RunEventType>(&model.event_type)?,
                    payload_json: model.payload_json,
                    created_at: UtcEpochMillis::from_millis(model.created_at),
                })
            })
            .collect()
    }

    async fn save_run(&self, context: AccountContext, run: &Run) -> box_core::Result<()> {
        run.assert_owned_by(context)?;
        let Some(current) = self.find_run(context, run.id).await? else {
            return Err(DomainError {
                kind: box_core::DomainErrorKind::NotFound,
                code: "not_found",
                message: "run not found".into(),
            });
        };
        if current.status.is_terminal() {
            return if current == *run {
                Ok(())
            } else {
                Err(DomainError::state_conflict("run is already terminal"))
            };
        }
        if run.status == RunStatus::Running && run.completed_at.is_some() {
            return Err(DomainError::validation(
                "running run cannot have completed_at",
            ));
        }
        let model = Self::model(context, run)?;
        let result = runs::Entity::update_many()
            .set(model)
            .filter(runs::Column::Id.eq(run.id.to_string()))
            .filter(runs::Column::AccountId.eq(context.account_id.to_string()))
            .filter(runs::Column::TenantId.eq(context.tenant_id.to_string()))
            .filter(runs::Column::Status.eq(text(&RunStatus::Running)))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        if result.rows_affected == 1 {
            Ok(())
        } else {
            Err(DomainError::state_conflict(
                "run changed while it was being settled",
            ))
        }
    }
}

impl SeaRepository {
    fn schedule_model(task: &ScheduledTask) -> box_core::Result<schedules::ActiveModel> {
        task.payload.spec.validate()?;
        if !task.payload.spec.webhook_headers.is_empty() {
            return Err(DomainError::feature_not_supported(
                "encrypted schedule webhook headers",
            ));
        }
        let payload_json = serde_json::to_string(&task.payload).map_err(internal)?;
        Ok(schedules::ActiveModel {
            id: Set(task.id.to_string()),
            account_id: Set(task.context.account_id.to_string()),
            tenant_id: Set(task.context.tenant_id.to_string()),
            box_id: Set(task.box_id.to_string()),
            cron: Set(task.payload.spec.cron.as_str().to_owned()),
            timezone: Set("UTC".to_owned()),
            payload_json: Set(payload_json),
            paused: Set(task.status == ScheduleStatus::Paused),
            next_run_at: Set(task.next_run_at.as_millis()),
            lease_token: Set(None),
            lease_expires_at: Set(None),
            created_at: Set(task.created_at.as_millis()),
            updated_at: Set(task.updated_at.as_millis()),
        })
    }

    fn to_schedule(model: schedules::Model) -> box_core::Result<ScheduledTask> {
        if model.timezone != "UTC" {
            return Err(DomainError::validation(
                "persisted schedule timezone must be UTC",
            ));
        }
        let payload =
            serde_json::from_str::<SchedulePayload>(&model.payload_json).map_err(internal)?;
        if payload.spec.cron.as_str() != model.cron {
            return Err(DomainError::validation(
                "persisted schedule cron fields are inconsistent",
            ));
        }
        Ok(ScheduledTask {
            id: ScheduleId::parse(&model.id)?,
            context: AccountContext {
                account_id: box_core::AccountId::parse(&model.account_id)?,
                tenant_id: TenantId::parse(&model.tenant_id)?,
            },
            box_id: BoxId::parse(&model.box_id)?,
            payload,
            status: if model.paused {
                ScheduleStatus::Paused
            } else {
                ScheduleStatus::Active
            },
            next_run_at: UtcEpochMillis::from_millis(model.next_run_at),
            created_at: UtcEpochMillis::from_millis(model.created_at),
            updated_at: UtcEpochMillis::from_millis(model.updated_at),
        })
    }
}

#[async_trait::async_trait]
impl box_scheduler::ScheduleRepository for SeaRepository {
    async fn create(&self, task: &ScheduledTask) -> box_core::Result<()> {
        Self::schedule_model(task)?
            .insert(self.db.connection())
            .await
            .map(|_| ())
            .map_err(internal)
    }

    async fn find(
        &self,
        context: AccountContext,
        box_id: BoxId,
        schedule_id: ScheduleId,
    ) -> box_core::Result<Option<ScheduledTask>> {
        let (account, tenant) = scope(context);
        schedules::Entity::find_by_id(schedule_id.to_string())
            .filter(schedules::Column::AccountId.eq(account))
            .filter(schedules::Column::TenantId.eq(tenant))
            .filter(schedules::Column::BoxId.eq(box_id.to_string()))
            .one(self.db.connection())
            .await
            .map_err(internal)?
            .map(Self::to_schedule)
            .transpose()
    }

    async fn list(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Vec<ScheduledTask>> {
        let (account, tenant) = scope(context);
        schedules::Entity::find()
            .filter(schedules::Column::AccountId.eq(account))
            .filter(schedules::Column::TenantId.eq(tenant))
            .filter(schedules::Column::BoxId.eq(box_id.to_string()))
            .order_by_asc(schedules::Column::CreatedAt)
            .all(self.db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(Self::to_schedule)
            .collect()
    }

    async fn save(&self, task: &ScheduledTask) -> box_core::Result<()> {
        task.payload.spec.validate()?;
        if !task.payload.spec.webhook_headers.is_empty() {
            return Err(DomainError::feature_not_supported(
                "encrypted schedule webhook headers",
            ));
        }
        let payload_json = serde_json::to_string(&task.payload).map_err(internal)?;
        let result = schedules::Entity::update_many()
            .col_expr(
                schedules::Column::Cron,
                Expr::value(task.payload.spec.cron.as_str()),
            )
            .col_expr(schedules::Column::PayloadJson, Expr::value(payload_json))
            .col_expr(
                schedules::Column::Paused,
                Expr::value(task.status == ScheduleStatus::Paused),
            )
            .col_expr(
                schedules::Column::NextRunAt,
                Expr::value(task.next_run_at.as_millis()),
            )
            .col_expr(
                schedules::Column::UpdatedAt,
                Expr::value(task.updated_at.as_millis()),
            )
            .filter(schedules::Column::Id.eq(task.id.to_string()))
            .filter(schedules::Column::AccountId.eq(task.context.account_id.to_string()))
            .filter(schedules::Column::TenantId.eq(task.context.tenant_id.to_string()))
            .filter(schedules::Column::BoxId.eq(task.box_id.to_string()))
            .filter(schedules::Column::LeaseToken.is_null())
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        if result.rows_affected == 1 {
            Ok(())
        } else {
            Err(DomainError::state_conflict(
                "schedule is running, missing, or was concurrently changed",
            ))
        }
    }

    async fn delete(
        &self,
        context: AccountContext,
        box_id: BoxId,
        schedule_id: ScheduleId,
    ) -> box_core::Result<bool> {
        let (account, tenant) = scope(context);
        let result = schedules::Entity::delete_many()
            .filter(schedules::Column::Id.eq(schedule_id.to_string()))
            .filter(schedules::Column::AccountId.eq(account))
            .filter(schedules::Column::TenantId.eq(tenant))
            .filter(schedules::Column::BoxId.eq(box_id.to_string()))
            .filter(schedules::Column::LeaseToken.is_null())
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        if result.rows_affected == 1 {
            return Ok(true);
        }
        if box_scheduler::ScheduleRepository::find(self, context, box_id, schedule_id)
            .await?
            .is_some()
        {
            Err(DomainError::state_conflict("schedule is currently running"))
        } else {
            Ok(false)
        }
    }

    async fn delete_all(&self, context: AccountContext, box_id: BoxId) -> box_core::Result<u64> {
        let (account, tenant) = scope(context);
        schedules::Entity::delete_many()
            .filter(schedules::Column::AccountId.eq(account))
            .filter(schedules::Column::TenantId.eq(tenant))
            .filter(schedules::Column::BoxId.eq(box_id.to_string()))
            .exec(self.db.connection())
            .await
            .map(|result| result.rows_affected)
            .map_err(internal)
    }

    async fn claim_due(
        &self,
        timestamp: UtcEpochMillis,
        lease_ttl: Duration,
        limit: usize,
    ) -> box_core::Result<Vec<ScheduleClaim>> {
        if limit == 0 || limit > 100 || lease_ttl.is_zero() {
            return Err(DomainError::validation("invalid schedule claim limits"));
        }
        let lease_millis = i64::try_from(lease_ttl.as_millis())
            .map_err(|_| DomainError::validation("schedule lease is too long"))?;
        let expires_at = timestamp
            .as_millis()
            .checked_add(lease_millis)
            .ok_or_else(|| DomainError::validation("schedule lease timestamp overflow"))?;
        let candidates = schedules::Entity::find()
            .filter(schedules::Column::Paused.eq(false))
            .filter(schedules::Column::NextRunAt.lte(timestamp.as_millis()))
            .filter(
                sea_orm::Condition::any()
                    .add(schedules::Column::LeaseExpiresAt.is_null())
                    .add(schedules::Column::LeaseExpiresAt.lte(timestamp.as_millis())),
            )
            .order_by_asc(schedules::Column::NextRunAt)
            .limit(u64::try_from(limit).expect("schedule claim limit is bounded") * 4)
            .all(self.db.connection())
            .await
            .map_err(internal)?;

        let mut claims = Vec::with_capacity(limit);
        for candidate in candidates {
            if claims.len() == limit {
                break;
            }
            let token = ScheduleLeaseToken::new();
            let claimed = schedules::Entity::update_many()
                .col_expr(
                    schedules::Column::LeaseToken,
                    Expr::value(Some(token.expose_for_storage().to_owned())),
                )
                .col_expr(
                    schedules::Column::LeaseExpiresAt,
                    Expr::value(Some(expires_at)),
                )
                .col_expr(
                    schedules::Column::UpdatedAt,
                    Expr::value(timestamp.as_millis()),
                )
                .filter(schedules::Column::Id.eq(candidate.id.clone()))
                .filter(schedules::Column::AccountId.eq(candidate.account_id.clone()))
                .filter(schedules::Column::TenantId.eq(candidate.tenant_id.clone()))
                .filter(schedules::Column::BoxId.eq(candidate.box_id.clone()))
                .filter(schedules::Column::Paused.eq(false))
                .filter(schedules::Column::NextRunAt.eq(candidate.next_run_at))
                .filter(
                    sea_orm::Condition::any()
                        .add(schedules::Column::LeaseExpiresAt.is_null())
                        .add(schedules::Column::LeaseExpiresAt.lte(timestamp.as_millis())),
                )
                .exec(self.db.connection())
                .await
                .map_err(internal)?;
            if claimed.rows_affected == 1 {
                let scheduled_at = UtcEpochMillis::from_millis(candidate.next_run_at);
                claims.push(ScheduleClaim {
                    task: Self::to_schedule(candidate)?,
                    scheduled_at,
                    lease_token: token,
                });
            }
        }
        Ok(claims)
    }

    async fn renew_claim(
        &self,
        claim: &ScheduleClaim,
        timestamp: UtcEpochMillis,
        lease_ttl: Duration,
    ) -> box_core::Result<bool> {
        if lease_ttl.is_zero() {
            return Err(DomainError::validation("schedule lease must be positive"));
        }
        let lease_millis = i64::try_from(lease_ttl.as_millis())
            .map_err(|_| DomainError::validation("schedule lease is too long"))?;
        let expires_at = timestamp
            .as_millis()
            .checked_add(lease_millis)
            .ok_or_else(|| DomainError::validation("schedule lease timestamp overflow"))?;
        schedules::Entity::update_many()
            .col_expr(
                schedules::Column::LeaseExpiresAt,
                Expr::value(Some(expires_at)),
            )
            .col_expr(
                schedules::Column::UpdatedAt,
                Expr::value(timestamp.as_millis()),
            )
            .filter(schedules::Column::Id.eq(claim.task.id.to_string()))
            .filter(schedules::Column::AccountId.eq(claim.task.context.account_id.to_string()))
            .filter(schedules::Column::TenantId.eq(claim.task.context.tenant_id.to_string()))
            .filter(schedules::Column::BoxId.eq(claim.task.box_id.to_string()))
            .filter(
                schedules::Column::LeaseToken.eq(claim.lease_token.expose_for_storage().to_owned()),
            )
            .filter(schedules::Column::LeaseExpiresAt.gt(timestamp.as_millis()))
            .exec(self.db.connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(internal)
    }

    async fn settle_claim(
        &self,
        claim: &ScheduleClaim,
        outcome: ScheduleRunOutcome,
    ) -> box_core::Result<bool> {
        let mut payload = claim.task.payload.clone();
        payload.last_run_at = Some(outcome.completed_at.as_millis());
        payload.last_run_status = Some(outcome.status.as_str().to_owned());
        payload.last_run_id = Some(outcome.run_id);
        payload.total_runs = payload.total_runs.saturating_add(1);
        if outcome.status == ScheduleRunStatus::Failed {
            payload.total_failures = payload.total_failures.saturating_add(1);
        }
        let next_run_at = payload.spec.cron.next_after(claim.scheduled_at)?;
        let payload_json = serde_json::to_string(&payload).map_err(internal)?;
        schedules::Entity::update_many()
            .col_expr(schedules::Column::PayloadJson, Expr::value(payload_json))
            .col_expr(
                schedules::Column::NextRunAt,
                Expr::value(next_run_at.as_millis()),
            )
            .col_expr(schedules::Column::LeaseToken, Expr::value(None::<String>))
            .col_expr(schedules::Column::LeaseExpiresAt, Expr::value(None::<i64>))
            .col_expr(
                schedules::Column::UpdatedAt,
                Expr::value(outcome.completed_at.as_millis()),
            )
            .filter(schedules::Column::Id.eq(claim.task.id.to_string()))
            .filter(schedules::Column::AccountId.eq(claim.task.context.account_id.to_string()))
            .filter(schedules::Column::TenantId.eq(claim.task.context.tenant_id.to_string()))
            .filter(schedules::Column::BoxId.eq(claim.task.box_id.to_string()))
            .filter(
                schedules::Column::LeaseToken.eq(claim.lease_token.expose_for_storage().to_owned()),
            )
            .exec(self.db.connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(internal)
    }
}
impl OperationRepository for SeaRepository {
    async fn find_by_idempotency_key(
        &self,
        context: AccountContext,
        kind: OperationKind,
        key: &IdempotencyKey,
    ) -> box_core::Result<Option<Operation>> {
        let (a, t) = scope(context);
        operations::Entity::find()
            .filter(operations::Column::AccountId.eq(a))
            .filter(operations::Column::TenantId.eq(t))
            .filter(operations::Column::Kind.eq(text(&kind)))
            .filter(operations::Column::IdempotencyKey.eq(key.as_str()))
            .one(self.db.connection())
            .await
            .map_err(internal)?
            .map(Self::to_operation)
            .transpose()
    }
    async fn create(&self, context: AccountContext, operation: &Operation) -> box_core::Result<()> {
        if operation.account_id != context.account_id || operation.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        };
        Self::operation_model(context, operation)
            .insert(self.db.connection())
            .await
            .map_err(|error| {
                if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
                    DomainError {
                        kind: box_core::DomainErrorKind::VersionConflict,
                        code: "database_unique_violation",
                        message: "operation idempotency key already exists".into(),
                    }
                } else {
                    internal(error)
                }
            })?;
        Ok(())
    }
    async fn save(&self, context: AccountContext, operation: &Operation) -> box_core::Result<()> {
        if operation.account_id != context.account_id || operation.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        };
        let (a, t) = scope(context);
        let r = operations::Entity::update_many()
            .col_expr(
                operations::Column::Status,
                sea_orm::sea_query::Expr::value(text(&operation.status)),
            )
            .col_expr(
                operations::Column::RetryCount,
                sea_orm::sea_query::Expr::value(i64::from(operation.retry_count)),
            )
            .col_expr(
                operations::Column::Error,
                sea_orm::sea_query::Expr::value(operation.error.clone()),
            )
            .col_expr(
                operations::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(now()),
            )
            .filter(operations::Column::Id.eq(operation.id.to_string()))
            .filter(operations::Column::AccountId.eq(a))
            .filter(operations::Column::TenantId.eq(t))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        if r.rows_affected == 1 {
            Ok(())
        } else {
            Err(DomainError::ownership())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRecord {
    pub id: box_core::AccountId,
    pub name: String,
    pub status: String,
    pub created_at: UtcEpochMillis,
    pub updated_at: UtcEpochMillis,
}

#[derive(Clone)]
pub struct AccountStore {
    db: DatabaseHandle,
}
impl AccountStore {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }
    pub async fn create(&self, value: &AccountRecord) -> box_core::Result<()> {
        if value.name.is_empty() || value.status.is_empty() {
            return Err(DomainError::validation(
                "account name and status are required",
            ));
        }
        accounts::ActiveModel {
            id: Set(value.id.to_string()),
            name: Set(value.name.clone()),
            status: Set(value.status.clone()),
            created_at: Set(value.created_at.as_millis()),
            updated_at: Set(value.updated_at.as_millis()),
        }
        .insert(self.db.connection())
        .await
        .map_err(internal)?;
        Ok(())
    }
    pub async fn find(&self, id: box_core::AccountId) -> box_core::Result<Option<AccountRecord>> {
        accounts::Entity::find_by_id(id.to_string())
            .one(self.db.connection())
            .await
            .map_err(internal)?
            .map(|model| {
                Ok(AccountRecord {
                    id: box_core::AccountId::parse(&model.id)?,
                    name: model.name,
                    status: model.status,
                    created_at: UtcEpochMillis::from_millis(model.created_at),
                    updated_at: UtcEpochMillis::from_millis(model.updated_at),
                })
            })
            .transpose()
    }
}

#[derive(Clone, Debug)]
pub struct ApiKeyRecord {
    pub id: String,
    pub account: AccountContext,
    pub prefix: String,
    pub scopes: BTreeSet<AuthScope>,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
}
#[derive(Clone)]
pub struct ApiKeyStore {
    db: DatabaseHandle,
    pepper: Vec<u8>,
}
impl ApiKeyStore {
    pub fn new(db: DatabaseHandle, pepper: impl AsRef<[u8]>) -> box_core::Result<Self> {
        if pepper.as_ref().len() < 32 {
            return Err(DomainError::validation(
                "API key HMAC pepper must contain at least 32 bytes",
            ));
        }
        Ok(Self {
            db,
            pepper: pepper.as_ref().to_vec(),
        })
    }
    fn digest(&self, secret: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.pepper).expect("HMAC accepts any key");
        mac.update(secret.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect()
    }
    fn decode_digest(value: &str) -> Option<Vec<u8>> {
        if value.len() != 64 {
            return None;
        }
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
            .collect()
    }
    pub async fn store(
        &self,
        context: AccountContext,
        prefix: &str,
        secret: &str,
        scopes: BTreeSet<AuthScope>,
        expires_at: Option<i64>,
    ) -> box_core::Result<ApiKeyRecord> {
        if prefix.is_empty() || prefix.len() > 64 || secret.is_empty() {
            return Err(DomainError::validation("invalid API key prefix or secret"));
        }
        let (a, t) = scope(context);
        let id = uuid::Uuid::now_v7().to_string();
        let time = now();
        api_keys::ActiveModel {
            id: Set(id.clone()),
            account_id: Set(a),
            tenant_id: Set(t),
            prefix: Set(prefix.into()),
            key_hmac: Set(self.digest(secret)),
            scopes_json: Set(text(&scopes)),
            last_used_at: Set(None),
            expires_at: Set(expires_at),
            created_at: Set(time),
            updated_at: Set(time),
        }
        .insert(self.db.connection())
        .await
        .map_err(|error| {
            if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
                DomainError::state_conflict("API key credential already exists")
            } else {
                internal(error)
            }
        })?;
        Ok(ApiKeyRecord {
            id,
            account: context,
            prefix: prefix.into(),
            scopes,
            expires_at,
            last_used_at: None,
            created_at: time,
        })
    }
    pub async fn list(&self, context: AccountContext) -> box_core::Result<Vec<ApiKeyRecord>> {
        let (account, tenant) = scope(context);
        api_keys::Entity::find()
            .filter(api_keys::Column::AccountId.eq(account))
            .filter(api_keys::Column::TenantId.eq(tenant))
            .order_by_desc(api_keys::Column::CreatedAt)
            .all(self.db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(|value| {
                Ok(ApiKeyRecord {
                    id: value.id,
                    account: context,
                    prefix: value.prefix,
                    scopes: parse(&value.scopes_json)?,
                    expires_at: value.expires_at,
                    last_used_at: value.last_used_at,
                    created_at: value.created_at,
                })
            })
            .collect()
    }
    pub async fn revoke(&self, context: AccountContext, id: &str) -> box_core::Result<bool> {
        if uuid::Uuid::parse_str(id).is_err() {
            return Err(DomainError::validation("invalid API key id"));
        }
        let (account, tenant) = scope(context);
        api_keys::Entity::delete_many()
            .filter(api_keys::Column::Id.eq(id))
            .filter(api_keys::Column::AccountId.eq(account))
            .filter(api_keys::Column::TenantId.eq(tenant))
            .exec(self.db.connection())
            .await
            .map(|result| result.rows_affected > 0)
            .map_err(internal)
    }
    /// Authenticates without a caller-provided tenant context. Prefix selects a
    /// small candidate set; HMAC verification uses `Mac::verify_slice`.
    pub async fn authenticate(
        &self,
        prefix: &str,
        raw_key: &str,
    ) -> box_core::Result<Option<AuthorizedContext>> {
        let candidates = api_keys::Entity::find()
            .filter(api_keys::Column::Prefix.eq(prefix))
            .all(self.db.connection())
            .await
            .map_err(internal)?;
        for candidate in candidates {
            let Some(expected) = Self::decode_digest(&candidate.key_hmac) else {
                continue;
            };
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&self.pepper).expect("HMAC accepts any key");
            mac.update(raw_key.as_bytes());
            if mac.verify_slice(&expected).is_err() {
                continue;
            }
            let timestamp = now();
            if candidate
                .expires_at
                .is_some_and(|expiry| expiry <= timestamp)
            {
                continue;
            }
            let account = AccountContext {
                account_id: box_core::AccountId::parse(&candidate.account_id)?,
                tenant_id: TenantId::parse(&candidate.tenant_id)?,
            };
            let scopes: BTreeSet<AuthScope> = parse(&candidate.scopes_json)?;
            let updated = api_keys::Entity::update_many()
                .col_expr(
                    api_keys::Column::LastUsedAt,
                    sea_orm::sea_query::Expr::value(Some(timestamp)),
                )
                .filter(api_keys::Column::Id.eq(candidate.id))
                .filter(api_keys::Column::AccountId.eq(account.account_id.to_string()))
                .filter(api_keys::Column::TenantId.eq(account.tenant_id.to_string()))
                .filter(
                    sea_orm::Condition::any()
                        .add(sea_orm::sea_query::Expr::col(api_keys::Column::ExpiresAt).is_null())
                        .add(api_keys::Column::ExpiresAt.gt(timestamp)),
                )
                .exec(self.db.connection())
                .await
                .map_err(internal)?;
            if updated.rows_affected == 1 {
                return Ok(Some(AuthorizedContext { account, scopes }));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use box_core::{
        AccountId, BoxSize, BoxStatus, CustomNetworkPolicy, Label, NetworkPolicy, Preview,
        PreviewAuth, PreviewRepository, Runtime, SnapshotRepository, SnapshotStatus, TenantId,
    };
    use box_scheduler::{ScheduleKind, ScheduleSpec, UtcCron};
    use std::collections::BTreeMap;
    async fn pragma_i64<C: ConnectionTrait>(db: &C, name: &str) -> i64 {
        db.query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            format!("PRAGMA {name}"),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap()
    }
    async fn pragma_string<C: ConnectionTrait>(db: &C, name: &str) -> String {
        db.query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            format!("PRAGMA {name}"),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap()
    }
    fn context() -> AccountContext {
        AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        }
    }
    fn long_custom_network_policy() -> CustomNetworkPolicy {
        let allowed_domains = (0..32)
            .map(|index| format!("rule-{index}.example.com"))
            .collect();
        let allowed_cidrs = (0..16)
            .map(|index| format!("198.51.100.{index}/32"))
            .collect();
        let denied_cidrs = (0..15)
            .map(|index| format!("203.0.113.{index}/32"))
            .collect();
        CustomNetworkPolicy::new(allowed_domains, allowed_cidrs, denied_cidrs).unwrap()
    }
    fn box_value(c: AccountContext) -> DomainBox {
        let mut value = DomainBox::new(
            c,
            BoxCreateSpec {
                name: Some("a".into()),
                labels: vec![Label::new("tag-b").unwrap(), Label::new("tag-a").unwrap()],
                runtime: Runtime::Node,
                size: BoxSize::Small,
                browser: true,
                keep_alive: false,
                ephemeral: Some(box_core::EphemeralSpec::new(Some(3_600)).unwrap()),
                attach_headers_requested: false,
                network_policy: NetworkPolicy::DenyAll,
            },
            UtcEpochMillis::from_millis(1),
        )
        .unwrap();
        value
            .bind_runtime(
                box_core::RuntimeBundleBinding::new("0".repeat(64), "1.0.0", "aarch64").unwrap(),
                UtcEpochMillis::from_millis(2),
            )
            .unwrap();
        value.source_snapshot_id = Some(box_core::SnapshotId::new());
        value
    }
    async fn seed_account(db: &DatabaseHandle, context: AccountContext) {
        let value = AccountRecord {
            id: context.account_id,
            name: "test".into(),
            status: "active".into(),
            created_at: UtcEpochMillis::from_millis(1),
            updated_at: UtcEpochMillis::from_millis(1),
        };
        let store = AccountStore::new(db.clone());
        store.create(&value).await.unwrap();
        assert_eq!(store.find(value.id).await.unwrap(), Some(value));
    }

    async fn portable_repository_suite(url: &str) {
        let db = connect(url, 4).await.unwrap();
        migrate(&db).await.unwrap();
        assert!(migrations_current(&db).await.unwrap());
        let context = context();
        seed_account(&db, context).await;
        let boxes = SeaRepository::new(db.clone());
        let mut value = box_value(context);
        value.spec.network_policy = NetworkPolicy::Custom(long_custom_network_policy());
        let NetworkPolicy::Custom(policy) = &value.spec.network_policy else {
            unreachable!("portable fixture must exercise custom network policy");
        };
        assert_eq!(
            policy.allowed_domains().len()
                + policy.allowed_cidrs().len()
                + policy.denied_cidrs().len(),
            63
        );
        assert!(
            serde_json::to_string(&value.spec.network_policy)
                .unwrap()
                .len()
                > 32
        );
        BoxRepository::create(&boxes, context, &value)
            .await
            .unwrap();
        assert_eq!(
            boxes.find(context, value.id).await.unwrap(),
            Some(value.clone())
        );
        assert!(
            boxes
                .find(
                    AccountContext {
                        account_id: context.account_id,
                        tenant_id: TenantId::new(),
                    },
                    value.id,
                )
                .await
                .unwrap()
                .is_none()
        );

        let version = value.version;
        value
            .transition(BoxStatus::Idle, UtcEpochMillis::from_millis(3))
            .unwrap();
        BoxRepository::save(&boxes, context, &value, version)
            .await
            .unwrap();
        assert_eq!(
            boxes.find(context, value.id).await.unwrap(),
            Some(value.clone())
        );
        assert_eq!(
            BoxRepository::save(&boxes, context, &value, version)
                .await
                .unwrap_err()
                .code,
            "version_conflict"
        );
        let lease = BoxLeaseToken::new("portable-matrix-lease").unwrap();
        assert!(
            boxes
                .acquire_lease(context, value.id, &lease, Duration::from_secs(30))
                .await
                .unwrap()
        );
        assert!(
            boxes
                .renew_lease(context, value.id, &lease, Duration::from_secs(30))
                .await
                .unwrap()
        );
        assert!(
            boxes
                .release_lease(context, value.id, &lease)
                .await
                .unwrap()
        );

        let runs = RunStore::new(db.clone());
        let mut run = Run::new_agent(
            context,
            value.id,
            "portable matrix",
            None,
            UtcEpochMillis::from_millis(10),
        )
        .unwrap();
        runs.create_run(context, &run).await.unwrap();
        runs.append_run_event(
            context,
            &RunEvent {
                run_id: run.id,
                account_id: context.account_id,
                tenant_id: context.tenant_id,
                sequence: 0,
                event_type: RunEventType::RunStart,
                payload_json: r#"{"run_id":"portable"}"#.into(),
                created_at: UtcEpochMillis::from_millis(11),
            },
        )
        .await
        .unwrap();
        run.settle(
            RunStatus::Completed,
            Some("ok".into()),
            None,
            UtcEpochMillis::from_millis(12),
        )
        .unwrap();
        runs.save_run(context, &run).await.unwrap();
        assert_eq!(runs.find_run(context, run.id).await.unwrap(), Some(run));

        let snapshots = SnapshotStore::new(db.clone());
        let mut snapshot = box_core::Snapshot::new(
            context,
            value.id,
            "portable".into(),
            UtcEpochMillis::from_millis(20),
        )
        .unwrap();
        SnapshotRepository::create_snapshot(&snapshots, context, &snapshot)
            .await
            .unwrap();
        snapshot.status = SnapshotStatus::Ready;
        snapshot.disk_path = Some(format!("snapshots/{}/disk.raw", snapshot.id));
        snapshot.size_bytes = 4_096;
        snapshot.checksum = Some("a".repeat(64));
        snapshot.updated_at = UtcEpochMillis::from_millis(21);
        SnapshotRepository::save_snapshot(&snapshots, context, &snapshot)
            .await
            .unwrap();
        assert_eq!(
            SnapshotRepository::find_snapshot(&snapshots, context, snapshot.id)
                .await
                .unwrap(),
            Some(snapshot)
        );

        let previews = PreviewStore::new(db.clone());
        let preview = Preview {
            id: box_core::PreviewId::new(),
            account_id: context.account_id,
            tenant_id: context.tenant_id,
            box_id: value.id,
            port: 3_000,
            auth: PreviewAuth::Bearer,
            token_hmac: "ab".repeat(32),
            expires_at: UtcEpochMillis::from_millis(1_800_000),
            created_at: UtcEpochMillis::from_millis(30),
            updated_at: UtcEpochMillis::from_millis(30),
        };
        previews.create_preview(context, &preview).await.unwrap();
        assert_eq!(
            previews
                .find_preview_by_token_hmac(&preview.token_hmac)
                .await
                .unwrap(),
            Some(preview)
        );

        let schedules = SeaRepository::new(db.clone());
        let schedule = ScheduledTask::new(
            context,
            value.id,
            ScheduleSpec {
                kind: ScheduleKind::Exec,
                cron: UtcCron::parse("*/5 * * * *").unwrap(),
                command: Some(vec!["true".into()]),
                prompt: None,
                folder: "/workspace/home".into(),
                model: None,
                agent_options: None,
                timeout_millis: Some(5_000),
                webhook_url: None,
                webhook_headers: BTreeMap::new(),
            },
            UtcEpochMillis::from_millis(1_700_000_000_000),
        )
        .unwrap();
        box_scheduler::ScheduleRepository::create(&schedules, &schedule)
            .await
            .unwrap();
        assert_eq!(
            box_scheduler::ScheduleRepository::find(&schedules, context, value.id, schedule.id,)
                .await
                .unwrap(),
            Some(schedule)
        );

        let recordings = BrowserRecordingStore::new(db.clone());
        let mut recording = box_browser::BrowserRecording::new(
            context,
            value.id,
            600,
            UtcEpochMillis::from_millis(1_700_000_000_100),
        )
        .unwrap();
        box_browser::BrowserRecordingRepository::create(&recordings, context, &recording)
            .await
            .unwrap();
        assert_eq!(
            box_browser::BrowserRecordingRepository::active(&recordings, context, value.id)
                .await
                .unwrap(),
            Some(recording.clone())
        );
        recording.status = box_browser::BrowserRecordingStatus::Completed;
        recording.ended_at = Some(UtcEpochMillis::from_millis(1_700_000_001_100));
        recording.duration_ms = Some(1_000);
        recording.size_bytes = Some(4_096);
        recording.segment_count = Some(1);
        recording.mp4_size_bytes = Some(3_000);
        recording.stopped_reason = Some("requested".into());
        recording.playlist_path = Some("scoped/playlist.m3u8".into());
        recording.download_path = Some("scoped/recording.mp4".into());
        recording.updated_at = UtcEpochMillis::from_millis(1_700_000_001_100);
        box_browser::BrowserRecordingRepository::save(&recordings, context, &recording)
            .await
            .unwrap();
        assert_eq!(
            box_browser::BrowserRecordingRepository::list(
                &recordings,
                context,
                value.id,
                None,
                100,
            )
            .await
            .unwrap(),
            vec![recording]
        );

        let keys = ApiKeyStore::new(db, [9_u8; 32]).unwrap();
        keys.store(
            context,
            "bx_matrix",
            "portable-secret",
            BTreeSet::from([AuthScope::BoxesRead]),
            None,
        )
        .await
        .unwrap();
        assert!(
            keys.authenticate("bx_matrix", "portable-secret")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            keys.authenticate("bx_matrix", "wrong-secret")
                .await
                .unwrap(),
            None
        );

        let audit = AuditStore::new(keys.db.clone());
        let audit_record = AuditRecord {
            id: uuid::Uuid::now_v7().to_string(),
            context,
            actor: "compat_api_key".into(),
            action: "POST /v2/box".into(),
            resource: "/v2/box".into(),
            request_id: Some("portable-matrix-request".into()),
            ip: Some("127.0.0.1".into()),
            metadata: serde_json::json!({"status_code":200,"succeeded":true}),
            created_at: 40,
        };
        audit.append(&audit_record).await.unwrap();
        assert_eq!(audit.list(context, 10).await.unwrap(), vec![audit_record]);
    }

    #[tokio::test]
    async fn sqlite_portable_repository_matrix() {
        portable_repository_suite("sqlite::memory:").await;
    }

    #[tokio::test]
    async fn optional_postgres_and_mysql_repository_matrix() {
        let mut configured = 0;
        for variable in ["BOXD_TEST_POSTGRES_URL", "BOXD_TEST_MYSQL_URL"] {
            let Ok(url) = std::env::var(variable) else {
                eprintln!("skipping {variable}: environment variable is not configured");
                continue;
            };
            configured += 1;
            portable_repository_suite(&url).await;
        }
        if configured == 0 {
            eprintln!("PostgreSQL/MySQL repository matrix explicitly skipped");
        }
    }
    #[tokio::test]
    async fn sqlite_bootstrap_crud_and_isolation() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        assert!(migrations_current(&db).await.unwrap());
        let repo = SeaRepository::new(db.clone());
        let c = context();
        seed_account(&db, c).await;
        let b = box_value(c);
        BoxRepository::create(&repo, c, &b).await.unwrap();
        let loaded = repo.find(c, b.id).await.unwrap().unwrap();
        assert_eq!(loaded, b);
        let same_account_other_tenant = AccountContext {
            account_id: c.account_id,
            tenant_id: TenantId::new(),
        };
        assert!(
            repo.find(same_account_other_tenant, b.id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(repo.list(c).await.unwrap().len(), 1);
        // The connection bootstrap executed this PRAGMA without error before migration.
        db.execute_unprepared("PRAGMA foreign_keys=ON")
            .await
            .unwrap();
        let missing_account = db.execute_unprepared("INSERT INTO boxes (id, account_id, tenant_id, runtime, size, status, ephemeral, keep_alive, network_policy, version, created_at, updated_at) VALUES ('missing', 'missing', 'tenant', 'node', 'small', 'idle', 0, 0, '\"deny_all\"', 0, 1, 1)").await.unwrap_err();
        assert!(matches!(
            missing_account.sql_err(),
            Some(SqlErr::ForeignKeyConstraintViolation(_))
        ));
        let cross_tenant = db.execute_unprepared(&format!("INSERT INTO box_labels (id, account_id, tenant_id, box_id, label, position, created_at) VALUES ('cross', '{}', '{}', '{}', 'cross', 0, 1)", c.account_id, TenantId::new(), b.id)).await.unwrap_err();
        assert!(matches!(
            cross_tenant.sql_err(),
            Some(SqlErr::ForeignKeyConstraintViolation(_))
        ));

        let unsupported = DomainBox::new(
            c,
            BoxCreateSpec {
                name: None,
                labels: vec![],
                runtime: Runtime::Node,
                size: BoxSize::Small,
                browser: false,
                keep_alive: false,
                ephemeral: None,
                attach_headers_requested: true,
                network_policy: NetworkPolicy::DenyAll,
            },
            UtcEpochMillis::from_millis(1),
        );
        assert_eq!(unsupported.unwrap_err().code, "feature_not_supported");
    }

    #[tokio::test]
    async fn schedule_repository_roundtrips_and_scopes_every_query() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let context = context();
        seed_account(&db, context).await;
        let box_value = box_value(context);
        let repository = SeaRepository::new(db);
        BoxRepository::create(&repository, context, &box_value)
            .await
            .unwrap();
        let mut task = ScheduledTask::new(
            context,
            box_value.id,
            ScheduleSpec {
                kind: ScheduleKind::Exec,
                cron: UtcCron::parse("*/5 * * * *").unwrap(),
                command: Some(vec!["printf".into(), "scheduled".into()]),
                prompt: None,
                folder: "/workspace/home".into(),
                model: None,
                agent_options: None,
                timeout_millis: Some(5_000),
                webhook_url: None,
                webhook_headers: BTreeMap::new(),
            },
            UtcEpochMillis::from_millis(1_700_000_000_000),
        )
        .unwrap();
        box_scheduler::ScheduleRepository::create(&repository, &task)
            .await
            .unwrap();

        assert_eq!(
            box_scheduler::ScheduleRepository::find(&repository, context, box_value.id, task.id,)
                .await
                .unwrap(),
            Some(task.clone())
        );
        assert_eq!(
            box_scheduler::ScheduleRepository::list(&repository, context, box_value.id)
                .await
                .unwrap(),
            vec![task.clone()]
        );
        let other_tenant = AccountContext {
            account_id: context.account_id,
            tenant_id: TenantId::new(),
        };
        assert!(
            box_scheduler::ScheduleRepository::find(
                &repository,
                other_tenant,
                box_value.id,
                task.id,
            )
            .await
            .unwrap()
            .is_none()
        );

        let scheduled_at = task.next_run_at;
        let claims = box_scheduler::ScheduleRepository::claim_due(
            &repository,
            scheduled_at,
            Duration::from_secs(30),
            8,
        )
        .await
        .unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].scheduled_at, scheduled_at);
        assert_eq!(
            claims[0].idempotency_key(),
            task.idempotency_key(scheduled_at)
        );
        assert!(
            box_scheduler::ScheduleRepository::claim_due(
                &repository,
                scheduled_at,
                Duration::from_secs(30),
                8,
            )
            .await
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            box_scheduler::ScheduleRepository::save(&repository, &task)
                .await
                .unwrap_err()
                .code,
            "state_conflict"
        );
        assert!(
            box_scheduler::ScheduleRepository::renew_claim(
                &repository,
                &claims[0],
                UtcEpochMillis::from_millis(scheduled_at.as_millis() + 1_000),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        );
        let recovered = box_scheduler::ScheduleRepository::claim_due(
            &repository,
            UtcEpochMillis::from_millis(scheduled_at.as_millis() + 31_001),
            Duration::from_secs(30),
            8,
        )
        .await
        .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].idempotency_key(), claims[0].idempotency_key());
        let completed_at = UtcEpochMillis::from_millis(scheduled_at.as_millis() + 32_000);
        assert!(
            !box_scheduler::ScheduleRepository::settle_claim(
                &repository,
                &claims[0],
                box_scheduler::ScheduleRunOutcome {
                    run_id: "stale-holder".into(),
                    status: box_scheduler::ScheduleRunStatus::Completed,
                    completed_at,
                },
            )
            .await
            .unwrap()
        );
        assert!(
            box_scheduler::ScheduleRepository::settle_claim(
                &repository,
                &recovered[0],
                box_scheduler::ScheduleRunOutcome {
                    run_id: "schedule-run-fixture".into(),
                    status: box_scheduler::ScheduleRunStatus::Completed,
                    completed_at,
                },
            )
            .await
            .unwrap()
        );
        let settled =
            box_scheduler::ScheduleRepository::find(&repository, context, box_value.id, task.id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(settled.payload.total_runs, 1);
        assert_eq!(settled.payload.total_failures, 0);
        assert_eq!(
            settled.payload.last_run_status.as_deref(),
            Some("completed")
        );
        assert_eq!(
            settled.payload.last_run_id.as_deref(),
            Some("schedule-run-fixture")
        );
        assert!(settled.next_run_at.as_millis() > scheduled_at.as_millis());
        task = settled;

        task.status = ScheduleStatus::Paused;
        task.updated_at = UtcEpochMillis::from_millis(1_700_000_001_000);
        box_scheduler::ScheduleRepository::save(&repository, &task)
            .await
            .unwrap();
        assert_eq!(
            box_scheduler::ScheduleRepository::find(&repository, context, box_value.id, task.id,)
                .await
                .unwrap()
                .unwrap()
                .status,
            ScheduleStatus::Paused
        );
        assert!(
            box_scheduler::ScheduleRepository::delete(&repository, context, box_value.id, task.id,)
                .await
                .unwrap()
        );
        assert!(
            !box_scheduler::ScheduleRepository::delete(
                &repository,
                context,
                box_value.id,
                task.id,
            )
            .await
            .unwrap()
        );

        task.id = ScheduleId::new();
        task.payload.spec.webhook_headers.clear();
        box_scheduler::ScheduleRepository::create(&repository, &task)
            .await
            .unwrap();
        let mut second_task = task.clone();
        second_task.id = ScheduleId::new();
        box_scheduler::ScheduleRepository::create(&repository, &second_task)
            .await
            .unwrap();
        assert_eq!(
            box_scheduler::ScheduleRepository::delete_all(&repository, other_tenant, box_value.id,)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            box_scheduler::ScheduleRepository::delete_all(&repository, context, box_value.id)
                .await
                .unwrap(),
            2
        );
        assert!(
            box_scheduler::ScheduleRepository::list(&repository, context, box_value.id)
                .await
                .unwrap()
                .is_empty()
        );

        task.id = ScheduleId::new();
        task.payload.spec.webhook_headers =
            BTreeMap::from([("authorization".into(), "must-never-be-persisted".into())]);
        assert_eq!(
            box_scheduler::ScheduleRepository::create(&repository, &task)
                .await
                .unwrap_err()
                .code,
            "feature_not_supported"
        );
    }

    #[tokio::test]
    async fn preview_store_scopes_owners_and_never_requires_plaintext_tokens() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let context = context();
        seed_account(&db, context).await;
        let box_value = box_value(context);
        BoxRepository::create(&SeaRepository::new(db.clone()), context, &box_value)
            .await
            .unwrap();
        let store = PreviewStore::new(db);
        let preview = Preview {
            id: box_core::PreviewId::new(),
            account_id: context.account_id,
            tenant_id: context.tenant_id,
            box_id: box_value.id,
            port: 3_000,
            auth: PreviewAuth::Bearer,
            token_hmac: "ab".repeat(32),
            expires_at: UtcEpochMillis::from_millis(1_800_000),
            created_at: UtcEpochMillis::from_millis(1),
            updated_at: UtcEpochMillis::from_millis(1),
        };
        store.create_preview(context, &preview).await.unwrap();
        assert_eq!(
            store
                .find_preview_by_token_hmac(&preview.token_hmac)
                .await
                .unwrap(),
            Some(preview.clone())
        );
        assert_eq!(
            store.list_previews(context, box_value.id).await.unwrap(),
            vec![preview.clone()]
        );
        assert!(
            store
                .list_previews(
                    AccountContext {
                        account_id: context.account_id,
                        tenant_id: TenantId::new(),
                    },
                    box_value.id,
                )
                .await
                .unwrap()
                .is_empty()
        );
        let mut duplicate_port = preview.clone();
        duplicate_port.id = box_core::PreviewId::new();
        duplicate_port.token_hmac = "cd".repeat(32);
        store
            .create_preview(context, &duplicate_port)
            .await
            .unwrap();
        assert_eq!(
            store.list_previews(context, box_value.id).await.unwrap(),
            vec![duplicate_port.clone()]
        );
        assert!(
            store
                .find_preview_by_token_hmac(&preview.token_hmac)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .delete_preview(
                    AccountContext {
                        account_id: context.account_id,
                        tenant_id: TenantId::new(),
                    },
                    box_value.id,
                    duplicate_port.port,
                )
                .await
                .unwrap()
        );
        assert!(
            store
                .delete_preview(context, box_value.id, duplicate_port.port)
                .await
                .unwrap()
        );
        assert!(
            store
                .find_preview_by_token_hmac(&duplicate_port.token_hmac)
                .await
                .unwrap()
                .is_none()
        );
        let mut expiring = preview;
        expiring.id = box_core::PreviewId::new();
        expiring.port = 3_001;
        expiring.token_hmac = "ef".repeat(32);
        store.create_preview(context, &expiring).await.unwrap();
        assert_eq!(
            store
                .delete_expired_previews(UtcEpochMillis::from_millis(1_799_999))
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .delete_expired_previews(expiring.expires_at)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn snapshot_store_roundtrips_status_and_enforces_tenant_scope() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let context = context();
        seed_account(&db, context).await;
        let value = box_value(context);
        let boxes = SeaRepository::new(db.clone());
        BoxRepository::create(&boxes, context, &value)
            .await
            .unwrap();
        let store = SnapshotStore::new(db);
        let mut snapshot = box_core::Snapshot::new(
            context,
            value.id,
            "before-upgrade".into(),
            UtcEpochMillis::from_millis(10),
        )
        .unwrap();
        SnapshotRepository::create_snapshot(&store, context, &snapshot)
            .await
            .unwrap();
        snapshot.status = SnapshotStatus::Ready;
        snapshot.disk_path = Some(format!("snapshots/{}/disk.raw", snapshot.id));
        snapshot.size_bytes = 4096;
        snapshot.checksum = Some("a".repeat(64));
        snapshot.updated_at = UtcEpochMillis::from_millis(20);
        SnapshotRepository::save_snapshot(&store, context, &snapshot)
            .await
            .unwrap();
        assert_eq!(
            SnapshotRepository::find_snapshot(&store, context, snapshot.id)
                .await
                .unwrap(),
            Some(snapshot.clone())
        );
        assert_eq!(
            SnapshotRepository::list_snapshots(&store, context, Some(value.id))
                .await
                .unwrap(),
            [snapshot.clone()]
        );
        let other = AccountContext {
            account_id: context.account_id,
            tenant_id: TenantId::new(),
        };
        assert!(
            SnapshotRepository::find_snapshot(&store, other, snapshot.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn run_store_is_scoped_monotonic_replayable_and_terminal() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let boxes = SeaRepository::new(db.clone());
        let runs = RunStore::new(db.clone());
        let c = context();
        seed_account(&db, c).await;
        let b = box_value(c);
        BoxRepository::create(&boxes, c, &b).await.unwrap();

        let mut run = Run::new_agent(
            c,
            b.id,
            "summarize",
            Some("openai/gpt-5".into()),
            UtcEpochMillis::from_millis(10),
        )
        .unwrap();
        runs.create_run(c, &run).await.unwrap();
        for (sequence, event_type, payload) in [
            (0, RunEventType::RunStart, r#"{"run_id":"fixture"}"#),
            (1, RunEventType::Text, r#"{"b":2,"a":1}"#),
        ] {
            runs.append_run_event(
                c,
                &RunEvent {
                    run_id: run.id,
                    account_id: c.account_id,
                    tenant_id: c.tenant_id,
                    sequence,
                    event_type,
                    payload_json: payload.into(),
                    created_at: UtcEpochMillis::from_millis(11 + sequence as i64),
                },
            )
            .await
            .unwrap();
        }
        let replay = runs.replay_run_events(c, run.id, Some(0)).await.unwrap();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].payload_json, r#"{"a":1,"b":2}"#);
        let duplicate = runs
            .append_run_event(
                c,
                &RunEvent {
                    run_id: run.id,
                    account_id: c.account_id,
                    tenant_id: c.tenant_id,
                    sequence: 1,
                    event_type: RunEventType::Text,
                    payload_json: r#"{"text":"duplicate"}"#.into(),
                    created_at: UtcEpochMillis::from_millis(13),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(duplicate.code, "state_conflict");

        let other_tenant = AccountContext {
            account_id: c.account_id,
            tenant_id: TenantId::new(),
        };
        assert!(runs.find_run(other_tenant, run.id).await.unwrap().is_none());
        assert!(
            runs.replay_run_events(other_tenant, run.id, None)
                .await
                .unwrap()
                .is_empty()
        );

        run.input_tokens = 3;
        run.output_tokens = 4;
        run.settle(
            RunStatus::Completed,
            Some("done".into()),
            None,
            UtcEpochMillis::from_millis(20),
        )
        .unwrap();
        runs.save_run(c, &run).await.unwrap();
        assert_eq!(runs.find_run(c, run.id).await.unwrap(), Some(run.clone()));
        assert_eq!(runs.list_runs(c, b.id).await.unwrap(), vec![run.clone()]);
        assert_eq!(
            runs.append_run_event(
                c,
                &RunEvent {
                    run_id: run.id,
                    account_id: c.account_id,
                    tenant_id: c.tenant_id,
                    sequence: 2,
                    event_type: RunEventType::Done,
                    payload_json: r#"{"output":"done"}"#.into(),
                    created_at: UtcEpochMillis::from_millis(20),
                },
            )
            .await
            .unwrap_err()
            .code,
            "state_conflict"
        );
    }

    #[tokio::test]
    async fn run_events_replay_after_sqlite_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("runs.sqlite3");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let context = context();
        let (run_id, box_id) = {
            let db = connect(&url, 1).await.unwrap();
            migrate(&db).await.unwrap();
            seed_account(&db, context).await;
            let boxes = SeaRepository::new(db.clone());
            let box_value = box_value(context);
            BoxRepository::create(&boxes, context, &box_value)
                .await
                .unwrap();
            let store = RunStore::new(db);
            let run = Run::new_agent(
                context,
                box_value.id,
                "persist",
                None,
                UtcEpochMillis::from_millis(100),
            )
            .unwrap();
            store.create_run(context, &run).await.unwrap();
            store
                .append_run_event(
                    context,
                    &RunEvent {
                        run_id: run.id,
                        account_id: context.account_id,
                        tenant_id: context.tenant_id,
                        sequence: 0,
                        event_type: RunEventType::RunStart,
                        payload_json: format!(r#"{{"run_id":"{}"}}"#, run.id),
                        created_at: UtcEpochMillis::from_millis(101),
                    },
                )
                .await
                .unwrap();
            (run.id, box_value.id)
        };

        let reopened = connect(&url, 1).await.unwrap();
        migrate(&reopened).await.unwrap();
        let store = RunStore::new(reopened);
        assert_eq!(store.list_runs(context, box_id).await.unwrap().len(), 1);
        let events = store
            .replay_run_events(context, run_id, None)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[0].event_type, RunEventType::RunStart);
    }
    #[tokio::test]
    async fn optimistic_idempotency_and_no_plaintext_key() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let repo = SeaRepository::new(db.clone());
        let c = context();
        seed_account(&db, c).await;
        let mut b = box_value(c);
        BoxRepository::create(&repo, c, &b).await.unwrap();
        let persisted_version = b.version;
        b.transition(BoxStatus::Idle, UtcEpochMillis::from_millis(2))
            .unwrap();
        b.spec.labels = vec![Label::new("updated").unwrap()];
        BoxRepository::save(&repo, c, &b, persisted_version)
            .await
            .unwrap();
        assert_eq!(repo.find(c, b.id).await.unwrap().unwrap(), b);
        assert_eq!(
            BoxRepository::save(&repo, c, &b, persisted_version)
                .await
                .unwrap_err()
                .code,
            "version_conflict"
        );
        let lease = BoxLeaseToken::new("lease-1").unwrap();
        let other_lease = BoxLeaseToken::new("lease-2").unwrap();
        assert!(
            repo.acquire_lease(c, b.id, &lease, Duration::from_secs(30))
                .await
                .unwrap()
        );
        assert!(
            repo.renew_lease(c, b.id, &lease, Duration::from_secs(30))
                .await
                .unwrap()
        );
        assert!(
            !repo
                .renew_lease(c, b.id, &other_lease, Duration::from_secs(30))
                .await
                .unwrap()
        );
        assert!(!repo.release_lease(c, b.id, &other_lease).await.unwrap());
        assert!(
            !repo
                .renew_lease(context(), b.id, &lease, Duration::from_secs(30))
                .await
                .unwrap()
        );
        assert!(repo.release_lease(c, b.id, &lease).await.unwrap());
        assert!(!repo.release_lease(c, b.id, &lease).await.unwrap());
        assert!(
            repo.acquire_lease(c, b.id, &lease, Duration::from_secs(30))
                .await
                .unwrap()
        );
        boxes::Entity::update_many()
            .col_expr(
                boxes::Column::LeaseExpiresAt,
                sea_orm::sea_query::Expr::value(Some(now() - 1)),
            )
            .filter(boxes::Column::Id.eq(b.id.to_string()))
            .exec(db.connection())
            .await
            .unwrap();
        assert!(
            !repo
                .renew_lease(c, b.id, &lease, Duration::from_secs(30))
                .await
                .unwrap()
        );
        let k = IdempotencyKey::new("delete-1").unwrap();
        assert_eq!(
            repo.delete_idempotently(c, b.id, &k).await.unwrap(),
            repo.delete_idempotently(c, b.id, &k).await.unwrap()
        );
        assert!(ApiKeyStore::new(db.clone(), b"short").is_err());
        let keys = ApiKeyStore::new(db.clone(), [7_u8; 32]).unwrap();
        let scopes = BTreeSet::from([AuthScope::BoxesRead]);
        keys.store(c, "bx_abc", "super-secret", scopes.clone(), None)
            .await
            .unwrap();
        keys.store(
            c,
            "bx_abc",
            "same-prefix-secret",
            BTreeSet::from([AuthScope::BoxesWrite]),
            None,
        )
        .await
        .unwrap();
        assert!(
            keys.authenticate("bx_abc", "super-secret")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            keys.authenticate("bx_abc", "wrong-secret").await.unwrap(),
            None
        );
        assert_eq!(
            keys.store(c, "bx_duplicate", "super-secret", BTreeSet::new(), None,)
                .await
                .unwrap_err()
                .code,
            "state_conflict"
        );
        assert!(
            keys.authenticate("bx_abc", "same-prefix-secret")
                .await
                .unwrap()
                .unwrap()
                .scopes
                .contains(&AuthScope::BoxesWrite)
        );
        let other = context();
        seed_account(&db, other).await;
        keys.store(
            other,
            "bx_abc",
            "other-secret",
            BTreeSet::from([AuthScope::Admin]),
            None,
        )
        .await
        .unwrap();
        let authorized = keys
            .authenticate("bx_abc", "other-secret")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authorized.account, other);
        assert!(authorized.scopes.contains(&AuthScope::Admin));
        keys.store(
            c,
            "bx_expired",
            "expired-secret",
            BTreeSet::new(),
            Some(now()),
        )
        .await
        .unwrap();
        assert_eq!(
            keys.authenticate("bx_expired", "expired-secret")
                .await
                .unwrap(),
            None
        );
        let stored = api_keys::Entity::find_by_id(
            keys.store(c, "bx_def", "another-secret", BTreeSet::new(), None)
                .await
                .unwrap()
                .id,
        )
        .one(db.connection())
        .await
        .unwrap()
        .unwrap()
        .key_hmac;
        assert_ne!(stored, "another-secret");
        assert!(!stored.contains("another-secret"));
        let nullable = api_keys::Entity::find_by_id(
            keys.store(c, "bx_null", "null-secret", BTreeSet::new(), None)
                .await
                .unwrap()
                .id,
        )
        .one(db.connection())
        .await
        .unwrap()
        .unwrap();
        assert_eq!(nullable.last_used_at, None);
        assert_eq!(nullable.expires_at, None);
    }

    #[tokio::test]
    async fn skills_are_tenant_scoped_upserted_and_source_pinned() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let context = context();
        seed_account(&db, context).await;
        let boxes = SeaRepository::new(db.clone());
        let value = box_value(context);
        BoxRepository::create(&boxes, context, &value)
            .await
            .unwrap();
        let skills = SkillStore::new(db);
        let mut skill = box_core::EnabledSkill::new(
            context,
            value.id,
            "upstash/context7/context7-cli".into(),
            "a".repeat(40),
            "b".repeat(64),
            UtcEpochMillis::from_millis(10),
        )
        .unwrap();
        box_core::SkillRepository::upsert_skill(&skills, context, &skill)
            .await
            .unwrap();
        assert_eq!(
            box_core::SkillRepository::list_skills(&skills, context, value.id)
                .await
                .unwrap(),
            vec![skill.clone()]
        );

        skill.source_commit = "c".repeat(40);
        skill.content_sha256 = "d".repeat(64);
        skill.updated_at = UtcEpochMillis::from_millis(11);
        box_core::SkillRepository::upsert_skill(&skills, context, &skill)
            .await
            .unwrap();
        let updated = box_core::SkillRepository::list_skills(&skills, context, value.id)
            .await
            .unwrap();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].source_commit, "c".repeat(40));
        assert_eq!(updated[0].content_sha256, "d".repeat(64));

        let other_tenant = AccountContext {
            account_id: context.account_id,
            tenant_id: TenantId::new(),
        };
        assert!(
            box_core::SkillRepository::list_skills(&skills, other_tenant, value.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !box_core::SkillRepository::delete_skill(
                &skills,
                other_tenant,
                value.id,
                &skill.skill_id,
            )
            .await
            .unwrap()
        );
        assert!(
            box_core::SkillRepository::delete_skill(&skills, context, value.id, &skill.skill_id,)
                .await
                .unwrap()
        );
        assert!(
            box_core::SkillRepository::list_skills(&skills, context, value.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn sqlite_file_allows_only_one_active_handle_and_releases_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("boxd.sqlite3");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let first = connect(&url, 2).await.unwrap();
        let held = first.begin().await.unwrap();
        assert_eq!(pragma_i64(&held, "foreign_keys").await, 1);
        assert_eq!(pragma_i64(&held, "busy_timeout").await, 5_000);
        assert_eq!(pragma_i64(first.connection(), "foreign_keys").await, 1);
        assert_eq!(pragma_i64(first.connection(), "busy_timeout").await, 5_000);
        assert_eq!(
            pragma_string(first.connection(), "journal_mode").await,
            "wal"
        );
        held.rollback().await.unwrap();
        let error = match connect(&url, 2).await {
            Ok(_) => panic!("second SQLite handle unexpectedly acquired the instance lock"),
            Err(error) => error,
        };
        assert_eq!(error.code, "database_instance_locked");
        #[cfg(unix)]
        {
            let alias = temp.path().join("boxd-alias.sqlite3");
            std::fs::hard_link(&path, &alias).unwrap();
            let alias_url = format!("sqlite://{}?mode=rwc", alias.display());
            let alias_error = match connect(&alias_url, 1).await {
                Ok(_) => panic!("hard-link alias unexpectedly bypassed the SQLite lock"),
                Err(error) => error,
            };
            assert_eq!(alias_error.code, "validation_error");
            std::fs::remove_file(alias).unwrap();
        }
        drop(first);
        connect(&url, 2).await.unwrap();
    }
}
