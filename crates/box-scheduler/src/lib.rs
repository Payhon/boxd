//! Durable UTC schedule domain and repository boundary.
//!
//! HTTP DTOs remain in `box-api`; database models remain in `box-db`. This crate owns the
//! phase-3 scheduling invariants shared by both sides.

use std::{collections::BTreeMap, str::FromStr, time::Duration};

use async_trait::async_trait;
use box_core::{AccountContext, BoxId, DomainError, RunId, UtcEpochMillis};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_CRON_BYTES: usize = 256;
const MAX_COMMAND_ARGS: usize = 240;
const MAX_COMMAND_ARG_BYTES: usize = 16 * 1024;
const MAX_COMMAND_BYTES: usize = 48 * 1024;
const MAX_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_FOLDER_BYTES: usize = 4 * 1024;
const MAX_MODEL_BYTES: usize = 255;
const MAX_WEBHOOK_HEADERS: usize = 32;
const MAX_WEBHOOK_HEADER_BYTES: usize = 8 * 1024;
const MAX_TIMEOUT_MILLIS: u64 = 300_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScheduleId(Uuid);

impl ScheduleId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn parse(raw: &str) -> box_core::Result<Self> {
        let id =
            Uuid::parse_str(raw).map_err(|_| DomainError::validation("invalid schedule id"))?;
        if id.get_version_num() != 7 {
            return Err(DomainError::validation("schedule id must be UUIDv7"));
        }
        Ok(Self(id))
    }

    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ScheduleId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ScheduleId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleKind {
    Exec,
    Prompt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    Active,
    Paused,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtcCron(String);

impl UtcCron {
    pub fn parse(raw: impl Into<String>) -> box_core::Result<Self> {
        let raw = raw.into();
        if raw.is_empty()
            || raw.len() > MAX_CRON_BYTES
            || raw.as_bytes().contains(&0)
            || raw.split_whitespace().count() != 5
        {
            return Err(DomainError::validation(
                "cron must be a five-field UTC expression",
            ));
        }
        Self::compiled(&raw)?;
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn next_after(&self, after: UtcEpochMillis) -> box_core::Result<UtcEpochMillis> {
        let after = Utc
            .timestamp_millis_opt(after.as_millis())
            .single()
            .ok_or_else(|| DomainError::validation("invalid scheduler timestamp"))?;
        let next = Self::compiled(&self.0)?
            .after(&after)
            .next()
            .ok_or_else(|| DomainError::validation("cron has no future occurrence"))?;
        Ok(UtcEpochMillis::from_millis(next.timestamp_millis()))
    }

    fn compiled(raw: &str) -> box_core::Result<cron::Schedule> {
        cron::Schedule::from_str(&format!("0 {raw}"))
            .map_err(|_| DomainError::validation("invalid UTC cron expression"))
    }
}

impl Serialize for UtcCron {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for UtcCron {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScheduleSpec {
    pub kind: ScheduleKind,
    pub cron: UtcCron,
    pub command: Option<Vec<String>>,
    pub prompt: Option<String>,
    pub folder: String,
    pub model: Option<String>,
    pub agent_options: Option<Value>,
    pub timeout_millis: Option<u64>,
    pub webhook_url: Option<String>,
    pub webhook_headers: BTreeMap<String, String>,
}

impl ScheduleSpec {
    pub fn validate(&self) -> box_core::Result<()> {
        match self.kind {
            ScheduleKind::Exec => {
                validate_command(self.command.as_deref())?;
                if self.prompt.is_some() || self.model.is_some() || self.agent_options.is_some() {
                    return Err(DomainError::validation(
                        "exec schedules cannot contain prompt or agent options",
                    ));
                }
            }
            ScheduleKind::Prompt => {
                validate_prompt(self.prompt.as_deref())?;
                if self.command.is_some() {
                    return Err(DomainError::validation(
                        "prompt schedules cannot contain command",
                    ));
                }
            }
        }
        validate_folder(&self.folder)?;
        validate_optional_text(self.model.as_deref(), MAX_MODEL_BYTES, "model")?;
        if self
            .timeout_millis
            .is_some_and(|value| value == 0 || value > MAX_TIMEOUT_MILLIS)
        {
            return Err(DomainError::validation(
                "schedule timeout must be between 1 and 300000 milliseconds",
            ));
        }
        validate_optional_text(
            self.webhook_url.as_deref(),
            MAX_WEBHOOK_HEADER_BYTES,
            "webhook URL",
        )?;
        validate_webhook_headers(&self.webhook_headers)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SchedulePatch {
    pub cron: Option<UtcCron>,
    pub command: Option<Option<Vec<String>>>,
    pub prompt: Option<Option<String>>,
    pub folder: Option<String>,
    pub model: Option<Option<String>>,
    pub agent_options: Option<Option<Value>>,
    pub timeout_millis: Option<Option<u64>>,
    pub webhook_url: Option<Option<String>>,
    pub webhook_headers: Option<BTreeMap<String, String>>,
}

impl SchedulePatch {
    pub fn apply(self, spec: &mut ScheduleSpec) -> box_core::Result<()> {
        if let Some(value) = self.cron {
            spec.cron = value;
        }
        if let Some(value) = self.command {
            spec.command = value;
        }
        if let Some(value) = self.prompt {
            spec.prompt = value;
        }
        if let Some(value) = self.folder {
            spec.folder = value;
        }
        if let Some(value) = self.model {
            spec.model = value;
        }
        if let Some(value) = self.agent_options {
            spec.agent_options = value;
        }
        if let Some(value) = self.timeout_millis {
            spec.timeout_millis = value;
        }
        if let Some(value) = self.webhook_url {
            spec.webhook_url = value;
        }
        if let Some(value) = self.webhook_headers {
            spec.webhook_headers = value;
        }
        spec.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SchedulePayload {
    pub spec: ScheduleSpec,
    pub last_run_at: Option<i64>,
    pub last_run_status: Option<String>,
    pub last_run_id: Option<String>,
    pub total_runs: u64,
    pub total_failures: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScheduledTask {
    pub id: ScheduleId,
    pub context: AccountContext,
    pub box_id: BoxId,
    pub payload: SchedulePayload,
    pub status: ScheduleStatus,
    pub next_run_at: UtcEpochMillis,
    pub created_at: UtcEpochMillis,
    pub updated_at: UtcEpochMillis,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ScheduleLeaseToken(String);

impl ScheduleLeaseToken {
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn expose_for_storage(&self) -> &str {
        &self.0
    }
}

impl Default for ScheduleLeaseToken {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ScheduleLeaseToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScheduleLeaseToken([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScheduleClaim {
    pub task: ScheduledTask,
    pub scheduled_at: UtcEpochMillis,
    pub lease_token: ScheduleLeaseToken,
}

impl ScheduleClaim {
    pub fn idempotency_key(&self) -> String {
        self.task.idempotency_key(self.scheduled_at)
    }

    /// Stable run identity for prompt occurrences. The guest uses the same
    /// UUID after a control-plane restart, so its completed-execution replay
    /// cache can return the original harness frames without executing twice.
    pub fn run_id(&self) -> RunId {
        let mut digest = Sha256::new();
        digest.update(self.task.id.as_uuid().as_bytes());
        digest.update(self.scheduled_at.as_millis().to_be_bytes());
        let digest = digest.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        // Mark the deterministic digest with RFC 4122 variant/version bits.
        bytes[6] = (bytes[6] & 0x0f) | 0x50;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        RunId::parse(&Uuid::from_bytes(bytes).to_string())
            .expect("deterministic UUID is a valid non-nil run id")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleRunStatus {
    Completed,
    Failed,
    Skipped,
}

impl ScheduleRunStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleRunOutcome {
    pub run_id: String,
    pub status: ScheduleRunStatus,
    pub completed_at: UtcEpochMillis,
}

impl ScheduledTask {
    pub fn new(
        context: AccountContext,
        box_id: BoxId,
        spec: ScheduleSpec,
        now: UtcEpochMillis,
    ) -> box_core::Result<Self> {
        spec.validate()?;
        let next_run_at = spec.cron.next_after(now)?;
        Ok(Self {
            id: ScheduleId::new(),
            context,
            box_id,
            payload: SchedulePayload {
                spec,
                last_run_at: None,
                last_run_status: None,
                last_run_id: None,
                total_runs: 0,
                total_failures: 0,
            },
            status: ScheduleStatus::Active,
            next_run_at,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn idempotency_key(&self, scheduled_at: UtcEpochMillis) -> String {
        format!("schedule-{}-{}", self.id, scheduled_at.as_millis())
    }
}

#[async_trait]
pub trait ScheduleRepository: Send + Sync {
    async fn create(&self, task: &ScheduledTask) -> box_core::Result<()>;
    async fn find(
        &self,
        context: AccountContext,
        box_id: BoxId,
        schedule_id: ScheduleId,
    ) -> box_core::Result<Option<ScheduledTask>>;
    async fn list(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Vec<ScheduledTask>>;
    async fn save(&self, task: &ScheduledTask) -> box_core::Result<()>;
    async fn delete(
        &self,
        context: AccountContext,
        box_id: BoxId,
        schedule_id: ScheduleId,
    ) -> box_core::Result<bool>;
    /// Deletes every schedule owned by one box. Callers must serialize this
    /// with box lifecycle operations so an in-flight occurrence cannot race a
    /// destructive box cleanup.
    async fn delete_all(&self, context: AccountContext, box_id: BoxId) -> box_core::Result<u64>;
    /// Atomically claims due active schedules. A failed worker leaves `next_run_at`
    /// unchanged so another holder retries the same deterministic occurrence after
    /// the lease expires.
    async fn claim_due(
        &self,
        now: UtcEpochMillis,
        lease_ttl: Duration,
        limit: usize,
    ) -> box_core::Result<Vec<ScheduleClaim>>;
    async fn renew_claim(
        &self,
        claim: &ScheduleClaim,
        now: UtcEpochMillis,
        lease_ttl: Duration,
    ) -> box_core::Result<bool>;
    /// Settles only when the opaque lease still matches, advances the cron from
    /// the claimed occurrence, updates public counters, and clears the lease.
    async fn settle_claim(
        &self,
        claim: &ScheduleClaim,
        outcome: ScheduleRunOutcome,
    ) -> box_core::Result<bool>;
}

fn validate_command(command: Option<&[String]>) -> box_core::Result<()> {
    let command = command.filter(|value| !value.is_empty()).ok_or_else(|| {
        DomainError::validation("exec schedule command must contain at least one argument")
    })?;
    if command.len() > MAX_COMMAND_ARGS {
        return Err(DomainError::validation(
            "exec schedule command has too many arguments",
        ));
    }
    let mut total = 0usize;
    for argument in command {
        if argument.is_empty()
            || argument.len() > MAX_COMMAND_ARG_BYTES
            || argument.as_bytes().contains(&0)
        {
            return Err(DomainError::validation(
                "exec schedule contains an invalid command argument",
            ));
        }
        total = total.saturating_add(argument.len());
    }
    if total > MAX_COMMAND_BYTES {
        return Err(DomainError::validation(
            "exec schedule command exceeds the total size limit",
        ));
    }
    Ok(())
}

fn validate_prompt(prompt: Option<&str>) -> box_core::Result<()> {
    let prompt = prompt
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DomainError::validation("prompt schedule requires a non-empty prompt"))?;
    if prompt.len() > MAX_PROMPT_BYTES || prompt.as_bytes().contains(&0) {
        return Err(DomainError::validation("invalid schedule prompt"));
    }
    Ok(())
}

fn validate_folder(folder: &str) -> box_core::Result<()> {
    if folder.is_empty()
        || folder.len() > MAX_FOLDER_BYTES
        || folder.as_bytes().contains(&0)
        || (!folder.starts_with("/workspace/home") && !folder.starts_with("/home/boxuser"))
        || folder.split('/').any(|part| part == "..")
    {
        return Err(DomainError::validation("invalid schedule folder"));
    }
    Ok(())
}

fn validate_optional_text(value: Option<&str>, limit: usize, label: &str) -> box_core::Result<()> {
    if value.is_some_and(|value| {
        value.is_empty() || value.len() > limit || value.as_bytes().contains(&0)
    }) {
        return Err(DomainError::validation(format!("invalid schedule {label}")));
    }
    Ok(())
}

fn validate_webhook_headers(headers: &BTreeMap<String, String>) -> box_core::Result<()> {
    if headers.len() > MAX_WEBHOOK_HEADERS {
        return Err(DomainError::validation("too many schedule webhook headers"));
    }
    for (name, value) in headers {
        if name.is_empty()
            || name.len() > 256
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.len() > MAX_WEBHOOK_HEADER_BYTES
            || value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err(DomainError::validation("invalid schedule webhook header"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use box_core::{AccountId, TenantId};

    fn context() -> AccountContext {
        AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        }
    }

    fn exec_spec(cron: &str) -> ScheduleSpec {
        ScheduleSpec {
            kind: ScheduleKind::Exec,
            cron: UtcCron::parse(cron).unwrap(),
            command: Some(vec!["printf".into(), "ok".into()]),
            prompt: None,
            folder: "/workspace/home".into(),
            model: None,
            agent_options: None,
            timeout_millis: None,
            webhook_url: None,
            webhook_headers: BTreeMap::new(),
        }
    }

    #[test]
    fn utc_cron_is_five_fields_and_computes_the_next_minute() {
        let cron = UtcCron::parse("* * * * *").unwrap();
        let next = cron
            .next_after(UtcEpochMillis::from_millis(1_700_000_000_123))
            .unwrap();
        assert_eq!(next.as_millis(), 1_700_000_040_000);
        assert!(UtcCron::parse("0 * * * * *").is_err());
        assert!(UtcCron::parse("61 * * * *").is_err());
    }

    #[test]
    fn schedule_kind_rejects_cross_kind_payloads() {
        let mut spec = exec_spec("0 9 * * *");
        spec.prompt = Some("not allowed".into());
        assert!(spec.validate().is_err());

        spec.kind = ScheduleKind::Prompt;
        spec.command = None;
        assert!(spec.validate().is_ok());
        spec.prompt = None;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn patch_preserves_omitted_fields_and_revalidates() {
        let mut spec = exec_spec("0 9 * * *");
        SchedulePatch {
            cron: Some(UtcCron::parse("30 10 * * 1-5").unwrap()),
            folder: Some("/workspace/home/project".into()),
            ..SchedulePatch::default()
        }
        .apply(&mut spec)
        .unwrap();
        assert_eq!(spec.cron.as_str(), "30 10 * * 1-5");
        assert_eq!(spec.command.as_ref().unwrap()[0], "printf");

        let error = SchedulePatch {
            command: Some(None),
            ..SchedulePatch::default()
        }
        .apply(&mut spec)
        .unwrap_err();
        assert_eq!(error.code, "validation_error");
    }

    #[test]
    fn idempotency_key_binds_schedule_and_occurrence() {
        let now = UtcEpochMillis::from_millis(1_700_000_000_000);
        let task =
            ScheduledTask::new(context(), BoxId::new(), exec_spec("* * * * *"), now).unwrap();
        let first = task.idempotency_key(UtcEpochMillis::from_millis(1_700_000_040_000));
        assert_eq!(
            first,
            task.idempotency_key(UtcEpochMillis::from_millis(1_700_000_040_000))
        );
        assert_ne!(
            first,
            task.idempotency_key(UtcEpochMillis::from_millis(1_700_000_100_000))
        );
        let first_claim = ScheduleClaim {
            task: task.clone(),
            scheduled_at: UtcEpochMillis::from_millis(1_700_000_040_000),
            lease_token: ScheduleLeaseToken::new(),
        };
        let retry_claim = ScheduleClaim {
            lease_token: ScheduleLeaseToken::new(),
            ..first_claim.clone()
        };
        assert_eq!(first_claim.run_id(), retry_claim.run_id());
        assert!(!format!("{task:?}").contains("secret-value"));
        let token = ScheduleLeaseToken::new();
        assert!(!format!("{token:?}").contains(token.expose_for_storage()));
    }
}
