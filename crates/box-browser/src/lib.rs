//! Phase-3 browser domain and driver boundary.
//!
//! This crate deliberately contains no Salvo handlers, persistence, or direct
//! Chromium process management. A guest-side adapter implements [`BrowserDriver`]
//! and the application service maps its typed results to the pinned SDK wire.

use async_trait::async_trait;
use box_core::{AccountContext, AccountId, BoxId, DomainError, TenantId, UtcEpochMillis};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

const MAX_URL_BYTES: usize = 16 * 1024;
const MAX_TAB_ID_BYTES: usize = 512;
const MAX_INSTRUCTION_BYTES: usize = 128 * 1024;
const MAX_SCHEMA_BYTES: usize = 1024 * 1024;
const MAX_NAVIGATION_TIMEOUT_MS: u64 = 2_147_000_000;
pub const DEFAULT_RECORDING_DURATION_SECONDS: u32 = 600;
pub const MAX_RECORDING_DURATION_SECONDS: u32 = 600;
pub const RECORDING_RETENTION_MILLIS: i64 = 14 * 24 * 60 * 60 * 1_000;

pub fn validate_recording_segment_name(raw: &str) -> Result<(), DomainError> {
    let digits = raw
        .strip_prefix("segment-")
        .and_then(|value| value.strip_suffix(".ts"))
        .ok_or_else(|| DomainError::validation("invalid browser recording segment"))?;
    if digits.len() != 5 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DomainError::validation("invalid browser recording segment"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BrowserRecordingId(uuid::Uuid);

impl BrowserRecordingId {
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }

    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let value = uuid::Uuid::parse_str(raw)
            .map_err(|_| DomainError::validation("invalid browser recording id"))?;
        if value.get_version_num() != 7 {
            return Err(DomainError::validation("invalid browser recording id"));
        }
        Ok(Self(value))
    }
}

impl Default for BrowserRecordingId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for BrowserRecordingId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserRecordingStatus {
    Recording,
    Completed,
    Failed,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserRecordingMarker {
    #[serde(rename = "type")]
    pub marker_type: String,
    pub at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tab_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserRecording {
    pub id: BrowserRecordingId,
    pub account_id: AccountId,
    pub tenant_id: TenantId,
    pub box_id: BoxId,
    pub status: BrowserRecordingStatus,
    pub started_at: UtcEpochMillis,
    pub ended_at: Option<UtcEpochMillis>,
    pub duration_ms: Option<u64>,
    pub size_bytes: Option<u64>,
    pub segment_count: Option<u32>,
    pub mp4_size_bytes: Option<u64>,
    pub stopped_reason: Option<String>,
    pub max_duration_seconds: u32,
    pub markers: Vec<BrowserRecordingMarker>,
    pub playlist_path: Option<String>,
    pub download_path: Option<String>,
    pub retention_at: UtcEpochMillis,
    pub updated_at: UtcEpochMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserRecordingUsage {
    pub retained_bytes: u64,
    pub active_count: u32,
}

impl BrowserRecording {
    pub fn new(
        context: AccountContext,
        box_id: BoxId,
        max_duration_seconds: u32,
        now: UtcEpochMillis,
    ) -> Result<Self, DomainError> {
        if max_duration_seconds == 0 || max_duration_seconds > MAX_RECORDING_DURATION_SECONDS {
            return Err(DomainError::validation(
                "recording max_duration_seconds must be between 1 and 600",
            ));
        }
        Ok(Self {
            id: BrowserRecordingId::new(),
            account_id: context.account_id,
            tenant_id: context.tenant_id,
            box_id,
            status: BrowserRecordingStatus::Recording,
            started_at: now,
            ended_at: None,
            duration_ms: None,
            size_bytes: None,
            segment_count: None,
            mp4_size_bytes: None,
            stopped_reason: None,
            max_duration_seconds,
            markers: Vec::new(),
            playlist_path: None,
            download_path: None,
            retention_at: UtcEpochMillis::from_millis(
                now.as_millis().saturating_add(RECORDING_RETENTION_MILLIS),
            ),
            updated_at: now,
        })
    }

    pub fn validate_scope(&self, context: AccountContext) -> Result<(), DomainError> {
        if self.account_id != context.account_id || self.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        }
        Ok(())
    }
}

#[async_trait]
pub trait BrowserRecordingRepository: Send + Sync {
    async fn create(
        &self,
        context: AccountContext,
        recording: &BrowserRecording,
    ) -> Result<(), DomainError>;
    async fn save(
        &self,
        context: AccountContext,
        recording: &BrowserRecording,
    ) -> Result<(), DomainError>;
    async fn find(
        &self,
        context: AccountContext,
        box_id: BoxId,
        id: BrowserRecordingId,
    ) -> Result<Option<BrowserRecording>, DomainError>;
    async fn list(
        &self,
        context: AccountContext,
        box_id: BoxId,
        cursor: Option<BrowserRecordingId>,
        limit: usize,
    ) -> Result<Vec<BrowserRecording>, DomainError>;
    async fn active(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> Result<Option<BrowserRecording>, DomainError>;
    async fn active_all(&self) -> Result<Vec<BrowserRecording>, DomainError>;
    async fn usage(&self, context: AccountContext) -> Result<BrowserRecordingUsage, DomainError>;
    async fn expired(
        &self,
        at: UtcEpochMillis,
        limit: usize,
    ) -> Result<Vec<BrowserRecording>, DomainError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WaitUntil {
    Load,
    Domcontentloaded,
    Networkidle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTab {
    pub url: String,
    #[serde(default)]
    pub wait_until: Option<WaitUntil>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

impl CreateTab {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_url(&self.url)?;
        if self
            .timeout
            .is_some_and(|timeout| timeout > MAX_NAVIGATION_TIMEOUT_MS)
        {
            return Err(DomainError::validation("browser timeout exceeds limit"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Navigate {
    pub url: String,
    pub tab: String,
}

impl Navigate {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_url(&self.url)?;
        validate_tab_id(&self.tab)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserTab {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserLink {
    pub text: String,
    pub href: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserContent {
    pub title: String,
    pub url: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<BrowserLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screenshot {
    pub tab: String,
    pub full_page: bool,
}

impl Screenshot {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_tab_id(&self.tab)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserInstruction {
    pub instruction: String,
    pub tab: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub schema: Option<Value>,
}

impl BrowserInstruction {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.instruction.is_empty() || self.instruction.len() > MAX_INSTRUCTION_BYTES {
            return Err(DomainError::validation("invalid browser instruction"));
        }
        validate_tab_id(&self.tab)?;
        if self.model.as_deref().is_some_and(str::is_empty) {
            return Err(DomainError::validation("browser model must not be empty"));
        }
        if self.schema.as_ref().is_some_and(|schema| {
            serde_json::to_vec(schema)
                .map(|wire| wire.len() > MAX_SCHEMA_BYTES)
                .unwrap_or(true)
        }) {
            return Err(DomainError::validation("browser schema exceeds limit"));
        }
        Ok(())
    }

    pub fn validate_extract(&self) -> Result<(), DomainError> {
        self.validate()?;
        if self.schema.is_none() {
            return Err(DomainError::validation(
                "browser extract schema is required",
            ));
        }
        Ok(())
    }

    pub fn validate_without_schema(&self) -> Result<(), DomainError> {
        self.validate()?;
        if self.schema.is_some() {
            return Err(DomainError::validation(
                "browser operation does not accept a schema",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRunInstruction {
    pub prompt: String,
    pub tab: String,
    #[serde(default)]
    pub schema: Option<Value>,
    #[serde(default)]
    pub max_steps: Option<u8>,
    #[serde(default)]
    pub model: Option<String>,
}

impl BrowserRunInstruction {
    pub fn validate(&self) -> Result<(), DomainError> {
        BrowserInstruction {
            instruction: self.prompt.clone(),
            tab: self.tab.clone(),
            model: self.model.clone(),
            schema: self.schema.clone(),
        }
        .validate()?;
        if self.max_steps.is_some_and(|steps| steps == 0 || steps > 30) {
            return Err(DomainError::validation(
                "browser max_steps must be between 1 and 30",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserObserveElement {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserObserveResult {
    pub elements: Vec<BrowserObserveElement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserActAction {
    pub selector: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserActResult {
    pub success: bool,
    pub message: String,
    pub action_description: String,
    pub actions: Vec<BrowserActAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_status: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserRunStep {
    pub step: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserRunResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    pub result: String,
    pub completed: bool,
    pub steps: Vec<BrowserRunStep>,
    pub step_count: u8,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[async_trait]
pub trait BrowserDriver: Send + Sync {
    async fn create_tab(&self, request: CreateTab) -> Result<BrowserTab, DomainError>;
    async fn list_tabs(&self) -> Result<Vec<BrowserTab>, DomainError>;
    async fn close_tab(&self, tab_id: &str) -> Result<(), DomainError>;
    async fn goto(&self, request: Navigate) -> Result<BrowserContent, DomainError>;
    async fn content(&self, tab_id: &str) -> Result<BrowserContent, DomainError>;
    async fn screenshot(&self, request: Screenshot) -> Result<Vec<u8>, DomainError>;
}

pub fn validate_tab_id(tab_id: &str) -> Result<(), DomainError> {
    if tab_id.is_empty()
        || tab_id.len() > MAX_TAB_ID_BYTES
        || !tab_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DomainError::validation("invalid browser tab id"));
    }
    Ok(())
}

fn validate_url(raw: &str) -> Result<(), DomainError> {
    if raw.is_empty() || raw.len() > MAX_URL_BYTES {
        return Err(DomainError::validation("invalid browser URL"));
    }
    if raw == "about:blank" {
        return Ok(());
    }
    let parsed = Url::parse(raw).map_err(|_| DomainError::validation("invalid browser URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(DomainError::validation(
            "browser URL must be an unauthenticated http or https URL",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_create_tab_wire_and_limits_are_strict() {
        let request: CreateTab = serde_json::from_str(
            r#"{"url":"https://example.invalid","wait_until":"networkidle","timeout":0}"#,
        )
        .unwrap();
        request.validate().unwrap();
        CreateTab {
            url: "about:blank".into(),
            wait_until: Some(WaitUntil::Load),
            timeout: None,
        }
        .validate()
        .unwrap();
        assert_eq!(request.wait_until, Some(WaitUntil::Networkidle));
        assert!(
            serde_json::from_str::<CreateTab>(
                r#"{"url":"https://example.invalid","ignored":true}"#
            )
            .is_err()
        );
        assert!(
            CreateTab {
                url: "file:///etc/passwd".into(),
                wait_until: None,
                timeout: None,
            }
            .validate()
            .is_err()
        );
        assert!(
            CreateTab {
                url: "about:blank#fragment".into(),
                wait_until: None,
                timeout: None,
            }
            .validate()
            .is_err()
        );
        assert!(
            CreateTab {
                url: "https://user:secret@example.invalid/".into(),
                wait_until: None,
                timeout: None,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn instructions_and_tab_ids_are_bounded() {
        assert!(validate_tab_id("tab_fixture-1.2").is_ok());
        assert!(validate_tab_id("tab/escape").is_err());
        assert!(
            BrowserInstruction {
                instruction: "extract".into(),
                tab: "tab_fixture".into(),
                model: None,
                schema: Some(serde_json::json!({"type":"object"})),
            }
            .validate()
            .is_ok()
        );
    }
}
