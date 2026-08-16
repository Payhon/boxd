//! Salvo boundary for the pinned `@upstash/box@0.6.3` wire protocol.
//!
//! This crate deliberately owns HTTP decoding, authentication and response mapping only.
//! Database, filesystem and VMM access are injected behind the service ports below.

use std::{
    path::{Component, Path},
    pin::Pin,
    sync::Arc,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use box_browser::{
    BrowserActResult, BrowserContent, BrowserInstruction, BrowserObserveResult,
    BrowserRunInstruction, BrowserRunResult, BrowserTab, CreateTab, Navigate, Screenshot,
    WaitUntil,
};
use box_core::{
    AccountContext, AuthScope, AuthorizedContext, DomainError, DomainErrorKind, PreviewAuth,
};
use box_observability::{HttpSurface, Telemetry};
use futures_util::{SinkExt, Stream, StreamExt};
use opentelemetry::{global, propagation::Extractor};
use salvo::http::HeaderValue;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use salvo_extra::websocket::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{Message as TungsteniteMessage, protocol::WebSocketConfig};
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

const MAX_UPLOAD_FILES: usize = 32;
const MAX_UPLOAD_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_UPLOAD_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_CUSTOM_HARNESS_ARGS: usize = 240;
const MAX_CUSTOM_HARNESS_ARG_BYTES: usize = 16 * 1024;
const MAX_CUSTOM_HARNESS_ARGS_BYTES: usize = 48 * 1024;

fn valid_custom_harness_command(command: &str) -> bool {
    if command.is_empty() || command.len() > 64 * 1024 || command.as_bytes().contains(&0) {
        return false;
    }
    let path = Path::new(command);
    if !path.is_absolute() {
        return !command.contains('/') && !matches!(command, "." | "..");
    }
    [Path::new("/workspace/home"), Path::new("/home/boxuser")]
        .into_iter()
        .filter_map(|root| path.strip_prefix(root).ok())
        .any(|relative| {
            let mut components = relative.components();
            components
                .next()
                .is_some_and(|component| matches!(component, Component::Normal(_)))
                && components.all(|component| matches!(component, Component::Normal(_)))
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadFile {
    pub path: String,
    pub contents: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiRunEvent {
    pub run_id: String,
    pub sequence: u64,
    pub event_type: String,
    pub payload_json: String,
}

pub type ApiRunStream =
    Pin<Box<dyn Stream<Item = Result<ApiRunEvent, DomainError>> + Send + 'static>>;

pub trait AdminTerminal: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AdminTerminal for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub type AdminTerminalStream = Box<dyn AdminTerminal>;

pub struct BrowserCdpConnection {
    pub stream: AdminTerminalStream,
    pub websocket_path: String,
}

pub struct BrowserScreencastConnection {
    pub frames: BrowserScreencastStream,
}

pub type BrowserScreencastStream =
    Pin<Box<dyn Stream<Item = Result<Vec<u8>, DomainError>> + Send + 'static>>;

struct SseClientGuard(Arc<dyn Telemetry>);

impl SseClientGuard {
    fn new(telemetry: Arc<dyn Telemetry>) -> Self {
        telemetry.add_sse_clients(1);
        Self(telemetry)
    }
}

impl Drop for SseClientGuard {
    fn drop(&mut self) {
        self.0.add_sse_clients(-1);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub context: AccountContext,
    pub actor: &'static str,
    pub action: String,
    pub resource: String,
    pub request_id: String,
    pub ip: Option<String>,
    pub status_code: u16,
    pub succeeded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AuditLogEntry {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub request_id: Option<String>,
    pub ip: Option<String>,
    pub status_code: u16,
    pub succeeded: bool,
    pub created_at: i64,
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError>;
    async fn list(
        &self,
        context: AccountContext,
        limit: u64,
    ) -> Result<Vec<AuditLogEntry>, DomainError>;
}

pub struct NoopAuditSink;

#[async_trait]
impl AuditSink for NoopAuditSink {
    async fn record(&self, _: AuditEvent) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list(&self, _: AccountContext, _: u64) -> Result<Vec<AuditLogEntry>, DomainError> {
        Ok(Vec::new())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApiKeyFingerprint([u8; 32]);

impl ApiKeyFingerprint {
    pub fn from_api_key(api_key: &str) -> Self {
        Self(Sha256::digest(api_key.as_bytes()).into())
    }

    pub fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for ApiKeyFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApiKeyFingerprint([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestQuotaDecision {
    Allowed,
    Rejected { retry_after_seconds: u64 },
}

#[async_trait]
pub trait RequestQuota: Send + Sync {
    async fn check(
        &self,
        context: &AuthorizedContext,
        credential: ApiKeyFingerprint,
    ) -> Result<RequestQuotaDecision, DomainError>;
    async fn charge_traffic(
        &self,
        _context: &AuthorizedContext,
        _credential: ApiKeyFingerprint,
        _bytes: u64,
    ) -> Result<RequestQuotaDecision, DomainError> {
        Ok(RequestQuotaDecision::Allowed)
    }
}

pub struct UnlimitedRequestQuota;

#[async_trait]
impl RequestQuota for UnlimitedRequestQuota {
    async fn check(
        &self,
        _: &AuthorizedContext,
        _: ApiKeyFingerprint,
    ) -> Result<RequestQuotaDecision, DomainError> {
        Ok(RequestQuotaDecision::Allowed)
    }
}

/// Compatibility authentication is intentionally separate from console sessions.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, api_key: &str) -> Result<AuthorizedContext, DomainError>;
}

#[async_trait]
pub trait SessionAuthenticator: Send + Sync {
    async fn authenticate_session(
        &self,
        session: &str,
        csrf: &str,
    ) -> Result<AccountContext, DomainError>;
}

pub struct AdminLoginResult {
    pub session: String,
    pub csrf: String,
    pub expires_at_millis: i64,
}

#[async_trait]
pub trait AdminLoginService: Send + Sync {
    async fn login(&self, username: &str, password: &str) -> Result<AdminLoginResult, DomainError>;
    async fn logout(&self, session: &str, csrf: &str) -> Result<(), DomainError>;
}

/// Phase-1 application port. Implementations live in composition/application crates.
/// The JSON values are pinned wire shapes at this boundary, never SeaORM entities.
#[async_trait]
pub trait ApiServices: Send + Sync {
    /// The composition root must prove every required Phase-1 dependency before
    /// readiness can succeed. The default is deliberately fail-closed.
    async fn ready(&self) -> Result<(), DomainError> {
        Err(DomainError {
            kind: DomainErrorKind::Unavailable,
            code: "not_ready",
            message: "required services are not ready".into(),
        })
    }
    async fn create_box(
        &self,
        context: AccountContext,
        request: CreateBoxRequest,
    ) -> Result<Value, DomainError>;
    async fn create_box_from_snapshot(
        &self,
        _context: AccountContext,
        _request: CreateBoxRequest,
    ) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("from snapshot"))
    }
    async fn list_boxes(
        &self,
        context: AccountContext,
        label: Option<String>,
    ) -> Result<Value, DomainError>;
    async fn get_box(&self, context: AccountContext, box_id: &str) -> Result<Value, DomainError>;
    async fn box_status(&self, context: AccountContext, box_id: &str)
    -> Result<Value, DomainError>;
    async fn pause_box(&self, context: AccountContext, box_id: &str) -> Result<Value, DomainError>;
    async fn resume_box(&self, context: AccountContext, box_id: &str)
    -> Result<Value, DomainError>;
    async fn delete_box(&self, context: AccountContext, box_id: &str) -> Result<(), DomainError>;
    async fn bulk_delete_boxes(
        &self,
        context: AccountContext,
        box_ids: Vec<String>,
    ) -> Result<(), DomainError>;
    async fn exec(
        &self,
        context: AccountContext,
        box_id: &str,
        request: ExecRequest,
    ) -> Result<ExecResult, DomainError>;
    async fn code(
        &self,
        context: AccountContext,
        box_id: &str,
        request: CodeRequest,
    ) -> Result<CodeResult, DomainError>;
    async fn read_file(
        &self,
        context: AccountContext,
        box_id: &str,
        path: String,
        encoding: Option<String>,
    ) -> Result<Value, DomainError>;
    async fn write_file(
        &self,
        context: AccountContext,
        box_id: &str,
        request: WriteFileRequest,
    ) -> Result<(), DomainError>;
    async fn list_files(
        &self,
        context: AccountContext,
        box_id: &str,
        folder: String,
    ) -> Result<Vec<FileEntry>, DomainError>;
    async fn read_file_bytes(
        &self,
        context: AccountContext,
        box_id: &str,
        path: String,
    ) -> Result<Vec<u8>, DomainError>;
    async fn upload_files(
        &self,
        context: AccountContext,
        box_id: &str,
        files: Vec<UploadFile>,
    ) -> Result<(), DomainError>;
    async fn env(
        &self,
        context: AccountContext,
        box_id: Option<&str>,
        method: &str,
        key: Option<&str>,
        body: Option<Value>,
    ) -> Result<Value, DomainError>;
    async fn labels(
        &self,
        context: AccountContext,
        box_id: &str,
        method: &str,
        label: Option<&str>,
    ) -> Result<Value, DomainError>;
    async fn list_runs(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("run history"))
    }
    async fn run_stream(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: AgentRunRequest,
    ) -> Result<ApiRunStream, DomainError> {
        Err(DomainError::feature_not_supported("agent run stream"))
    }
    async fn run_webhook(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: AgentWebhookRunRequest,
    ) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("webhook run"))
    }
    async fn resume_run_stream(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _run_id: &str,
        _after_sequence: u64,
    ) -> Result<ApiRunStream, DomainError> {
        Err(DomainError::feature_not_supported("agent run replay"))
    }
    async fn logs(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _offset: usize,
        _limit: usize,
    ) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("box logs"))
    }
    async fn cancel_run(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _run_id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("run cancellation"))
    }
    async fn configure_model(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _model: String,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("model configuration"))
    }
    async fn configure_custom_runner(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _config: CustomAgentConfiguration,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported(
            "custom harness configuration",
        ))
    }
    async fn get_startup_command(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<String, DomainError> {
        Err(DomainError::feature_not_supported("startup configuration"))
    }
    async fn set_startup_command(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _command: String,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("startup configuration"))
    }
    async fn delete_startup_command(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("startup configuration"))
    }
    async fn git_exec(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: GitExecRequest,
    ) -> Result<GitExecResult, DomainError> {
        Err(DomainError::feature_not_supported("git exec"))
    }
    async fn git_diff(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _folder: Option<String>,
    ) -> Result<String, DomainError> {
        Err(DomainError::feature_not_supported("git diff"))
    }
    async fn git_status(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _folder: Option<String>,
    ) -> Result<String, DomainError> {
        Err(DomainError::feature_not_supported("git status"))
    }
    async fn git_checkout(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: GitCheckoutRequest,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("git checkout"))
    }
    async fn git_update_config(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: GitConfigUpdateRequest,
    ) -> Result<GitConfigResult, DomainError> {
        Err(DomainError::feature_not_supported("git config"))
    }
    async fn git_commit(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: GitCommitRequest,
    ) -> Result<GitCommitResult, DomainError> {
        Err(DomainError::feature_not_supported("git commit"))
    }
    async fn git_clone(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: GitCloneRequest,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("git clone"))
    }
    async fn git_push(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: GitPushRequest,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("git push"))
    }
    async fn git_create_pr(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: GitCreatePrRequest,
    ) -> Result<PullRequest, DomainError> {
        Err(DomainError::feature_not_supported(
            "git create pull request",
        ))
    }
    async fn create_snapshot(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _name: String,
    ) -> Result<Snapshot, DomainError> {
        Err(DomainError::feature_not_supported("snapshot"))
    }
    async fn list_snapshots(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<Vec<Snapshot>, DomainError> {
        Err(DomainError::feature_not_supported("snapshot"))
    }
    async fn delete_snapshot(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _snapshot_id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("snapshot"))
    }
    async fn delete_snapshots(
        &self,
        _context: AccountContext,
        _snapshot_ids: Option<Vec<String>>,
    ) -> Result<u64, DomainError> {
        Err(DomainError::feature_not_supported("snapshot"))
    }
    async fn create_schedule(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: ScheduleCreateRequest,
    ) -> Result<ScheduleResponse, DomainError> {
        Err(DomainError::feature_not_supported("schedule"))
    }
    async fn list_schedules(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<Vec<ScheduleResponse>, DomainError> {
        Err(DomainError::feature_not_supported("schedule"))
    }
    async fn get_schedule(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _schedule_id: &str,
    ) -> Result<ScheduleResponse, DomainError> {
        Err(DomainError::feature_not_supported("schedule"))
    }
    async fn update_schedule(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _schedule_id: &str,
        _request: ScheduleUpdateRequest,
    ) -> Result<ScheduleResponse, DomainError> {
        Err(DomainError::feature_not_supported("schedule"))
    }
    async fn set_schedule_paused(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _schedule_id: &str,
        _paused: bool,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("schedule"))
    }
    async fn delete_schedule(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _schedule_id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("schedule"))
    }
    async fn browser_create_tab(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: CreateTab,
    ) -> Result<BrowserTab, DomainError> {
        Err(DomainError::feature_not_supported("browser tabs"))
    }
    async fn browser_list_tabs(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<Vec<BrowserTab>, DomainError> {
        Err(DomainError::feature_not_supported("browser tabs"))
    }
    async fn browser_close_tab(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _tab_id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("browser tabs"))
    }
    async fn browser_goto(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: Navigate,
    ) -> Result<BrowserContent, DomainError> {
        Err(DomainError::feature_not_supported("browser navigation"))
    }
    async fn browser_content(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _tab_id: &str,
    ) -> Result<BrowserContent, DomainError> {
        Err(DomainError::feature_not_supported("browser content"))
    }
    async fn browser_screenshot(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: Screenshot,
    ) -> Result<Vec<u8>, DomainError> {
        Err(DomainError::feature_not_supported("browser screenshot"))
    }
    async fn browser_extract(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: BrowserInstruction,
    ) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("browser extract"))
    }
    async fn browser_observe(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: BrowserInstruction,
    ) -> Result<BrowserObserveResult, DomainError> {
        Err(DomainError::feature_not_supported("browser observe"))
    }
    async fn browser_act(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: BrowserInstruction,
    ) -> Result<BrowserActResult, DomainError> {
        Err(DomainError::feature_not_supported("browser act"))
    }
    async fn browser_run(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: BrowserRunInstruction,
    ) -> Result<BrowserRunResult, DomainError> {
        Err(DomainError::feature_not_supported("browser run"))
    }
    async fn browser_connect(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<String, DomainError> {
        Err(DomainError::feature_not_supported("browser connect"))
    }
    async fn open_browser_cdp(&self, _ticket: &str) -> Result<BrowserCdpConnection, DomainError> {
        Err(DomainError::feature_not_supported("browser connect"))
    }
    async fn browser_screencast(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _tab_id: &str,
    ) -> Result<String, DomainError> {
        Err(DomainError::feature_not_supported("browser screencast"))
    }
    async fn open_browser_screencast(
        &self,
        _ticket: &str,
    ) -> Result<BrowserScreencastConnection, DomainError> {
        Err(DomainError::feature_not_supported("browser screencast"))
    }
    async fn browser_recording_start(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _request: BrowserRecordingStartRequest,
    ) -> Result<BrowserRecordingResponse, DomainError> {
        Err(DomainError::feature_not_supported("browser recording"))
    }
    async fn browser_recording_stop(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<BrowserRecordingResponse, DomainError> {
        Err(DomainError::feature_not_supported("browser recording"))
    }
    async fn browser_recording_list(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _cursor: Option<String>,
        _limit: usize,
    ) -> Result<BrowserRecordingListResponse, DomainError> {
        Err(DomainError::feature_not_supported("browser recording"))
    }
    async fn browser_recording_get(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _recording_id: &str,
    ) -> Result<BrowserRecordingResponse, DomainError> {
        Err(DomainError::feature_not_supported("browser recording"))
    }
    async fn browser_recording_playlist(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _recording_id: &str,
    ) -> Result<Vec<u8>, DomainError> {
        Err(DomainError::feature_not_supported("browser recording"))
    }
    async fn browser_recording_segment(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _recording_id: &str,
        _segment: &str,
    ) -> Result<Vec<u8>, DomainError> {
        Err(DomainError::feature_not_supported("browser recording"))
    }
    async fn browser_recording_download(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _recording_id: &str,
    ) -> Result<BrowserRecordingDownload, DomainError> {
        Err(DomainError::feature_not_supported("browser recording"))
    }
    async fn create_preview(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _port: u16,
        _auth: PreviewAuth,
    ) -> Result<PublicUrl, DomainError> {
        Err(DomainError::feature_not_supported("preview"))
    }
    async fn list_previews(
        &self,
        _context: AccountContext,
        _box_id: &str,
    ) -> Result<Vec<PublicUrl>, DomainError> {
        Err(DomainError::feature_not_supported("preview"))
    }
    async fn delete_preview(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _port: u16,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("preview"))
    }
    async fn add_skill(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _skill_id: String,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("skills"))
    }
    async fn remove_skill(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _skill_id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("skills"))
    }
    async fn admin_list_boxes(&self, context: AccountContext) -> Result<Value, DomainError> {
        self.list_boxes(context, None).await
    }
    async fn admin_list_runs(&self, _context: AccountContext) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("admin run list"))
    }
    async fn admin_list_snapshots(&self, _context: AccountContext) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("admin snapshot list"))
    }
    async fn admin_list_schedules(&self, _context: AccountContext) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("admin schedule list"))
    }
    async fn admin_set_schedule_paused(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _schedule_id: &str,
        _paused: bool,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported(
            "admin schedule mutation",
        ))
    }
    async fn admin_delete_schedule(
        &self,
        _context: AccountContext,
        _box_id: &str,
        _schedule_id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported(
            "admin schedule mutation",
        ))
    }
    async fn admin_list_api_keys(&self, _context: AccountContext) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("admin API keys"))
    }
    async fn admin_create_api_key(
        &self,
        _context: AccountContext,
        _request: AdminCreateApiKeyRequest,
    ) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("admin API keys"))
    }
    async fn admin_revoke_api_key(
        &self,
        _context: AccountContext,
        _id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("admin API keys"))
    }
    async fn admin_pause_box(
        &self,
        context: AccountContext,
        id: &str,
    ) -> Result<Value, DomainError> {
        self.pause_box(context, id).await
    }
    async fn admin_resume_box(
        &self,
        context: AccountContext,
        id: &str,
    ) -> Result<Value, DomainError> {
        self.resume_box(context, id).await
    }
    async fn admin_delete_box(&self, context: AccountContext, id: &str) -> Result<(), DomainError> {
        self.delete_box(context, id).await
    }
    async fn admin_cancel_run(
        &self,
        _context: AccountContext,
        _id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("admin run cancel"))
    }
    async fn admin_delete_snapshot(
        &self,
        _context: AccountContext,
        _id: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::feature_not_supported("admin snapshot delete"))
    }
    async fn admin_issue_terminal_ticket(
        &self,
        _context: AccountContext,
        _id: &str,
    ) -> Result<Value, DomainError> {
        Err(DomainError::feature_not_supported("admin terminal"))
    }
    async fn open_admin_terminal(&self, _ticket: &str) -> Result<AdminTerminalStream, DomainError> {
        Err(DomainError::feature_not_supported("admin terminal"))
    }
}

#[derive(Clone)]
pub struct ApiState {
    pub authenticator: Arc<dyn Authenticator>,
    pub sessions: Arc<dyn SessionAuthenticator>,
    pub admin_login: Arc<dyn AdminLoginService>,
    pub services: Arc<dyn ApiServices>,
    pub audit: Arc<dyn AuditSink>,
    pub request_quota: Arc<dyn RequestQuota>,
    pub telemetry: Arc<dyn Telemetry>,
    pub body_limit_bytes: usize,
}

#[derive(Deserialize, Clone, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateBoxRequest {
    pub name: Option<String>,
    pub labels: Option<Vec<String>>,
    pub size: Option<String>,
    pub keep_alive: Option<bool>,
    pub init_command: Option<String>,
    pub model: Option<String>,
    pub agent: Option<Value>,
    pub agent_api_key: Option<String>,
    pub custom_runner: Option<Value>,
    pub runtime: Option<String>,
    pub browser: Option<bool>,
    pub github_token: Option<String>,
    pub git_user_name: Option<String>,
    pub git_user_email: Option<String>,
    pub env_vars: Option<Value>,
    pub attach_headers: Option<Value>,
    pub network_policy: Option<Value>,
    pub skills: Option<Value>,
    pub mcp_servers: Option<Value>,
    pub ephemeral: Option<bool>,
    pub ttl: Option<u32>,
    pub snapshot_id: Option<String>,
}

const MAX_BULK_DELETE_BOXES: usize = 100;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct BulkDeleteRequest {
    ids: Vec<String>,
}

impl BulkDeleteRequest {
    fn validate(self) -> Result<Vec<String>, DomainError> {
        if self.ids.is_empty() {
            return Err(DomainError::validation("ids must not be empty"));
        }
        if self.ids.len() > MAX_BULK_DELETE_BOXES {
            return Err(DomainError::validation(format!(
                "at most {MAX_BULK_DELETE_BOXES} box ids may be deleted at once"
            )));
        }
        let mut unique = std::collections::BTreeSet::new();
        for id in &self.ids {
            if id.is_empty() || !unique.insert(id.clone()) {
                return Err(DomainError::validation(
                    "box ids must be non-empty and unique",
                ));
            }
        }
        Ok(self.ids)
    }
}
impl CreateBoxRequest {
    fn validate_from_snapshot(&self) -> Result<(), DomainError> {
        if self.snapshot_id.as_deref().is_none_or(str::is_empty) {
            return Err(DomainError::validation("snapshot_id is required"));
        }
        let mut request = self.clone();
        request.snapshot_id = None;
        request.validate_create()
    }

    fn validate_create(&self) -> Result<(), DomainError> {
        if self.ttl.is_some() && self.ephemeral != Some(true) {
            return Err(DomainError::validation("ttl requires ephemeral=true"));
        }
        self.custom_agent()?;
        if self.agent_api_key.is_some() || self.mcp_servers.is_some() {
            return Err(DomainError::feature_not_supported(
                "startup, managed agent, or mcp_servers",
            ));
        }
        if let Some(skills) = &self.skills {
            let skills = skills
                .as_array()
                .ok_or_else(|| DomainError::validation("skills must be an array"))?;
            if skills.len() > 16
                || skills
                    .iter()
                    .any(|skill| skill.as_str().is_none_or(str::is_empty))
            {
                return Err(DomainError::validation("invalid skills configuration"));
            }
        }
        if let Some(token) = &self.github_token {
            validate_git_token(token)?;
        }
        if let Some(value) = &self.git_user_name {
            validate_git_text(value, "git user name")?;
        }
        if let Some(value) = &self.git_user_email {
            validate_git_text(value, "git user email")?;
        }
        if let Some(command) = &self.init_command
            && (command.is_empty() || command.len() > 64 * 1024 || command.as_bytes().contains(&0))
        {
            return Err(DomainError::validation("invalid init_command"));
        }
        if self.init_command.is_some() && self.keep_alive != Some(true) {
            return Err(DomainError::validation(
                "init_command requires keep_alive=true",
            ));
        }
        if self.attach_headers.is_some() {
            return Err(DomainError::feature_not_supported("attach_headers"));
        }
        if self.network_policy.as_ref().is_some_and(|policy| {
            !matches!(
                policy.get("mode").and_then(Value::as_str),
                Some("allow-all" | "deny-all")
            )
        }) {
            return Err(DomainError::feature_not_supported("custom network_policy"));
        }
        if self.snapshot_id.is_some() {
            return Err(DomainError::feature_not_supported("from snapshot"));
        }
        if let Some(labels) = &self.labels
            && (labels.len() > 5
                || labels.iter().any(|label| {
                    label.is_empty()
                        || label.len() > 20
                        || !label.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')
                        })
                }))
        {
            return Err(DomainError::validation(
                "labels must be at most five 1..=20 ASCII ._-: values",
            ));
        }
        if self.ttl.is_some() && self.ephemeral != Some(true) {
            return Err(DomainError::validation("ttl requires ephemeral=true"));
        }
        if self.ephemeral == Some(true) && !(1..=259_200).contains(&self.ttl.unwrap_or(259_200)) {
            return Err(DomainError::validation("ttl must be between 1 and 259200"));
        }
        Ok(())
    }

    pub fn custom_agent(&self) -> Result<Option<CustomAgentConfiguration>, DomainError> {
        let Some(agent) = &self.agent else {
            if self.model.is_some() || self.custom_runner.is_some() {
                return Err(DomainError::validation(
                    "agent=custom is required with model or custom_runner",
                ));
            }
            return Ok(None);
        };
        let (model, custom, nested_object) = match agent {
            // This is the pinned SDK wire shape: appendAgentConfigToBody emits
            // agent/model/custom_runner as three top-level fields.
            Value::String(harness) if harness == "custom" => {
                let custom = self
                    .custom_runner
                    .as_ref()
                    .and_then(Value::as_object)
                    .ok_or_else(|| DomainError::validation("custom_runner is required"))?;
                (self.model.as_deref().unwrap_or("custom"), custom, None)
            }
            Value::String(_) => {
                return Err(DomainError::feature_not_supported(
                    "only Agent.Custom is implemented in Phase 2",
                ));
            }
            // Retain the already-persisted pre-Phase-2 nested representation as
            // an input compatibility bridge; new SDK requests use the branch above.
            Value::Object(object) => {
                if object.get("harness").and_then(Value::as_str) != Some("custom") {
                    return Err(DomainError::feature_not_supported(
                        "only Agent.Custom is implemented in Phase 2",
                    ));
                }
                if self.model.is_some() || self.custom_runner.is_some() {
                    return Err(DomainError::validation(
                        "mixed nested and top-level agent configuration",
                    ));
                }
                let custom = object
                    .get("customHarness")
                    .and_then(Value::as_object)
                    .ok_or_else(|| DomainError::validation("customHarness is required"))?;
                (
                    object
                        .get("model")
                        .and_then(Value::as_str)
                        .unwrap_or("custom"),
                    custom,
                    Some(object),
                )
            }
            _ => return Err(DomainError::validation("agent must be a string")),
        };
        if model.is_empty() || model.len() > 255 || model.as_bytes().contains(&0) {
            return Err(DomainError::validation("invalid custom agent model"));
        }
        let command = custom
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| DomainError::validation("customHarness.command is required"))?;
        let protocol = custom
            .get("protocol")
            .map(|value| {
                value.as_str().ok_or_else(|| {
                    DomainError::validation("customHarness.protocol must be a string")
                })
            })
            .transpose()?
            .unwrap_or("box-sse-v1");
        if !valid_custom_harness_command(command) {
            return Err(DomainError::validation(
                "customHarness.command must be a PATH executable or an absolute path under /workspace/home or /home/boxuser",
            ));
        }
        let args = custom
            .get("args")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| DomainError::validation("customHarness.args must be an array"))?
                    .iter()
                    .map(|argument| {
                        argument
                            .as_str()
                            .ok_or_else(|| {
                                DomainError::validation("customHarness.args must contain strings")
                            })
                            .map(str::to_owned)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        if args.len() > MAX_CUSTOM_HARNESS_ARGS
            || args.iter().any(|argument| {
                argument.len() > MAX_CUSTOM_HARNESS_ARG_BYTES || argument.as_bytes().contains(&0)
            })
            || args
                .iter()
                .try_fold(0usize, |total, argument| total.checked_add(argument.len()))
                .is_none_or(|total| total > MAX_CUSTOM_HARNESS_ARGS_BYTES)
        {
            return Err(DomainError::validation("invalid customHarness.args"));
        }
        if protocol != "box-sse-v1" {
            return Err(DomainError::feature_not_supported(
                "custom harness protocol feature_not_supported",
            ));
        }
        let allowed = ["harness", "model", "customHarness"];
        if nested_object
            .is_some_and(|object| object.keys().any(|key| !allowed.contains(&key.as_str())))
            || custom
                .keys()
                .any(|key| !matches!(key.as_str(), "command" | "args" | "protocol"))
        {
            return Err(DomainError::validation(
                "unknown custom agent configuration field",
            ));
        }
        Ok(Some(CustomAgentConfiguration {
            model: model.into(),
            command: command.into(),
            args,
            protocol: protocol.into(),
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct CustomAgentConfiguration {
    pub model: String,
    pub command: String,
    pub args: Vec<String>,
    pub protocol: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ModelConfigurationRequest {
    model: String,
}

impl ModelConfigurationRequest {
    fn validate(self) -> Result<String, DomainError> {
        if self.model.is_empty() || self.model.len() > 255 || self.model.as_bytes().contains(&0) {
            return Err(DomainError::validation("invalid custom agent model"));
        }
        Ok(self.model)
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CustomRunnerConfigurationRequest {
    custom_runner: Value,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct StartupConfigurationRequest {
    init_command: String,
}

impl StartupConfigurationRequest {
    fn validate(self) -> Result<String, DomainError> {
        if self.init_command.is_empty()
            || self.init_command.len() > 64 * 1024
            || self.init_command.as_bytes().contains(&0)
        {
            return Err(DomainError::validation("invalid init_command"));
        }
        Ok(self.init_command)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GitExecRequest {
    pub args: Vec<String>,
    pub folder: Option<String>,
}

impl GitExecRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.args.is_empty() || self.args.len() > 128 {
            return Err(DomainError::validation("invalid git args"));
        }
        let total = self.args.iter().try_fold(0usize, |total, arg| {
            if arg.is_empty() || arg.len() > 4096 || arg.as_bytes().contains(&0) {
                return Err(DomainError::validation("invalid git arg"));
            }
            total
                .checked_add(arg.len())
                .ok_or_else(|| DomainError::validation("git args are too large"))
        })?;
        if total > 32 * 1024 {
            return Err(DomainError::validation("git args are too large"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct GitExecResult {
    pub output: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GitCheckoutRequest {
    pub branch: String,
    pub folder: Option<String>,
}

#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GitCloneRequest {
    pub repo: String,
    pub branch: Option<String>,
    pub depth: Option<u32>,
    pub github_token: Option<String>,
    pub folder: Option<String>,
}

impl GitCloneRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.repo.is_empty()
            || self.repo.len() > 4096
            || self.repo.as_bytes().contains(&0)
            || self.repo.contains(['\r', '\n'])
        {
            return Err(DomainError::validation("invalid git repository"));
        }
        if let Some(branch) = &self.branch {
            validate_git_text(branch, "git branch")?;
            if branch.starts_with('-') {
                return Err(DomainError::validation("invalid git branch"));
            }
        }
        if self
            .depth
            .is_some_and(|depth| depth == 0 || depth > 1_000_000)
        {
            return Err(DomainError::validation("invalid git clone depth"));
        }
        if let Some(token) = &self.github_token {
            validate_git_token(token)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GitPushRequest {
    pub branch: Option<String>,
    pub folder: Option<String>,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GitCreatePrRequest {
    pub title: String,
    pub body: Option<String>,
    pub base: Option<String>,
    pub folder: Option<String>,
}

impl GitCreatePrRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.title.is_empty() || self.title.len() > 1024 || self.title.as_bytes().contains(&0) {
            return Err(DomainError::validation("invalid pull request title"));
        }
        if self
            .body
            .as_ref()
            .is_some_and(|body| body.len() > 1024 * 1024 || body.as_bytes().contains(&0))
        {
            return Err(DomainError::validation("invalid pull request body"));
        }
        if let Some(base) = &self.base {
            validate_git_text(base, "pull request base")?;
            if base.starts_with('-') {
                return Err(DomainError::validation("invalid pull request base"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PullRequest {
    pub url: String,
    pub number: u64,
    pub title: String,
    pub base: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct SnapshotCreateRequest {
    name: String,
}

impl SnapshotCreateRequest {
    fn validate(self) -> Result<String, DomainError> {
        if self.name.is_empty() || self.name.len() > 255 || self.name.as_bytes().contains(&0) {
            return Err(DomainError::validation("invalid snapshot name"));
        }
        Ok(self.name)
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct SnapshotDeleteRequest {
    ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct Snapshot {
    pub id: String,
    pub name: String,
    pub box_id: String,
    pub size_bytes: u64,
    pub status: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleCreateRequest {
    pub r#type: String,
    pub cron: String,
    pub command: Option<Vec<String>>,
    pub prompt: Option<String>,
    pub folder: String,
    pub model: Option<String>,
    pub agent_options: Option<Value>,
    pub timeout: Option<u64>,
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_headers: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum PatchField<T> {
    #[default]
    Missing,
    Present(Option<T>),
}

impl<'de, T> Deserialize<'de> for PatchField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleUpdateRequest {
    #[serde(default)]
    pub cron: PatchField<String>,
    #[serde(default)]
    pub command: PatchField<Vec<String>>,
    #[serde(default)]
    pub prompt: PatchField<String>,
    #[serde(default)]
    pub folder: PatchField<String>,
    #[serde(default)]
    pub model: PatchField<String>,
    #[serde(default)]
    pub agent_options: PatchField<Value>,
    #[serde(default)]
    pub timeout: PatchField<u64>,
    #[serde(default)]
    pub webhook_url: PatchField<String>,
    #[serde(default)]
    pub webhook_headers: PatchField<std::collections::BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct ScheduleResponse {
    pub id: String,
    pub box_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    pub r#type: String,
    pub cron: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_options: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qstash_schedule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_headers: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_id: Option<String>,
    pub total_runs: u64,
    pub total_failures: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserCreateTabRequest {
    pub url: String,
    pub wait_until: Option<String>,
    pub timeout: Option<u64>,
}

impl BrowserCreateTabRequest {
    fn validate(self) -> Result<CreateTab, DomainError> {
        let wait_until = match self.wait_until.as_deref() {
            None => None,
            Some("load") => Some(WaitUntil::Load),
            Some("domcontentloaded") => Some(WaitUntil::Domcontentloaded),
            Some("networkidle") => Some(WaitUntil::Networkidle),
            Some(_) => return Err(DomainError::validation("invalid browser wait_until")),
        };
        let request = CreateTab {
            url: self.url,
            wait_until,
            timeout: self.timeout,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserNavigateRequest {
    pub url: String,
    pub tab: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserScreencastRequest {
    pub tab: String,
}

#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserRecordingStartRequest {
    pub max_duration_seconds: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct BrowserRecordingMarkerResponse {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct BrowserRecordingResponse {
    pub id: String,
    pub box_id: String,
    pub status: String,
    pub started_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mp4_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u32>,
    pub markers: Vec<BrowserRecordingMarkerResponse>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct BrowserRecordingListResponse {
    pub recordings: Vec<BrowserRecordingResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

pub struct BrowserRecordingDownload {
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
}

impl BrowserScreencastRequest {
    fn validate(self) -> Result<String, DomainError> {
        box_browser::validate_tab_id(&self.tab)?;
        Ok(self.tab)
    }
}

impl BrowserNavigateRequest {
    fn validate(self) -> Result<Navigate, DomainError> {
        let request = Navigate {
            url: self.url,
            tab: self.tab,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PreviewCreateRequest {
    port: u16,
    bearer_token: Option<bool>,
    basic_auth: Option<bool>,
}

impl PreviewCreateRequest {
    fn validate(self) -> Result<(u16, PreviewAuth), DomainError> {
        if self.port == 0 || matches!(self.port, 18_080 | 18_081) {
            return Err(DomainError::validation("invalid or reserved preview port"));
        }
        let auth = match (
            self.bearer_token.unwrap_or(false),
            self.basic_auth.unwrap_or(false),
        ) {
            (true, true) => {
                return Err(DomainError::validation(
                    "bearer_token and basic_auth are mutually exclusive",
                ));
            }
            (true, false) => PreviewAuth::Bearer,
            (false, true) => PreviewAuth::Basic,
            (false, false) => PreviewAuth::Public,
        };
        Ok((self.port, auth))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PublicUrl {
    pub url: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl GitPushRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        if let Some(branch) = &self.branch {
            validate_git_text(branch, "git branch")?;
            if branch.starts_with('-') {
                return Err(DomainError::validation("invalid git branch"));
            }
        }
        Ok(())
    }
}

impl GitCheckoutRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_git_text(&self.branch, "branch")?;
        if self.branch.starts_with('-') {
            return Err(DomainError::validation("invalid git branch"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GitConfigUpdateRequest {
    pub git_user_name: Option<String>,
    pub git_user_email: Option<String>,
}

impl GitConfigUpdateRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.git_user_name.is_none() && self.git_user_email.is_none() {
            return Err(DomainError::validation(
                "at least one git config value is required",
            ));
        }
        if let Some(value) = &self.git_user_name {
            validate_git_text(value, "git user name")?;
        }
        if let Some(value) = &self.git_user_email {
            validate_git_text(value, "git user email")?;
        }
        Ok(())
    }
}

fn validate_git_text(value: &str, field: &str) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > 255 || value.as_bytes().contains(&0) {
        return Err(DomainError::validation(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_git_token(value: &str) -> Result<(), DomainError> {
    if value.is_empty()
        || value.len() > 16 * 1024
        || value.as_bytes().contains(&0)
        || value.contains(['\r', '\n'])
    {
        return Err(DomainError::validation("invalid github token"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct GitConfigResult {
    pub git_user_name: String,
    pub git_user_email: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GitCommitRequest {
    pub message: String,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub folder: Option<String>,
}

impl GitCommitRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.message.is_empty()
            || self.message.len() > 64 * 1024
            || self.message.as_bytes().contains(&0)
        {
            return Err(DomainError::validation("invalid git commit message"));
        }
        if let Some(value) = &self.author_name {
            validate_git_text(value, "git author name")?;
        }
        if let Some(value) = &self.author_email {
            validate_git_text(value, "git author email")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct GitCommitResult {
    pub sha: String,
    pub message: String,
}

impl CustomRunnerConfigurationRequest {
    fn validate(self) -> Result<CustomAgentConfiguration, DomainError> {
        let request = serde_json::from_value::<CreateBoxRequest>(json!({
            "agent": "custom",
            "custom_runner": self.custom_runner,
        }))
        .map_err(|_| DomainError::validation("invalid custom_runner"))?;
        request
            .custom_agent()?
            .ok_or_else(|| DomainError::validation("custom_runner is required"))
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentRunRequest {
    pub prompt: String,
    pub folder: Option<String>,
    pub json_schema: Option<Value>,
    pub agent_options: Option<Value>,
    pub files: Option<Value>,
}

#[derive(Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RunWebhook {
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWebhookRunRequest {
    pub prompt: String,
    pub folder: Option<String>,
    pub json_schema: Option<Value>,
    pub agent_options: Option<Value>,
    pub files: Option<Value>,
    pub webhook: RunWebhook,
}

impl AgentRunRequest {
    fn validate_phase_two(&self) -> Result<(), DomainError> {
        if self.prompt.is_empty()
            || self.prompt.len() > 128 * 1024
            || self.prompt.as_bytes().contains(&0)
        {
            return Err(DomainError::validation("invalid run prompt"));
        }
        if self.json_schema.is_some() || self.agent_options.is_some() || self.files.is_some() {
            return Err(DomainError::feature_not_supported(
                "run files, response schema, or agent options",
            ));
        }
        Ok(())
    }
}

impl AgentWebhookRunRequest {
    fn validate_phase_two(&self) -> Result<(), DomainError> {
        AgentRunRequest {
            prompt: self.prompt.clone(),
            folder: self.folder.clone(),
            json_schema: self.json_schema.clone(),
            agent_options: self.agent_options.clone(),
            files: self.files.clone(),
        }
        .validate_phase_two()?;
        if self.webhook.url.is_empty()
            || self.webhook.url.len() > 2048
            || self.webhook.url.as_bytes().contains(&0)
            || self.webhook.headers.len() > 32
        {
            return Err(DomainError::validation("invalid webhook configuration"));
        }
        let parsed = url::Url::parse(&self.webhook.url)
            .map_err(|_| DomainError::validation("invalid webhook URL"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || !matches!(
                (parsed.scheme(), parsed.port_or_known_default()),
                ("http", Some(80)) | ("https", Some(443))
            )
        {
            return Err(DomainError::validation("invalid webhook URL"));
        }
        let mut total = 0usize;
        for (name, value) in &self.webhook.headers {
            let forbidden = [
                "host",
                "content-type",
                "content-length",
                "transfer-encoding",
                "connection",
                "keep-alive",
                "proxy-connection",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailer",
                "upgrade",
                "x-boxd-webhook-id",
            ];
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
                || forbidden
                    .iter()
                    .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
                || value.len() > 4096
                || value
                    .bytes()
                    .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
            {
                return Err(DomainError::validation("invalid webhook header"));
            }
            total = total
                .checked_add(name.len() + value.len())
                .ok_or_else(|| DomainError::validation("webhook headers exceed size limit"))?;
        }
        if total > 16 * 1024 {
            return Err(DomainError::validation("webhook headers exceed size limit"));
        }
        Ok(())
    }

    pub fn run_request(&self) -> AgentRunRequest {
        AgentRunRequest {
            prompt: self.prompt.clone(),
            folder: self.folder.clone(),
            json_schema: self.json_schema.clone(),
            agent_options: self.agent_options.clone(),
            files: self.files.clone(),
        }
    }
}
#[derive(Deserialize, ToSchema)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub folder: Option<String>,
    pub timeout: Option<u64>,
}
#[derive(Deserialize, ToSchema)]
pub struct CodeRequest {
    pub code: String,
    pub language: Option<String>,
    pub folder: Option<String>,
    pub timeout: Option<u64>,
}
#[derive(Deserialize, ToSchema)]
pub struct WriteFileRequest {
    pub path: String,
    pub content: String,
    pub encoding: Option<String>,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct LabelRequest {
    label: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct SkillRequest {
    skill_id: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCreateApiKeyRequest {
    pub scopes: Vec<AuthScope>,
    pub expires_at: Option<i64>,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct AdminLoginRequest {
    username: String,
    password: String,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct ExecResult {
    pub output: String,
    pub error: String,
    pub exit_code: i32,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct CodeResult {
    pub output: String,
    pub error: String,
    pub exit_code: i32,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub mod_time: String,
}

#[derive(Clone)]
struct StateHoop(ApiState);
#[async_trait]
impl Handler for StateHoop {
    async fn handle(&self, _: &mut Request, depot: &mut Depot, _: &mut Response, _: &mut FlowCtrl) {
        depot.insert_typed(self.0.clone());
    }
}

fn error(
    res: &mut Response,
    status: StatusCode,
    error: &str,
    message: impl Into<String>,
    request_id: &str,
) {
    res.render_with_status(
        status,
        Json(json!({"error": error, "message": message.into(), "request_id": request_id})),
    );
}
fn request_id(req: &Request) -> String {
    req.header::<String>("x-request-id")
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

struct HeaderExtractor<'a>(&'a salvo::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(salvo::http::HeaderName::as_str).collect()
    }
}
fn state(depot: &Depot) -> &ApiState {
    depot
        .get_typed::<ApiState>()
        .expect("ApiState hoop must be installed")
}
#[handler]
async fn compatibility_auth(
    req: &Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let request_id = request_id(req);
    let Some(key) = req.header::<String>("x-box-api-key") else {
        error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "X-Box-Api-Key is required",
            &request_id,
        );
        ctrl.skip_rest();
        return;
    };
    match state(depot).authenticator.authenticate(&key).await {
        Ok(context) => {
            // Preserve the authenticated actor for structural audit even when
            // the request is rejected by quota before reaching a use case.
            depot.insert_typed(context.clone());
            depot.insert_typed(request_id.clone());
            let fingerprint = ApiKeyFingerprint::from_api_key(&key);
            depot.insert_typed(fingerprint);
            let quota = state(depot)
                .request_quota
                .check(&context, fingerprint)
                .await;
            match quota {
                Ok(RequestQuotaDecision::Allowed) => {}
                Ok(RequestQuotaDecision::Rejected {
                    retry_after_seconds,
                }) => {
                    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                        res.headers_mut().insert("retry-after", value);
                    }
                    error(
                        res,
                        StatusCode::TOO_MANY_REQUESTS,
                        "quota_exceeded",
                        "API key request quota exceeded",
                        &request_id,
                    );
                    ctrl.skip_rest();
                    return;
                }
                Err(error_value) => {
                    map_error(res, error_value, &request_id);
                    ctrl.skip_rest();
                    return;
                }
            }
            let request_bytes = req
                .headers()
                .get(salvo::http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
                .or_else(|| salvo::http::Body::size_hint(req.body()).exact())
                .unwrap_or(0);
            match state(depot)
                .request_quota
                .charge_traffic(&context, fingerprint, request_bytes)
                .await
            {
                Ok(RequestQuotaDecision::Allowed) => {}
                Ok(RequestQuotaDecision::Rejected {
                    retry_after_seconds,
                }) => {
                    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                        res.headers_mut().insert("retry-after", value);
                    }
                    error(
                        res,
                        StatusCode::TOO_MANY_REQUESTS,
                        "quota_exceeded",
                        "API key traffic quota exceeded",
                        &request_id,
                    );
                    ctrl.skip_rest();
                    return;
                }
                Err(error_value) => {
                    map_error(res, error_value, &request_id);
                    ctrl.skip_rest();
                    return;
                }
            }
        }
        Err(_) => {
            error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid API key",
                &request_id,
            );
            ctrl.skip_rest();
        }
    }
}
#[handler]
async fn admin_auth(req: &mut Request, depot: &mut Depot, res: &mut Response, ctrl: &mut FlowCtrl) {
    let request_id = request_id(req);
    let session = req.cookie("boxd_session").map(|v| v.value().to_owned());
    let csrf = req.header::<String>("x-csrf-token");
    match (session, csrf) {
        (Some(session), Some(csrf)) => match state(depot)
            .sessions
            .authenticate_session(&session, &csrf)
            .await
        {
            Ok(account) => {
                depot.insert_typed(account);
                depot.insert_typed(request_id);
            }
            Err(_) => {
                error(
                    res,
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "valid admin session and CSRF token are required",
                    &request_id,
                );
                ctrl.skip_rest();
            }
        },
        _ => {
            error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "valid admin session and CSRF token are required",
                &request_id,
            );
            ctrl.skip_rest();
        }
    }
}
fn context(depot: &Depot, res: &mut Response) -> Option<AuthorizedContext> {
    depot
        .get_typed::<AuthorizedContext>()
        .ok()
        .cloned()
        .or_else(|| {
            error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing authorization context",
                "unknown",
            );
            None
        })
}
fn map_error(res: &mut Response, error_value: DomainError, request_id: &str) {
    let status = if error_value.code == "invalid_terminal_ticket" {
        StatusCode::UNAUTHORIZED
    } else if error_value.code == "quota_exceeded" {
        StatusCode::TOO_MANY_REQUESTS
    } else if error_value.code == "payload_too_large" {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        match error_value.kind {
            DomainErrorKind::Validation => StatusCode::BAD_REQUEST,
            DomainErrorKind::NotFound => StatusCode::NOT_FOUND,
            DomainErrorKind::Ownership => StatusCode::FORBIDDEN,
            DomainErrorKind::StateConflict | DomainErrorKind::VersionConflict => {
                StatusCode::CONFLICT
            }
            DomainErrorKind::FeatureNotSupported => StatusCode::NOT_IMPLEMENTED,
            DomainErrorKind::Capacity => StatusCode::UNPROCESSABLE_ENTITY,
            DomainErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            DomainErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    };
    error(
        res,
        status,
        error_value.code,
        error_value.message,
        request_id,
    );
}
async fn json_body<T: for<'de> Deserialize<'de>>(
    req: &mut Request,
    depot: &Depot,
) -> Result<T, DomainError> {
    req.parse_json_with_max_size(state(depot).body_limit_bytes)
        .await
        .map_err(|error| {
            if error.to_string().contains("too large") {
                DomainError {
                    kind: DomainErrorKind::Validation,
                    code: "payload_too_large",
                    message: "payload too large".into(),
                }
            } else {
                DomainError::validation("invalid JSON body")
            }
        })
}

fn payload_too_large() -> DomainError {
    DomainError {
        kind: DomainErrorKind::Validation,
        code: "payload_too_large",
        message: "payload too large".into(),
    }
}

fn box_file_route(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/v2/box/")?;
    let (box_id, suffix) = rest.split_once('/')?;
    (!box_id.is_empty()).then_some((box_id, suffix))
}

async fn parse_upload(req: &mut Request, depot: &Depot) -> Result<Vec<UploadFile>, DomainError> {
    let max = state(depot).body_limit_bytes.min(MAX_UPLOAD_TOTAL_BYTES);
    let form = req.form_data_max_size(max).await.map_err(|error| {
        if matches!(error, salvo::http::ParseError::PayloadTooLarge) {
            payload_too_large()
        } else {
            DomainError::validation("invalid multipart upload")
        }
    })?;
    if form.fields.len() != 1 || form.files.len() != 1 {
        return Err(DomainError::validation(
            "multipart upload accepts only paths and files",
        ));
    }
    let paths = form
        .fields
        .get_vec("paths")
        .ok_or_else(|| DomainError::validation("paths are required"))?;
    let parts = form
        .files
        .get_vec("files")
        .ok_or_else(|| DomainError::validation("files are required"))?;
    if paths.is_empty() || paths.len() != parts.len() || paths.len() > MAX_UPLOAD_FILES {
        return Err(DomainError::validation(
            "paths and files must have the same length between one and 32",
        ));
    }
    let total = parts.iter().try_fold(0_u64, |total, part| {
        if part.size() > MAX_UPLOAD_FILE_BYTES {
            return Err(payload_too_large());
        }
        total.checked_add(part.size()).ok_or_else(payload_too_large)
    })?;
    if total > MAX_UPLOAD_TOTAL_BYTES as u64 {
        return Err(payload_too_large());
    }
    let mut files = Vec::with_capacity(parts.len());
    for (path, part) in paths.iter().zip(parts) {
        let contents = tokio::fs::read(part.path())
            .await
            .map_err(|_| DomainError {
                kind: DomainErrorKind::Internal,
                code: "upload_read_failed",
                message: "could not read validated upload".into(),
            })?;
        files.push(UploadFile {
            path: path.clone(),
            contents,
        });
    }
    Ok(files)
}

#[handler]
async fn security_headers(res: &mut Response) {
    res.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    res.headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    res.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        ),
    );
}

#[handler]
async fn audit_requests(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let method = req.method().as_str().to_owned();
    let resource = req.uri().path().to_owned();
    let audited = method != "GET"
        && (resource.starts_with("/v2/box") || resource.starts_with("/api/admin/v1"));
    let ip = match req.remote_addr() {
        salvo::conn::SocketAddr::IPv4(address) => Some(address.ip().to_string()),
        salvo::conn::SocketAddr::IPv6(address) => Some(address.ip().to_string()),
        _ => None,
    };
    ctrl.call_next(req, depot, res).await;
    if !audited {
        return;
    }
    let (context, actor) = if let Ok(authorized) = depot.get_typed::<AuthorizedContext>() {
        (authorized.account, "compat_api_key")
    } else if let Ok(context) = depot.get_typed::<AccountContext>() {
        (*context, "admin_session")
    } else {
        return;
    };
    let status = res.status_code.unwrap_or(StatusCode::OK);
    let event = AuditEvent {
        context,
        actor,
        action: format!("{method} {resource}"),
        resource,
        request_id: depot
            .get_typed::<String>()
            .cloned()
            .unwrap_or_else(|_| request_id(req)),
        ip,
        status_code: status.as_u16(),
        succeeded: status.is_success(),
    };
    if let Err(error) = state(depot).audit.record(event).await {
        tracing::error!(code = error.code, "durable request audit failed");
    }
}

#[handler]
async fn record_http_metrics(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let surface = match req.uri().path() {
        path if path.starts_with("/v2/box") => HttpSurface::Compatibility,
        path if path.starts_with("/api/admin/v1") => HttpSurface::Admin,
        path if path.starts_with("/health/") => HttpSurface::Health,
        "/metrics" => HttpSurface::Metrics,
        "/openapi.json" => HttpSurface::OpenApi,
        _ => HttpSurface::Other,
    };
    let surface_label = match surface {
        HttpSurface::Compatibility => "compatibility",
        HttpSurface::Admin => "admin",
        HttpSurface::Health => "health",
        HttpSurface::Metrics => "metrics",
        HttpSurface::OpenApi => "openapi",
        HttpSurface::Other => "other",
    };
    let request_id = request_id(req);
    depot.insert_typed(request_id.clone());
    let span = tracing::info_span!(
        "http.request",
        otel.kind = "server",
        http.request.method = %req.method(),
        http.response.status_code = tracing::field::Empty,
        boxd.surface = surface_label,
        request.id = %request_id,
    );
    let parent = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    });
    let _ = span.set_parent(parent);
    let started = std::time::Instant::now();
    ctrl.call_next(req, depot, res)
        .instrument(span.clone())
        .await;
    let status = res.status_code.unwrap_or(StatusCode::OK);
    span.record("http.response.status_code", status.as_u16());
    if !res.headers().contains_key("x-request-id")
        && let Ok(value) = HeaderValue::from_str(&request_id)
    {
        res.headers_mut().insert("x-request-id", value);
    }
    if surface == HttpSurface::Compatibility
        && let (Ok(context), Ok(fingerprint)) = (
            depot.get_typed::<AuthorizedContext>(),
            depot.get_typed::<ApiKeyFingerprint>(),
        )
        && let Some(response_bytes) = salvo::http::Body::size_hint(&res.body).exact()
    {
        match state(depot)
            .request_quota
            .charge_traffic(context, *fingerprint, response_bytes)
            .await
        {
            Ok(RequestQuotaDecision::Allowed) => {}
            Ok(RequestQuotaDecision::Rejected {
                retry_after_seconds,
            }) => {
                // The use case has already completed by the time an exact
                // response body size is known. Account the overage and make
                // subsequent requests wait, but never turn a completed
                // mutation into a misleading 429 response.
                tracing::warn!(
                    retry_after_seconds,
                    "API key response traffic quota exhausted"
                );
            }
            Err(error_value) => {
                tracing::error!(
                    code = error_value.code,
                    "API key response traffic accounting failed"
                );
            }
        }
    }
    state(depot)
        .telemetry
        .record_http(surface, status.as_u16(), started.elapsed());
}

#[handler]
async fn health_live(res: &mut Response) {
    res.render(Json(json!({"status":"live"})));
}
#[handler]
async fn health_ready(depot: &Depot, res: &mut Response) {
    match state(depot).services.ready().await {
        Ok(()) => res.render(Json(json!({"status":"ready"}))),
        Err(error_value) => map_error(res, error_value, "readiness"),
    }
}
#[handler]
async fn capabilities(res: &mut Response) {
    res.render(Json(json!({"phase":"phase_3_complete","implemented":["box_lifecycle","async_create","ephemeral_create","init_command","startup_configuration","exec","code_javascript_typescript_python","file_read_write_list","file_upload_download_direct_folder","labels","encrypted_environment","runtime_bundle_binding","admin_session","run_history","custom_agent_box_sse_v1","custom_agent_absolute_command","custom_agent_model_update","custom_agent_runner_update","run_stream","run_stream_replay","run_stream_keepalive","run_cancel","run_webhook_at_least_once","agent_stderr_logs","git_exec","git_diff","git_status","git_checkout","git_config","git_commit","git_clone_https_github","git_push_https_github","git_create_pr_github","git_askpass","snapshot_create_list_delete","snapshot_restore","preview_issue_list_delete","preview_http_websocket_proxy","skills_context7_install_remove","console_management_surfaces","console_terminal_single_use_ticket","schedule_exec_prompt_crud_utc_lease","schedule_webhook_encrypted_at_least_once","console_schedule_management","browser_tabs_goto_content_screenshot","browser_extract_observe_act_run","browser_cdp_single_use_ticket","browser_screencast_view_only","browser_recording_hls_download_retention","api_key_request_rate_quota","tenant_box_disk_run_traffic_quotas","structured_mutation_audit","prometheus_metrics","otlp_trace_export","sqlite_postgresql_mysql_repository_matrix"],"unsupported":["nested_tree_download_upstash_box_0_6_3","run_prompt_files","run_response_schema","run_agent_options","managed_agent","schedule_agent_options","mcp_servers","attach_headers","custom_network_policy"]})));
}

#[handler]
async fn admin_api(req: &mut Request, depot: &Depot, res: &mut Response) {
    let request_id = depot
        .get_typed::<String>()
        .cloned()
        .unwrap_or_else(|_| request_id(req));
    let Some(account) = depot.get_typed::<AccountContext>().ok().copied() else {
        error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing administrator account context",
            &request_id,
        );
        return;
    };
    let path = req
        .uri()
        .path()
        .strip_prefix("/api/admin/v1/")
        .unwrap_or_default();
    let result = match (req.method().as_str(), path) {
        ("GET", "boxes") => state(depot).services.admin_list_boxes(account).await,
        ("GET", "runs") => state(depot).services.admin_list_runs(account).await,
        ("GET", "snapshots") => state(depot).services.admin_list_snapshots(account).await,
        ("GET", "schedules") => state(depot).services.admin_list_schedules(account).await,
        ("GET", "api-keys") => state(depot).services.admin_list_api_keys(account).await,
        ("GET", "audit") => {
            let limit = req.query::<u64>("limit").unwrap_or(100);
            state(depot)
                .audit
                .list(account, limit)
                .await
                .map(|entries| json!({"audit_logs": entries}))
        }
        ("POST", "api-keys") => match json_body::<AdminCreateApiKeyRequest>(req, depot).await {
            Ok(body) => {
                state(depot)
                    .services
                    .admin_create_api_key(account, body)
                    .await
            }
            Err(error_value) => Err(error_value),
        },
        ("DELETE", tail) if tail.starts_with("api-keys/") => state(depot)
            .services
            .admin_revoke_api_key(account, &tail["api-keys/".len()..])
            .await
            .map(|_| json!({})),
        ("POST", tail) if tail.starts_with("boxes/") && tail.ends_with("/pause") => {
            let id = &tail["boxes/".len()..tail.len() - "/pause".len()];
            state(depot).services.admin_pause_box(account, id).await
        }
        ("POST", tail) if tail.starts_with("boxes/") && tail.ends_with("/resume") => {
            let id = &tail["boxes/".len()..tail.len() - "/resume".len()];
            state(depot).services.admin_resume_box(account, id).await
        }
        ("POST", tail) if tail.starts_with("boxes/") && tail.ends_with("/terminal-ticket") => {
            let id = &tail["boxes/".len()..tail.len() - "/terminal-ticket".len()];
            state(depot)
                .services
                .admin_issue_terminal_ticket(account, id)
                .await
        }
        ("DELETE", tail) if tail.starts_with("boxes/") => state(depot)
            .services
            .admin_delete_box(account, &tail["boxes/".len()..])
            .await
            .map(|_| json!({})),
        ("POST", tail) if tail.starts_with("runs/") && tail.ends_with("/cancel") => {
            let id = &tail["runs/".len()..tail.len() - "/cancel".len()];
            state(depot)
                .services
                .admin_cancel_run(account, id)
                .await
                .map(|_| json!({}))
        }
        ("POST", tail)
            if tail.starts_with("schedules/")
                && (tail.ends_with("/pause") || tail.ends_with("/resume")) =>
        {
            let paused = tail.ends_with("/pause");
            let suffix = if paused { "/pause" } else { "/resume" };
            let identity = &tail["schedules/".len()..tail.len() - suffix.len()];
            let mut parts = identity.split('/');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(box_id), Some(schedule_id), None) => state(depot)
                    .services
                    .admin_set_schedule_paused(account, box_id, schedule_id, paused)
                    .await
                    .map(|_| json!({})),
                _ => Err(DomainError::validation("invalid admin schedule path")),
            }
        }
        ("DELETE", tail) if tail.starts_with("schedules/") => {
            let identity = &tail["schedules/".len()..];
            let mut parts = identity.split('/');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(box_id), Some(schedule_id), None) => state(depot)
                    .services
                    .admin_delete_schedule(account, box_id, schedule_id)
                    .await
                    .map(|_| json!({})),
                _ => Err(DomainError::validation("invalid admin schedule path")),
            }
        }
        ("DELETE", tail) if tail.starts_with("snapshots/") => state(depot)
            .services
            .admin_delete_snapshot(account, &tail["snapshots/".len()..])
            .await
            .map(|_| json!({})),
        _ => Err(DomainError {
            kind: DomainErrorKind::NotFound,
            code: "not_found",
            message: "admin route not found".into(),
        }),
    };
    match result {
        Ok(value) => res.render(Json(value)),
        Err(error_value) => map_error(res, error_value, &request_id),
    }
}

#[handler]
async fn admin_terminal(req: &mut Request, depot: &Depot, res: &mut Response) {
    let request_id = request_id(req);
    let Some(ticket) = req.query::<String>("ticket") else {
        error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_terminal_ticket",
            "terminal ticket is required",
            &request_id,
        );
        return;
    };
    let terminal = match state(depot).services.open_admin_terminal(&ticket).await {
        Ok(terminal) => terminal,
        Err(error_value) => {
            map_error(res, error_value, &request_id);
            return;
        }
    };
    let upgraded = WebSocketUpgrade::new()
        .max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .upgrade(req, res, move |socket| async move {
            let (mut socket_write, mut socket_read) = socket.split();
            let (mut terminal_read, mut terminal_write) = tokio::io::split(terminal);
            let upload = async {
                while let Some(message) = socket_read.next().await {
                    let message = message.map_err(std::io::Error::other)?;
                    if message.is_close() {
                        terminal_write.shutdown().await?;
                        return Ok::<(), std::io::Error>(());
                    }
                    if message.is_text() || message.is_binary() {
                        let data = message.as_bytes();
                        if data.len() > 64 * 1024 {
                            return Err(std::io::Error::other(
                                "terminal input frame exceeds limit",
                            ));
                        }
                        terminal_write.write_all(data).await?;
                    }
                }
                terminal_write.shutdown().await
            };
            let download = async {
                let mut buffer = vec![0_u8; 64 * 1024];
                loop {
                    let count = terminal_read.read(&mut buffer).await?;
                    if count == 0 {
                        return Ok::<(), std::io::Error>(());
                    }
                    socket_write
                        .send(Message::binary(buffer[..count].to_vec()))
                        .await
                        .map_err(std::io::Error::other)?;
                }
            };
            tokio::select! {
                _ = upload => {}
                _ = download => {}
            }
        })
        .await;
    if let Err(error_value) = upgraded {
        error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_websocket_upgrade",
            error_value.to_string(),
            &request_id,
        );
    }
}

#[handler]
async fn browser_cdp(req: &mut Request, depot: &Depot, res: &mut Response) {
    const MAX_CDP_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
    const MAX_CDP_FRAME_BYTES: usize = 1024 * 1024;

    let request_id = request_id(req);
    let Some(ticket) = req.query::<String>("ticket") else {
        error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_browser_ticket",
            "browser ticket is required",
            &request_id,
        );
        return;
    };
    let connection = match state(depot).services.open_browser_cdp(&ticket).await {
        Ok(connection) => connection,
        Err(error_value) => {
            map_error(res, error_value, &request_id);
            return;
        }
    };
    let guest_url = format!("ws://127.0.0.1{}", connection.websocket_path);
    let config = WebSocketConfig::default()
        .read_buffer_size(64 * 1024)
        .write_buffer_size(64 * 1024)
        .max_write_buffer_size(MAX_CDP_MESSAGE_BYTES + 64 * 1024)
        .max_message_size(Some(MAX_CDP_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_CDP_FRAME_BYTES));
    let (guest, _) = match tokio_tungstenite::client_async_with_config(
        guest_url,
        connection.stream,
        Some(config),
    )
    .await
    {
        Ok(value) => value,
        Err(_) => {
            error(
                res,
                StatusCode::BAD_GATEWAY,
                "browser_connect_failed",
                "browser CDP handshake failed",
                &request_id,
            );
            return;
        }
    };
    let upgraded = WebSocketUpgrade::new()
        .max_message_size(MAX_CDP_MESSAGE_BYTES)
        .max_frame_size(MAX_CDP_FRAME_BYTES)
        .upgrade(req, res, move |socket| async move {
            let (mut external_write, mut external_read) = socket.split();
            let (mut guest_write, mut guest_read) = guest.split();
            let upload = async {
                while let Some(message) = external_read.next().await {
                    let message = message.map_err(std::io::Error::other)?;
                    let guest_message = if message.is_text() {
                        TungsteniteMessage::text(
                            message.as_str().map_err(std::io::Error::other)?.to_owned(),
                        )
                    } else if message.is_binary() {
                        TungsteniteMessage::binary(message.as_bytes().to_vec())
                    } else if message.is_ping() {
                        TungsteniteMessage::Ping(message.as_bytes().to_vec().into())
                    } else if message.is_pong() {
                        TungsteniteMessage::Pong(message.as_bytes().to_vec().into())
                    } else if message.is_close() {
                        guest_write
                            .send(TungsteniteMessage::Close(None))
                            .await
                            .map_err(std::io::Error::other)?;
                        return Ok::<(), std::io::Error>(());
                    } else {
                        return Err(std::io::Error::other("unsupported browser CDP frame"));
                    };
                    guest_write
                        .send(guest_message)
                        .await
                        .map_err(std::io::Error::other)?;
                }
                guest_write.close().await.map_err(std::io::Error::other)
            };
            let download = async {
                while let Some(message) = guest_read.next().await {
                    let external_message = match message.map_err(std::io::Error::other)? {
                        TungsteniteMessage::Text(value) => Message::text(value.as_str()),
                        TungsteniteMessage::Binary(value) => Message::binary(value.to_vec()),
                        TungsteniteMessage::Ping(value) => Message::ping(value.to_vec()),
                        TungsteniteMessage::Pong(value) => Message::pong(value.to_vec()),
                        TungsteniteMessage::Close(Some(frame)) => {
                            Message::close_with(u16::from(frame.code), frame.reason.as_str())
                        }
                        TungsteniteMessage::Close(None) => Message::close(),
                        TungsteniteMessage::Frame(_) => {
                            return Err(std::io::Error::other("unexpected raw browser CDP frame"));
                        }
                    };
                    let closed = external_message.is_close();
                    external_write
                        .send(external_message)
                        .await
                        .map_err(std::io::Error::other)?;
                    if closed {
                        return Ok::<(), std::io::Error>(());
                    }
                }
                Ok::<(), std::io::Error>(())
            };
            tokio::select! {
                _ = upload => {}
                _ = download => {}
            }
        })
        .await;
    if let Err(error_value) = upgraded {
        error(
            res,
            StatusCode::BAD_REQUEST,
            "browser_websocket_upgrade_failed",
            error_value.to_string(),
            &request_id,
        );
    }
}

const SCREENCAST_VIEW_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>boxd browser view</title><style>html,body{margin:0;width:100%;height:100%;background:#111;color:#ddd;font:14px system-ui}body{display:grid;place-items:center}img{max-width:100%;max-height:100%;object-fit:contain}#status{position:fixed;left:12px;bottom:10px;padding:4px 8px;background:#000a;border-radius:4px}</style></head>
<body><img id="frame" alt="Live browser view"><div id="status">Connecting…</div><script src="/v2/box/browser/screencast/client.js"></script></body></html>"#;

const SCREENCAST_VIEW_JS: &str = r#"(() => {
  'use strict';
  const image = document.getElementById('frame');
  const status = document.getElementById('status');
  const ticket = new URLSearchParams(location.search).get('ticket') || '';
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${scheme}//${location.host}/v2/box/browser/screencast/ws?ticket=${encodeURIComponent(ticket)}`);
  socket.binaryType = 'blob';
  let previous = null;
  socket.onopen = () => { status.textContent = 'Live'; };
  socket.onmessage = event => {
    if (!(event.data instanceof Blob)) return;
    const next = URL.createObjectURL(event.data);
    image.onload = () => { if (previous) URL.revokeObjectURL(previous); previous = next; };
    image.src = next;
  };
  socket.onerror = () => { status.textContent = 'Unavailable'; };
  socket.onclose = () => { status.textContent = 'Disconnected'; };
})();"#;

fn valid_browser_ticket(ticket: &str) -> bool {
    ticket.len() == 64 && ticket.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[handler]
async fn browser_screencast_page(req: &Request, res: &mut Response) {
    let valid = req
        .query::<String>("ticket")
        .is_some_and(|ticket| valid_browser_ticket(&ticket));
    if !valid {
        error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_browser_ticket",
            "browser ticket is required",
            &request_id(req),
        );
        return;
    }
    res.headers_mut().remove("x-frame-options");
    res.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; script-src 'self'; img-src blob:; connect-src 'self' ws: wss:; style-src 'unsafe-inline'; frame-ancestors *; base-uri 'none'; form-action 'none'"),
    );
    res.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    res.render(Text::Html(SCREENCAST_VIEW_HTML));
}

#[handler]
async fn browser_screencast_client(res: &mut Response) {
    res.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static("public, max-age=3600"),
    );
    res.render(Text::Js(SCREENCAST_VIEW_JS));
}

#[handler]
async fn browser_screencast_ws(req: &mut Request, depot: &Depot, res: &mut Response) {
    let request_id = request_id(req);
    let Some(ticket) = req
        .query::<String>("ticket")
        .filter(|ticket| valid_browser_ticket(ticket))
    else {
        error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_browser_ticket",
            "browser ticket is required",
            &request_id,
        );
        return;
    };
    let connection = match state(depot).services.open_browser_screencast(&ticket).await {
        Ok(connection) => connection,
        Err(error_value) => {
            map_error(res, error_value, &request_id);
            return;
        }
    };
    let mut frames = connection.frames;
    let upgraded = WebSocketUpgrade::new()
        .max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .upgrade(req, res, move |mut external| async move {
            loop {
                tokio::select! {
                    external_message = external.next() => {
                        match external_message {
                            Some(Ok(message)) if message.is_ping() => {
                                let _ = external.send(Message::pong(message.as_bytes().to_vec())).await;
                            }
                            _ => break,
                        }
                    }
                    frame = frames.next() => {
                        match frame {
                            Some(Ok(frame)) => {
                                if external.send(Message::binary(frame)).await.is_err() {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                }
            }
            let _ = external.close().await;
        })
        .await;
    if let Err(error_value) = upgraded {
        error(
            res,
            StatusCode::BAD_REQUEST,
            "browser_websocket_upgrade_failed",
            error_value.to_string(),
            &request_id,
        );
    }
}

#[handler]
async fn openapi(res: &mut Response) {
    res.render(Json(phase_one_openapi()));
}

#[handler]
async fn admin_login(req: &mut Request, depot: &Depot, res: &mut Response) {
    let request_id = request_id(req);
    let body = match json_body::<AdminLoginRequest>(req, depot).await {
        Ok(body) => body,
        Err(error_value) => {
            map_error(res, error_value, &request_id);
            return;
        }
    };
    match state(depot)
        .admin_login
        .login(&body.username, &body.password)
        .await
    {
        Ok(created) => {
            let max_age = ((created.expires_at_millis
                - std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64)
                / 1_000)
                .max(0);
            let secure = if req.uri().scheme_str() == Some("https") {
                "; Secure"
            } else {
                ""
            };
            let cookie = format!(
                "boxd_session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
                created.session
            );
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                res.headers_mut().insert("set-cookie", value);
                res.render(Json(json!({
                    "csrf_token": created.csrf,
                    "expires_at": created.expires_at_millis
                })));
            } else {
                map_error(
                    res,
                    DomainError {
                        kind: DomainErrorKind::Internal,
                        code: "authentication_error",
                        message: "could not issue administrator session".into(),
                    },
                    &request_id,
                );
            }
        }
        Err(_) => error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid credentials",
            &request_id,
        ),
    }
}

#[handler]
async fn admin_logout(req: &mut Request, depot: &Depot, res: &mut Response) {
    let request_id = request_id(req);
    let session = req
        .cookie("boxd_session")
        .map(|value| value.value().to_owned());
    let csrf = req.header::<String>("x-csrf-token");
    match (session, csrf) {
        (Some(session), Some(csrf)) => {
            if let Err(error_value) = state(depot).admin_login.logout(&session, &csrf).await {
                map_error(res, error_value, &request_id);
                return;
            }
            res.headers_mut().insert(
                "set-cookie",
                HeaderValue::from_static(
                    "boxd_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                ),
            );
            res.render(Json(json!({})));
        }
        _ => error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "valid admin session and CSRF token are required",
            &request_id,
        ),
    }
}
#[handler]
async fn api(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let request_id = depot
        .get_typed::<String>()
        .cloned()
        .unwrap_or_else(|_| request_id(req));
    let Some(auth) = context(depot, res) else {
        return;
    };
    let path = req.uri().path().to_owned();
    let method = req.method().as_str().to_owned();
    if let Some(required) = required_scope(&method, &path)
        && !auth.allows(required)
    {
        map_error(
            res,
            DomainError {
                kind: DomainErrorKind::Ownership,
                code: "forbidden_scope",
                message: "API key does not grant the required scope".into(),
            },
            &request_id,
        );
        return;
    }
    let account = auth.account;
    let service = &state(depot).services;
    if method == "POST"
        && (path.ends_with("/run") || path.ends_with("/run/stream"))
        && req
            .headers()
            .get(salvo::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("multipart/form-data"))
    {
        map_error(
            res,
            DomainError::feature_not_supported("run prompt files"),
            &request_id,
        );
        return;
    }
    if method == "POST" && path.ends_with("/run/stream") {
        let Some(box_id) = path
            .strip_prefix("/v2/box/")
            .and_then(|value| value.strip_suffix("/run/stream"))
            .filter(|value| !value.is_empty() && !value.contains('/'))
        else {
            map_error(res, DomainError::validation("invalid box id"), &request_id);
            return;
        };
        let events = if let Some(last_event_id) = req.header::<String>("last-event-id") {
            match parse_last_event_id(&last_event_id) {
                Ok((run_id, sequence)) => {
                    service
                        .resume_run_stream(account, box_id, &run_id, sequence)
                        .await
                }
                Err(error) => Err(error),
            }
        } else {
            let request = match json_body::<AgentRunRequest>(req, depot).await {
                Ok(request) => request,
                Err(error) => {
                    map_error(res, error, &request_id);
                    return;
                }
            };
            if let Err(error) = request.validate_phase_two() {
                map_error(res, error, &request_id);
                return;
            }
            service.run_stream(account, box_id, request).await
        };
        match events {
            Ok(events) => {
                let client = SseClientGuard::new(state(depot).telemetry.clone());
                let events = events.map(move |result| {
                    let _client = &client;
                    match result {
                        Ok(event) => Ok::<_, std::io::Error>(
                            salvo::sse::SseEvent::default()
                                .id(format!("{}:{}", event.run_id, event.sequence))
                                .name(event.event_type)
                                .text(event.payload_json),
                        ),
                        Err(error) => Err(std::io::Error::other(format!(
                            "{}: {}",
                            error.code, error.message
                        ))),
                    }
                });
                res.headers_mut()
                    .insert("x-accel-buffering", HeaderValue::from_static("no"));
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_ENCODING,
                    HeaderValue::from_static("identity"),
                );
                salvo::sse::SseKeepAlive::new(events)
                    .max_interval(std::time::Duration::from_secs(15))
                    .comment("keepalive")
                    .stream(res);
            }
            Err(error) => map_error(res, error, &request_id),
        }
        return;
    }
    if method == "GET"
        && let Some((box_id, suffix)) = box_file_route(&path)
    {
        let parts = suffix.split('/').collect::<Vec<_>>();
        if let [
            "browser",
            "recordings",
            recording_id,
            artifact @ ("playlist" | "download"),
        ] = parts.as_slice()
        {
            let result = if *artifact == "playlist" {
                if let Some(segment) = req.query::<String>("segment") {
                    service
                        .browser_recording_segment(account, box_id, recording_id, &segment)
                        .await
                        .map(|bytes| (bytes, "video/mp2t"))
                } else {
                    service
                        .browser_recording_playlist(account, box_id, recording_id)
                        .await
                        .map(|bytes| (bytes, "application/vnd.apple.mpegurl"))
                }
            } else {
                service
                    .browser_recording_download(account, box_id, recording_id)
                    .await
                    .map(|download| (download.bytes, download.content_type))
            };
            match result {
                Ok((bytes, content_type)) => {
                    if let Ok(value) = HeaderValue::from_str(content_type) {
                        res.headers_mut()
                            .insert(salvo::http::header::CONTENT_TYPE, value);
                    }
                    if let Ok(length) = HeaderValue::from_str(&bytes.len().to_string()) {
                        res.headers_mut()
                            .insert(salvo::http::header::CONTENT_LENGTH, length);
                    }
                    if res.write_body(bytes).is_err() {
                        map_error(
                            res,
                            DomainError {
                                kind: DomainErrorKind::Internal,
                                code: "response_write_failed",
                                message: "could not write recording response".into(),
                            },
                            &request_id,
                        );
                    }
                }
                Err(error) => map_error(res, error, &request_id),
            }
            return;
        }
    }
    if let Some((box_id, suffix)) = box_file_route(&path) {
        let raw_result = match (method.as_str(), suffix) {
            ("GET", "files/download") => {
                let path = req
                    .query::<String>("folder")
                    .ok_or_else(|| DomainError::validation("folder is required"));
                match path {
                    Ok(path) => service
                        .read_file_bytes(account, box_id, path)
                        .await
                        .map(Some),
                    Err(error) => Err(error),
                }
            }
            ("POST", "files/upload") => match parse_upload(req, depot).await {
                Ok(files) => service
                    .upload_files(account, box_id, files)
                    .await
                    .map(|()| None),
                Err(error) => Err(error),
            },
            _ => Ok(None),
        };
        if matches!(
            (method.as_str(), suffix),
            ("GET", "files/download") | ("POST", "files/upload")
        ) {
            match raw_result {
                Ok(Some(bytes)) => {
                    res.headers_mut().insert(
                        salvo::http::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/octet-stream"),
                    );
                    if let Ok(length) = HeaderValue::from_str(&bytes.len().to_string()) {
                        res.headers_mut()
                            .insert(salvo::http::header::CONTENT_LENGTH, length);
                    }
                    if res.write_body(bytes).is_err() {
                        map_error(
                            res,
                            DomainError {
                                kind: DomainErrorKind::Internal,
                                code: "response_write_failed",
                                message: "could not write file response".into(),
                            },
                            &request_id,
                        );
                    }
                }
                Ok(None) => res.render(Json(json!({}))),
                Err(error) => map_error(res, error, &request_id),
            }
            return;
        }
    }
    let outcome: Result<Value, DomainError> = match (method.as_str(), path.as_str()) {
        ("POST", "/v2/box") => match json_body::<CreateBoxRequest>(req, depot).await {
            Ok(body) => match body.validate_create() {
                Ok(()) => service.create_box(account, body).await,
                Err(error) => Err(error),
            },
            Err(e) => Err(e),
        },
        ("POST", "/v2/box/from-snapshot") => {
            match json_body::<CreateBoxRequest>(req, depot).await {
                Ok(body) => match body.validate_from_snapshot() {
                    Ok(()) => service.create_box_from_snapshot(account, body).await,
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            }
        }
        ("GET", "/v2/box") => {
            service
                .list_boxes(account, req.query::<String>("label"))
                .await
        }
        ("DELETE", "/v2/box") => match json_body::<BulkDeleteRequest>(req, depot).await {
            Ok(body) => match body.validate() {
                Ok(ids) => service
                    .bulk_delete_boxes(account, ids)
                    .await
                    .map(|()| json!({})),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        ("DELETE", "/v2/box/snapshots") => {
            match json_body::<SnapshotDeleteRequest>(req, depot).await {
                Ok(body) => service
                    .delete_snapshots(account, body.ids)
                    .await
                    .map(|deleted| json!({"deleted":deleted})),
                Err(error) => Err(error),
            }
        }
        _ if path.starts_with("/v2/box/settings/env") => {
            let key = path.strip_prefix("/v2/box/settings/env/");
            match if method == "PUT" {
                json_body::<Value>(req, depot).await.map(Some)
            } else {
                Ok(None)
            } {
                Ok(body) => service.env(account, None, &method, key, body).await,
                Err(error) => Err(error),
            }
        }
        _ => dispatch_box(&method, &path, req, depot, account).await,
    };
    match outcome {
        Ok(value) => res.render(Json(value)),
        Err(value) => map_error(res, value, &request_id),
    }
}

fn parse_last_event_id(value: &str) -> Result<(String, u64), DomainError> {
    let (run_id, sequence) = value
        .split_once(':')
        .ok_or_else(|| DomainError::validation("invalid Last-Event-ID"))?;
    Uuid::parse_str(run_id).map_err(|_| DomainError::validation("invalid Last-Event-ID"))?;
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| DomainError::validation("invalid Last-Event-ID"))?;
    Ok((run_id.into(), sequence))
}

fn required_scope(method: &str, path: &str) -> Option<AuthScope> {
    if !path.starts_with("/v2/box") {
        return None;
    }
    if path.ends_with("/exec")
        || path.ends_with("/code")
        || path.ends_with("/run")
        || path.ends_with("/run/stream")
        || path.ends_with("/cancel")
    {
        return Some(AuthScope::RunsWrite);
    }
    if (path.starts_with("/v2/box/settings/env")
        || path.contains("/settings/env")
        || path.ends_with("/startup"))
        && method == "GET"
    {
        return Some(AuthScope::SecretsRead);
    }
    if method == "GET" {
        Some(AuthScope::BoxesRead)
    } else {
        Some(AuthScope::BoxesWrite)
    }
}
async fn dispatch_box(
    method: &str,
    path: &str,
    req: &mut Request,
    depot: &Depot,
    account: AccountContext,
) -> Result<Value, DomainError> {
    let Some(rest) = path.strip_prefix("/v2/box/") else {
        return Err(DomainError {
            kind: DomainErrorKind::NotFound,
            code: "not_found",
            message: "route not found".into(),
        });
    };
    let mut parts = rest.split('/');
    let box_id = parts.next().unwrap_or_default();
    let suffix = parts.collect::<Vec<_>>().join("/");
    let service = &state(depot).services;
    if method == "POST" {
        let run_parts = suffix.split('/').collect::<Vec<_>>();
        if let ["runs", run_id, "cancel"] = run_parts.as_slice() {
            service.cancel_run(account, box_id, run_id).await?;
            return Ok(json!({}));
        }
    }
    if method == "DELETE" {
        let snapshot_parts = suffix.split('/').collect::<Vec<_>>();
        if let ["snapshots", snapshot_id] = snapshot_parts.as_slice() {
            service
                .delete_snapshot(account, box_id, snapshot_id)
                .await?;
            return Ok(json!({}));
        }
        if let ["preview", raw_port] = snapshot_parts.as_slice() {
            let port = raw_port
                .parse::<u16>()
                .map_err(|_| DomainError::validation("invalid preview port"))?;
            service.delete_preview(account, box_id, port).await?;
            return Ok(json!({}));
        }
        if let Some(skill_id) = suffix.strip_prefix("config/skills/") {
            service.remove_skill(account, box_id, skill_id).await?;
            return Ok(json!({}));
        }
        if let Some(tab_id) = suffix.strip_prefix("browser/tabs/") {
            box_browser::validate_tab_id(tab_id)?;
            service.browser_close_tab(account, box_id, tab_id).await?;
            return Ok(json!({}));
        }
    }
    let schedule_parts = suffix.split('/').collect::<Vec<_>>();
    match (method, schedule_parts.as_slice()) {
        ("POST", ["browser", "recordings"]) => {
            let request: BrowserRecordingStartRequest = json_body(req, depot).await?;
            return service
                .browser_recording_start(account, box_id, request)
                .await
                .map(|value| serde_json::to_value(value).expect("serializable recording"));
        }
        ("POST", ["browser", "recordings", "stop"]) => {
            return service
                .browser_recording_stop(account, box_id)
                .await
                .map(|value| serde_json::to_value(value).expect("serializable recording"));
        }
        ("GET", ["browser", "recordings"]) => {
            let limit = req.query::<usize>("limit").unwrap_or(100);
            if limit == 0 || limit > 100 {
                return Err(DomainError::validation(
                    "recording limit must be between 1 and 100",
                ));
            }
            return service
                .browser_recording_list(account, box_id, req.query::<String>("cursor"), limit)
                .await
                .map(|value| serde_json::to_value(value).expect("serializable recordings"));
        }
        ("GET", ["browser", "recordings", recording_id]) => {
            return service
                .browser_recording_get(account, box_id, recording_id)
                .await
                .map(|value| serde_json::to_value(value).expect("serializable recording"));
        }
        ("GET", ["schedules", schedule_id]) => {
            return service
                .get_schedule(account, box_id, schedule_id)
                .await
                .map(|value| serde_json::to_value(value).expect("serializable schedule"));
        }
        ("PATCH", ["schedules", schedule_id]) => {
            let request: ScheduleUpdateRequest = json_body(req, depot).await?;
            return service
                .update_schedule(account, box_id, schedule_id, request)
                .await
                .map(|value| serde_json::to_value(value).expect("serializable schedule"));
        }
        ("DELETE", ["schedules", schedule_id]) => {
            service
                .delete_schedule(account, box_id, schedule_id)
                .await?;
            return Ok(json!({}));
        }
        ("POST", ["schedules", schedule_id, "pause"]) => {
            service
                .set_schedule_paused(account, box_id, schedule_id, true)
                .await?;
            return Ok(json!({}));
        }
        ("POST", ["schedules", schedule_id, "resume"]) => {
            service
                .set_schedule_paused(account, box_id, schedule_id, false)
                .await?;
            return Ok(json!({}));
        }
        _ => {}
    }
    match (method, suffix.as_str()) {
        ("GET", "") => service.get_box(account, box_id).await,
        ("DELETE", "") => {
            service.delete_box(account, box_id).await?;
            Ok(json!({}))
        }
        ("GET", "status") => service.box_status(account, box_id).await,
        ("POST", "pause") => service.pause_box(account, box_id).await,
        ("POST", "resume") => service.resume_box(account, box_id).await,
        ("POST", "run") => {
            let request: AgentWebhookRunRequest = json_body(req, depot).await?;
            request.validate_phase_two()?;
            service.run_webhook(account, box_id, request).await
        }
        ("GET", "startup") => service
            .get_startup_command(account, box_id)
            .await
            .map(|init_command| json!({"init_command":init_command})),
        ("PUT", "startup") => {
            let body: StartupConfigurationRequest = json_body(req, depot).await?;
            service
                .set_startup_command(account, box_id, body.validate()?)
                .await?;
            Ok(json!({}))
        }
        ("DELETE", "startup") => {
            service.delete_startup_command(account, box_id).await?;
            Ok(json!({}))
        }
        ("POST", "git/exec") => {
            let request: GitExecRequest = json_body(req, depot).await?;
            request.validate()?;
            let result = service.git_exec(account, box_id, request).await?;
            Ok(serde_json::to_value(result).expect("serializable git exec result"))
        }
        ("GET", "git/diff") => service
            .git_diff(account, box_id, req.query::<String>("folder"))
            .await
            .map(|diff| json!({"diff":diff})),
        ("GET", "git/status") => service
            .git_status(account, box_id, req.query::<String>("folder"))
            .await
            .map(|status| json!({"status":status})),
        ("POST", "git/checkout") => {
            let request: GitCheckoutRequest = json_body(req, depot).await?;
            request.validate()?;
            service.git_checkout(account, box_id, request).await?;
            Ok(json!({}))
        }
        ("PUT", "git-config") => {
            let request: GitConfigUpdateRequest = json_body(req, depot).await?;
            request.validate()?;
            let result = service.git_update_config(account, box_id, request).await?;
            Ok(serde_json::to_value(result).expect("serializable git config result"))
        }
        ("POST", "git/commit") => {
            let request: GitCommitRequest = json_body(req, depot).await?;
            request.validate()?;
            let result = service.git_commit(account, box_id, request).await?;
            Ok(serde_json::to_value(result).expect("serializable git commit result"))
        }
        ("POST", "git/clone") => {
            let request: GitCloneRequest = json_body(req, depot).await?;
            request.validate()?;
            service.git_clone(account, box_id, request).await?;
            Ok(json!({}))
        }
        ("POST", "git/push") => {
            let request: GitPushRequest = json_body(req, depot).await?;
            request.validate()?;
            service.git_push(account, box_id, request).await?;
            Ok(json!({}))
        }
        ("POST", "git/create-pr") => {
            let request: GitCreatePrRequest = json_body(req, depot).await?;
            request.validate()?;
            let result = service.git_create_pr(account, box_id, request).await?;
            Ok(serde_json::to_value(result).expect("serializable pull request"))
        }
        ("POST", "snapshots") => {
            let request: SnapshotCreateRequest = json_body(req, depot).await?;
            let snapshot = service
                .create_snapshot(account, box_id, request.validate()?)
                .await?;
            Ok(serde_json::to_value(snapshot).expect("serializable snapshot"))
        }
        ("GET", "snapshots") => service
            .list_snapshots(account, box_id)
            .await
            .map(|snapshots| json!({"snapshots":snapshots})),
        ("POST", "schedules") => {
            let request: ScheduleCreateRequest = json_body(req, depot).await?;
            service
                .create_schedule(account, box_id, request)
                .await
                .map(|value| serde_json::to_value(value).expect("serializable schedule"))
        }
        ("GET", "schedules") => service
            .list_schedules(account, box_id)
            .await
            .map(|value| serde_json::to_value(value).expect("serializable schedules")),
        ("POST", "browser/connect") => service
            .browser_connect(account, box_id)
            .await
            .map(|cdp_url| json!({"cdp_url": cdp_url})),
        ("POST", "browser/screencast") => {
            let request: BrowserScreencastRequest = json_body(req, depot).await?;
            service
                .browser_screencast(account, box_id, &request.validate()?)
                .await
                .map(|screencast_url| json!({"screencast_url": screencast_url}))
        }
        ("POST", "browser/tabs") => {
            let request: BrowserCreateTabRequest = json_body(req, depot).await?;
            let tab = service
                .browser_create_tab(account, box_id, request.validate()?)
                .await?;
            Ok(serde_json::to_value(tab).expect("serializable browser tab"))
        }
        ("GET", "browser/tabs") => service
            .browser_list_tabs(account, box_id)
            .await
            .map(|tabs| json!({"tabs": tabs})),
        ("POST", "browser/goto") => {
            let request: BrowserNavigateRequest = json_body(req, depot).await?;
            let content = service
                .browser_goto(account, box_id, request.validate()?)
                .await?;
            Ok(serde_json::to_value(content).expect("serializable browser content"))
        }
        ("GET", "browser/content") => {
            let tab = req
                .query::<String>("tab")
                .ok_or_else(|| DomainError::validation("browser tab is required"))?;
            box_browser::validate_tab_id(&tab)?;
            let content = service.browser_content(account, box_id, &tab).await?;
            Ok(serde_json::to_value(content).expect("serializable browser content"))
        }
        ("GET", "browser/screenshot") => {
            let tab = req
                .query::<String>("tab")
                .ok_or_else(|| DomainError::validation("browser tab is required"))?;
            let encoding = req
                .query::<String>("encoding")
                .ok_or_else(|| DomainError::validation("screenshot encoding is required"))?;
            if encoding != "base64" {
                return Err(DomainError::validation(
                    "only base64 screenshot encoding is supported",
                ));
            }
            let request = Screenshot {
                tab,
                full_page: req.query::<bool>("full_page").unwrap_or(false),
            };
            request.validate()?;
            let bytes = service.browser_screenshot(account, box_id, request).await?;
            Ok(json!({"data":BASE64_STANDARD.encode(bytes)}))
        }
        ("POST", "browser/extract") => {
            let request: BrowserInstruction = json_body(req, depot).await?;
            request.validate_extract()?;
            service
                .browser_extract(account, box_id, request)
                .await
                .map(|data| json!({"data": data}))
        }
        ("POST", "browser/observe") => {
            let request: BrowserInstruction = json_body(req, depot).await?;
            request.validate_without_schema()?;
            service
                .browser_observe(account, box_id, request)
                .await
                .map(|result| serde_json::to_value(result).expect("serializable browser result"))
        }
        ("POST", "browser/act") => {
            let request: BrowserInstruction = json_body(req, depot).await?;
            request.validate_without_schema()?;
            service
                .browser_act(account, box_id, request)
                .await
                .map(|result| serde_json::to_value(result).expect("serializable browser result"))
        }
        ("POST", "browser/run") => {
            let request: BrowserRunInstruction = json_body(req, depot).await?;
            request.validate()?;
            service
                .browser_run(account, box_id, request)
                .await
                .map(|result| serde_json::to_value(result).expect("serializable browser result"))
        }
        ("POST", "preview") => {
            let request: PreviewCreateRequest = json_body(req, depot).await?;
            let (port, auth) = request.validate()?;
            let preview = service.create_preview(account, box_id, port, auth).await?;
            Ok(serde_json::to_value(preview).expect("serializable public URL"))
        }
        ("GET", "preview") => service
            .list_previews(account, box_id)
            .await
            .map(|previews| json!({"previews":previews})),
        ("POST", "config/skills") => {
            let body: SkillRequest = json_body(req, depot).await?;
            service.add_skill(account, box_id, body.skill_id).await?;
            Ok(json!({}))
        }
        ("POST", "exec") => {
            let result = service
                .exec(account, box_id, json_body(req, depot).await?)
                .await?;
            Ok(serde_json::to_value(result).expect("serializable exec result"))
        }
        ("POST", "code") => {
            let result = service
                .code(account, box_id, json_body(req, depot).await?)
                .await?;
            Ok(serde_json::to_value(result).expect("serializable code result"))
        }
        ("PUT", "config/model") => {
            let body: ModelConfigurationRequest = json_body(req, depot).await?;
            service
                .configure_model(account, box_id, body.validate()?)
                .await?;
            Ok(json!({}))
        }
        ("PUT", "config/custom-runner") => {
            let body: CustomRunnerConfigurationRequest = json_body(req, depot).await?;
            service
                .configure_custom_runner(account, box_id, body.validate()?)
                .await?;
            Ok(json!({}))
        }
        ("GET", "runs") => service.list_runs(account, box_id).await,
        ("GET", "logs") => {
            let offset = req.query::<usize>("offset").unwrap_or(0);
            let limit = req.query::<usize>("limit").unwrap_or(100);
            if limit == 0 || limit > 1_000 {
                return Err(DomainError::validation("limit must be between 1 and 1000"));
            }
            service.logs(account, box_id, offset, limit).await
        }
        ("GET", "files/read") => {
            service
                .read_file(
                    account,
                    box_id,
                    req.query::<String>("path")
                        .ok_or_else(|| DomainError::validation("path is required"))?,
                    req.query("encoding"),
                )
                .await
        }
        ("POST", "files/write") => {
            service
                .write_file(account, box_id, json_body(req, depot).await?)
                .await?;
            Ok(json!({}))
        }
        ("GET", "files/list") => Ok(json!({ "files": service
                .list_files(
                    account,
                    box_id,
                    req.query::<String>("folder")
                        .unwrap_or_else(|| "/workspace/home".into()),
                )
                .await? })),
        ("POST", "config/labels") => {
            let body: LabelRequest = json_body(req, depot).await?;
            service
                .labels(account, box_id, method, Some(&body.label))
                .await
        }
        ("DELETE", _) if suffix.starts_with("config/labels/") => {
            service
                .labels(
                    account,
                    box_id,
                    method,
                    suffix.strip_prefix("config/labels/"),
                )
                .await
        }
        _ if suffix.starts_with("settings/env") => {
            service
                .env(
                    account,
                    Some(box_id),
                    method,
                    suffix
                        .strip_prefix("settings/env/")
                        .filter(|value| !value.is_empty()),
                    None,
                )
                .await
        }
        _ if manifest_path(method, path) => Err(DomainError::feature_not_supported(
            "this pinned SDK operation",
        )),
        _ => Err(DomainError {
            kind: DomainErrorKind::NotFound,
            code: "not_found",
            message: "route not found".into(),
        }),
    }
}

// 77 direct dispatches plus one response-linked operation are matched here. Parameter values
// are intentionally not used for registration decisions.
fn manifest_path(method: &str, path: &str) -> bool {
    const ROUTES: &[(&str, &str)] = &[
        ("DELETE", "/v2/box"),
        ("GET", "/v2/box"),
        ("POST", "/v2/box"),
        ("POST", "/v2/box/from-snapshot"),
        ("DELETE", "/v2/box/snapshots"),
        ("GET", "/v2/box/{id}"),
        ("DELETE", "/v2/box/{id}"),
        ("GET", "/v2/box/{id}/status"),
        ("POST", "/v2/box/{id}/pause"),
        ("POST", "/v2/box/{id}/resume"),
        ("GET", "/v2/box/{id}/startup"),
        ("PUT", "/v2/box/{id}/startup"),
        ("DELETE", "/v2/box/{id}/startup"),
        ("PUT", "/v2/box/{id}/config/model"),
        ("PUT", "/v2/box/{id}/config/custom-runner"),
        ("PUT", "/v2/box/{id}/config/network-policy"),
        ("POST", "/v2/box/{id}/config/skills"),
        ("DELETE", "/v2/box/{id}/config/skills/{tail}"),
        ("POST", "/v2/box/{id}/config/labels"),
        ("DELETE", "/v2/box/{id}/config/labels/{tail}"),
        ("POST", "/v2/box/{id}/run"),
        ("POST", "/v2/box/{id}/run/stream"),
        ("POST", "/v2/box/{id}/runs/{tail}/cancel"),
        ("GET", "/v2/box/{id}/runs"),
        ("GET", "/v2/box/{id}/logs"),
        ("POST", "/v2/box/{id}/exec"),
        ("POST", "/v2/box/{id}/exec-stream"),
        ("POST", "/v2/box/{id}/code"),
        ("POST", "/v2/box/{id}/code-stream"),
        ("GET", "/v2/box/{id}/files/read"),
        ("POST", "/v2/box/{id}/files/write"),
        ("GET", "/v2/box/{id}/files/list"),
        ("POST", "/v2/box/{id}/files/upload"),
        ("GET", "/v2/box/{id}/files/download"),
        ("POST", "/v2/box/{id}/git/clone"),
        ("POST", "/v2/box/{id}/git/commit"),
        ("POST", "/v2/box/{id}/git/push"),
        ("POST", "/v2/box/{id}/git/create-pr"),
        ("POST", "/v2/box/{id}/git/exec"),
        ("POST", "/v2/box/{id}/git/checkout"),
        ("GET", "/v2/box/{id}/git/diff"),
        ("GET", "/v2/box/{id}/git/status"),
        ("PUT", "/v2/box/{id}/git-config"),
        ("POST", "/v2/box/{id}/snapshots"),
        ("GET", "/v2/box/{id}/snapshots"),
        ("DELETE", "/v2/box/{id}/snapshots/{tail}"),
        ("POST", "/v2/box/{id}/schedules"),
        ("GET", "/v2/box/{id}/schedules"),
        ("GET", "/v2/box/{id}/schedules/{tail}"),
        ("PATCH", "/v2/box/{id}/schedules/{tail}"),
        ("DELETE", "/v2/box/{id}/schedules/{tail}"),
        ("POST", "/v2/box/{id}/schedules/{tail}/pause"),
        ("POST", "/v2/box/{id}/schedules/{tail}/resume"),
        ("POST", "/v2/box/{id}/preview"),
        ("GET", "/v2/box/{id}/preview"),
        ("DELETE", "/v2/box/{id}/preview/{tail}"),
        ("POST", "/v2/box/{id}/browser/tabs"),
        ("GET", "/v2/box/{id}/browser/tabs"),
        ("DELETE", "/v2/box/{id}/browser/tabs/{tail}"),
        ("POST", "/v2/box/{id}/browser/goto"),
        ("POST", "/v2/box/{id}/browser/extract"),
        ("POST", "/v2/box/{id}/browser/observe"),
        ("POST", "/v2/box/{id}/browser/act"),
        ("POST", "/v2/box/{id}/browser/run"),
        ("GET", "/v2/box/{id}/browser/content"),
        ("GET", "/v2/box/{id}/browser/screenshot"),
        ("POST", "/v2/box/{id}/browser/connect"),
        ("POST", "/v2/box/{id}/browser/screencast"),
        ("POST", "/v2/box/{id}/browser/recordings"),
        ("POST", "/v2/box/{id}/browser/recordings/stop"),
        ("GET", "/v2/box/{id}/browser/recordings"),
        ("GET", "/v2/box/{id}/browser/recordings/{tail}"),
        ("GET", "/v2/box/{id}/browser/recordings/{tail}/playlist"),
        ("GET", "/v2/box/{id}/browser/recordings/{tail}/download"),
        ("GET", "/v2/box/settings/env"),
        ("PUT", "/v2/box/settings/env"),
        ("PUT", "/v2/box/settings/env/{tail}"),
        ("DELETE", "/v2/box/settings/env/{tail}"),
    ];
    ROUTES
        .iter()
        .any(|(m, pattern)| *m == method && route_matches(pattern, path))
}

fn phase_one_documented_implementation(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("DELETE" | "GET" | "POST", "/v2/box")
            | ("POST", "/v2/box/from-snapshot")
            | ("DELETE" | "GET", "/v2/box/{box_id}")
            | ("GET", "/v2/box/{box_id}/status")
            | ("POST", "/v2/box/{box_id}/pause" | "/v2/box/{box_id}/resume")
            | ("GET" | "PUT" | "DELETE", "/v2/box/{box_id}/startup")
            | ("POST", "/v2/box/{box_id}/exec" | "/v2/box/{box_id}/code")
            | ("POST", "/v2/box/{box_id}/git/exec")
            | (
                "GET",
                "/v2/box/{box_id}/git/diff" | "/v2/box/{box_id}/git/status"
            )
            | ("POST", "/v2/box/{box_id}/git/checkout")
            | ("POST", "/v2/box/{box_id}/git/commit")
            | ("POST", "/v2/box/{box_id}/git/clone")
            | ("POST", "/v2/box/{box_id}/git/push")
            | ("POST", "/v2/box/{box_id}/git/create-pr")
            | ("PUT", "/v2/box/{box_id}/git-config")
            | ("DELETE", "/v2/box/snapshots")
            | ("POST" | "GET", "/v2/box/{box_id}/snapshots")
            | ("DELETE", "/v2/box/{box_id}/snapshots/{snapshot_id}")
            | ("POST" | "GET", "/v2/box/{box_id}/preview")
            | ("DELETE", "/v2/box/{box_id}/preview/{port}")
            | (
                "GET",
                "/v2/box/{box_id}/files/read"
                    | "/v2/box/{box_id}/files/list"
                    | "/v2/box/{box_id}/files/download"
            )
            | (
                "POST",
                "/v2/box/{box_id}/files/write" | "/v2/box/{box_id}/files/upload"
            )
            | ("POST", "/v2/box/{box_id}/config/labels")
            | ("POST", "/v2/box/{box_id}/config/skills")
            | (
                "PUT",
                "/v2/box/{box_id}/config/model" | "/v2/box/{box_id}/config/custom-runner"
            )
            | ("DELETE", "/v2/box/{box_id}/config/labels/{label}")
            | ("DELETE", "/v2/box/{box_id}/config/skills/{skill_id+}")
            | ("GET" | "PUT", "/v2/box/settings/env")
            | ("PUT" | "DELETE", "/v2/box/settings/env/{key}")
            | ("GET" | "PUT", "/v2/box/{box_id}/settings/env")
            | ("PUT" | "DELETE", "/v2/box/{box_id}/settings/env/{id}")
            | ("GET", "/v2/box/{box_id}/runs")
            | ("GET", "/v2/box/{box_id}/logs")
            | ("POST", "/v2/box/{box_id}/run")
            | ("POST", "/v2/box/{box_id}/run/stream")
            | ("POST", "/v2/box/{box_id}/runs/{run_id}/cancel")
            | ("POST" | "GET", "/v2/box/{box_id}/schedules")
            | (
                "GET" | "PATCH" | "DELETE",
                "/v2/box/{box_id}/schedules/{id}"
            )
            | (
                "POST",
                "/v2/box/{box_id}/schedules/{id}/pause" | "/v2/box/{box_id}/schedules/{id}/resume"
            )
            | ("POST" | "GET", "/v2/box/{box_id}/browser/tabs")
            | ("DELETE", "/v2/box/{box_id}/browser/tabs/{tab_id}")
            | ("POST", "/v2/box/{box_id}/browser/goto")
            | (
                "POST",
                "/v2/box/{box_id}/browser/extract"
                    | "/v2/box/{box_id}/browser/observe"
                    | "/v2/box/{box_id}/browser/act"
                    | "/v2/box/{box_id}/browser/run"
            )
            | (
                "GET",
                "/v2/box/{box_id}/browser/content" | "/v2/box/{box_id}/browser/screenshot"
            )
            | (
                "POST",
                "/v2/box/{box_id}/browser/connect" | "/v2/box/{box_id}/browser/screencast"
            )
            | ("POST" | "GET", "/v2/box/{box_id}/browser/recordings")
            | ("POST", "/v2/box/{box_id}/browser/recordings/stop")
            | ("GET", "/v2/box/{box_id}/browser/recordings/{id}")
            | (
                "GET",
                "/v2/box/{box_id}/browser/recordings/{id}/playlist"
                    | "/v2/box/{box_id}/browser/recordings/{id}/download"
            )
    )
}
fn route_matches(pattern: &str, path: &str) -> bool {
    let expected = pattern
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let actual = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
    let mut index = 0;
    while index < expected.len() {
        match expected[index] {
            "{tail}" => return actual.len() > index,
            "{id}" => {
                if actual.get(index).is_none_or(|value| value.is_empty()) {
                    return false;
                }
            }
            segment => {
                if actual.get(index) != Some(&segment) {
                    return false;
                }
            }
        }
        index += 1;
    }
    actual.len() == expected.len()
}
#[handler]
async fn not_found(req: &Request, res: &mut Response) {
    let id = request_id(req);
    error(
        res,
        StatusCode::NOT_FOUND,
        "not_found",
        "route not found",
        &id,
    );
}

/// Build the API router for the `boxd` composition root. It never opens a port.
pub fn build_router(state_value: ApiState) -> Router {
    Router::new()
        .hoop(security_headers)
        .hoop(StateHoop(state_value))
        .hoop(audit_requests)
        .hoop(record_http_metrics)
        .push(Router::with_path("health/live").get(health_live))
        .push(Router::with_path("health/ready").get(health_ready))
        .push(Router::with_path("openapi.json").get(openapi))
        .push(Router::with_path("api/admin/v1/auth/login").post(admin_login))
        .push(Router::with_path("api/admin/v1/auth/logout").post(admin_logout))
        .push(Router::with_path("api/admin/v1/terminal").get(admin_terminal))
        .push(Router::with_path("v2/box/browser/cdp").get(browser_cdp))
        .push(Router::with_path("v2/box/browser/screencast/view").get(browser_screencast_page))
        .push(
            Router::with_path("v2/box/browser/screencast/client.js").get(browser_screencast_client),
        )
        .push(Router::with_path("v2/box/browser/screencast/ws").get(browser_screencast_ws))
        .push(
            Router::with_path("api/admin/v1/capabilities")
                .hoop(admin_auth)
                .get(capabilities),
        )
        .push(
            Router::with_path("api/admin/v1/{**path}")
                .hoop(admin_auth)
                .get(admin_api)
                .post(admin_api)
                .delete(admin_api),
        )
        .push(
            Router::with_path("v2/box/{box_id}")
                .hoop(compatibility_auth)
                .get(api)
                .post(api)
                .put(api)
                .delete(api)
                .patch(api),
        )
        .push(
            Router::with_path("v2/box/{**path}")
                .hoop(compatibility_auth)
                .get(api)
                .post(api)
                .put(api)
                .delete(api)
                .patch(api),
        )
        .push(
            Router::with_path("v2/box")
                .hoop(compatibility_auth)
                .get(api)
                .post(api)
                .delete(api),
        )
        .push(Router::with_path("{**path}").goal(not_found))
}

/// OpenAPI 3.1 projection of the pinned compatibility manifest. Implemented
/// and deliberate 501 routes are both described so consumers can distinguish
/// a known contract from an accidental 404. DTO schemas are generated from the
/// same Rust types used by request decoding.
pub fn phase_one_openapi() -> Value {
    use salvo::oapi::{Components, OpenApi, Operation, PathItem, PathItemType};
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../compat/upstash-box-0.6.3/route-manifest.json"
    ))
    .expect("pinned route manifest is valid JSON");
    let mut document = OpenApi::new(
        "boxd Phase 3 partial compatibility API",
        env!("CARGO_PKG_VERSION"),
    );
    for route in manifest["routes"].as_array().expect("manifest routes") {
        let path = route["path"].as_str().expect("manifest path");
        let method = match route["method"].as_str().expect("manifest method") {
            "GET" => PathItemType::Get,
            "POST" => PathItemType::Post,
            "PUT" => PathItemType::Put,
            "DELETE" => PathItemType::Delete,
            "PATCH" => PathItemType::Patch,
            other => panic!("unsupported pinned manifest method {other}"),
        };
        document
            .paths
            .insert(path, PathItem::new(method, Operation::new()));
    }
    let mut components = Components::new();
    for (name, schema) in [
        (
            "CreateBoxRequest",
            CreateBoxRequest::to_schema(&mut components),
        ),
        ("ExecRequest", ExecRequest::to_schema(&mut components)),
        ("CodeRequest", CodeRequest::to_schema(&mut components)),
        (
            "WriteFileRequest",
            WriteFileRequest::to_schema(&mut components),
        ),
        (
            "BulkDeleteRequest",
            BulkDeleteRequest::to_schema(&mut components),
        ),
        ("LabelRequest", LabelRequest::to_schema(&mut components)),
        ("SkillRequest", SkillRequest::to_schema(&mut components)),
        ("ExecResult", ExecResult::to_schema(&mut components)),
        ("CodeResult", CodeResult::to_schema(&mut components)),
        ("FileEntry", FileEntry::to_schema(&mut components)),
        (
            "AgentRunRequest",
            AgentRunRequest::to_schema(&mut components),
        ),
        (
            "AgentWebhookRunRequest",
            AgentWebhookRunRequest::to_schema(&mut components),
        ),
        ("RunWebhook", RunWebhook::to_schema(&mut components)),
        (
            "ModelConfigurationRequest",
            ModelConfigurationRequest::to_schema(&mut components),
        ),
        (
            "StartupConfigurationRequest",
            StartupConfigurationRequest::to_schema(&mut components),
        ),
        ("GitExecRequest", GitExecRequest::to_schema(&mut components)),
        ("GitExecResult", GitExecResult::to_schema(&mut components)),
        (
            "GitCheckoutRequest",
            GitCheckoutRequest::to_schema(&mut components),
        ),
        (
            "GitConfigUpdateRequest",
            GitConfigUpdateRequest::to_schema(&mut components),
        ),
        (
            "GitConfigResult",
            GitConfigResult::to_schema(&mut components),
        ),
        (
            "GitCommitRequest",
            GitCommitRequest::to_schema(&mut components),
        ),
        (
            "GitCommitResult",
            GitCommitResult::to_schema(&mut components),
        ),
        (
            "GitCloneRequest",
            GitCloneRequest::to_schema(&mut components),
        ),
        ("GitPushRequest", GitPushRequest::to_schema(&mut components)),
        (
            "GitCreatePrRequest",
            GitCreatePrRequest::to_schema(&mut components),
        ),
        ("PullRequest", PullRequest::to_schema(&mut components)),
        (
            "SnapshotCreateRequest",
            SnapshotCreateRequest::to_schema(&mut components),
        ),
        ("Snapshot", Snapshot::to_schema(&mut components)),
        (
            "SnapshotDeleteRequest",
            SnapshotDeleteRequest::to_schema(&mut components),
        ),
        (
            "PreviewCreateRequest",
            PreviewCreateRequest::to_schema(&mut components),
        ),
        ("PublicUrl", PublicUrl::to_schema(&mut components)),
        (
            "ScheduleCreateRequest",
            ScheduleCreateRequest::to_schema(&mut components),
        ),
        (
            "ScheduleResponse",
            ScheduleResponse::to_schema(&mut components),
        ),
        (
            "BrowserScreencastRequest",
            BrowserScreencastRequest::to_schema(&mut components),
        ),
        (
            "BrowserRecordingStartRequest",
            BrowserRecordingStartRequest::to_schema(&mut components),
        ),
        (
            "BrowserRecordingResponse",
            BrowserRecordingResponse::to_schema(&mut components),
        ),
        (
            "BrowserRecordingListResponse",
            BrowserRecordingListResponse::to_schema(&mut components),
        ),
    ] {
        components.schemas.insert(name, schema);
    }
    document.components = components;
    // Fill the security and high-value wire contracts explicitly while DTO
    // bodies continue to refer to the derive-generated component schemas.
    let mut value = serde_json::to_value(document).expect("OpenAPI is serializable");
    value["components"]["securitySchemes"] = json!({
        "BoxApiKey": {"type":"apiKey","in":"header","name":"X-Box-Api-Key"},
        "AdminSession": {"type":"apiKey","in":"cookie","name":"boxd_session"}
    });
    let error_response = json!({"description":"Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/ApiError"}}}});
    // The pinned manifest is executable compatibility evidence, so even a
    // deliberately unsupported operation must be a complete OpenAPI operation
    // rather than an empty placeholder. Concrete Phase 1 DTOs below override
    // this conservative projection.
    for route in manifest["routes"].as_array().expect("manifest routes") {
        let path = route["path"].as_str().expect("manifest path");
        let raw_method = route["method"].as_str().expect("manifest method");
        let method = raw_method.to_ascii_lowercase();
        let mut parameters = Vec::new();
        for segment in path.split('/') {
            if let Some(name) = segment
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
            {
                parameters.push(json!({
                    "name": name.trim_end_matches('+'),
                    "in": "path",
                    "required": true,
                    "schema": {"type":"string"}
                }));
            }
        }
        for query in route["query"].as_array().into_iter().flatten() {
            let name = query
                .as_str()
                .or_else(|| query.get("name").and_then(Value::as_str))
                .expect("manifest query name");
            parameters.push(json!({
                "name":name,"in":"query","required":false,"schema":{"type":"string"}
            }));
        }
        let variant = &route["operation_variants"][0];
        let responses = if phase_one_documented_implementation(raw_method, path) {
            json!({
                "200":{"description":"Phase 1 compatibility response","content":{"application/json":{"schema":{"type":"object"}}}},
                "400":error_response.clone(),
                "401":{"description":"Missing or invalid API key"}
            })
        } else {
            json!({
                "400":error_response.clone(),
                "401":{"description":"Missing or invalid API key"},
                "501":{"description":"Known compatibility operation not implemented in Phase 1","content":{"application/json":{"schema":{"$ref":"#/components/schemas/ApiError"}}}}
            })
        };
        let mut operation = json!({
            "security":[{"BoxApiKey":[]}],
            "parameters":parameters,
            "responses":responses
        });
        if variant["body_kind"].as_str() != Some("none") {
            operation["requestBody"] = json!({
                "required":true,
                "content":{"application/json":{"schema":{"type":"object"}}}
            });
        }
        value["paths"][path][&method] = operation;
    }
    value["components"]["schemas"]["ApiError"] = json!({
        "type":"object","required":["error","message","request_id"],"properties":{"error":{"type":"string"},"message":{"type":"string"},"request_id":{"type":"string"}}
    });
    value["components"]["schemas"]["BoxResponse"] = json!({
        "type":"object","required":["id","customer_id","status","runtime","size","labels","enabled_skills","keep_alive","ephemeral","network_policy","created_at","updated_at"],
        "properties":{"id":{"type":"string","format":"uuid"},"customer_id":{"type":"string","format":"uuid"},"status":{"type":"string"},"name":{"type":["string","null"]},"runtime":{"type":"string"},"size":{"type":"string"},"labels":{"type":"array","items":{"type":"string"}},"enabled_skills":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$"}},"keep_alive":{"type":"boolean"},"ephemeral":{"type":"boolean"},"expires_at":{"type":["integer","null"]},"network_policy":{"type":"object","required":["mode"],"properties":{"mode":{"type":"string","enum":["allow-all","deny-all"]}}},"created_at":{"type":"integer"},"updated_at":{"type":"integer"}}
    });
    value["components"]["schemas"]["EmptyResponse"] =
        json!({"type":"object","additionalProperties":false});
    value["components"]["schemas"]["CustomRunnerConfigurationRequest"] = json!({
        "type":"object",
        "additionalProperties":false,
        "required":["custom_runner"],
        "properties":{"custom_runner":{
            "type":"object",
            "additionalProperties":false,
            "required":["command"],
            "properties":{
                "command":{"type":"string","minLength":1},
                "args":{"type":"array","items":{"type":"string"}},
                "protocol":{"type":"string","enum":["box-sse-v1"]}
            }
        }}
    });
    value["components"]["schemas"]["StatusResponse"] =
        json!({"type":"object","required":["status"],"properties":{"status":{"type":"string"}}});
    value["components"]["schemas"]["StartupConfigurationResponse"] = json!({
        "type":"object","required":["init_command"],"properties":{"init_command":{"type":"string"}}
    });
    value["components"]["schemas"]["GitDiffResponse"] =
        json!({"type":"object","required":["diff"],"properties":{"diff":{"type":"string"}}});
    value["components"]["schemas"]["GitStatusResponse"] =
        json!({"type":"object","required":["status"],"properties":{"status":{"type":"string"}}});
    value["components"]["schemas"]["SnapshotListResponse"] = json!({"type":"object","required":["snapshots"],"properties":{"snapshots":{"type":"array","items":{"$ref":"#/components/schemas/Snapshot"}}}});
    value["components"]["schemas"]["SnapshotDeleteResponse"] = json!({"type":"object","required":["deleted"],"properties":{"deleted":{"type":"integer","minimum":0}}});
    value["components"]["schemas"]["PreviewListResponse"] = json!({"type":"object","required":["previews"],"properties":{"previews":{"type":"array","items":{"$ref":"#/components/schemas/PublicUrl"}}}});
    value["components"]["schemas"]["ScheduleUpdateRequest"] = json!({
        "type":"object","additionalProperties":false,
        "properties":{
            "cron":{"type":["string","null"]},
            "command":{"type":["array","null"],"items":{"type":"string"}},
            "prompt":{"type":["string","null"]},
            "folder":{"type":["string","null"]},
            "model":{"type":["string","null"]},
            "agent_options":{"type":["object","null"]},
            "timeout":{"type":["integer","null"],"minimum":1,"maximum":300000},
            "webhook_url":{"type":["string","null"]},
            "webhook_headers":{"type":["object","null"],"additionalProperties":{"type":"string"}}
        }
    });
    value["components"]["schemas"]["EnvResponse"] = json!({"type":"object","required":["env_vars"],"properties":{"env_vars":{"type":"object","additionalProperties":{"type":"string"}}}});
    value["components"]["schemas"]["EnvReplaceRequest"] = json!({"type":"object","required":["env_vars"],"properties":{"env_vars":{"type":"object","additionalProperties":{"type":"string"}}}});
    value["components"]["schemas"]["EnvValueRequest"] =
        json!({"type":"object","required":["value"],"properties":{"value":{"type":"string"}}});
    value["components"]["schemas"]["FileContentResponse"] = json!({"type":"object","required":["content"],"properties":{"content":{"type":"string","description":"UTF-8 text or strict base64 according to the encoding query"}}});
    value["components"]["schemas"]["FileListResponse"] = json!({"type":"object","required":["files"],"properties":{"files":{"type":"array","items":{"$ref":"#/components/schemas/FileEntry"}}}});
    value["components"]["schemas"]["LabelsResponse"] = json!({"type":"object","required":["labels"],"properties":{"labels":{"type":"array","items":{"type":"string"}}}});
    value["components"]["schemas"]["BoxRunData"] = json!({
        "type":"object",
        "required":["id","box_id","customer_id","type","status","input_tokens","output_tokens","cost_usd","duration_ms","created_at"],
        "properties":{
            "id":{"type":"string","format":"uuid"},
            "box_id":{"type":"string","format":"uuid"},
            "customer_id":{"type":"string","format":"uuid"},
            "type":{"type":"string","enum":["agent","shell"]},
            "status":{"type":"string","enum":["running","completed","failed","cancelled"]},
            "prompt":{"type":"string"},"model":{"type":"string"},"output":{"type":"string"},
            "input_tokens":{"type":"integer","minimum":0},"output_tokens":{"type":"integer","minimum":0},
            "cached_input_tokens":{"type":"integer","minimum":0},"cost_usd":{"type":"number","minimum":0},
            "duration_ms":{"type":"integer","minimum":0},"cpu_ns":{"type":"integer","minimum":0},
            "compute_cost_usd":{"type":"number","minimum":0},"memory_peak_bytes":{"type":"integer","minimum":0},
            "error_message":{"type":"string"},"session_id":{"type":"string"},
            "created_at":{"type":"integer"},"completed_at":{"type":"integer"}
        }
    });
    value["components"]["schemas"]["RunListResponse"] = json!({
        "type":"object","required":["runs"],"properties":{"runs":{"type":"array","items":{"$ref":"#/components/schemas/BoxRunData"}}}
    });
    value["components"]["schemas"]["WebhookAcceptedResponse"] = json!({
        "type":"object","additionalProperties":false,"required":["status","run_id"],
        "properties":{"status":{"type":"string","enum":["accepted"]},"run_id":{"type":"string","format":"uuid"}}
    });
    value["components"]["schemas"]["LogEntry"] = json!({
        "type":"object","required":["timestamp","level","source","message"],
        "properties":{"timestamp":{"type":"integer"},"level":{"type":"string","enum":["info","warn","error"]},"source":{"type":"string","enum":["system","agent","user"]},"message":{"type":"string"}}
    });
    value["components"]["schemas"]["LogListResponse"] = json!({
        "type":"object","required":["logs"],"properties":{"logs":{"type":"array","items":{"$ref":"#/components/schemas/LogEntry"}}}
    });
    value["paths"]["/v2/box"]["post"] = json!({
        "security":[{"BoxApiKey":[]}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CreateBoxRequest"}}}},
        "responses":{"200":{"description":"Creating or ready box","content":{"application/json":{"schema":{"$ref":"#/components/schemas/BoxResponse"}}}},"400":error_response,"401":{"description":"Missing or invalid API key"}}
    });
    value["paths"]["/v2/box/from-snapshot"]["post"] = json!({
        "security":[{"BoxApiKey":[]}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"allOf":[{"$ref":"#/components/schemas/CreateBoxRequest"}],"required":["snapshot_id"]}}}},
        "responses":{"200":{"description":"Creating or ready box restored from an immutable snapshot","content":{"application/json":{"schema":{"$ref":"#/components/schemas/BoxResponse"}}}},"400":error_response,"401":{"description":"Missing or invalid API key"},"404":{"description":"Snapshot not found"},"409":{"description":"Snapshot is not ready"}}
    });
    value["paths"]["/v2/box/{box_id}/exec"]["post"] = json!({
        "security":[{"BoxApiKey":[]}],
        "parameters":[{"name":"box_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}},{"name":"Last-Event-ID","in":"header","required":false,"description":"Reconnect cursor formatted as <run_id>:<sequence>","schema":{"type":"string"}}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ExecRequest"}}}},
        "responses":{"200":{"description":"Execution result","content":{"application/json":{"schema":{"$ref":"#/components/schemas/ExecResult"}}}},"400":error_response,"401":{"description":"Missing or invalid API key"}}
    });
    value["paths"]["/v2/box/{box_id}/logs"]["get"] = json!({
        "security":[{"BoxApiKey":[]}],
        "parameters":[{"name":"box_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}},{"name":"offset","in":"query","required":false,"schema":{"type":"integer","minimum":0}},{"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":1000,"default":100}}],
        "responses":{"200":{"description":"Pinned structured box logs","content":{"application/json":{"schema":{"$ref":"#/components/schemas/LogListResponse"}}}},"400":error_response,"401":{"description":"Missing or invalid API key"}}
    });
    value["paths"]["/v2/box/{box_id}/runs"]["get"] = json!({
        "security":[{"BoxApiKey":[]}],
        "parameters":[{"name":"box_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}],
        "responses":{"200":{"description":"Run history, newest first","content":{"application/json":{"schema":{"$ref":"#/components/schemas/RunListResponse"}}}},"401":{"description":"Missing or invalid API key"}}
    });
    value["paths"]["/v2/box/{box_id}/run/stream"]["post"] = json!({
        "security":[{"BoxApiKey":[]}],
        "parameters":[{"name":"box_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/AgentRunRequest"}}}},
        "responses":{"200":{"description":"box-sse-v1 agent events","content":{"text/event-stream":{"schema":{"type":"string"}}}},"400":error_response,"401":{"description":"Missing or invalid API key"}}
    });
    value["paths"]["/v2/box/{box_id}/run"]["post"] = json!({
        "security":[{"BoxApiKey":[]}],
        "parameters":[{"name":"box_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/AgentWebhookRunRequest"}}}},
        "responses":{"200":{"description":"Webhook run accepted","content":{"application/json":{"schema":{"$ref":"#/components/schemas/WebhookAcceptedResponse"}}}},"400":error_response,"401":{"description":"Missing or invalid API key"}}
    });
    value["paths"]["/v2/box"]["delete"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/BulkDeleteRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/code"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CodeRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/code"]["post"]["responses"]["200"] = json!({
        "description":"Code result","content":{"application/json":{"schema":{"$ref":"#/components/schemas/CodeResult"}}}
    });
    value["paths"]["/v2/box/{box_id}/files/write"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/WriteFileRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/config/labels"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/LabelRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/config/skills"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/SkillRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/config/model"]["put"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ModelConfigurationRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/config/custom-runner"]["put"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CustomRunnerConfigurationRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/startup"]["put"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/StartupConfigurationRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/git/exec"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/GitExecRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/git/checkout"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/GitCheckoutRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/git-config"]["put"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/GitConfigUpdateRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/git/commit"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/GitCommitRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/git/clone"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/GitCloneRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/git/push"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/GitPushRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/git/create-pr"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/GitCreatePrRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/snapshots"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/SnapshotCreateRequest"}}}
    });
    value["paths"]["/v2/box/snapshots"]["delete"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/SnapshotDeleteRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/preview"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/PreviewCreateRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/schedules"]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ScheduleCreateRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/schedules/{id}"]["patch"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ScheduleUpdateRequest"}}}
    });
    value["paths"]["/v2/box/{box_id}/files/upload"]["post"]["requestBody"] = json!({
        "required":true,"content":{"multipart/form-data":{"schema":{"type":"object","required":["paths","files"],"properties":{"paths":{"type":"array","items":{"type":"string"}},"files":{"type":"array","items":{"type":"string","format":"binary"}}}}}}
    });
    value["paths"]["/v2/box/{box_id}/files/download"]["get"]["responses"]["200"] = json!({
        "description":"Raw file bytes","headers":{"Content-Length":{"schema":{"type":"integer"}}},"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary"}}}
    });
    value["paths"]["/v2/box/{box_id}/files/read"]["get"]["responses"]["200"] = json!({
        "description":"UTF-8 or base64 file content","content":{"application/json":{"schema":{"type":"object","required":["content"],"properties":{"content":{"type":"string"}}}}}
    });
    value["paths"]["/v2/box/{box_id}/files/list"]["get"]["responses"]["200"] = json!({
        "description":"Recursive file listing","content":{"application/json":{"schema":{"type":"object","required":["files"],"properties":{"files":{"type":"array","items":{"$ref":"#/components/schemas/FileEntry"}}}}}}
    });
    let response_ref = |schema: &str| {
        json!({
            "description":"Phase 2 compatibility response",
            "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}
        })
    };
    for (method, path, schema) in [
        ("get", "/v2/box", "BoxResponse"),
        ("delete", "/v2/box", "EmptyResponse"),
        ("get", "/v2/box/{box_id}", "BoxResponse"),
        ("delete", "/v2/box/{box_id}", "EmptyResponse"),
        ("get", "/v2/box/{box_id}/status", "StatusResponse"),
        ("post", "/v2/box/{box_id}/pause", "BoxResponse"),
        ("post", "/v2/box/{box_id}/resume", "BoxResponse"),
        (
            "get",
            "/v2/box/{box_id}/startup",
            "StartupConfigurationResponse",
        ),
        ("put", "/v2/box/{box_id}/startup", "EmptyResponse"),
        ("delete", "/v2/box/{box_id}/startup", "EmptyResponse"),
        ("post", "/v2/box/{box_id}/git/exec", "GitExecResult"),
        ("get", "/v2/box/{box_id}/git/diff", "GitDiffResponse"),
        ("get", "/v2/box/{box_id}/git/status", "GitStatusResponse"),
        ("post", "/v2/box/{box_id}/git/checkout", "EmptyResponse"),
        ("put", "/v2/box/{box_id}/git-config", "GitConfigResult"),
        ("post", "/v2/box/{box_id}/git/commit", "GitCommitResult"),
        ("post", "/v2/box/{box_id}/git/clone", "EmptyResponse"),
        ("post", "/v2/box/{box_id}/git/push", "EmptyResponse"),
        ("post", "/v2/box/{box_id}/git/create-pr", "PullRequest"),
        ("post", "/v2/box/{box_id}/snapshots", "Snapshot"),
        ("get", "/v2/box/{box_id}/snapshots", "SnapshotListResponse"),
        ("post", "/v2/box/{box_id}/preview", "PublicUrl"),
        ("get", "/v2/box/{box_id}/preview", "PreviewListResponse"),
        ("delete", "/v2/box/{box_id}/preview/{port}", "EmptyResponse"),
        (
            "delete",
            "/v2/box/{box_id}/snapshots/{snapshot_id}",
            "EmptyResponse",
        ),
        ("delete", "/v2/box/snapshots", "SnapshotDeleteResponse"),
        ("post", "/v2/box/{box_id}/schedules", "ScheduleResponse"),
        ("get", "/v2/box/{box_id}/schedules/{id}", "ScheduleResponse"),
        (
            "patch",
            "/v2/box/{box_id}/schedules/{id}",
            "ScheduleResponse",
        ),
        ("delete", "/v2/box/{box_id}/schedules/{id}", "EmptyResponse"),
        (
            "post",
            "/v2/box/{box_id}/schedules/{id}/pause",
            "EmptyResponse",
        ),
        (
            "post",
            "/v2/box/{box_id}/schedules/{id}/resume",
            "EmptyResponse",
        ),
        ("post", "/v2/box/{box_id}/files/write", "EmptyResponse"),
        ("post", "/v2/box/{box_id}/files/upload", "EmptyResponse"),
        ("post", "/v2/box/{box_id}/config/labels", "LabelsResponse"),
        ("post", "/v2/box/{box_id}/config/skills", "EmptyResponse"),
        ("put", "/v2/box/{box_id}/config/model", "EmptyResponse"),
        (
            "put",
            "/v2/box/{box_id}/config/custom-runner",
            "EmptyResponse",
        ),
        (
            "delete",
            "/v2/box/{box_id}/config/labels/{label}",
            "LabelsResponse",
        ),
        (
            "delete",
            "/v2/box/{box_id}/config/skills/{skill_id+}",
            "EmptyResponse",
        ),
        ("get", "/v2/box/settings/env", "EnvResponse"),
        ("put", "/v2/box/settings/env", "EmptyResponse"),
        ("put", "/v2/box/settings/env/{key}", "EmptyResponse"),
        ("delete", "/v2/box/settings/env/{key}", "EmptyResponse"),
    ] {
        value["paths"][path][method]["responses"]["200"] = response_ref(schema);
    }
    value["paths"]["/v2/box/{box_id}/schedules"]["get"]["responses"]["200"] = json!({
        "description":"Schedules","content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/ScheduleResponse"}}}}
    });
    value["paths"]["/v2/box"]["get"]["responses"]["200"] = json!({"description":"Boxes","content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/BoxResponse"}}}}});
    value["paths"]["/v2/box/settings/env"]["put"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/EnvReplaceRequest"}}}});
    value["paths"]["/v2/box/settings/env/{key}"]["put"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/EnvValueRequest"}}}});
    value["components"]["schemas"]["BrowserScreencastResponse"] = json!({
        "type":"object","required":["screencast_url"],"additionalProperties":false,
        "properties":{"screencast_url":{"type":"string","format":"uri","description":"Short-lived view-only browser URL"}}
    });
    value["components"]["schemas"]["BrowserExtractRequest"] = json!({
        "type":"object","required":["instruction","tab","schema"],"additionalProperties":false,
        "properties":{
            "instruction":{"type":"string","minLength":1,"maxLength":16384},
            "tab":{"type":"string","minLength":1,"maxLength":256},
            "model":{"type":"string","minLength":1},
            "schema":{"type":"object","description":"JSON Schema for the extracted data"}
        }
    });
    value["components"]["schemas"]["BrowserInstructionRequest"] = json!({
        "type":"object","required":["instruction","tab"],"additionalProperties":false,
        "properties":{
            "instruction":{"type":"string","minLength":1,"maxLength":16384},
            "tab":{"type":"string","minLength":1,"maxLength":256},
            "model":{"type":"string","minLength":1}
        }
    });
    value["components"]["schemas"]["BrowserRunRequest"] = json!({
        "type":"object","required":["prompt","tab"],"additionalProperties":false,
        "properties":{
            "prompt":{"type":"string","minLength":1,"maxLength":16384},
            "tab":{"type":"string","minLength":1,"maxLength":256},
            "schema":{"type":"object","description":"Optional JSON Schema for final data"},
            "max_steps":{"type":"integer","minimum":1,"maximum":30},
            "model":{"type":"string","minLength":1}
        }
    });
    value["components"]["schemas"]["BrowserExtractResponse"] = json!({
        "type":"object","required":["data"],"additionalProperties":false,
        "properties":{"data":{}}
    });
    value["components"]["schemas"]["BrowserObserveElement"] = json!({
        "type":"object","required":["description"],"additionalProperties":false,
        "properties":{
            "description":{"type":"string"},
            "selector":{"type":"string"},
            "url":{"type":"string","format":"uri"}
        }
    });
    value["components"]["schemas"]["BrowserObserveResponse"] = json!({
        "type":"object","required":["elements"],"additionalProperties":false,
        "properties":{"elements":{"type":"array","items":{"$ref":"#/components/schemas/BrowserObserveElement"}}}
    });
    value["components"]["schemas"]["BrowserActAction"] = json!({
        "type":"object","required":["selector","description"],"additionalProperties":false,
        "properties":{
            "selector":{"type":"string"},"description":{"type":"string"},
            "method":{"type":"string"},"arguments":{"type":"array","items":{"type":"string"}}
        }
    });
    value["components"]["schemas"]["BrowserActResponse"] = json!({
        "type":"object",
        "required":["success","message","action_description","actions","input_tokens","output_tokens"],
        "additionalProperties":false,
        "properties":{
            "success":{"type":"boolean"},"message":{"type":"string"},
            "action_description":{"type":"string"},
            "actions":{"type":"array","items":{"$ref":"#/components/schemas/BrowserActAction"}},
            "cache_status":{"type":"string"},
            "input_tokens":{"type":"integer","format":"uint64"},
            "output_tokens":{"type":"integer","format":"uint64"}
        }
    });
    value["components"]["schemas"]["BrowserRunStep"] = json!({
        "type":"object","required":["step"],"additionalProperties":false,
        "properties":{
            "step":{"type":"integer","minimum":1,"maximum":30},
            "action":{"type":"string"},"reasoning":{"type":"string"},
            "url":{"type":"string","format":"uri"}
        }
    });
    value["components"]["schemas"]["BrowserRunResponse"] = json!({
        "type":"object",
        "required":["result","completed","steps","step_count","input_tokens","output_tokens"],
        "additionalProperties":false,
        "properties":{
            "data":{},"result":{"type":"string"},"completed":{"type":"boolean"},
            "steps":{"type":"array","items":{"$ref":"#/components/schemas/BrowserRunStep"}},
            "step_count":{"type":"integer","minimum":0,"maximum":30},
            "input_tokens":{"type":"integer","format":"uint64"},
            "output_tokens":{"type":"integer","format":"uint64"}
        }
    });
    for (path, request, response) in [
        (
            "/v2/box/{box_id}/browser/extract",
            "BrowserExtractRequest",
            "BrowserExtractResponse",
        ),
        (
            "/v2/box/{box_id}/browser/observe",
            "BrowserInstructionRequest",
            "BrowserObserveResponse",
        ),
        (
            "/v2/box/{box_id}/browser/act",
            "BrowserInstructionRequest",
            "BrowserActResponse",
        ),
        (
            "/v2/box/{box_id}/browser/run",
            "BrowserRunRequest",
            "BrowserRunResponse",
        ),
    ] {
        value["paths"][path]["post"]["requestBody"] = json!({
            "required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{request}")}}}
        });
        value["paths"][path]["post"]["responses"]["200"] = response_ref(response);
    }
    value["paths"]["/v2/box/{box_id}/browser/screencast"]["post"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/BrowserScreencastRequest"}}}});
    value["paths"]["/v2/box/{box_id}/browser/screencast"]["post"]["responses"]["200"] =
        response_ref("BrowserScreencastResponse");
    value["components"]["schemas"]["BrowserRecordingStartRequest"] = json!({
        "type":"object","additionalProperties":false,
        "properties":{"max_duration_seconds":{"type":"integer","minimum":1,"maximum":600,"default":600}}
    });
    value["components"]["schemas"]["BrowserRecordingMarkerResponse"] = json!({
        "type":"object","additionalProperties":false,"required":["type","at_ms"],
        "properties":{
            "type":{"type":"string","enum":["tab_switch","run"]},
            "at_ms":{"type":"integer","format":"uint64"},
            "end_ms":{"type":"integer","format":"uint64"},
            "label":{"type":"string"},"tab_id":{"type":"string"}
        }
    });
    value["components"]["schemas"]["BrowserRecordingResponse"] = json!({
        "type":"object","additionalProperties":false,
        "required":["id","box_id","status","started_at","markers"],
        "properties":{
            "id":{"type":"string","format":"uuid"},"box_id":{"type":"string","format":"uuid"},
            "status":{"type":"string","enum":["recording","completed","failed","deleted"]},
            "started_at":{"type":"integer","format":"int64","description":"Epoch milliseconds"},
            "expires_at":{"type":"integer","format":"int64","description":"Epoch seconds"},
            "ended_at":{"type":"integer","format":"int64","description":"Epoch milliseconds"},
            "duration_ms":{"type":"integer","format":"uint64"},
            "size_bytes":{"type":"integer","format":"uint64"},
            "segment_count":{"type":"integer","format":"uint32"},
            "mp4_size_bytes":{"type":"integer","format":"uint64"},
            "stopped_reason":{"type":"string","enum":["requested","max_duration","idle","browser_disconnected","lost"]},
            "max_duration_seconds":{"type":"integer","minimum":1,"maximum":600},
            "markers":{"type":"array","items":{"$ref":"#/components/schemas/BrowserRecordingMarkerResponse"}}
        }
    });
    value["components"]["schemas"]["BrowserRecordingListResponse"] = json!({
        "type":"object","additionalProperties":false,"required":["recordings"],
        "properties":{
            "recordings":{"type":"array","items":{"$ref":"#/components/schemas/BrowserRecordingResponse"}},
            "next_cursor":{"type":"string","format":"uuid"}
        }
    });
    let recording_base = "/v2/box/{box_id}/browser/recordings";
    value["paths"][recording_base]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/BrowserRecordingStartRequest"}}}
    });
    value["paths"][recording_base]["post"]["responses"]["200"] =
        response_ref("BrowserRecordingResponse");
    value["paths"][recording_base]["get"]["responses"]["200"] =
        response_ref("BrowserRecordingListResponse");
    value["paths"]["/v2/box/{box_id}/browser/recordings/stop"]["post"]["responses"]["200"] =
        response_ref("BrowserRecordingResponse");
    value["paths"]["/v2/box/{box_id}/browser/recordings/{id}"]["get"]["responses"]["200"] =
        response_ref("BrowserRecordingResponse");
    value["paths"]["/v2/box/{box_id}/browser/recordings/{id}/playlist"]["get"]["responses"]["200"] = json!({
        "description":"Authenticated HLS playlist or segment",
        "content":{"application/vnd.apple.mpegurl":{"schema":{"type":"string"}},"video/mp2t":{"schema":{"type":"string","format":"binary"}}}
    });
    value["paths"]["/v2/box/{box_id}/browser/recordings/{id}/playlist"]["get"]["parameters"].as_array_mut().expect("playlist parameters").push(json!({
        "name":"segment","in":"query","required":false,"schema":{"type":"string","pattern":"^segment-[0-9]{5}\\.ts$"}
    }));
    value["paths"]["/v2/box/{box_id}/browser/recordings/{id}/download"]["get"]["responses"]["200"] = json!({
        "description":"Recording download","content":{"video/mp4":{"schema":{"type":"string","format":"binary"}},"video/mp2t":{"schema":{"type":"string","format":"binary"}}}
    });
    value["paths"]["/api/admin/v1/auth/login"] = json!({"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["username","password"]}}}},"responses":{"200":{"description":"Authenticated admin session"},"401":{"description":"Invalid credentials"}}}});
    value["paths"]["/api/admin/v1/capabilities"] = json!({"get":{"security":[{"AdminSession":[]}],"parameters":[{"name":"X-CSRF-Token","in":"header","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"Phase capabilities"},"401":{"description":"Invalid admin session"}}}});
    value["components"]["schemas"]["AdminCreateApiKeyRequest"] = json!({"type":"object","required":["scopes"],"additionalProperties":false,"properties":{"scopes":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string","enum":["boxes_read","boxes_write","runs_write","secrets_read","admin"]}},"expires_at":{"type":["integer","null"],"format":"int64"}}});
    let admin_security = json!([{"AdminSession":[]}]);
    let csrf =
        json!([{"name":"X-CSRF-Token","in":"header","required":true,"schema":{"type":"string"}}]);
    for (path, description) in [
        ("/api/admin/v1/boxes", "Tenant boxes"),
        ("/api/admin/v1/runs", "Tenant runs"),
        ("/api/admin/v1/snapshots", "Tenant snapshots"),
        ("/api/admin/v1/schedules", "Tenant schedules"),
    ] {
        value["paths"][path] = json!({"get":{"security":admin_security.clone(),"parameters":csrf.clone(),"responses":{"200":{"description":description},"401":{"description":"Invalid admin session"}}}});
    }
    value["paths"]["/api/admin/v1/api-keys"] = json!({
        "get":{"security":admin_security.clone(),"parameters":csrf.clone(),"responses":{"200":{"description":"Tenant API keys without plaintext"},"401":{"description":"Invalid admin session"}}},
        "post":{"security":admin_security.clone(),"parameters":csrf.clone(),"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/AdminCreateApiKeyRequest"}}}},"responses":{"200":{"description":"Created API key; plaintext is returned once"},"401":{"description":"Invalid admin session"}}}
    });
    value["paths"]["/api/admin/v1/api-keys/{id}"] = json!({"delete":{"security":admin_security.clone(),"parameters":[{"name":"X-CSRF-Token","in":"header","required":true,"schema":{"type":"string"}},{"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}],"responses":{"200":{"description":"API key revoked"},"404":{"description":"API key not found"}}}});
    let admin_path = |name: &str| json!([{"name":"X-CSRF-Token","in":"header","required":true,"schema":{"type":"string"}},{"name":name,"in":"path","required":true,"schema":{"type":"string"}}]);
    value["paths"]["/api/admin/v1/boxes/{box_id}/pause"] = json!({"post":{"security":admin_security.clone(),"parameters":admin_path("box_id"),"responses":{"200":{"description":"Box paused"},"409":{"description":"Invalid state"}}}});
    value["paths"]["/api/admin/v1/boxes/{box_id}/resume"] = json!({"post":{"security":admin_security.clone(),"parameters":admin_path("box_id"),"responses":{"200":{"description":"Box resumed"},"409":{"description":"Invalid state"}}}});
    value["paths"]["/api/admin/v1/boxes/{box_id}"] = json!({"delete":{"security":admin_security.clone(),"parameters":admin_path("box_id"),"responses":{"200":{"description":"Box deletion completed"},"404":{"description":"Box not found"}}}});
    value["paths"]["/api/admin/v1/runs/{run_id}/cancel"] = json!({"post":{"security":admin_security.clone(),"parameters":admin_path("run_id"),"responses":{"200":{"description":"Run cancelled"},"404":{"description":"Run not found"}}}});
    value["paths"]["/api/admin/v1/snapshots/{snapshot_id}"] = json!({"delete":{"security":admin_security.clone(),"parameters":admin_path("snapshot_id"),"responses":{"200":{"description":"Snapshot deleted"},"404":{"description":"Snapshot not found"}}}});
    let admin_schedule_path = json!([
        {"name":"X-CSRF-Token","in":"header","required":true,"schema":{"type":"string"}},
        {"name":"box_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}},
        {"name":"schedule_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}
    ]);
    value["paths"]["/api/admin/v1/schedules/{box_id}/{schedule_id}/pause"] = json!({"post":{"security":admin_security.clone(),"parameters":admin_schedule_path.clone(),"responses":{"200":{"description":"Schedule paused"},"404":{"description":"Schedule not found"}}}});
    value["paths"]["/api/admin/v1/schedules/{box_id}/{schedule_id}/resume"] = json!({"post":{"security":admin_security.clone(),"parameters":admin_schedule_path.clone(),"responses":{"200":{"description":"Schedule resumed"},"404":{"description":"Schedule not found"}}}});
    value["paths"]["/api/admin/v1/schedules/{box_id}/{schedule_id}"] = json!({"delete":{"security":admin_security.clone(),"parameters":admin_schedule_path,"responses":{"200":{"description":"Schedule deleted"},"404":{"description":"Schedule not found"}}}});
    value["paths"]["/api/admin/v1/boxes/{box_id}/terminal-ticket"] = json!({"post":{"security":admin_security,"parameters":admin_path("box_id"),"responses":{"200":{"description":"60 second single-use terminal ticket","content":{"application/json":{"schema":{"type":"object","required":["ticket","expires_at","websocket_url"],"properties":{"ticket":{"type":"string","writeOnly":true},"expires_at":{"type":"integer","format":"int64"},"websocket_url":{"type":"string"}}}}}},"409":{"description":"Box is not idle"}}}});
    value["paths"]["/api/admin/v1/terminal"] = json!({"get":{"parameters":[{"name":"ticket","in":"query","required":true,"schema":{"type":"string","writeOnly":true}}],"responses":{"101":{"description":"Binary terminal WebSocket"},"401":{"description":"Invalid, expired, or replayed ticket"}}}});
    value
}

/// Marker retained for callers that only need an API-boundary type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ApiBoundary;

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::test::{ResponseExt, TestClient};
    use std::sync::Mutex;

    struct RecordedWebhookRun {
        prompt: String,
        url: String,
        headers: std::collections::BTreeMap<String, String>,
    }

    #[derive(Default)]
    struct MockServices {
        contexts: Mutex<Vec<AccountContext>>,
        creates: Mutex<Vec<CreateBoxRequest>>,
        models: Mutex<Vec<String>>,
        runners: Mutex<Vec<CustomAgentConfiguration>>,
        startup: Mutex<Option<String>>,
        git_execs: Mutex<Vec<GitExecRequest>>,
        list_paths: Mutex<Vec<String>>,
        bulk_ids: Mutex<Vec<Vec<String>>>,
        uploads: Mutex<Vec<Vec<UploadFile>>>,
        added_skills: Mutex<Vec<String>>,
        removed_skills: Mutex<Vec<String>>,
        admin_key_requests: Mutex<Vec<AdminCreateApiKeyRequest>>,
        webhook_runs: Mutex<Vec<RecordedWebhookRun>>,
        schedule_creates: Mutex<Vec<ScheduleCreateRequest>>,
        schedule_updates: Mutex<Vec<ScheduleUpdateRequest>>,
        schedule_actions: Mutex<Vec<(String, String)>>,
        audits: Mutex<Vec<AuditEvent>>,
    }
    impl MockServices {
        fn seen(&self, context: AccountContext) {
            self.contexts.lock().unwrap().push(context);
        }
    }
    #[async_trait]
    impl AuditSink for MockServices {
        async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
            self.audits.lock().unwrap().push(event);
            Ok(())
        }
        async fn list(
            &self,
            context: AccountContext,
            limit: u64,
        ) -> Result<Vec<AuditLogEntry>, DomainError> {
            if limit == 0 || limit > 1_000 {
                return Err(DomainError::validation("invalid audit limit"));
            }
            Ok(self
                .audits
                .lock()
                .unwrap()
                .iter()
                .rev()
                .filter(|event| event.context == context)
                .take(limit as usize)
                .enumerate()
                .map(|(index, event)| AuditLogEntry {
                    id: format!("audit-{index}"),
                    actor: event.actor.into(),
                    action: event.action.clone(),
                    resource: event.resource.clone(),
                    request_id: Some(event.request_id.clone()),
                    ip: event.ip.clone(),
                    status_code: event.status_code,
                    succeeded: event.succeeded,
                    created_at: index as i64,
                })
                .collect())
        }
    }
    #[async_trait]
    impl ApiServices for MockServices {
        async fn ready(&self) -> Result<(), DomainError> {
            Ok(())
        }

        async fn create_box(
            &self,
            c: AccountContext,
            request: CreateBoxRequest,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            self.creates.lock().unwrap().push(request);
            Ok(json!({"id":"box_fixture","status":"idle","size":"small","labels":[]}))
        }
        async fn create_box_from_snapshot(
            &self,
            c: AccountContext,
            request: CreateBoxRequest,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            self.creates.lock().unwrap().push(request);
            Ok(json!({"id":"restored_box_fixture","status":"creating","size":"small","labels":[]}))
        }
        async fn list_boxes(
            &self,
            c: AccountContext,
            _: Option<String>,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!([]))
        }
        async fn get_box(&self, c: AccountContext, _: &str) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"id":"box_fixture","status":"idle","size":"small","labels":[]}))
        }
        async fn box_status(&self, c: AccountContext, _: &str) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"status":"idle"}))
        }
        async fn pause_box(&self, c: AccountContext, _: &str) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"status":"paused"}))
        }
        async fn resume_box(&self, c: AccountContext, _: &str) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"status":"idle"}))
        }
        async fn delete_box(&self, c: AccountContext, _: &str) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn bulk_delete_boxes(
            &self,
            c: AccountContext,
            ids: Vec<String>,
        ) -> Result<(), DomainError> {
            self.seen(c);
            self.bulk_ids.lock().unwrap().push(ids);
            Ok(())
        }
        async fn exec(
            &self,
            c: AccountContext,
            _: &str,
            _: ExecRequest,
        ) -> Result<ExecResult, DomainError> {
            self.seen(c);
            Ok(ExecResult {
                output: "ok".into(),
                error: String::new(),
                exit_code: 0,
            })
        }
        async fn code(
            &self,
            c: AccountContext,
            _: &str,
            _: CodeRequest,
        ) -> Result<CodeResult, DomainError> {
            self.seen(c);
            Ok(CodeResult {
                output: "ok".into(),
                error: String::new(),
                exit_code: 0,
            })
        }
        async fn read_file(
            &self,
            c: AccountContext,
            _: &str,
            _: String,
            _: Option<String>,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"content":"ok"}))
        }
        async fn write_file(
            &self,
            c: AccountContext,
            _: &str,
            _: WriteFileRequest,
        ) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn list_files(
            &self,
            c: AccountContext,
            _: &str,
            path: String,
        ) -> Result<Vec<FileEntry>, DomainError> {
            self.seen(c);
            self.list_paths.lock().unwrap().push(path);
            Ok(vec![FileEntry {
                name: "a".into(),
                path: "/workspace/a".into(),
                size: 2,
                is_dir: false,
                mod_time: "2026-01-01T00:00:00Z".into(),
            }])
        }
        async fn read_file_bytes(
            &self,
            c: AccountContext,
            _: &str,
            _: String,
        ) -> Result<Vec<u8>, DomainError> {
            self.seen(c);
            Ok(vec![0, 1, 255])
        }
        async fn upload_files(
            &self,
            c: AccountContext,
            _: &str,
            files: Vec<UploadFile>,
        ) -> Result<(), DomainError> {
            self.seen(c);
            self.uploads.lock().unwrap().push(files);
            Ok(())
        }
        async fn env(
            &self,
            c: AccountContext,
            _: Option<&str>,
            _: &str,
            _: Option<&str>,
            _: Option<Value>,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({}))
        }
        async fn labels(
            &self,
            c: AccountContext,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"labels":[]}))
        }
        async fn add_skill(
            &self,
            c: AccountContext,
            _: &str,
            skill_id: String,
        ) -> Result<(), DomainError> {
            self.seen(c);
            self.added_skills.lock().unwrap().push(skill_id);
            Ok(())
        }
        async fn remove_skill(
            &self,
            c: AccountContext,
            _: &str,
            skill_id: &str,
        ) -> Result<(), DomainError> {
            self.seen(c);
            self.removed_skills
                .lock()
                .unwrap()
                .push(skill_id.to_owned());
            Ok(())
        }
        async fn admin_list_boxes(&self, c: AccountContext) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!([]))
        }
        async fn admin_list_runs(&self, c: AccountContext) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"runs":[]}))
        }
        async fn admin_list_snapshots(&self, c: AccountContext) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"snapshots":[]}))
        }
        async fn admin_list_schedules(&self, c: AccountContext) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"schedules":[]}))
        }
        async fn admin_set_schedule_paused(
            &self,
            c: AccountContext,
            _: &str,
            _: &str,
            _: bool,
        ) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn admin_delete_schedule(
            &self,
            c: AccountContext,
            _: &str,
            _: &str,
        ) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn admin_list_api_keys(&self, c: AccountContext) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"api_keys":[]}))
        }
        async fn admin_create_api_key(
            &self,
            c: AccountContext,
            request: AdminCreateApiKeyRequest,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            self.admin_key_requests.lock().unwrap().push(request);
            Ok(
                json!({"id":"01900000-0000-7000-8000-000000000099","prefix":"boxd_compat_fixture","api_key":"one-time-secret"}),
            )
        }
        async fn admin_revoke_api_key(
            &self,
            c: AccountContext,
            _: &str,
        ) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn admin_cancel_run(&self, c: AccountContext, _: &str) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn admin_delete_snapshot(
            &self,
            c: AccountContext,
            _: &str,
        ) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn admin_issue_terminal_ticket(
            &self,
            c: AccountContext,
            _: &str,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({
                "ticket":"a".repeat(64),
                "expires_at":42,
                "websocket_url":format!("/api/admin/v1/terminal?ticket={}", "a".repeat(64)),
            }))
        }
        async fn open_admin_terminal(
            &self,
            ticket: &str,
        ) -> Result<AdminTerminalStream, DomainError> {
            if ticket != "a".repeat(64) {
                return Err(DomainError {
                    kind: DomainErrorKind::Ownership,
                    code: "invalid_terminal_ticket",
                    message: "invalid ticket".into(),
                });
            }
            let (client, mut peer) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let mut bytes = [0_u8; 1024];
                loop {
                    let Ok(count) = peer.read(&mut bytes).await else {
                        return;
                    };
                    if count == 0 || peer.write_all(&bytes[..count]).await.is_err() {
                        return;
                    }
                }
            });
            Ok(Box::new(client))
        }
        async fn browser_extract(
            &self,
            c: AccountContext,
            _: &str,
            request: BrowserInstruction,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"instruction":request.instruction,"ok":true}))
        }
        async fn browser_observe(
            &self,
            c: AccountContext,
            _: &str,
            _: BrowserInstruction,
        ) -> Result<BrowserObserveResult, DomainError> {
            self.seen(c);
            Ok(BrowserObserveResult {
                elements: vec![box_browser::BrowserObserveElement {
                    description: "Submit".into(),
                    selector: Some("#submit".into()),
                    url: None,
                }],
            })
        }
        async fn browser_act(
            &self,
            c: AccountContext,
            _: &str,
            _: BrowserInstruction,
        ) -> Result<BrowserActResult, DomainError> {
            self.seen(c);
            Ok(BrowserActResult {
                success: true,
                message: "clicked".into(),
                action_description: "Click submit".into(),
                actions: vec![box_browser::BrowserActAction {
                    selector: "#submit".into(),
                    description: "Submit".into(),
                    method: Some("click".into()),
                    arguments: None,
                }],
                cache_status: Some("MISS".into()),
                input_tokens: 7,
                output_tokens: 3,
            })
        }
        async fn browser_run(
            &self,
            c: AccountContext,
            _: &str,
            _: BrowserRunInstruction,
        ) -> Result<BrowserRunResult, DomainError> {
            self.seen(c);
            Ok(BrowserRunResult {
                data: Some(json!({"ok":true})),
                result: "done".into(),
                completed: true,
                steps: vec![box_browser::BrowserRunStep {
                    step: 1,
                    action: Some("Click submit".into()),
                    reasoning: Some("Finish".into()),
                    url: Some("https://example.invalid".into()),
                }],
                step_count: 1,
                input_tokens: 9,
                output_tokens: 4,
            })
        }
        async fn open_browser_cdp(
            &self,
            ticket: &str,
        ) -> Result<BrowserCdpConnection, DomainError> {
            if ticket != "b".repeat(64) {
                return Err(DomainError {
                    kind: DomainErrorKind::Ownership,
                    code: "invalid_browser_ticket",
                    message: "invalid ticket".into(),
                });
            }
            let (client, peer) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let Ok(mut socket) = tokio_tungstenite::accept_async(peer).await else {
                    return;
                };
                let Some(Ok(TungsteniteMessage::Text(request))) = socket.next().await else {
                    return;
                };
                let Ok(request) = serde_json::from_str::<Value>(request.as_str()) else {
                    return;
                };
                let response = json!({
                    "id": request["id"],
                    "result": {"product": "Chrome/fixture"}
                });
                let _ = socket
                    .send(TungsteniteMessage::text(response.to_string()))
                    .await;
            });
            Ok(BrowserCdpConnection {
                stream: Box::new(client),
                websocket_path: "/devtools/browser/fixture".into(),
            })
        }
        async fn open_browser_screencast(
            &self,
            ticket: &str,
        ) -> Result<BrowserScreencastConnection, DomainError> {
            if ticket != "d".repeat(64) {
                return Err(DomainError {
                    kind: DomainErrorKind::Ownership,
                    code: "invalid_browser_ticket",
                    message: "invalid ticket".into(),
                });
            }
            Ok(BrowserScreencastConnection {
                frames: Box::pin(futures_util::stream::iter(vec![Ok(
                    b"\xff\xd8boxd-jpeg-fixture\xff\xd9".to_vec(),
                )])),
            })
        }
        async fn browser_recording_start(
            &self,
            c: AccountContext,
            box_id: &str,
            request: BrowserRecordingStartRequest,
        ) -> Result<BrowserRecordingResponse, DomainError> {
            self.seen(c);
            assert_eq!(request.max_duration_seconds, Some(42));
            Ok(recording_fixture(box_id, "recording"))
        }
        async fn browser_recording_stop(
            &self,
            c: AccountContext,
            box_id: &str,
        ) -> Result<BrowserRecordingResponse, DomainError> {
            self.seen(c);
            Ok(recording_fixture(box_id, "completed"))
        }
        async fn browser_recording_list(
            &self,
            c: AccountContext,
            box_id: &str,
            _cursor: Option<String>,
            _limit: usize,
        ) -> Result<BrowserRecordingListResponse, DomainError> {
            self.seen(c);
            Ok(BrowserRecordingListResponse {
                recordings: vec![recording_fixture(box_id, "completed")],
                next_cursor: None,
            })
        }
        async fn browser_recording_get(
            &self,
            c: AccountContext,
            box_id: &str,
            _: &str,
        ) -> Result<BrowserRecordingResponse, DomainError> {
            self.seen(c);
            Ok(recording_fixture(box_id, "completed"))
        }
        async fn browser_recording_playlist(
            &self,
            c: AccountContext,
            _: &str,
            _: &str,
        ) -> Result<Vec<u8>, DomainError> {
            self.seen(c);
            Ok(b"#EXTM3U\nplaylist?segment=segment-00000.ts\n".to_vec())
        }
        async fn browser_recording_segment(
            &self,
            c: AccountContext,
            _: &str,
            _: &str,
            segment: &str,
        ) -> Result<Vec<u8>, DomainError> {
            self.seen(c);
            assert_eq!(segment, "segment-00000.ts");
            Ok(b"mpeg-ts-fixture".to_vec())
        }
        async fn browser_recording_download(
            &self,
            c: AccountContext,
            _: &str,
            _: &str,
        ) -> Result<BrowserRecordingDownload, DomainError> {
            self.seen(c);
            Ok(BrowserRecordingDownload {
                bytes: b"mp4-fixture".to_vec(),
                content_type: "video/mp4",
            })
        }
        async fn list_runs(&self, c: AccountContext, box_id: &str) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(json!({"runs":[{
                "id":"01900000-0000-7000-8000-000000000001",
                "box_id":box_id,
                "customer_id":c.account_id.to_string(),
                "type":"agent","status":"completed","input_tokens":1,"output_tokens":1,
                "cost_usd":0,"duration_ms":1,"created_at":1
            }]}))
        }
        async fn run_stream(
            &self,
            c: AccountContext,
            _: &str,
            _: AgentRunRequest,
        ) -> Result<ApiRunStream, DomainError> {
            self.seen(c);
            Ok(Box::pin(futures_util::stream::iter(vec![
                Ok(ApiRunEvent {
                    run_id: "01900000-0000-7000-8000-000000000001".into(),
                    sequence: 0,
                    event_type: "run_start".into(),
                    payload_json: r#"{"run_id":"run-1"}"#.into(),
                }),
                Ok(ApiRunEvent {
                    run_id: "01900000-0000-7000-8000-000000000001".into(),
                    sequence: 1,
                    event_type: "done".into(),
                    payload_json: r#"{"output":"ok"}"#.into(),
                }),
            ])))
        }
        async fn run_webhook(
            &self,
            c: AccountContext,
            _: &str,
            request: AgentWebhookRunRequest,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            self.webhook_runs.lock().unwrap().push(RecordedWebhookRun {
                prompt: request.prompt,
                url: request.webhook.url,
                headers: request.webhook.headers,
            });
            Ok(json!({"status":"accepted","run_id":"01900000-0000-7000-8000-000000000001"}))
        }
        async fn resume_run_stream(
            &self,
            c: AccountContext,
            _: &str,
            run_id: &str,
            after_sequence: u64,
        ) -> Result<ApiRunStream, DomainError> {
            self.seen(c);
            Ok(Box::pin(futures_util::stream::iter(vec![Ok(
                ApiRunEvent {
                    run_id: run_id.into(),
                    sequence: after_sequence + 1,
                    event_type: "done".into(),
                    payload_json: r#"{"output":"replayed"}"#.into(),
                },
            )])))
        }
        async fn logs(
            &self,
            c: AccountContext,
            _: &str,
            offset: usize,
            limit: usize,
        ) -> Result<Value, DomainError> {
            self.seen(c);
            Ok(
                json!({"logs":[{"timestamp":1,"level":"warn","source":"agent","message":format!("stderr-{offset}-{limit}")}]}),
            )
        }
        async fn cancel_run(&self, c: AccountContext, _: &str, _: &str) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn configure_model(
            &self,
            c: AccountContext,
            _: &str,
            model: String,
        ) -> Result<(), DomainError> {
            self.seen(c);
            self.models.lock().unwrap().push(model);
            Ok(())
        }
        async fn configure_custom_runner(
            &self,
            c: AccountContext,
            _: &str,
            config: CustomAgentConfiguration,
        ) -> Result<(), DomainError> {
            self.seen(c);
            self.runners.lock().unwrap().push(config);
            Ok(())
        }
        async fn get_startup_command(
            &self,
            c: AccountContext,
            _: &str,
        ) -> Result<String, DomainError> {
            self.seen(c);
            Ok(self.startup.lock().unwrap().clone().unwrap_or_default())
        }
        async fn set_startup_command(
            &self,
            c: AccountContext,
            _: &str,
            command: String,
        ) -> Result<(), DomainError> {
            self.seen(c);
            *self.startup.lock().unwrap() = Some(command);
            Ok(())
        }
        async fn delete_startup_command(
            &self,
            c: AccountContext,
            _: &str,
        ) -> Result<(), DomainError> {
            self.seen(c);
            *self.startup.lock().unwrap() = None;
            Ok(())
        }
        async fn git_exec(
            &self,
            c: AccountContext,
            _: &str,
            request: GitExecRequest,
        ) -> Result<GitExecResult, DomainError> {
            self.seen(c);
            self.git_execs.lock().unwrap().push(request);
            Ok(GitExecResult {
                output: "git version fixture".into(),
            })
        }
        async fn git_diff(
            &self,
            c: AccountContext,
            _: &str,
            _: Option<String>,
        ) -> Result<String, DomainError> {
            self.seen(c);
            Ok("diff fixture".into())
        }
        async fn git_status(
            &self,
            c: AccountContext,
            _: &str,
            _: Option<String>,
        ) -> Result<String, DomainError> {
            self.seen(c);
            Ok("status fixture".into())
        }
        async fn git_checkout(
            &self,
            c: AccountContext,
            _: &str,
            _: GitCheckoutRequest,
        ) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn git_update_config(
            &self,
            c: AccountContext,
            _: &str,
            request: GitConfigUpdateRequest,
        ) -> Result<GitConfigResult, DomainError> {
            self.seen(c);
            Ok(GitConfigResult {
                git_user_name: request.git_user_name.unwrap_or_default(),
                git_user_email: request.git_user_email.unwrap_or_default(),
            })
        }
        async fn git_commit(
            &self,
            c: AccountContext,
            _: &str,
            request: GitCommitRequest,
        ) -> Result<GitCommitResult, DomainError> {
            self.seen(c);
            Ok(GitCommitResult {
                sha: "0123456789abcdef".into(),
                message: request.message,
            })
        }
        async fn git_clone(
            &self,
            c: AccountContext,
            _: &str,
            request: GitCloneRequest,
        ) -> Result<(), DomainError> {
            self.seen(c);
            request.validate()
        }
        async fn git_push(
            &self,
            c: AccountContext,
            _: &str,
            request: GitPushRequest,
        ) -> Result<(), DomainError> {
            self.seen(c);
            request.validate()
        }
        async fn git_create_pr(
            &self,
            c: AccountContext,
            _: &str,
            request: GitCreatePrRequest,
        ) -> Result<PullRequest, DomainError> {
            self.seen(c);
            request.validate()?;
            Ok(PullRequest {
                url: "https://github.com/example/repository/pull/42".into(),
                number: 42,
                title: request.title,
                base: request.base.unwrap_or_else(|| "main".into()),
            })
        }
        async fn create_snapshot(
            &self,
            c: AccountContext,
            box_id: &str,
            name: String,
        ) -> Result<Snapshot, DomainError> {
            self.seen(c);
            Ok(Snapshot {
                id: "01900000-0000-7000-8000-000000000099".into(),
                name,
                box_id: box_id.into(),
                size_bytes: 4096,
                status: "ready".into(),
                created_at: 1,
            })
        }
        async fn list_snapshots(
            &self,
            c: AccountContext,
            box_id: &str,
        ) -> Result<Vec<Snapshot>, DomainError> {
            self.seen(c);
            Ok(vec![Snapshot {
                id: "01900000-0000-7000-8000-000000000099".into(),
                name: "fixture".into(),
                box_id: box_id.into(),
                size_bytes: 4096,
                status: "ready".into(),
                created_at: 1,
            }])
        }
        async fn delete_snapshot(
            &self,
            c: AccountContext,
            _: &str,
            _: &str,
        ) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
        async fn delete_snapshots(
            &self,
            c: AccountContext,
            ids: Option<Vec<String>>,
        ) -> Result<u64, DomainError> {
            self.seen(c);
            Ok(ids.map_or(1, |ids| ids.len() as u64))
        }
        async fn create_schedule(
            &self,
            c: AccountContext,
            box_id: &str,
            request: ScheduleCreateRequest,
        ) -> Result<ScheduleResponse, DomainError> {
            self.seen(c);
            let schedule = schedule_fixture(box_id, &request.r#type);
            self.schedule_creates.lock().unwrap().push(request);
            Ok(schedule)
        }
        async fn list_schedules(
            &self,
            c: AccountContext,
            box_id: &str,
        ) -> Result<Vec<ScheduleResponse>, DomainError> {
            self.seen(c);
            Ok(vec![schedule_fixture(box_id, "exec")])
        }
        async fn get_schedule(
            &self,
            c: AccountContext,
            box_id: &str,
            _: &str,
        ) -> Result<ScheduleResponse, DomainError> {
            self.seen(c);
            Ok(schedule_fixture(box_id, "exec"))
        }
        async fn update_schedule(
            &self,
            c: AccountContext,
            box_id: &str,
            _: &str,
            request: ScheduleUpdateRequest,
        ) -> Result<ScheduleResponse, DomainError> {
            self.seen(c);
            self.schedule_updates.lock().unwrap().push(request);
            Ok(schedule_fixture(box_id, "exec"))
        }
        async fn set_schedule_paused(
            &self,
            c: AccountContext,
            _: &str,
            schedule_id: &str,
            paused: bool,
        ) -> Result<(), DomainError> {
            self.seen(c);
            self.schedule_actions.lock().unwrap().push((
                if paused { "pause" } else { "resume" }.into(),
                schedule_id.into(),
            ));
            Ok(())
        }
        async fn delete_schedule(
            &self,
            c: AccountContext,
            _: &str,
            schedule_id: &str,
        ) -> Result<(), DomainError> {
            self.seen(c);
            self.schedule_actions
                .lock()
                .unwrap()
                .push(("delete".into(), schedule_id.into()));
            Ok(())
        }
        async fn create_preview(
            &self,
            c: AccountContext,
            _: &str,
            port: u16,
            auth: PreviewAuth,
        ) -> Result<PublicUrl, DomainError> {
            self.seen(c);
            Ok(PublicUrl {
                url: format!("https://boxd.example/p/fixture-{port}/"),
                port,
                token: (auth == PreviewAuth::Bearer).then(|| "bearer-fixture".into()),
                username: (auth == PreviewAuth::Basic).then(|| "boxd".into()),
                password: (auth == PreviewAuth::Basic).then(|| "password-fixture".into()),
            })
        }
        async fn list_previews(
            &self,
            c: AccountContext,
            _: &str,
        ) -> Result<Vec<PublicUrl>, DomainError> {
            self.seen(c);
            Ok(vec![PublicUrl {
                url: "https://boxd.example/p/fixture/".into(),
                port: 3_000,
                token: None,
                username: None,
                password: None,
            }])
        }
        async fn delete_preview(
            &self,
            c: AccountContext,
            _: &str,
            _: u16,
        ) -> Result<(), DomainError> {
            self.seen(c);
            Ok(())
        }
    }
    fn schedule_fixture(box_id: &str, schedule_type: &str) -> ScheduleResponse {
        ScheduleResponse {
            id: "01900000-0000-7000-8000-000000000077".into(),
            box_id: box_id.into(),
            customer_id: Some("01900000-0000-7000-8000-000000000010".into()),
            r#type: schedule_type.into(),
            cron: "*/5 * * * *".into(),
            command: (schedule_type == "exec").then(|| vec!["echo".into(), "ready".into()]),
            prompt: (schedule_type == "prompt").then(|| "check status".into()),
            folder: Some("/workspace/home".into()),
            model: None,
            agent_options: None,
            timeout: Some(60),
            status: "active".into(),
            qstash_schedule_id: None,
            webhook_url: None,
            webhook_headers: None,
            last_run_at: None,
            last_run_status: None,
            last_run_id: None,
            total_runs: 0,
            total_failures: 0,
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
        }
    }

    fn recording_fixture(box_id: &str, status: &str) -> BrowserRecordingResponse {
        BrowserRecordingResponse {
            id: "01900000-0000-7000-8000-000000000055".into(),
            box_id: box_id.into(),
            status: status.into(),
            started_at: 1_700_000_000_000,
            expires_at: Some(1_701_209_600),
            ended_at: (status != "recording").then_some(1_700_000_001_000),
            duration_ms: (status != "recording").then_some(1_000),
            size_bytes: (status != "recording").then_some(16),
            segment_count: (status != "recording").then_some(1),
            mp4_size_bytes: (status != "recording").then_some(11),
            stopped_reason: (status != "recording").then(|| "requested".into()),
            max_duration_seconds: Some(42),
            markers: vec![BrowserRecordingMarkerResponse {
                marker_type: "tab_switch".into(),
                at_ms: 0,
                end_ms: None,
                label: Some("fixture".into()),
                tab_id: Some("tab_fixture".into()),
            }],
        }
    }
    struct MockAuth(AuthorizedContext);
    #[async_trait]
    impl Authenticator for MockAuth {
        async fn authenticate(&self, key: &str) -> Result<AuthorizedContext, DomainError> {
            if key == "good" {
                Ok(self.0.clone())
            } else {
                Err(DomainError::validation("bad key"))
            }
        }
    }
    struct MockSession;
    #[async_trait]
    impl SessionAuthenticator for MockSession {
        async fn authenticate_session(
            &self,
            session: &str,
            csrf: &str,
        ) -> Result<AccountContext, DomainError> {
            if session == "session" && csrf == "csrf" {
                Ok(AccountContext {
                    account_id: box_core::AccountId::parse("01900000-0000-7000-8000-000000000010")
                        .unwrap(),
                    tenant_id: box_core::TenantId::parse("01900000-0000-7000-8000-000000000011")
                        .unwrap(),
                })
            } else {
                Err(DomainError::validation("bad session"))
            }
        }
    }
    struct MockAdminLogin;
    #[async_trait]
    impl AdminLoginService for MockAdminLogin {
        async fn login(
            &self,
            username: &str,
            password: &str,
        ) -> Result<AdminLoginResult, DomainError> {
            if username == "admin" && password == "correct password" {
                Ok(AdminLoginResult {
                    session: "boxd_session_fixture_secret".into(),
                    csrf: "boxd_csrf_fixture".into(),
                    expires_at_millis: i64::MAX,
                })
            } else {
                Err(DomainError::validation("bad credentials"))
            }
        }
        async fn logout(&self, session: &str, csrf: &str) -> Result<(), DomainError> {
            if session == "session" && csrf == "csrf" {
                Ok(())
            } else {
                Err(DomainError::validation("bad session"))
            }
        }
    }
    fn router_with_dependencies(
        limit: usize,
        request_quota: Arc<dyn RequestQuota>,
        telemetry: Arc<dyn Telemetry>,
    ) -> (salvo::Service, Arc<MockServices>, AccountContext) {
        let account = AccountContext {
            account_id: box_core::AccountId::new(),
            tenant_id: box_core::TenantId::new(),
        };
        let services = Arc::new(MockServices::default());
        let state = ApiState {
            authenticator: Arc::new(MockAuth(AuthorizedContext {
                account,
                scopes: std::collections::BTreeSet::from([AuthScope::Admin]),
            })),
            sessions: Arc::new(MockSession),
            admin_login: Arc::new(MockAdminLogin),
            services: services.clone(),
            audit: services.clone(),
            request_quota,
            telemetry,
            body_limit_bytes: limit,
        };
        (salvo::Service::new(build_router(state)), services, account)
    }
    fn router_with_quota(
        limit: usize,
        request_quota: Arc<dyn RequestQuota>,
    ) -> (salvo::Service, Arc<MockServices>, AccountContext) {
        router_with_dependencies(
            limit,
            request_quota,
            Arc::new(box_observability::NoopTelemetry),
        )
    }
    fn router(limit: usize) -> (salvo::Service, Arc<MockServices>, AccountContext) {
        router_with_quota(limit, Arc::new(UnlimitedRequestQuota))
    }
    fn request(method: &str, path: &str) -> salvo::test::RequestBuilder {
        let url = format!("http://boxd.test{path}");
        match method {
            "GET" => TestClient::get(url),
            "POST" => TestClient::post(url),
            "PUT" => TestClient::put(url),
            "PATCH" => TestClient::patch(url),
            "DELETE" => TestClient::delete(url),
            _ => unreachable!(),
        }
        .add_header("x-box-api-key", "good", true)
    }

    struct RejectingRequestQuota;

    #[async_trait]
    impl RequestQuota for RejectingRequestQuota {
        async fn check(
            &self,
            _: &AuthorizedContext,
            credential: ApiKeyFingerprint,
        ) -> Result<RequestQuotaDecision, DomainError> {
            assert_eq!(credential, ApiKeyFingerprint::from_api_key("good"));
            Ok(RequestQuotaDecision::Rejected {
                retry_after_seconds: 17,
            })
        }
    }

    struct RejectingTrafficQuota;

    #[async_trait]
    impl RequestQuota for RejectingTrafficQuota {
        async fn check(
            &self,
            _: &AuthorizedContext,
            _: ApiKeyFingerprint,
        ) -> Result<RequestQuotaDecision, DomainError> {
            Ok(RequestQuotaDecision::Allowed)
        }

        async fn charge_traffic(
            &self,
            _: &AuthorizedContext,
            credential: ApiKeyFingerprint,
            bytes: u64,
        ) -> Result<RequestQuotaDecision, DomainError> {
            assert_eq!(credential, ApiKeyFingerprint::from_api_key("good"));
            if bytes == 0 {
                Ok(RequestQuotaDecision::Allowed)
            } else {
                Ok(RequestQuotaDecision::Rejected {
                    retry_after_seconds: 23,
                })
            }
        }
    }

    #[tokio::test]
    async fn compatibility_request_quota_returns_stable_429_without_dispatching() {
        let (service, services, _) = router_with_quota(1024, Arc::new(RejectingRequestQuota));
        let mut response = request("POST", "/v2/box")
            .json(&json!({}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::TOO_MANY_REQUESTS));
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("17")
        );
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(body["error"], "quota_exceeded");
        assert_eq!(body["message"], "API key request quota exceeded");
        assert!(services.creates.lock().unwrap().is_empty());
        let audits = services.audits.lock().unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].status_code, 429);
        assert!(!audits[0].succeeded);
    }

    #[tokio::test]
    async fn compatibility_request_traffic_quota_rejects_before_dispatching() {
        let (service, services, _) = router_with_quota(1024, Arc::new(RejectingTrafficQuota));
        let mut response = request("POST", "/v2/box")
            .json(&json!({}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::TOO_MANY_REQUESTS));
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("23")
        );
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(body["error"], "quota_exceeded");
        assert_eq!(body["message"], "API key traffic quota exceeded");
        assert!(services.creates.lock().unwrap().is_empty());
        let audits = services.audits.lock().unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].status_code, 429);
        assert!(!audits[0].succeeded);
    }

    #[test]
    fn service_quota_errors_map_to_stable_429() {
        let mut response = Response::new();
        map_error(
            &mut response,
            DomainError {
                kind: DomainErrorKind::Capacity,
                code: "quota_exceeded",
                message: "tenant run quota exceeded".into(),
            },
            "request-fixture",
        );
        assert_eq!(response.status_code, Some(StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test]
    async fn http_metrics_use_closed_surface_and_status_labels() {
        let telemetry = Arc::new(box_observability::MetricsRegistry::default());
        let (service, _, _) =
            router_with_dependencies(1024, Arc::new(UnlimitedRequestQuota), telemetry.clone());
        let response = request("GET", "/v2/box").send(&service).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let rendered = telemetry.render_prometheus();
        assert!(
            rendered
                .contains("boxd_http_requests_total{surface=\"compatibility\",status=\"200\"} 1")
        );
        assert!(!rendered.contains("/v2/box"));
    }

    #[test]
    fn pinned_manifest_paths_are_recognised_and_unknown_paths_are_not() {
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../compat/upstash-box-0.6.3/route-manifest.json"
        ))
        .unwrap();
        for route in manifest["routes"].as_array().unwrap() {
            let method = route["method"].as_str().unwrap();
            let path = route["path"]
                .as_str()
                .unwrap()
                .replace("{box_id}", "box-id")
                .replace("{skill_id+}", "nested/skill")
                .replace("{snapshot_id}", "snapshot-id")
                .replace("{run_id}", "run-id")
                .replace("{tab_id}", "tab-id")
                .replace("{label}", "label")
                .replace("{port}", "3000")
                .replace("{id}", "id");
            assert!(manifest_path(method, &path), "{method} {path}");
        }
        assert!(!manifest_path("GET", "/v2/box/not-a-box/unknown"));
    }

    #[tokio::test]
    async fn skills_routes_preserve_pinned_identity_and_capability_is_truthful() {
        let (service, services, _) = router(1024);
        let skill_id = "upstash/context7/context7-cli";
        let response = request("POST", "/v2/box/box-id/config/skills")
            .json(&json!({"skill_id":skill_id}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            services.added_skills.lock().unwrap().as_slice(),
            &[skill_id.to_owned()]
        );

        let response = request(
            "DELETE",
            "/v2/box/box-id/config/skills/upstash/context7/context7-cli",
        )
        .send(&service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            services.removed_skills.lock().unwrap().as_slice(),
            &[skill_id.to_owned()]
        );

        let response = request("POST", "/v2/box/box-id/config/skills")
            .json(&json!({"skill_id":"owner/repo","ignored":true}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));

        let mut response = TestClient::get("http://boxd.test/api/admin/v1/capabilities")
            .add_header("cookie", "boxd_session=session", true)
            .add_header("x-csrf-token", "csrf", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body = response.take_json::<Value>().await.unwrap();
        assert_eq!(body["phase"], "phase_3_complete");
        assert!(
            body["implemented"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "skills_context7_install_remove")
        );
        assert!(
            !body["unsupported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "skills")
        );
    }

    #[tokio::test]
    async fn admin_surfaces_use_session_context_csrf_and_never_compatibility_keys() {
        let (service, services, _) = router(1024);
        let admin = |method: &str, path: &str| {
            let url = format!("http://boxd.test/api/admin/v1{path}");
            let request = match method {
                "GET" => TestClient::get(url),
                "POST" => TestClient::post(url),
                "DELETE" => TestClient::delete(url),
                _ => unreachable!(),
            };
            request
                .add_header("cookie", "boxd_session=session", true)
                .add_header("x-csrf-token", "csrf", true)
        };
        for path in [
            "/boxes",
            "/runs",
            "/snapshots",
            "/schedules",
            "/api-keys",
            "/audit",
        ] {
            let response = admin("GET", path).send(&service).await;
            assert_eq!(response.status_code, Some(StatusCode::OK), "{path}");
        }
        let mut created = admin("POST", "/api-keys")
            .json(&json!({"scopes":["boxes_read","boxes_write"],"expires_at":null}))
            .send(&service)
            .await;
        assert_eq!(created.status_code, Some(StatusCode::OK));
        assert_eq!(
            created.take_json::<Value>().await.unwrap()["api_key"],
            "one-time-secret"
        );
        {
            let requests = services.admin_key_requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(
                requests[0].scopes,
                vec![AuthScope::BoxesRead, AuthScope::BoxesWrite]
            );
        }
        let response = admin("DELETE", "/api-keys/01900000-0000-7000-8000-000000000099")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        for (method, path) in [
            ("POST", "/boxes/box-id/pause"),
            ("POST", "/boxes/box-id/resume"),
            ("POST", "/runs/run-id/cancel"),
            ("POST", "/schedules/box-id/schedule-id/pause"),
            ("POST", "/schedules/box-id/schedule-id/resume"),
            ("DELETE", "/schedules/box-id/schedule-id"),
            ("DELETE", "/snapshots/snapshot-id"),
            ("DELETE", "/boxes/box-id"),
        ] {
            let response = admin(method, path).send(&service).await;
            assert_eq!(
                response.status_code,
                Some(StatusCode::OK),
                "{method} {path}"
            );
        }
        let mut ticket = admin("POST", "/boxes/box-id/terminal-ticket")
            .send(&service)
            .await;
        assert_eq!(ticket.status_code, Some(StatusCode::OK));
        let ticket = ticket.take_json::<Value>().await.unwrap();
        assert_eq!(ticket["ticket"].as_str().unwrap().len(), 64);
        let mut audit = admin("GET", "/audit?limit=100").send(&service).await;
        assert_eq!(audit.status_code, Some(StatusCode::OK));
        let audit = audit.take_json::<Value>().await.unwrap();
        assert!(
            audit["audit_logs"].as_array().unwrap().iter().any(|entry| {
                entry["actor"] == "admin_session"
                    && entry["action"] == "POST /api/admin/v1/api-keys"
            }),
            "unexpected audit payload: {audit}"
        );

        let response = TestClient::get("http://boxd.test/api/admin/v1/boxes")
            .add_header("x-box-api-key", "good", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn terminal_websocket_bridges_binary_bytes_with_bearer_ticket_only() {
        use salvo::conn::{Acceptor, Listener, TcpListener};
        use std::time::Duration;
        use tokio::net::TcpStream;

        let (service, _, _) = router(1024);
        let acceptor = TcpListener::new("127.0.0.1:0").bind().await;
        let address = acceptor.holdings()[0]
            .local_addr
            .clone()
            .into_std()
            .unwrap();
        let server = tokio::spawn(async move {
            Server::new(acceptor).serve(service).await;
        });
        let ticket = "a".repeat(64);
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket.write_all(format!("GET /api/admin/v1/terminal?ticket={ticket} HTTP/1.1\r\nHost: {address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
        let mut handshake = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !handshake.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            tokio::time::timeout_at(deadline, socket.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            handshake.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&handshake).starts_with("HTTP/1.1 101"));
        let payload = b"terminal websocket fixture";
        let mask = [1_u8, 2, 3, 4];
        let mut frame = vec![0x82, 0x80 | payload.len() as u8];
        frame.extend(mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        socket.write_all(&frame).await.unwrap();
        let mut header = [0_u8; 2];
        tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut header))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(header[0], 0x82);
        let length = usize::from(header[1] & 0x7f);
        let mut response = vec![0_u8; length];
        socket.read_exact(&mut response).await.unwrap();
        assert_eq!(response, payload);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn browser_cdp_ticket_bridges_a_real_websocket_handshake_and_message() {
        use salvo::conn::{Acceptor, Listener, TcpListener};

        let (service, _, _) = router(1024);
        let acceptor = TcpListener::new("127.0.0.1:0").bind().await;
        let address = acceptor.holdings()[0]
            .local_addr
            .clone()
            .into_std()
            .unwrap();
        let server = tokio::spawn(async move {
            Server::new(acceptor).serve(service).await;
        });
        let ticket = "b".repeat(64);
        let (mut socket, _) = tokio_tungstenite::connect_async(format!(
            "ws://{address}/v2/box/browser/cdp?ticket={ticket}"
        ))
        .await
        .unwrap();
        socket
            .send(TungsteniteMessage::text(
                json!({"id":7,"method":"Browser.getVersion"}).to_string(),
            ))
            .await
            .unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let TungsteniteMessage::Text(response) = response else {
            panic!("browser CDP response must be text");
        };
        let response: Value = serde_json::from_str(response.as_str()).unwrap();
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["product"], "Chrome/fixture");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn browser_screencast_is_view_only_rate_bounded_and_streams_real_cdp_frame() {
        use salvo::conn::{Acceptor, Listener, TcpListener};

        let (service, _, _) = router(1024);
        let acceptor = TcpListener::new("127.0.0.1:0").bind().await;
        let address = acceptor.holdings()[0]
            .local_addr
            .clone()
            .into_std()
            .unwrap();
        let server = tokio::spawn(async move {
            Server::new(acceptor).serve(service).await;
        });
        let ticket = "d".repeat(64);
        let (mut socket, _) = tokio_tungstenite::connect_async(format!(
            "ws://{address}/v2/box/browser/screencast/ws?ticket={ticket}"
        ))
        .await
        .unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let TungsteniteMessage::Binary(response) = response else {
            panic!("browser screencast frame must be binary");
        };
        assert_eq!(response.as_ref(), b"\xff\xd8boxd-jpeg-fixture\xff\xd9");
        socket
            .send(TungsteniteMessage::text("input-is-not-accepted"))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .is_none_or(|message| message.is_err() || message.unwrap().is_close())
        );
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn generated_openapi_covers_every_pinned_method_path_and_dto_schema() {
        let document = phase_one_openapi();
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../compat/upstash-box-0.6.3/route-manifest.json"
        ))
        .unwrap();
        for route in manifest["routes"].as_array().unwrap() {
            let path = route["path"].as_str().unwrap();
            let method = route["method"].as_str().unwrap().to_ascii_lowercase();
            let operation = &document["paths"][path][&method];
            assert!(operation.is_object(), "{} {}", route["method"], path);
            assert!(
                operation["responses"].is_object(),
                "responses {method} {path}"
            );
            assert!(
                operation["responses"]["200"].is_object()
                    ^ operation["responses"]["501"].is_object(),
                "operation must be documented as implemented xor Phase 1 unsupported: {method} {path}"
            );
            assert!(operation["security"].is_array(), "security {method} {path}");
            for segment in path.split('/').filter(|segment| segment.starts_with('{')) {
                let name = segment
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .trim_end_matches('+');
                assert!(
                    operation["parameters"]
                        .as_array()
                        .is_some_and(|parameters| {
                            parameters.iter().any(|parameter| {
                                parameter["in"] == "path" && parameter["name"] == name
                            })
                        }),
                    "path parameter {name} {method} {path}"
                );
            }
        }
        for schema in [
            "CreateBoxRequest",
            "ExecRequest",
            "CodeRequest",
            "WriteFileRequest",
            "ExecResult",
            "CodeResult",
            "FileEntry",
            "BoxRunData",
            "RunListResponse",
            "AgentWebhookRunRequest",
            "RunWebhook",
            "WebhookAcceptedResponse",
            "ModelConfigurationRequest",
            "CustomRunnerConfigurationRequest",
            "StartupConfigurationRequest",
            "StartupConfigurationResponse",
            "GitExecRequest",
            "GitExecResult",
            "GitCheckoutRequest",
            "GitConfigUpdateRequest",
            "GitConfigResult",
            "GitDiffResponse",
            "GitStatusResponse",
            "GitCommitRequest",
            "GitCommitResult",
            "BrowserScreencastRequest",
            "BrowserScreencastResponse",
        ] {
            assert!(
                document["components"]["schemas"][schema].is_object(),
                "{schema}"
            );
        }
        let value = document;
        assert_eq!(
            value["components"]["securitySchemes"]["BoxApiKey"]["name"],
            "X-Box-Api-Key"
        );
        assert_eq!(
            value["paths"]["/v2/box"]["post"]["requestBody"]["content"]["application/json"]["schema"]
                ["$ref"],
            "#/components/schemas/CreateBoxRequest"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/exec"]["post"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ExecResult"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/run"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/AgentWebhookRunRequest"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/run"]["post"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/WebhookAcceptedResponse"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/browser/screencast"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/BrowserScreencastRequest"
        );
        assert!(value["paths"]["/api/admin/v1/auth/login"]["post"].is_object());
        assert_eq!(
            value["components"]["schemas"]["ApiError"]["required"],
            json!(["error", "message", "request_id"])
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/files/upload"]["post"]["requestBody"]["content"]["multipart/form-data"]
                ["schema"]["properties"]["files"]["items"]["format"],
            "binary"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/files/download"]["get"]["responses"]["200"]["content"]
                ["application/octet-stream"]["schema"]["format"],
            "binary"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/config/model"]["put"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ModelConfigurationRequest"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/config/custom-runner"]["put"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/CustomRunnerConfigurationRequest"
        );
        assert!(
            value["paths"]["/v2/box/{box_id}/config/model"]["put"]["responses"]["501"].is_null()
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/startup"]["put"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/StartupConfigurationRequest"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/startup"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/StartupConfigurationResponse"
        );
        assert_eq!(
            value["paths"]["/v2/box/{box_id}/git/exec"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/GitExecRequest"
        );
        for (method, path) in [
            ("post", "/v2/box"),
            ("delete", "/v2/box"),
            ("get", "/v2/box/{box_id}"),
            ("get", "/v2/box/{box_id}/status"),
            ("post", "/v2/box/{box_id}/pause"),
            ("post", "/v2/box/{box_id}/resume"),
            ("post", "/v2/box/{box_id}/code"),
            ("post", "/v2/box/{box_id}/files/write"),
            ("get", "/v2/box/settings/env"),
            ("put", "/v2/box/settings/env"),
        ] {
            let schema = &value["paths"][path][method]["responses"]["200"]["content"]["application/json"]
                ["schema"];
            assert!(
                schema.get("$ref").is_some()
                    || schema.get("items").is_some()
                    || schema.get("properties").is_some(),
                "implemented route cannot use a bare object schema: {method} {path}"
            );
        }
    }

    #[test]
    fn create_accepts_only_strict_phase_two_custom_agent_and_validates_ttl_and_labels() {
        let invalid = |source: &str| {
            serde_json::from_str::<CreateBoxRequest>(source)
                .unwrap()
                .validate_create()
                .unwrap_err()
                .code
        };
        assert!(
            serde_json::from_str::<CreateBoxRequest>(r#"{"browser":true}"#)
                .unwrap()
                .validate_create()
                .is_ok()
        );
        let custom = serde_json::from_str::<CreateBoxRequest>(
            r#"{"agent":"custom","model":"custom","custom_runner":{"command":"/workspace/home/bin/fixture-harness","args":["--flag","value"]}}"#,
        )
        .unwrap();
        assert_eq!(
            custom.custom_agent().unwrap().unwrap(),
            CustomAgentConfiguration {
                model: "custom".into(),
                command: "/workspace/home/bin/fixture-harness".into(),
                args: vec!["--flag".into(), "value".into()],
                protocol: "box-sse-v1".into(),
            }
        );
        assert!(custom.validate_create().is_ok());
        assert_eq!(
            invalid(r#"{"agent":"codex","model":"gpt-5"}"#),
            "feature_not_supported"
        );
        assert_eq!(
            invalid(
                r#"{"agent":"custom","custom_runner":{"command":"relative/tool","protocol":"box-sse-v1"}}"#
            ),
            "validation_error"
        );
        assert_eq!(
            invalid(
                r#"{"agent":"custom","custom_runner":{"command":"/workspace/home/../escape"}}"#
            ),
            "validation_error"
        );
        assert_eq!(
            invalid(r#"{"agent":"custom","custom_runner":{"command":"/usr/local/bin/tool"}}"#),
            "validation_error"
        );
        assert_eq!(
            invalid(
                r#"{"agent":"custom","custom_runner":{"command":"fixture-harness","protocol":"other"}}"#
            ),
            "feature_not_supported"
        );
        assert_eq!(
            invalid(r#"{"attach_headers":{"a":"b"}}"#),
            "feature_not_supported"
        );
        assert!(
            serde_json::from_str::<CreateBoxRequest>(r#"{"network_policy":{"mode":"allow-all"}}"#)
                .unwrap()
                .validate_create()
                .is_ok()
        );
        assert_eq!(
            invalid(r#"{"network_policy":{"mode":"custom"}}"#),
            "feature_not_supported"
        );
        assert!(
            serde_json::from_str::<CreateBoxRequest>(r#"{"network_policy":{"mode":"deny-all"}}"#)
                .unwrap()
                .validate_create()
                .is_ok()
        );
        assert_eq!(
            invalid(r#"{"ephemeral":true,"ttl":259201}"#),
            "validation_error"
        );
        assert_eq!(invalid(r#"{"ttl":60}"#), "validation_error");
        assert_eq!(
            invalid(r#"{"labels":["invalid space"]}"#),
            "validation_error"
        );
        assert_eq!(
            invalid(r#"{"init_command":"echo ready"}"#),
            "validation_error"
        );
        assert!(
            serde_json::from_str::<CreateBoxRequest>(
                r#"{"keep_alive":true,"init_command":"echo ready"}"#
            )
            .unwrap()
            .validate_create()
            .is_ok()
        );
        assert!(serde_json::from_str::<CreateBoxRequest>(r#"{"runtime":"node","size":"small","ephemeral":true,"ttl":1,"labels":["ci:fixture"]}"#).unwrap().validate_create().is_ok());
        assert!(serde_json::from_str::<CreateBoxRequest>(r#"{"github_token":"token-fixture","git_user_name":"Box User","git_user_email":"box@example.test"}"#).unwrap().validate_create().is_ok());
        assert_eq!(
            invalid(r#"{"github_token":"bad\ntoken"}"#),
            "validation_error"
        );
    }

    #[tokio::test]
    async fn pinned_sdk_custom_harness_create_wire_reaches_the_use_case() {
        let (service, services, _) = router(1024 * 1024);
        let mut response = TestClient::post("http://boxd.test/v2/box")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({
                "agent": "custom",
                "model": "custom-v1",
                "custom_runner": {
                    "command": "/home/boxuser/bin/harness",
                    "args": ["--flag", "value"]
                }
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["id"],
            "box_fixture"
        );
        let creates = services.creates.lock().unwrap();
        assert_eq!(creates.len(), 1);
        assert_eq!(
            creates[0].custom_agent().unwrap().unwrap(),
            CustomAgentConfiguration {
                model: "custom-v1".into(),
                command: "/home/boxuser/bin/harness".into(),
                args: vec!["--flag".into(), "value".into()],
                protocol: "box-sse-v1".into(),
            }
        );
    }

    #[tokio::test]
    async fn pinned_sdk_model_and_custom_runner_updates_are_strict_and_dispatched() {
        let (service, services, _) = router(1024 * 1024);
        for (path, body) in [
            ("/v2/box/box-id/config/model", json!({"model":"custom-v2"})),
            (
                "/v2/box/box-id/config/custom-runner",
                json!({"custom_runner":{
                    "command":"/workspace/home/bin/new-harness",
                    "args":["--json"],
                }}),
            ),
        ] {
            let response = TestClient::put(format!("http://boxd.test{path}"))
                .add_header("x-box-api-key", "good", true)
                .json(&body)
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::OK));
        }
        assert_eq!(services.models.lock().unwrap().as_slice(), ["custom-v2"]);
        assert_eq!(
            services.runners.lock().unwrap().as_slice(),
            [CustomAgentConfiguration {
                model: "custom".into(),
                command: "/workspace/home/bin/new-harness".into(),
                args: vec!["--json".into()],
                protocol: "box-sse-v1".into(),
            }]
        );
    }

    #[tokio::test]
    async fn pinned_sdk_startup_get_put_delete_wire_is_strict_and_dispatched() {
        let (service, services, _) = router(1024 * 1024);
        let response = TestClient::put("http://boxd.test/v2/box/box-id/startup")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"init_command":"echo ready"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            services.startup.lock().unwrap().as_deref(),
            Some("echo ready")
        );

        let mut response = TestClient::get("http://boxd.test/v2/box/box-id/startup")
            .add_header("x-box-api-key", "good", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"init_command":"echo ready"})
        );

        let response = TestClient::put("http://boxd.test/v2/box/box-id/startup")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"init_command":"", "ignored":true}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));

        let response = TestClient::delete("http://boxd.test/v2/box/box-id/startup")
            .add_header("x-box-api-key", "good", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert!(services.startup.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn pinned_sdk_git_exec_wire_is_strict_and_dispatched() {
        let (service, services, _) = router(1024 * 1024);
        let mut response = TestClient::post("http://boxd.test/v2/box/box-id/git/exec")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"args":["status","--short"],"folder":"repo"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"output":"git version fixture"})
        );
        {
            let requests = services.git_execs.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].args, ["status", "--short"]);
            assert_eq!(requests[0].folder.as_deref(), Some("repo"));
        }

        for body in [json!({"args":[]}), json!({"args":["status"],"extra":true})] {
            let response = TestClient::post("http://boxd.test/v2/box/box-id/git/exec")
                .add_header("x-box-api-key", "good", true)
                .json(&body)
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        }

        for (path, key, value) in [
            ("git/diff?folder=repo", "diff", "diff fixture"),
            ("git/status?folder=repo", "status", "status fixture"),
        ] {
            let mut response = TestClient::get(format!("http://boxd.test/v2/box/box-id/{path}"))
                .add_header("x-box-api-key", "good", true)
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::OK));
            assert_eq!(response.take_json::<Value>().await.unwrap()[key], value);
        }
        let response = TestClient::post("http://boxd.test/v2/box/box-id/git/checkout")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"branch":"feature/test","folder":"repo"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let mut response = TestClient::put("http://boxd.test/v2/box/box-id/git-config")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"git_user_name":"Box User","git_user_email":"box@example.test"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"git_user_name":"Box User","git_user_email":"box@example.test"})
        );
        let mut response = TestClient::post("http://boxd.test/v2/box/box-id/git/commit")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({
                "message":"pinned commit",
                "author_name":"Box User",
                "author_email":"box@example.test",
                "folder":"repo"
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"sha":"0123456789abcdef","message":"pinned commit"})
        );
        let response = TestClient::post("http://boxd.test/v2/box/box-id/git/clone")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({
                "repo":"https://github.com/example/repository.git",
                "branch":"main",
                "depth":1,
                "github_token":"github-fixture-token",
                "folder":"repo-parent"
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let response = TestClient::post("http://boxd.test/v2/box/box-id/git/push")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"branch":"main","folder":"repo"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let mut response = TestClient::post("http://boxd.test/v2/box/box-id/git/create-pr")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"title":"Pinned pull request","body":"Body fixture","base":"main","folder":"repo"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"url":"https://github.com/example/repository/pull/42","number":42,"title":"Pinned pull request","base":"main"})
        );

        let response = TestClient::post("http://boxd.test/v2/box/box-id/git/clone")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"repo":"https://github.com/example/repository.git","depth":0}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn pinned_sdk_snapshot_create_poll_list_and_delete_shapes_are_dispatched() {
        let (service, _, _) = router(1024 * 1024);
        let mut response = TestClient::post("http://boxd.test/v2/box/box-id/snapshots")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"name":"before-change"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let snapshot = response.take_json::<Value>().await.unwrap();
        assert_eq!(snapshot["name"], "before-change");
        assert_eq!(snapshot["status"], "ready");

        let mut response = TestClient::get("http://boxd.test/v2/box/box-id/snapshots")
            .add_header("x-box-api-key", "good", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["snapshots"][0]["name"],
            "fixture"
        );
        let response = TestClient::delete(
            "http://boxd.test/v2/box/box-id/snapshots/01900000-0000-7000-8000-000000000099",
        )
        .add_header("x-box-api-key", "good", true)
        .send(&service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let mut response = TestClient::delete("http://boxd.test/v2/box/snapshots")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"ids":["01900000-0000-7000-8000-000000000099"]}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"deleted":1})
        );

        let mut response = TestClient::post("http://boxd.test/v2/box/from-snapshot")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({
                "snapshot_id":"01900000-0000-7000-8000-000000000099",
                "name":"restored",
                "size":"medium"
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["status"],
            "creating"
        );
    }

    #[tokio::test]
    async fn pinned_sdk_schedule_crud_wire_preserves_optional_patch_semantics() {
        let (service, services, _) = router(1024 * 1024);
        let schedule_id = "01900000-0000-7000-8000-000000000077";

        let mut response = request("POST", "/v2/box/box-id/schedules")
            .json(&json!({
                "type":"exec", "cron":"*/5 * * * *",
                "command":["echo","ready"], "folder":"/workspace/home",
                "webhook_headers":{}
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let created = response.take_json::<Value>().await.unwrap();
        assert_eq!(created["id"], schedule_id);
        assert_eq!(created["type"], "exec");
        assert_eq!(created["command"], json!(["echo", "ready"]));
        assert!(created.get("prompt").is_none());

        let response = request("POST", "/v2/box/box-id/schedules")
            .json(&json!({
                "type":"prompt", "cron":"0 9 * * 1-5",
                "prompt":"check status", "folder":"/workspace/home",
                "model":"custom", "agent_options":{"stream":true}, "timeout":120,
                "webhook_url":"https://example.test/hook",
                "webhook_headers":{"authorization":"redacted-fixture"}
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        {
            let creates = services.schedule_creates.lock().unwrap();
            assert_eq!(creates.len(), 2);
            assert_eq!(creates[0].r#type, "exec");
            assert_eq!(creates[0].command.as_ref().unwrap(), &["echo", "ready"]);
            assert_eq!(creates[1].r#type, "prompt");
            assert_eq!(creates[1].prompt.as_deref(), Some("check status"));
            assert_eq!(creates[1].timeout, Some(120));
            assert_eq!(
                creates[1]
                    .webhook_headers
                    .get("authorization")
                    .map(String::as_str),
                Some("redacted-fixture")
            );
        }

        let mut response = request("GET", "/v2/box/box-id/schedules")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let listed = response.take_json::<Value>().await.unwrap();
        assert!(listed.is_array(), "pinned SDK expects a bare Schedule[]");
        assert_eq!(listed[0]["id"], schedule_id);

        let mut response = request("GET", &format!("/v2/box/box-id/schedules/{schedule_id}"))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["total_runs"],
            0
        );

        let response = request("PATCH", &format!("/v2/box/box-id/schedules/{schedule_id}"))
            .json(&json!({
                "cron":"0 * * * *", "command":[], "model":"",
                "agent_options":null, "webhook_url":null, "webhook_headers":{}
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        {
            let updates = services.schedule_updates.lock().unwrap();
            assert_eq!(updates.len(), 1);
            assert_eq!(
                updates[0].cron,
                PatchField::Present(Some("0 * * * *".into()))
            );
            assert_eq!(updates[0].command, PatchField::Present(Some(Vec::new())));
            assert_eq!(updates[0].prompt, PatchField::Missing);
            assert_eq!(updates[0].model, PatchField::Present(Some(String::new())));
            assert_eq!(updates[0].agent_options, PatchField::Present(None));
            assert_eq!(updates[0].webhook_url, PatchField::Present(None));
            assert_eq!(
                updates[0].webhook_headers,
                PatchField::Present(Some(std::collections::BTreeMap::new()))
            );
        }

        let response = request("PATCH", &format!("/v2/box/box-id/schedules/{schedule_id}"))
            .json(&json!({"unknown":true}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));

        for (method, action) in [("POST", "pause"), ("POST", "resume"), ("DELETE", "")] {
            let suffix = if action.is_empty() {
                format!("/v2/box/box-id/schedules/{schedule_id}")
            } else {
                format!("/v2/box/box-id/schedules/{schedule_id}/{action}")
            };
            let response = request(method, &suffix).send(&service).await;
            assert_eq!(response.status_code, Some(StatusCode::OK));
        }
        assert_eq!(
            services.schedule_actions.lock().unwrap().as_slice(),
            &[
                ("pause".into(), schedule_id.into()),
                ("resume".into(), schedule_id.into()),
                ("delete".into(), schedule_id.into()),
            ]
        );
    }

    #[tokio::test]
    async fn browser_basics_decode_pinned_wire_but_remain_fail_closed_without_driver() {
        let (service, _, _) = router(1024 * 1024);
        for (method, path, body) in [
            (
                "POST",
                "/v2/box/box-id/browser/tabs",
                Some(json!({
                    "url":"https://example.invalid",
                    "wait_until":"networkidle",
                    "timeout":0
                })),
            ),
            (
                "POST",
                "/v2/box/box-id/browser/goto",
                Some(json!({"url":"https://example.invalid","tab":"tab_fixture"})),
            ),
            ("GET", "/v2/box/box-id/browser/tabs", None),
            (
                "GET",
                "/v2/box/box-id/browser/content?tab=tab_fixture",
                None,
            ),
            (
                "GET",
                "/v2/box/box-id/browser/screenshot?encoding=base64&tab=tab_fixture&full_page=true",
                None,
            ),
            ("POST", "/v2/box/box-id/browser/connect", None),
            (
                "POST",
                "/v2/box/box-id/browser/screencast",
                Some(json!({"tab":"tab_fixture"})),
            ),
            ("DELETE", "/v2/box/box-id/browser/tabs/tab_fixture", None),
        ] {
            let request = request(method, path);
            let mut response = match body {
                Some(body) => request.json(&body).send(&service).await,
                None => request.send(&service).await,
            };
            let status = response.status_code;
            let response_body = response.take_string().await.unwrap();
            assert_eq!(
                status,
                Some(StatusCode::NOT_IMPLEMENTED),
                "{method} {path}: {response_body}"
            );
        }

        for body in [
            json!({"url":"file:///etc/passwd"}),
            json!({"url":"https://example.invalid","ignored":true}),
            json!({"url":"https://example.invalid","wait_until":"idle"}),
        ] {
            let response = request("POST", "/v2/box/box-id/browser/tabs")
                .json(&body)
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        }

        let response = request("POST", "/v2/box/box-id/browser/screencast")
            .json(&json!({"tab":"tab/invalid"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));

        let ticket = "c".repeat(64);
        let mut response = TestClient::get(format!(
            "http://boxd.test/v2/box/browser/screencast/view?ticket={ticket}"
        ))
        .send(&service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert!(
            response
                .take_string()
                .await
                .unwrap()
                .contains("Live browser view")
        );
        assert!(!response.headers().contains_key("x-frame-options"));
        assert!(
            response
                .headers()
                .get("content-security-policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("frame-ancestors *")
        );
        let response = TestClient::get("http://boxd.test/v2/box/browser/screencast/view")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn browser_model_actions_decode_and_encode_the_pinned_sdk_wire() {
        let (service, _, _) = router(2 * 1024 * 1024);
        let mut response = request("POST", "/v2/box/box-id/browser/extract")
            .json(&json!({
                "instruction":"extract fixture",
                "schema":{"type":"object"},
                "tab":"tab_fixture",
                "model":"openai/fixture"
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"data":{"instruction":"extract fixture","ok":true}})
        );

        let mut response = request("POST", "/v2/box/box-id/browser/observe")
            .json(&json!({
                "instruction":"find submit","tab":"tab_fixture","model":"openai/fixture"
            }))
            .send(&service)
            .await;
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"elements":[{"description":"Submit","selector":"#submit"}]})
        );

        let mut response = request("POST", "/v2/box/box-id/browser/act")
            .json(&json!({"instruction":"submit","tab":"tab_fixture"}))
            .send(&service)
            .await;
        let body = response.take_json::<Value>().await.unwrap();
        assert_eq!(body["action_description"], "Click submit");
        assert_eq!(body["cache_status"], "MISS");
        assert_eq!(body["input_tokens"], 7);

        let mut response = request("POST", "/v2/box/box-id/browser/run")
            .json(&json!({
                "prompt":"finish task","tab":"tab_fixture","max_steps":3,
                "schema":{"type":"object"},"model":"openai/fixture"
            }))
            .send(&service)
            .await;
        let body = response.take_json::<Value>().await.unwrap();
        assert_eq!(body["data"], json!({"ok":true}));
        assert_eq!(body["step_count"], 1);
        assert_eq!(body["steps"][0]["step"], 1);

        for (path, body) in [
            (
                "/v2/box/box-id/browser/extract",
                json!({"instruction":"x","tab":"tab_fixture"}),
            ),
            (
                "/v2/box/box-id/browser/observe",
                json!({"instruction":"x","tab":"tab_fixture","schema":{}}),
            ),
            (
                "/v2/box/box-id/browser/run",
                json!({"prompt":"x","tab":"tab_fixture","max_steps":31}),
            ),
        ] {
            let response = request("POST", path).json(&body).send(&service).await;
            assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        }
    }

    #[tokio::test]
    async fn browser_recording_routes_preserve_metadata_hls_segments_and_download_types() {
        let (service, _, _) = router(2 * 1024 * 1024);
        let id = "01900000-0000-7000-8000-000000000055";
        let mut response = request("POST", "/v2/box/box-id/browser/recordings")
            .json(&json!({"max_duration_seconds":42}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body = response.take_json::<Value>().await.unwrap();
        assert_eq!(body["status"], "recording");
        assert_eq!(body["markers"][0]["type"], "tab_switch");

        let mut response = request("POST", "/v2/box/box-id/browser/recordings/stop")
            .send(&service)
            .await;
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["status"],
            "completed"
        );

        let mut response = request(
            "GET",
            "/v2/box/box-id/browser/recordings?cursor=cursor-fixture&limit=100",
        )
        .send(&service)
        .await;
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["recordings"][0]["id"],
            id
        );
        let mut response = request("GET", &format!("/v2/box/box-id/browser/recordings/{id}"))
            .send(&service)
            .await;
        assert_eq!(response.take_json::<Value>().await.unwrap()["id"], id);

        let mut response = request(
            "GET",
            &format!("/v2/box/box-id/browser/recordings/{id}/playlist"),
        )
        .send(&service)
        .await;
        assert_eq!(
            response.headers()[salvo::http::header::CONTENT_TYPE],
            "application/vnd.apple.mpegurl"
        );
        assert!(response.take_string().await.unwrap().contains("#EXTM3U"));
        let mut response = request(
            "GET",
            &format!("/v2/box/box-id/browser/recordings/{id}/playlist?segment=segment-00000.ts"),
        )
        .send(&service)
        .await;
        assert_eq!(
            response.headers()[salvo::http::header::CONTENT_TYPE],
            "video/mp2t"
        );
        assert_eq!(response.take_string().await.unwrap(), "mpeg-ts-fixture");
        let mut response = request(
            "GET",
            &format!("/v2/box/box-id/browser/recordings/{id}/download"),
        )
        .send(&service)
        .await;
        assert_eq!(
            response.headers()[salvo::http::header::CONTENT_TYPE],
            "video/mp4"
        );
        assert_eq!(response.take_string().await.unwrap(), "mp4-fixture");
    }

    #[tokio::test]
    async fn pinned_sdk_preview_auth_shapes_are_strict_and_credentials_are_create_only() {
        let (service, _, _) = router(1024 * 1024);
        let mut response = TestClient::post("http://boxd.test/v2/box/box-id/preview")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({"port":3000,"bearer_token":true}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let created = response.take_json::<Value>().await.unwrap();
        assert_eq!(created["port"], 3000);
        assert_eq!(created["token"], "bearer-fixture");
        assert!(created.get("username").is_none());

        let mut response = TestClient::get("http://boxd.test/v2/box/box-id/preview")
            .add_header("x-box-api-key", "good", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let listed = response.take_json::<Value>().await.unwrap();
        assert_eq!(listed["previews"][0]["port"], 3000);
        assert!(listed["previews"][0].get("token").is_none());

        let response = TestClient::delete("http://boxd.test/v2/box/box-id/preview/3000")
            .add_header("x-box-api-key", "good", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));

        for body in [
            json!({"port":0}),
            json!({"port":18080}),
            json!({"port":18081}),
            json!({"port":3000,"bearer_token":true,"basic_auth":true}),
            json!({"port":3000,"unknown":true}),
        ] {
            let response = TestClient::post("http://boxd.test/v2/box/box-id/preview")
                .add_header("x-box-api-key", "good", true)
                .json(&body)
                .send(&service)
                .await;
            assert_eq!(
                response.status_code,
                Some(StatusCode::BAD_REQUEST),
                "{body}"
            );
        }
    }

    #[test]
    fn per_box_and_account_env_reads_require_secrets_scope() {
        assert_eq!(
            required_scope("GET", "/v2/box/settings/env"),
            Some(AuthScope::SecretsRead)
        );
        assert_eq!(
            required_scope("GET", "/v2/box/box-id/settings/env"),
            Some(AuthScope::SecretsRead)
        );
        assert_eq!(
            required_scope("GET", "/v2/box/box-id/startup"),
            Some(AuthScope::SecretsRead)
        );
        assert_eq!(
            required_scope("GET", "/v2/box/box-id"),
            Some(AuthScope::BoxesRead)
        );
    }

    #[tokio::test]
    async fn all_manifest_routes_are_in_process_non_404_and_unknown_is_404() {
        let (router, _, _) = router(1024 * 1024);
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../compat/upstash-box-0.6.3/route-manifest.json"
        ))
        .unwrap();
        for route in manifest["routes"].as_array().unwrap() {
            let method = route["method"].as_str().unwrap();
            let path = route["path"]
                .as_str()
                .unwrap()
                .replace("{box_id}", "box-id")
                .replace("{skill_id+}", "nested/skill")
                .replace("{snapshot_id}", "snapshot-id")
                .replace("{run_id}", "run-id")
                .replace("{tab_id}", "tab-id")
                .replace("{label}", "label")
                .replace("{port}", "3000")
                .replace("{id}", "id");
            let mut response = request(method, &path).json(&json!({"command":["sh","-c","true"],"code":"1","path":"/workspace/a","content":"a"})).send(&router).await;
            let status = response.status_code;
            let body = response.take_string().await.unwrap();
            assert_ne!(
                status,
                Some(StatusCode::NOT_FOUND),
                "{method} {path}: {body}"
            );
        }
        let mut response = request("GET", "/v2/box/box-id/not-a-route")
            .send(&router)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["error"],
            "not_found"
        );
    }

    #[tokio::test]
    async fn file_list_without_folder_uses_the_pinned_sdk_default_cwd() {
        let (service, services, _) = router(1024 * 1024);
        let mut response = TestClient::get("http://boxd.test/v2/box/box-id/files/list")
            .add_header("x-box-api-key", "good", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let _ = response.take_json::<Value>().await.unwrap();
        assert_eq!(
            services.list_paths.lock().unwrap().as_slice(),
            ["/workspace/home"]
        );
    }

    #[tokio::test]
    async fn mutating_compatibility_requests_are_structurally_audited_without_body_data() {
        let (service, services, account) = router(1024 * 1024);
        let response = request("POST", "/v2/box")
            .json(&json!({"runtime":"node"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let response = request("POST", "/v2/box")
            .json(&json!({"runtime":"node","unknown":"must-not-be-audited"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        let response = request("GET", "/v2/box").send(&service).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));

        let audits = services.audits.lock().unwrap();
        assert_eq!(audits.len(), 2);
        assert_eq!(audits[0].context, account);
        assert_eq!(audits[0].actor, "compat_api_key");
        assert_eq!(audits[0].action, "POST /v2/box");
        assert_eq!(audits[0].resource, "/v2/box");
        assert_eq!(audits[0].status_code, 200);
        assert!(audits[0].succeeded);
        assert_eq!(audits[1].status_code, 400);
        assert!(!audits[1].succeeded);
        assert!(!format!("{audits:?}").contains("must-not-be-audited"));
    }

    #[tokio::test]
    async fn run_history_uses_the_pinned_runs_wrapper() {
        let (service, _, account) = router(1024 * 1024);
        let mut response = request("GET", "/v2/box/box-id/runs").send(&service).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body = response.take_json::<Value>().await.unwrap();
        assert_eq!(body["runs"].as_array().unwrap().len(), 1);
        assert_eq!(body["runs"][0]["box_id"], "box-id");
        assert_eq!(
            body["runs"][0]["customer_id"],
            account.account_id.to_string()
        );
    }

    #[tokio::test]
    async fn custom_agent_run_stream_uses_pinned_sse_framing_and_cancel_route() {
        let (service, _, _) = router(1024 * 1024);
        let mut response = request("POST", "/v2/box/box-id/run/stream")
            .json(&json!({"prompt":"hello","folder":"nested"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response
                .headers()
                .get(salvo::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/event-stream"
        );
        assert_eq!(response.headers().get("x-accel-buffering").unwrap(), "no");
        assert_eq!(
            response
                .headers()
                .get(salvo::http::header::CONTENT_ENCODING)
                .unwrap(),
            "identity"
        );
        let body = response.take_string().await.unwrap();
        assert!(body.contains("event:run_start\ndata:{\"run_id\":\"run-1\"}\nid:01900000-0000-7000-8000-000000000001:0\n\n"));
        assert!(body.contains(
            "event:done\ndata:{\"output\":\"ok\"}\nid:01900000-0000-7000-8000-000000000001:1\n\n"
        ));

        let mut replayed = request("POST", "/v2/box/box-id/run/stream")
            .add_header(
                "last-event-id",
                "01900000-0000-7000-8000-000000000001:7",
                true,
            )
            .send(&service)
            .await;
        assert_eq!(replayed.status_code, Some(StatusCode::OK));
        assert!(replayed.take_string().await.unwrap().contains(
            "event:done\ndata:{\"output\":\"replayed\"}\nid:01900000-0000-7000-8000-000000000001:8\n\n"
        ));

        let mut logs = request("GET", "/v2/box/box-id/logs?offset=2&limit=7")
            .send(&service)
            .await;
        assert_eq!(logs.status_code, Some(StatusCode::OK));
        assert_eq!(
            logs.take_json::<Value>().await.unwrap()["logs"][0]["message"],
            "stderr-2-7"
        );

        let mut cancelled = request(
            "POST",
            "/v2/box/box-id/runs/01900000-0000-7000-8000-000000000001/cancel",
        )
        .send(&service)
        .await;
        assert_eq!(cancelled.status_code, Some(StatusCode::OK));
        assert_eq!(cancelled.take_json::<Value>().await.unwrap(), json!({}));
    }

    #[tokio::test]
    async fn pinned_webhook_run_is_strict_and_returns_the_accepted_shape() {
        let (service, services, _) = router(1024 * 1024);
        let mut response = TestClient::post("http://boxd.test/v2/box/box-id/run")
            .add_header("x-box-api-key", "good", true)
            .json(&json!({
                "prompt":"ship it",
                "webhook":{
                    "url":"https://hooks.example.test/completed?opaque=1",
                    "headers":{"Authorization":"Bearer fixture"}
                }
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap(),
            json!({"status":"accepted","run_id":"01900000-0000-7000-8000-000000000001"})
        );
        {
            let requests = services.webhook_runs.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].prompt, "ship it");
            assert_eq!(
                requests[0].url,
                "https://hooks.example.test/completed?opaque=1"
            );
            assert_eq!(
                requests[0].headers.get("Authorization").map(String::as_str),
                Some("Bearer fixture")
            );
        }

        for body in [
            json!({"prompt":"x","webhook":{"url":"https://example.test"},"extra":true}),
            json!({"prompt":"x","webhook":{"url":"https://example.test","headers":{"X-Test":"bad\r\nvalue"}}}),
            json!({"prompt":"x","webhook":{"url":"https://example.test","headers":{"Host":"attacker.test"}}}),
            json!({"prompt":"x","webhook":{"url":"https://example.test","headers":{"Content-Type":"text/plain"}}}),
            json!({"prompt":"x","webhook":{"url":"https://example.test","headers":{"Proxy-Authorization":"secret"}}}),
            json!({"prompt":"x","webhook":{"url":"https://example.test","headers":{"TE":"trailers"}}}),
            json!({"prompt":"x","webhook":{"url":"https://example.test"},"json_schema":{}}),
            json!({"prompt":"x","webhook":{"url":"https://example.test"},"agent_options":{}}),
            json!({"prompt":"x","webhook":{"url":"https://example.test"},"files":[]}),
        ] {
            let response = TestClient::post("http://boxd.test/v2/box/box-id/run")
                .add_header("x-box-api-key", "good", true)
                .json(&body)
                .send(&service)
                .await;
            assert!(matches!(
                response.status_code,
                Some(StatusCode::BAD_REQUEST | StatusCode::NOT_IMPLEMENTED)
            ));
        }
        for path in ["/v2/box/box-id/run", "/v2/box/box-id/run/stream"] {
            let response = request("POST", path)
                .bytes(b"--fixture--\r\n".to_vec())
                .add_header(
                    "content-type",
                    "multipart/form-data; boundary=fixture",
                    true,
                )
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_IMPLEMENTED));
        }
    }

    #[tokio::test]
    async fn binary_download_and_strict_bulk_delete_use_public_sdk_routes() {
        let (service, services, _) = router(1024 * 1024);
        let mut download = request(
            "GET",
            "/v2/box/box-id/files/download?folder=%2Fworkspace%2Fbinary",
        )
        .send(&service)
        .await;
        assert_eq!(download.status_code, Some(StatusCode::OK));
        assert_eq!(
            download
                .headers()
                .get(salvo::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            download.take_bytes(None).await.unwrap().as_ref(),
            [0, 1, 255]
        );

        let response = request("DELETE", "/v2/box")
            .json(&json!({"ids":["one","two"]}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            services.bulk_ids.lock().unwrap().as_slice(),
            &[vec!["one".to_owned(), "two".to_owned()]]
        );
        for body in [
            json!({"ids":[]}),
            json!({"ids":["same","same"]}),
            json!({"ids":["one"],"ignored":true}),
        ] {
            let response = request("DELETE", "/v2/box")
                .json(&body)
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        }
    }

    #[tokio::test]
    async fn multipart_upload_pairs_repeated_paths_and_files_before_dispatch() {
        let (service, services, _) = router(1024 * 1024);
        let boundary = "boxd-test-boundary";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"paths\"\r\n\r\n/workspace/a.bin\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"paths\"\r\n\r\n/workspace/b.bin\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nA\0B\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"b.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nCD\r\n--{boundary}--\r\n"
        )
        .into_bytes();
        let response = request("POST", "/v2/box/box-id/files/upload")
            .bytes(body)
            .add_header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
                true,
            )
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            services.uploads.lock().unwrap().last().unwrap(),
            &vec![
                UploadFile {
                    path: "/workspace/a.bin".into(),
                    contents: b"A\0B".to_vec(),
                },
                UploadFile {
                    path: "/workspace/b.bin".into(),
                    contents: b"CD".to_vec(),
                },
            ]
        );

        let (limited, _, _) = router(32);
        let oversized = request("POST", "/v2/box/box-id/files/upload")
            .bytes(vec![b'x'; 128])
            .add_header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
                true,
            )
            .send(&limited)
            .await;
        assert_eq!(oversized.status_code, Some(StatusCode::PAYLOAD_TOO_LARGE));
    }

    #[tokio::test]
    async fn auth_context_dto_body_limit_and_admin_chain_are_enforced() {
        let (service, services, account) = router(1024);
        let response = TestClient::get("http://boxd.test/v2/box")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert!(response.headers().contains_key("x-request-id"));
        let response = TestClient::get("http://boxd.test/v2/box")
            .add_header("x-box-api-key", "wrong", true)
            .add_header("x-request-id", "phase3-trace-fixture", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(
            response.headers().get("x-request-id").unwrap(),
            "phase3-trace-fixture"
        );
        let mut response = request("POST", "/v2/box")
            .json(&json!({"name":"fixture"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["id"],
            "box_fixture"
        );
        assert_eq!(services.contexts.lock().unwrap().as_slice(), &[account]);
        let mut response = request("POST", "/v2/box")
            .json(&json!({"browser":true}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["id"],
            "box_fixture"
        );
        assert_eq!(services.creates.lock().unwrap()[1].browser, Some(true));
        let (limited_router, _, _) = router(16);
        let mut response = request("POST", "/v2/box")
            .raw_json("{\"name\":\"this is too large\"}")
            .send(&limited_router)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::PAYLOAD_TOO_LARGE));
        assert!(
            !response.take_json::<Value>().await.unwrap()["request_id"]
                .as_str()
                .unwrap()
                .is_empty()
        );
        let response = TestClient::get("http://boxd.test/api/admin/v1/capabilities")
            .add_header("x-box-api-key", "good", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        let response = TestClient::get("http://boxd.test/api/admin/v1/capabilities")
            .add_header("cookie", "boxd_session=session", true)
            .add_header("x-csrf-token", "csrf", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[tokio::test]
    async fn admin_login_uses_http_only_cookie_and_independent_csrf() {
        let (service, _, _) = router(1024);
        let mut response = TestClient::post("http://boxd.test/api/admin/v1/auth/login")
            .json(&json!({"username":"admin","password":"correct password"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(!cookie.contains("correct password"));
        let body = response.take_json::<Value>().await.unwrap();
        assert_eq!(body["csrf_token"], "boxd_csrf_fixture");
        assert!(!body.to_string().contains("boxd_session_fixture_secret"));

        let response = TestClient::post("http://boxd.test/api/admin/v1/auth/logout")
            .add_header("cookie", "boxd_session=session", true)
            .add_header("x-csrf-token", "csrf", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert!(
            response
                .headers()
                .get("set-cookie")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
    }
}
