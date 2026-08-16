//! Guest-side agent.  This crate never executes a host command: its Unix
//! executor is intended to run only inside the microVM image.
#![allow(clippy::result_large_err)]

mod chromium;

pub use chromium::ChromiumBrowserBackend;

use async_trait::async_trait;
use box_agent_proto::{PROTOCOL_VERSION, v1::*};
use futures_util::{Stream, stream};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command,
    sync::Notify,
};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WRITE_FRAMES: usize = 4096;
const FILE_FRAME_BYTES: usize = 1024 * 1024;
const MAX_LIST_ENTRIES: usize = 4_096;
const MAX_LIST_ENCODED_BYTES: usize = 2 * 1024 * 1024;
const MAX_EXEC_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_EXEC_TIMEOUT_MS: u64 = 300_000;
const MAX_EXEC_ARGS: usize = 256;
const MAX_EXEC_ARG_BYTES: usize = 64 * 1024;
const MAX_EXEC_TOTAL_BYTES: usize = 256 * 1024;
const MAX_EXEC_CWD_BYTES: usize = 4_096;
const EXEC_FRAME_BYTES: usize = 256 * 1024;
const MAX_ENV_VARS: usize = 128;
const MAX_ENV_NAME_BYTES: usize = 128;
const MAX_ENV_TOTAL_BYTES: usize = 64 * 1024;
const NONCE_LEN: usize = 32;
const MAX_HARNESS_PROMPT_BYTES: usize = 128 * 1024;
const MAX_HARNESS_LABEL_BYTES: usize = 255;
const MAX_HARNESS_EVENTS: usize = 4_096;
const MAX_HARNESS_EVENT_BYTES: usize = 1024 * 1024;
const MAX_HARNESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_HARNESS_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TUNNEL_FRAME_BYTES: usize = 1024 * 1024;
const MAX_SKILL_FILES: usize = 128;
const MAX_SKILL_BYTES: usize = 1024 * 1024;
const MAX_SKILL_PATH_BYTES: usize = 512;
const AGENT_CONTROL_PORT: u32 = 18_080;
const MAX_COMPLETED_EXECUTIONS: usize = 64;
const MAX_COMPLETED_EXECUTION_BYTES: usize = 32 * 1024 * 1024;
const MAX_BROWSER_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_BROWSER_FRAME_BYTES: usize = 1024 * 1024;
const MAX_BROWSER_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BROWSER_FRAMES: usize = 64;

const HARNESS_EVENT_TYPES: [&str; 6] = ["text", "thinking", "tool", "tool_result", "done", "error"];

fn is_allowed_absolute_harness_command(command: &str) -> bool {
    let path = Path::new(command);
    if !path.is_absolute() {
        return false;
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

fn validate_environment(environment: &HashMap<String, String>) -> Result<(), Status> {
    if environment.len() > MAX_ENV_VARS {
        return Err(Status::invalid_argument("too many environment variables"));
    }
    let mut total = 0usize;
    for (name, value) in environment {
        let mut bytes = name.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
        if !valid_first
            || name.len() > MAX_ENV_NAME_BYTES
            || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || name.as_bytes().contains(&0)
            || value.as_bytes().contains(&0)
        {
            return Err(Status::invalid_argument("invalid environment variable"));
        }
        total = total.saturating_add(name.len()).saturating_add(value.len());
        if total > MAX_ENV_TOTAL_BYTES {
            return Err(Status::invalid_argument("environment exceeds size limit"));
        }
    }
    Ok(())
}

fn validate_exec_request(request: &ExecRequest) -> Result<(), Status> {
    if request.argv.is_empty() || request.argv.len() > MAX_EXEC_ARGS {
        return Err(Status::invalid_argument("invalid exec argument count"));
    }
    let total = request.argv.iter().try_fold(0usize, |total, argument| {
        if argument.as_bytes().contains(&0) || argument.len() > MAX_EXEC_ARG_BYTES {
            return Err(Status::invalid_argument("invalid exec argument"));
        }
        total
            .checked_add(argument.len())
            .ok_or_else(|| Status::invalid_argument("exec arguments exceed size limit"))
    })?;
    if total > MAX_EXEC_TOTAL_BYTES {
        return Err(Status::invalid_argument("exec arguments exceed size limit"));
    }
    if request.cwd.len() > MAX_EXEC_CWD_BYTES || request.cwd.as_bytes().contains(&0) {
        return Err(Status::invalid_argument("exec cwd exceeds size limit"));
    }
    Ok(())
}

fn validate_skill_name(name: &str) -> Result<(), Status> {
    if name.is_empty()
        || name.len() > 128
        || matches!(name, "." | "..")
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._-".contains(&byte))
        })
    {
        return Err(Status::invalid_argument("invalid skill name"));
    }
    Ok(())
}

fn skill_file_pieces(path: &str) -> Result<Vec<CString>, Status> {
    if path.is_empty() || path.len() > MAX_SKILL_PATH_BYTES || Path::new(path).is_absolute() {
        return Err(Status::invalid_argument("invalid skill file path"));
    }
    let pieces = Path::new(path)
        .components()
        .map(|component| match component {
            Component::Normal(name) => CString::new(name.as_bytes())
                .map_err(|_| Status::invalid_argument("invalid skill file path")),
            _ => Err(Status::invalid_argument("invalid skill file path")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if pieces.is_empty() {
        return Err(Status::invalid_argument("invalid skill file path"));
    }
    Ok(pieces)
}

fn validate_harness_request(request: &RunHarnessRequest) -> Result<(), Status> {
    if request.execution_id.is_empty() {
        return Err(Status::invalid_argument("execution id required"));
    }
    if request.command.is_empty()
        || request.command.len() > MAX_EXEC_ARG_BYTES
        || request.command.as_bytes().contains(&0)
    {
        return Err(Status::invalid_argument("invalid harness command"));
    }
    let command = Path::new(&request.command);
    if command.is_absolute() && !is_allowed_absolute_harness_command(&request.command) {
        return Err(Status::permission_denied(
            "absolute harness command outside allowed roots",
        ));
    }
    if !command.is_absolute()
        && (request.command.contains('/') || matches!(request.command.as_str(), "." | ".."))
    {
        return Err(Status::permission_denied(
            "harness command must be a PATH executable",
        ));
    }
    if request.prompt.len() > MAX_HARNESS_PROMPT_BYTES || request.prompt.as_bytes().contains(&0) {
        return Err(Status::invalid_argument(
            "harness prompt exceeds size limit",
        ));
    }
    for (name, value) in [
        ("model", request.model.as_str()),
        ("session", request.session_id.as_str()),
    ] {
        if value.is_empty() && name == "model" {
            return Err(Status::invalid_argument("harness model required"));
        }
        if value.len() > MAX_HARNESS_LABEL_BYTES || value.as_bytes().contains(&0) {
            return Err(Status::invalid_argument(format!(
                "harness {name} exceeds size limit"
            )));
        }
    }
    validate_environment(&request.environment)?;

    let mut argv = Vec::with_capacity(request.args.len().saturating_add(8));
    argv.push(request.command.clone());
    argv.extend(request.args.iter().cloned());
    argv.extend([
        "-p".into(),
        request.prompt.clone(),
        "--model".into(),
        request.model.clone(),
        "--stream".into(),
    ]);
    if !request.session_id.is_empty() {
        argv.extend(["--session".into(), request.session_id.clone()]);
    }
    validate_exec_request(&ExecRequest {
        argv,
        cwd: request.cwd.clone(),
        execution_id: request.execution_id.clone(),
        timeout_ms: request.timeout_ms,
        max_output_bytes: request.max_output_bytes,
        environment: request.environment.clone(),
    })
}

fn harness_exec_request(request: RunHarnessRequest) -> ExecRequest {
    let mut argv = Vec::with_capacity(request.args.len().saturating_add(8));
    argv.push(request.command);
    argv.extend(request.args);
    argv.extend([
        "-p".into(),
        request.prompt,
        "--model".into(),
        request.model,
        "--stream".into(),
    ]);
    if !request.session_id.is_empty() {
        argv.extend(["--session".into(), request.session_id]);
    }
    let max_output_bytes = usize::try_from(request.max_output_bytes)
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(MAX_HARNESS_OUTPUT_BYTES)
        .min(MAX_HARNESS_OUTPUT_BYTES) as u64;
    ExecRequest {
        argv,
        cwd: request.cwd,
        execution_id: request.execution_id,
        timeout_ms: request.timeout_ms.clamp(1, MAX_EXEC_TIMEOUT_MS),
        max_output_bytes,
        environment: request.environment,
    }
}

struct HarnessParser {
    execution_id: String,
    buffer: Vec<u8>,
    event_count: usize,
    total_bytes: usize,
    terminal_type: Option<String>,
}

impl HarnessParser {
    fn new(execution_id: &str) -> Self {
        Self {
            execution_id: execution_id.into(),
            buffer: Vec::new(),
            event_count: 0,
            total_bytes: 0,
            terminal_type: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Vec<HarnessEvent>, Status> {
        self.total_bytes = self.total_bytes.saturating_add(bytes.len());
        if self.total_bytes > MAX_HARNESS_OUTPUT_BYTES {
            return Err(Status::resource_exhausted(
                "harness output exceeds size limit",
            ));
        }
        self.buffer.extend_from_slice(bytes);
        let mut parsed = Vec::new();
        while let Some((end, delimiter_len)) = harness_event_delimiter(&self.buffer) {
            let block = self.buffer[..end].to_vec();
            self.buffer.drain(..end + delimiter_len);
            if block.is_empty() {
                continue;
            }
            parsed.push(self.parse_block(&block)?);
        }
        if self.buffer.len() > MAX_HARNESS_EVENT_BYTES {
            return Err(Status::resource_exhausted(
                "harness event stream exceeds limit",
            ));
        }
        Ok(parsed)
    }

    fn parse_block(&mut self, block: &[u8]) -> Result<HarnessEvent, Status> {
        if self.terminal_type.is_some() {
            return Err(Status::data_loss("harness event after terminal event"));
        }
        if self.event_count >= MAX_HARNESS_EVENTS || block.len() > MAX_HARNESS_EVENT_BYTES {
            return Err(Status::resource_exhausted(
                "harness event stream exceeds limit",
            ));
        }
        let block = std::str::from_utf8(block)
            .map_err(|_| Status::data_loss("harness stdout must be UTF-8"))?
            .replace("\r\n", "\n");
        let mut lines = block.lines();
        let event_type = lines
            .next()
            .and_then(|line| line.strip_prefix("event: "))
            .filter(|event| HARNESS_EVENT_TYPES.contains(event))
            .ok_or_else(|| Status::data_loss("invalid harness event type"))?;
        let payload = lines
            .next()
            .and_then(|line| line.strip_prefix("data: "))
            .ok_or_else(|| Status::data_loss("harness event data required"))?;
        if lines.next().is_some() {
            return Err(Status::data_loss("invalid harness event framing"));
        }
        let payload: serde_json::Value = serde_json::from_str(payload)
            .map_err(|_| Status::data_loss("harness event data must be JSON"))?;
        let payload_json = serde_json::to_string(&payload)
            .map_err(|_| Status::internal("harness event serialization failed"))?;
        let terminal = matches!(event_type, "done" | "error");
        if terminal {
            self.terminal_type = Some(event_type.into());
        }
        let event = HarnessEvent {
            sequence: self.event_count as u64,
            event_type: event_type.into(),
            payload_json,
            terminal,
            execution_id: self.execution_id.clone(),
            stderr: Vec::new(),
        };
        self.event_count = self.event_count.saturating_add(1);
        Ok(event)
    }

    fn finish(&self, exit_code: i32) -> Result<(), Status> {
        if !self.buffer.is_empty() {
            return Err(Status::data_loss("incomplete harness event framing"));
        }
        let terminal_type = self
            .terminal_type
            .as_deref()
            .ok_or_else(|| Status::data_loss("harness terminal event required"))?;
        if exit_code != 0 && terminal_type != "error" {
            return Err(Status::failed_precondition(
                "harness exited unsuccessfully without error event",
            ));
        }
        Ok(())
    }
}

fn harness_event_delimiter(buffer: &[u8]) -> Option<(usize, usize)> {
    for index in 0..buffer.len() {
        if buffer.get(index..index + 2) == Some(b"\n\n") {
            return Some((index, 2));
        }
        if buffer.get(index..index + 4) == Some(b"\r\n\r\n") {
            return Some((index, 4));
        }
    }
    None
}

#[cfg(test)]
fn parse_harness_stdout(
    execution_id: &str,
    frames: Vec<ExecFrame>,
) -> Result<Vec<HarnessEvent>, Status> {
    let mut parser = HarnessParser::new(execution_id);
    let mut events = Vec::new();
    let mut expected_sequence = 0u64;
    let mut exit_code = None;
    for frame in frames {
        if frame.execution_id != execution_id || frame.sequence != expected_sequence {
            return Err(Status::data_loss("invalid harness exec frame sequence"));
        }
        expected_sequence = expected_sequence.saturating_add(1);
        if exit_code.is_some() {
            return Err(Status::data_loss("harness exec frame after exit"));
        }
        events.extend(parser.push(&frame.stdout)?);
        if frame.exited {
            exit_code = Some(frame.exit_code);
        }
    }
    let exit_code = exit_code.ok_or_else(|| Status::data_loss("harness exit frame required"))?;
    parser.finish(exit_code)?;
    Ok(events)
}

fn live_harness_stream(
    executor: Arc<dyn ProcessExecutor>,
    execution_id: String,
    mut frames: FrameStream,
    active: ActiveOperation,
) -> HarnessStream {
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let _active = active;
        let mut parser = HarnessParser::new(&execution_id);
        let mut expected_sequence = 0u64;
        let mut output_sequence = 0u64;
        let mut pending_terminal = None;
        let mut receiver_open = true;
        let mut failure = None;
        let mut exited = false;
        while let Some(result) = frames.next().await {
            let frame = match result {
                Ok(frame) => frame,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            };
            if frame.execution_id != execution_id || frame.sequence != expected_sequence {
                failure = Some(Status::data_loss("invalid harness exec frame sequence"));
                break;
            }
            expected_sequence = expected_sequence.saturating_add(1);
            if exited {
                failure = Some(Status::data_loss("harness exec frame after exit"));
                break;
            }
            if !frame.stderr.is_empty() && receiver_open {
                receiver_open = sender
                    .send(Ok(HarnessEvent {
                        sequence: output_sequence,
                        event_type: "stderr".into(),
                        payload_json: String::new(),
                        terminal: false,
                        execution_id: execution_id.clone(),
                        stderr: frame.stderr.clone(),
                    }))
                    .await
                    .is_ok();
                output_sequence = output_sequence.saturating_add(1);
            }
            match parser.push(&frame.stdout) {
                Ok(events) => {
                    for mut event in events {
                        if event.terminal {
                            pending_terminal = Some(event);
                        } else {
                            event.sequence = output_sequence;
                            output_sequence = output_sequence.saturating_add(1);
                            if receiver_open {
                                receiver_open = sender.send(Ok(event)).await.is_ok();
                            }
                        }
                    }
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
            if frame.exited {
                exited = true;
                if let Err(error) = parser.finish(frame.exit_code) {
                    failure = Some(error);
                    break;
                }
                if let Some(mut event) = pending_terminal.take()
                    && receiver_open
                {
                    event.sequence = output_sequence;
                    receiver_open = sender.send(Ok(event)).await.is_ok();
                }
            }
        }
        if failure.is_none() && !exited {
            failure = Some(Status::data_loss("harness exit frame required"));
        }
        if let Some(error) = failure {
            // Drop the bounded process receiver before cancellation. This lets
            // the host-owned process task detach and continue draining/reaping
            // instead of deadlocking on a full channel while cancel waits.
            drop(frames);
            let _ = executor.cancel(&execution_id).await;
            if receiver_open {
                let _ = sender.send(Err(error)).await;
            }
        }
    });
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(receiver))
}

fn chunk_exec_frames(frames: Vec<ExecFrame>) -> Vec<ExecFrame> {
    let mut output = Vec::new();
    let mut sequence = 0u64;
    for frame in frames {
        let mut stdout = frame.stdout.chunks(EXEC_FRAME_BYTES);
        let mut stderr = frame.stderr.chunks(EXEC_FRAME_BYTES);
        loop {
            let out = stdout.next();
            let err = stderr.next();
            if out.is_none() && err.is_none() {
                break;
            }
            for (stdout, stderr) in [
                (out.unwrap_or_default(), &[][..]),
                (&[][..], err.unwrap_or_default()),
            ] {
                if stdout.is_empty() && stderr.is_empty() {
                    continue;
                }
                output.push(ExecFrame {
                    sequence,
                    stdout: stdout.to_vec(),
                    stderr: stderr.to_vec(),
                    exit_code: 0,
                    exited: false,
                    execution_id: frame.execution_id.clone(),
                });
                sequence = sequence.saturating_add(1);
            }
        }
        if frame.exited {
            output.push(ExecFrame {
                sequence,
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: frame.exit_code,
                exited: true,
                execution_id: frame.execution_id,
            });
            sequence = sequence.saturating_add(1);
        }
    }
    output
}

async fn read_limited<R: AsyncRead + Unpin>(
    mut reader: R,
    max: usize,
    label: &'static str,
) -> Result<Vec<u8>, Status> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|_| Status::internal(label))?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > max {
            return Err(Status::resource_exhausted("exec output exceeds limit"));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

pub type FrameStream = Pin<Box<dyn Stream<Item = Result<ExecFrame, Status>> + Send + 'static>>;
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<BytesFrame, Status>> + Send + 'static>>;
pub type HarnessStream = Pin<Box<dyn Stream<Item = Result<HarnessEvent, Status>> + Send + 'static>>;
pub type TunnelStream = Pin<Box<dyn Stream<Item = Result<TunnelFrame, Status>> + Send + 'static>>;
pub type BrowserStream = Pin<Box<dyn Stream<Item = Result<BrowserFrame, Status>> + Send + 'static>>;
pub type StatsStream = Pin<Box<dyn Stream<Item = Result<StatsFrame, Status>> + Send + 'static>>;

#[async_trait]
pub trait ProcessExecutor: Send + Sync {
    async fn exec(&self, request: ExecRequest) -> Result<Vec<ExecFrame>, Status>;
    async fn exec_stream(&self, request: ExecRequest) -> Result<FrameStream, Status> {
        let frames = chunk_exec_frames(self.exec(request).await?);
        Ok(Box::pin(stream::iter(frames.into_iter().map(Ok))))
    }
    async fn cancel(&self, execution_id: &str) -> Result<bool, Status>;
    async fn wait_idle(&self, _: Duration) -> Result<bool, Status> {
        Ok(true)
    }
}

#[async_trait]
pub trait BrowserBackend: Send + Sync {
    async fn execute(&self, request: BrowserRequest) -> Result<Vec<BrowserFrame>, Status>;
}

struct UnavailableBrowserBackend;

#[async_trait]
impl BrowserBackend for UnavailableBrowserBackend {
    async fn execute(&self, _: BrowserRequest) -> Result<Vec<BrowserFrame>, Status> {
        Err(Status::unimplemented("feature_not_supported"))
    }
}

fn validate_browser_request(request: &BrowserRequest) -> Result<(), Status> {
    if !matches!(
        request.operation.as_str(),
        "create_tab"
            | "list_tabs"
            | "close_tab"
            | "goto"
            | "content"
            | "screenshot"
            | "connect"
            | "screencast"
            | "recording_target"
            | "snapshot"
            | "perform"
    ) {
        return Err(Status::unimplemented("feature_not_supported"));
    }
    let total = request
        .operation
        .len()
        .saturating_add(request.tab_id.len())
        .saturating_add(request.url.len())
        .saturating_add(request.wait_until.len())
        .saturating_add(request.json_payload.len());
    if total > MAX_BROWSER_REQUEST_BYTES {
        return Err(Status::resource_exhausted("browser request exceeds limit"));
    }
    Ok(())
}

fn validate_browser_frames(frames: &[BrowserFrame]) -> Result<(), Status> {
    if frames.is_empty() || frames.len() > MAX_BROWSER_FRAMES {
        return Err(Status::data_loss("invalid browser frame count"));
    }
    let mut total = 0usize;
    for (index, frame) in frames.iter().enumerate() {
        if frame.sequence != index as u64 || frame.eof != (index + 1 == frames.len()) {
            return Err(Status::data_loss("invalid browser frame sequence"));
        }
        if frame.json_payload.len().saturating_add(frame.data.len()) > MAX_BROWSER_FRAME_BYTES {
            return Err(Status::resource_exhausted(
                "browser frame exceeds transport limit",
            ));
        }
        total = total
            .saturating_add(frame.json_payload.len())
            .saturating_add(frame.data.len());
        if total > MAX_BROWSER_RESPONSE_BYTES {
            return Err(Status::resource_exhausted("browser response exceeds limit"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[derive(Default)]
pub struct FakeExecutor {
    pub frames: Mutex<Vec<ExecFrame>>,
    pub cancelled: Mutex<Vec<String>>,
    pub requests: Mutex<Vec<ExecRequest>>,
}
#[cfg(test)]
#[async_trait]
impl ProcessExecutor for FakeExecutor {
    async fn exec(&self, request: ExecRequest) -> Result<Vec<ExecFrame>, Status> {
        self.requests
            .lock()
            .map_err(|_| Status::internal("executor lock"))?
            .push(request);
        Ok(self
            .frames
            .lock()
            .map_err(|_| Status::internal("executor lock"))?
            .clone())
    }
    async fn cancel(&self, id: &str) -> Result<bool, Status> {
        self.cancelled
            .lock()
            .map_err(|_| Status::internal("executor lock"))?
            .push(id.into());
        Ok(true)
    }
}

#[cfg(test)]
pub struct FailingIdleExecutor;
#[cfg(test)]
#[async_trait]
impl ProcessExecutor for FailingIdleExecutor {
    async fn exec(&self, _: ExecRequest) -> Result<Vec<ExecFrame>, Status> {
        Ok(vec![])
    }
    async fn cancel(&self, _: &str) -> Result<bool, Status> {
        Ok(false)
    }
    async fn wait_idle(&self, _: Duration) -> Result<bool, Status> {
        Err(Status::internal("idle probe failed"))
    }
}

/// Capability-based paths implemented with dirfd-relative, no-follow syscalls.
/// A guest may mutate its workspace concurrently; no operation re-resolves a
/// checked pathname from the ambient filesystem.
#[derive(Clone)]
pub struct FileSandbox {
    roots: Vec<Arc<File>>,
}

struct ExecutableSnapshot {
    temp_root: File,
    directory: File,
    name: CString,
    path: String,
}

impl Drop for ExecutableSnapshot {
    fn drop(&mut self) {
        let executable = CString::new("command").expect("constant has no NUL");
        // SAFETY: both descriptors and names are retained, trusted capabilities.
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), executable.as_ptr(), 0);
            libc::unlinkat(
                self.temp_root.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            );
        }
    }
}

impl FileSandbox {
    pub fn new(workspace: PathBuf, home: PathBuf) -> std::io::Result<Self> {
        let mut roots = Vec::new();
        for path in [workspace, home] {
            let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "sandbox root contains NUL",
                )
            })?;
            // SAFETY: path is a live NUL-terminated pathname. O_NOFOLLOW makes
            // validation and descriptor acquisition one atomic kernel step.
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fd is live and metadata points to writable stat storage.
            if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
                let error = std::io::Error::last_os_error();
                // SAFETY: ownership has not yet transferred to File.
                unsafe { libc::close(fd) };
                return Err(error);
            }
            // SAFETY: successful fstat initialized metadata.
            let metadata = unsafe { metadata.assume_init() };
            if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
                // SAFETY: ownership has not yet transferred to File.
                unsafe { libc::close(fd) };
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "sandbox root is not a directory",
                ));
            }
            // SAFETY: successful open returned a uniquely owned descriptor.
            roots.push(Arc::new(unsafe { File::from_raw_fd(fd) }));
        }
        Ok(Self { roots })
    }

    /// Flushes every filesystem represented by the retained sandbox roots.
    ///
    /// Guest commands can write through ordinary POSIX file descriptors rather
    /// than the agent's atomic file API. A directory `fsync` is not sufficient
    /// to persist those file contents before the microVM is stopped, so Linux
    /// guests use `syncfs` on the already validated root capabilities.
    pub fn sync_filesystems(&self) -> Result<(), Status> {
        for root in &self.roots {
            #[cfg(target_os = "linux")]
            // SAFETY: root is a live descriptor owned by this FileSandbox.
            // syncfs neither takes ownership nor dereferences guest memory.
            let result = unsafe { libc::syncfs(root.as_raw_fd()) };

            #[cfg(not(target_os = "linux"))]
            // Host-side tests build the guest crate on non-Linux platforms.
            // fsync keeps that test path meaningful; production guests always
            // take the Linux syncfs branch above.
            // SAFETY: root is a live descriptor owned by this FileSandbox.
            let result = unsafe { libc::fsync(root.as_raw_fd()) };

            if result != 0 {
                return Err(Status::internal("sandbox filesystem sync failed"));
            }
        }
        Ok(())
    }
    fn pieces(raw: &str) -> Result<(Option<usize>, Vec<CString>), Status> {
        if raw.is_empty() || raw.as_bytes().contains(&0) {
            return Err(Status::invalid_argument("invalid path"));
        }
        let path = Path::new(raw);
        let (root, path) = if path.is_absolute() {
            if let Ok(relative) = path.strip_prefix("/workspace") {
                (Some(0), relative)
            } else if let Ok(relative) = path.strip_prefix("/home/boxuser") {
                (Some(1), relative)
            } else {
                return Err(Status::permission_denied("path outside sandbox"));
            }
        } else {
            (None, path)
        };
        let mut out = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => out.push(
                    CString::new(name.as_encoded_bytes())
                        .map_err(|_| Status::invalid_argument("invalid path"))?,
                ),
                Component::CurDir => {}
                _ => return Err(Status::permission_denied("path outside sandbox")),
            }
        }
        if out.is_empty() && root.is_none() {
            return Err(Status::invalid_argument("invalid path"));
        }
        Ok((root, out))
    }
    fn open_dir(fd: i32, name: &CString) -> std::io::Result<OwnedFd> {
        // SAFETY: fd is an owned directory fd and name is NUL-terminated. O_NOFOLLOW
        // prevents traversing a link introduced after a prior component was checked.
        let raw = unsafe {
            libc::openat(
                fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(raw) })
        }
    }
    /// Ensures the pinned SDK default cwd exists without following a guest
    /// controlled link. The directory is created relative to the retained
    /// workspace descriptor and assigned to the unprivileged box user.
    pub fn ensure_sdk_workspace(&self) -> Result<(), Status> {
        let workspace = self
            .roots
            .first()
            .ok_or_else(|| Status::failed_precondition("workspace root is unavailable"))?;
        let name = CString::new("home").expect("constant has no NUL");
        // SAFETY: workspace is a retained directory descriptor and name is a
        // fixed NUL-terminated component. EEXIST is validated with O_NOFOLLOW
        // below, so a preexisting symlink is never accepted.
        let created = unsafe { libc::mkdirat(workspace.as_raw_fd(), name.as_ptr(), 0o755) };
        if created != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(Status::internal("SDK workspace creation failed"));
        }
        let directory = Self::open_dir(workspace.as_raw_fd(), &name)
            .map_err(|_| Status::failed_precondition("SDK workspace is unsafe"))?;
        let (uid, gid) = file_owner_ids()?;
        // SAFETY: directory is the no-follow opened workspace/home descriptor.
        if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0
            || unsafe { libc::fchmod(directory.as_raw_fd(), 0o755) } != 0
        {
            return Err(Status::internal("SDK workspace ownership failed"));
        }
        Ok(())
    }
    fn parent_and_leaf(&self, raw: &str) -> Result<(OwnedFd, CString), Status> {
        let (selected_root, parts) = Self::pieces(raw)?;
        if parts.is_empty() {
            return Err(Status::invalid_argument("path must name a file"));
        }
        let leaf = parts.last().expect("non-empty checked").clone();
        for (index, root) in self.roots.iter().enumerate() {
            if selected_root.is_some_and(|selected| selected != index) {
                continue;
            }
            let mut current: OwnedFd = match root.try_clone() {
                Ok(file) => file.into(),
                Err(_) => continue,
            };
            let mut ok = true;
            for part in &parts[..parts.len() - 1] {
                match Self::open_dir(current.as_raw_fd(), part) {
                    Ok(next) => current = next,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return Ok((current, leaf));
            }
        }
        Err(Status::permission_denied("path outside sandbox"))
    }
    fn open_file(&self, raw: &str) -> Result<File, Status> {
        let (parent, leaf) = self.parent_and_leaf(raw)?;
        // SAFETY: parent is held open and leaf was validated above; no-follow closes
        // the final-component symlink race.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(Status::not_found("file unavailable"));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn snapshot_executable(&self, raw: &str) -> Result<ExecutableSnapshot, Status> {
        if !is_allowed_absolute_harness_command(raw) {
            return Err(Status::permission_denied(
                "absolute executable outside allowed roots",
            ));
        }
        let mut source = self.open_file(raw)?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: source is live and metadata points to writable stat storage.
        if unsafe { libc::fstat(source.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
            return Err(Status::internal("executable metadata failed"));
        }
        // SAFETY: successful fstat initialized metadata.
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_mode & 0o111 == 0
            || metadata.st_size < 0
            || metadata.st_size as u64 > MAX_HARNESS_EXECUTABLE_BYTES
        {
            return Err(Status::permission_denied(
                "harness command is not an executable regular file",
            ));
        }
        #[cfg(target_os = "macos")]
        let temp_path = "/private/tmp";
        #[cfg(not(target_os = "macos"))]
        let temp_path = "/tmp";
        let temp = CString::new(temp_path).expect("constant has no NUL");
        // SAFETY: the platform temp root is fixed and O_NOFOLLOW rejects a
        // replaced root link. macOS /tmp itself is a symlink, so tests use its
        // canonical system-owned /private/tmp target; the production guest is Linux.
        let temp_fd = unsafe {
            libc::open(
                temp.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if temp_fd < 0 {
            return Err(Status::internal("private executable root unavailable"));
        }
        // SAFETY: successful open returned a uniquely owned descriptor.
        let temp_root = unsafe { File::from_raw_fd(temp_fd) };
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| Status::internal("secure randomness unavailable"))?;
        let name = CString::new(format!(".boxd-exec-{:032x}", u128::from_be_bytes(random)))
            .expect("hex name has no NUL");
        // SAFETY: temp_root is retained and name is an unpredictable component.
        if unsafe { libc::mkdirat(temp_root.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(Status::internal(
                "private executable directory creation failed",
            ));
        }
        let directory = match Self::open_dir(temp_root.as_raw_fd(), &name) {
            Ok(directory) => File::from(directory),
            Err(_) => {
                // SAFETY: name was created beneath retained temp_root above.
                unsafe {
                    libc::unlinkat(temp_root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(Status::internal("private executable directory unavailable"));
            }
        };
        let path = format!("{temp_path}/{}/command", name.to_string_lossy());
        let snapshot = ExecutableSnapshot {
            temp_root,
            directory,
            name,
            path,
        };
        let executable = CString::new("command").expect("constant has no NUL");
        // SAFETY: directory and executable are retained/validated; O_EXCL and
        // O_NOFOLLOW prevent replacement.
        let output_fd = unsafe {
            libc::openat(
                snapshot.directory.as_raw_fd(),
                executable.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o500,
            )
        };
        if output_fd < 0 {
            return Err(Status::internal("private executable creation failed"));
        }
        // SAFETY: successful open returned a uniquely owned descriptor.
        let mut output = unsafe { File::from_raw_fd(output_fd) };
        let mut bounded_source =
            std::io::Read::by_ref(&mut source).take(MAX_HARNESS_EXECUTABLE_BYTES + 1);
        let copied = std::io::copy(&mut bounded_source, &mut output)
            .map_err(|_| Status::internal("executable snapshot copy failed"))?;
        if copied != metadata.st_size as u64 || copied > MAX_HARNESS_EXECUTABLE_BYTES {
            return Err(Status::failed_precondition(
                "harness executable changed while snapshotting",
            ));
        }
        output
            .sync_all()
            .map_err(|_| Status::internal("executable snapshot sync failed"))?;
        // The unprivileged child may traverse/read/execute but cannot list or
        // modify this root-owned snapshot. It is unlinked immediately after a
        // successful spawn handshake.
        if unsafe { libc::fchmod(output.as_raw_fd(), 0o555) } != 0
            || unsafe { libc::fchmod(snapshot.directory.as_raw_fd(), 0o711) } != 0
        {
            return Err(Status::internal("executable snapshot permissions failed"));
        }
        Ok(snapshot)
    }
    pub fn read(&self, path: &str) -> Result<Vec<u8>, Status> {
        let file = self.open_file(path)?;
        let size = file
            .metadata()
            .map_err(|_| Status::internal("metadata"))?
            .len();
        if size > MAX_FILE_BYTES as u64 {
            return Err(Status::resource_exhausted("file exceeds agent limit"));
        }
        let mut bytes = Vec::with_capacity(size as usize);
        file.take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Status::internal("read failed"))?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Status::resource_exhausted("file exceeds agent limit"));
        }
        Ok(bytes)
    }
    pub fn list(&self, path: &str) -> Result<Vec<FileEntry>, Status> {
        let (selected_root, parts) = Self::pieces(path)?;
        if parts.is_empty() {
            let root = selected_root
                .and_then(|index| self.roots.get(index))
                .ok_or_else(|| Status::permission_denied("path outside sandbox"))?;
            let directory = root
                .try_clone()
                .map_err(|_| Status::internal("directory clone failed"))?;
            return list_directory(&directory);
        }
        let (parent, leaf) = self.parent_and_leaf(path)?;
        let dir = Self::open_dir(parent.as_raw_fd(), &leaf)
            .map_err(|_| Status::not_found("directory unavailable"))?;
        list_directory(&File::from(dir))
    }
    pub fn atomic_write(&self, path: &str, data: &[u8]) -> Result<(), Status> {
        if data.len() > MAX_FILE_BYTES {
            return Err(Status::resource_exhausted("file exceeds agent limit"));
        }
        let (parent, leaf) = self.parent_and_leaf(path)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| Status::internal("secure randomness unavailable"))?;
        let temp = CString::new(format!(".boxd-write-{:x}", u128::from_be_bytes(random)))
            .expect("constant string");
        // SAFETY: parent is owned and temp/leaf are validated C strings. O_EXCL and
        // O_NOFOLLOW prevent link following and replacement of another temporary file.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(Status::internal("atomic write setup failed"));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let (uid, gid) = file_owner_ids()?;
        let result = (|| -> std::io::Result<()> {
            // SAFETY: file is the newly created, still-unlinked-by-name temp
            // file owned by this agent; uid/gid identify the guest boxuser.
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            file.write_all(data)?;
            file.sync_all()?;
            std::mem::drop(file);
            let rc = unsafe {
                libc::renameat(
                    parent.as_raw_fd(),
                    temp.as_ptr(),
                    parent.as_raw_fd(),
                    leaf.as_ptr(),
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let rc = unsafe { libc::fsync(parent.as_raw_fd()) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(parent.as_raw_fd(), temp.as_ptr(), 0);
            }
        }
        result.map_err(|_| Status::internal("atomic write failed"))
    }
    fn ensure_owned_dir(
        parent: i32,
        name: &CString,
        mode: libc::mode_t,
    ) -> Result<OwnedFd, Status> {
        // SAFETY: parent is retained and name is a validated single component.
        let created = unsafe { libc::mkdirat(parent, name.as_ptr(), mode) };
        if created != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(Status::internal("skill directory creation failed"));
        }
        let directory = Self::open_dir(parent, name)
            .map_err(|_| Status::failed_precondition("skill directory is unsafe"))?;
        let (uid, gid) = file_owner_ids()?;
        // SAFETY: directory is the no-follow opened directory created or verified above.
        if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0
            || unsafe { libc::fchmod(directory.as_raw_fd(), mode) } != 0
        {
            return Err(Status::internal("skill directory ownership failed"));
        }
        Ok(directory)
    }
    fn remove_tree_at(parent: i32, name: &CString) -> Result<bool, Status> {
        let directory = match Self::open_dir(parent, name) {
            Ok(directory) => File::from(directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => {
                // A guest may replace an installed entry with a symlink or regular file.
                // unlinkat removes that final component without following it.
                let result = unsafe { libc::unlinkat(parent, name.as_ptr(), 0) };
                if result == 0 {
                    return Ok(true);
                }
                return Err(Status::failed_precondition(
                    "installed skill path is unsafe",
                ));
            }
        };
        for entry in list_directory(&directory)? {
            let child = CString::new(entry.path.as_bytes())
                .map_err(|_| Status::internal("invalid installed skill entry"))?;
            if entry.directory {
                Self::remove_tree_at(directory.as_raw_fd(), &child)?;
            } else if unsafe { libc::unlinkat(directory.as_raw_fd(), child.as_ptr(), 0) } != 0 {
                return Err(Status::internal("installed skill file removal failed"));
            }
        }
        directory
            .sync_all()
            .map_err(|_| Status::internal("installed skill sync failed"))?;
        drop(directory);
        if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(Status::internal("installed skill directory removal failed"));
        }
        Ok(true)
    }
    pub fn install_skill(&self, name: &str, files: &[SkillFile]) -> Result<bool, Status> {
        validate_skill_name(name)?;
        if files.is_empty() || files.len() > MAX_SKILL_FILES {
            return Err(Status::resource_exhausted("skill file count exceeds limit"));
        }
        let mut seen = HashSet::new();
        let mut total = 0usize;
        let validated = files
            .iter()
            .map(|file| {
                total = total
                    .checked_add(file.content.len())
                    .ok_or_else(|| Status::resource_exhausted("skill size overflow"))?;
                if total > MAX_SKILL_BYTES || !seen.insert(file.path.clone()) {
                    return Err(Status::resource_exhausted(
                        "skill content exceeds limit or contains duplicate paths",
                    ));
                }
                Ok((skill_file_pieces(&file.path)?, file))
            })
            .collect::<Result<Vec<_>, Status>>()?;
        if !seen.contains("SKILL.md") {
            return Err(Status::invalid_argument("skill package requires SKILL.md"));
        }
        let home = self
            .roots
            .get(1)
            .ok_or_else(|| Status::failed_precondition("home root is unavailable"))?;
        let agents = Self::ensure_owned_dir(
            home.as_raw_fd(),
            &CString::new(".agents").expect("constant"),
            0o755,
        )?;
        let skills = Self::ensure_owned_dir(
            agents.as_raw_fd(),
            &CString::new("skills").expect("constant"),
            0o755,
        )?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| Status::internal("secure randomness unavailable"))?;
        let suffix = format!("{:032x}", u128::from_be_bytes(random));
        let staging_name = CString::new(format!(".boxd-install-{suffix}")).expect("hex name");
        let backup_name = CString::new(format!(".boxd-backup-{suffix}")).expect("hex name");
        let target_name = CString::new(name).map_err(|_| Status::invalid_argument("skill name"))?;
        let staging = Self::ensure_owned_dir(skills.as_raw_fd(), &staging_name, 0o755)?;
        let install_result = (|| -> Result<(), Status> {
            for (pieces, source) in &validated {
                let mut directory = staging
                    .try_clone()
                    .map_err(|_| Status::internal("skill staging clone failed"))?;
                for piece in &pieces[..pieces.len() - 1] {
                    directory = Self::ensure_owned_dir(directory.as_raw_fd(), piece, 0o755)?;
                }
                let leaf = pieces.last().expect("validated non-empty path");
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        leaf.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_CLOEXEC
                            | libc::O_NOFOLLOW,
                        0o644,
                    )
                };
                if fd < 0 {
                    return Err(Status::internal("skill file creation failed"));
                }
                let mut output = unsafe { File::from_raw_fd(fd) };
                let (uid, gid) = file_owner_ids()?;
                if unsafe { libc::fchown(output.as_raw_fd(), uid, gid) } != 0 {
                    return Err(Status::internal("skill file ownership failed"));
                }
                output
                    .write_all(&source.content)
                    .and_then(|_| output.sync_all())
                    .map_err(|_| Status::internal("skill file write failed"))?;
            }
            if unsafe { libc::fsync(staging.as_raw_fd()) } != 0 {
                return Err(Status::internal("skill staging sync failed"));
            }
            let had_target = match Self::open_dir(skills.as_raw_fd(), &target_name) {
                Ok(directory) => {
                    drop(directory);
                    if unsafe {
                        libc::renameat(
                            skills.as_raw_fd(),
                            target_name.as_ptr(),
                            skills.as_raw_fd(),
                            backup_name.as_ptr(),
                        )
                    } != 0
                    {
                        return Err(Status::internal("existing skill backup failed"));
                    }
                    true
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(_) => return Err(Status::failed_precondition("existing skill path is unsafe")),
            };
            if unsafe {
                libc::renameat(
                    skills.as_raw_fd(),
                    staging_name.as_ptr(),
                    skills.as_raw_fd(),
                    target_name.as_ptr(),
                )
            } != 0
            {
                if had_target {
                    unsafe {
                        libc::renameat(
                            skills.as_raw_fd(),
                            backup_name.as_ptr(),
                            skills.as_raw_fd(),
                            target_name.as_ptr(),
                        );
                    }
                }
                return Err(Status::internal("skill publish failed"));
            }
            if unsafe { libc::fsync(skills.as_raw_fd()) } != 0 {
                return Err(Status::internal("skill publish sync failed"));
            }
            if had_target {
                Self::remove_tree_at(skills.as_raw_fd(), &backup_name)?;
            }
            Ok(())
        })();
        drop(staging);
        if install_result.is_err() {
            let _ = Self::remove_tree_at(skills.as_raw_fd(), &staging_name);
        }
        install_result.map(|_| true)
    }
    pub fn remove_skill(&self, name: &str) -> Result<bool, Status> {
        validate_skill_name(name)?;
        let home = self
            .roots
            .get(1)
            .ok_or_else(|| Status::failed_precondition("home root is unavailable"))?;
        let agents = match Self::open_dir(
            home.as_raw_fd(),
            &CString::new(".agents").expect("constant"),
        ) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(Status::failed_precondition("skills root is unsafe")),
        };
        let skills = match Self::open_dir(
            agents.as_raw_fd(),
            &CString::new("skills").expect("constant"),
        ) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(Status::failed_precondition("skills root is unsafe")),
        };
        Self::remove_tree_at(
            skills.as_raw_fd(),
            &CString::new(name).map_err(|_| Status::invalid_argument("skill name"))?,
        )
    }
    pub fn cwd_fd(&self, path: &str) -> Result<OwnedFd, Status> {
        let (selected_root, parts) = Self::pieces(path)?;
        for (index, root) in self.roots.iter().enumerate() {
            if selected_root.is_some_and(|selected| selected != index) {
                continue;
            }
            let mut current: OwnedFd = match root.try_clone() {
                Ok(file) => file.into(),
                Err(_) => continue,
            };
            let mut ok = true;
            for part in &parts {
                match Self::open_dir(current.as_raw_fd(), part) {
                    Ok(next) => current = next,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return Ok(current);
            }
        }
        Err(Status::permission_denied("cwd outside sandbox"))
    }
}

fn list_directory(directory: &File) -> Result<Vec<FileEntry>, Status> {
    let current = CString::new(".").expect("constant path has no NUL");
    // SAFETY: openat uses the retained directory only as an anchor and returns
    // a fresh open-file description with its own directory offset. This is
    // required for concurrent listings; dup would share the OFD offset.
    let duplicate = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            current.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if duplicate < 0 {
        return Err(Status::internal("directory clone failed"));
    }
    // SAFETY: duplicate is a live directory descriptor and ownership transfers.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not take ownership on failure.
        unsafe { libc::close(duplicate) };
        return Err(Status::internal("directory read failed"));
    }
    let mut out = Vec::new();
    loop {
        #[cfg(target_os = "macos")]
        // SAFETY: __error returns this thread's errno storage.
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(target_os = "linux")]
        // SAFETY: __errno_location returns this thread's errno storage.
        unsafe {
            *libc::__errno_location() = 0;
        }
        // SAFETY: stream remains live until closed after iteration.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            #[cfg(target_os = "macos")]
            // SAFETY: __error returns this thread's errno storage.
            let read_error = unsafe { *libc::__error() };
            #[cfg(target_os = "linux")]
            // SAFETY: __errno_location returns this thread's errno storage.
            let read_error = unsafe { *libc::__errno_location() };
            if read_error != 0 {
                // SAFETY: stream is live and owns only duplicate.
                unsafe { libc::closedir(stream) };
                return Err(Status::internal("directory iteration failed"));
            }
            break;
        }
        // SAFETY: d_name is NUL-terminated within the returned dirent.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        // SAFETY: stat storage is initialized by successful fstatat and neither
        // descriptor nor name is retained by the syscall.
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            // SAFETY: stream owns only the duplicated descriptor.
            unsafe { libc::closedir(stream) };
            return Err(Status::internal("metadata failed"));
        }
        // SAFETY: fstatat succeeded and initialized the structure.
        let metadata = unsafe { metadata.assume_init() };
        out.push(FileEntry {
            path: name.to_string_lossy().into_owned(),
            directory: metadata.st_mode & libc::S_IFMT == libc::S_IFDIR,
            size: u64::try_from(metadata.st_size).unwrap_or(0),
            modified_at_unix_millis: metadata
                .st_mtime
                .saturating_mul(1_000)
                .saturating_add(metadata.st_mtime_nsec / 1_000_000),
        });
    }
    // SAFETY: stream is live and owns only duplicate.
    unsafe { libc::closedir(stream) };
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

#[derive(Clone)]
pub struct UnixProcessExecutor {
    sandbox: FileSandbox,
    processes: Arc<Mutex<ProcessRegistry>>,
    idle: Arc<Notify>,
    grace: Duration,
    #[cfg(unix)]
    identity: fn() -> Result<UserIdentity, Status>,
    #[cfg(unix)]
    drop_privileges: bool,
}

#[derive(Default)]
struct ProcessRegistry {
    starting: HashSet<String>,
    running: HashMap<String, i32>,
    completed: HashMap<String, CompletedExecution>,
    completed_order: VecDeque<String>,
    completed_bytes: usize,
}

struct CompletedExecution {
    request: ExecRequest,
    frames: Vec<ExecFrame>,
    bytes: usize,
}

impl ProcessRegistry {
    fn is_idle(&self) -> bool {
        self.starting.is_empty() && self.running.is_empty()
    }

    fn replay(&self, id: &str, request: &ExecRequest) -> Result<Option<Vec<ExecFrame>>, Status> {
        let Some(completed) = self.completed.get(id) else {
            return Ok(None);
        };
        if completed.request != *request {
            return Err(Status::already_exists(
                "execution id was completed with a different request",
            ));
        }
        Ok(Some(completed.frames.clone()))
    }

    fn record(&mut self, id: String, request: ExecRequest, frames: Vec<ExecFrame>) {
        let bytes = frames.iter().fold(0usize, |total, frame| {
            total
                .saturating_add(frame.stdout.len())
                .saturating_add(frame.stderr.len())
                .saturating_add(frame.execution_id.len())
        });
        if bytes > MAX_COMPLETED_EXECUTION_BYTES {
            return;
        }
        while self.completed.len() >= MAX_COMPLETED_EXECUTIONS
            || self.completed_bytes.saturating_add(bytes) > MAX_COMPLETED_EXECUTION_BYTES
        {
            let Some(oldest) = self.completed_order.pop_front() else {
                break;
            };
            if let Some(removed) = self.completed.remove(&oldest) {
                self.completed_bytes = self.completed_bytes.saturating_sub(removed.bytes);
            }
        }
        self.completed_bytes = self.completed_bytes.saturating_add(bytes);
        self.completed_order.push_back(id.clone());
        self.completed.insert(
            id,
            CompletedExecution {
                request,
                frames,
                bytes,
            },
        );
    }
}

#[cfg(unix)]
struct StartReservation {
    id: String,
    registry: Arc<Mutex<ProcessRegistry>>,
    idle: Arc<Notify>,
    armed: bool,
}

#[cfg(unix)]
impl StartReservation {
    fn finish(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for StartReservation {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut registry) = self.registry.lock() {
                registry.starting.remove(&self.id);
            }
            self.idle.notify_waiters();
        }
    }
}

#[cfg(unix)]
struct RunningProcessGuard {
    id: String,
    pgid: i32,
    registry: Arc<Mutex<ProcessRegistry>>,
    idle: Arc<Notify>,
    armed: bool,
}

#[cfg(unix)]
impl RunningProcessGuard {
    fn finish(&mut self) -> Result<(), Status> {
        self.registry
            .lock()
            .map_err(|_| Status::internal("process registry lock"))?
            .running
            .remove(&self.id);
        self.idle.notify_waiters();
        self.armed = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for RunningProcessGuard {
    fn drop(&mut self) {
        if self.armed {
            // SAFETY: guards are constructed only for a positive spawned child pid.
            unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
            let id = self.id.clone();
            let pgid = self.pgid;
            let registry = Arc::clone(&self.registry);
            let idle = Arc::clone(&self.idle);
            // A dropped async exec future no longer owns a Tokio Child that can
            // be awaited. Keep the registry entry until a dedicated reaper has
            // observed waitpid, so quiesce/wait_idle never mistakes kill-sent
            // for child-reaped.
            std::thread::spawn(move || {
                let mut status = 0;
                loop {
                    // SAFETY: pgid is also the direct child pid returned by spawn.
                    let result = unsafe { libc::waitpid(pgid, &mut status, 0) };
                    if result == pgid
                        || (result < 0
                            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
                    {
                        break;
                    }
                    if result < 0
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                    {
                        break;
                    }
                }
                if let Ok(mut registry) = registry.lock() {
                    registry.running.remove(&id);
                }
                idle.notify_waiters();
            });
        }
    }
}
impl UnixProcessExecutor {
    pub fn new(sandbox: FileSandbox) -> Self {
        Self {
            sandbox,
            processes: Arc::new(Mutex::new(ProcessRegistry::default())),
            idle: Arc::new(Notify::new()),
            grace: Duration::from_secs(2),
            #[cfg(unix)]
            identity: boxuser_identity,
            #[cfg(unix)]
            drop_privileges: true,
        }
    }

    #[cfg(all(test, unix))]
    fn new_for_current_user(sandbox: FileSandbox) -> Self {
        Self {
            sandbox,
            processes: Arc::new(Mutex::new(ProcessRegistry::default())),
            idle: Arc::new(Notify::new()),
            grace: Duration::from_secs(2),
            identity: current_user_identity,
            drop_privileges: false,
        }
    }
    fn execution_id(requested: &str) -> Result<String, Status> {
        if !requested.is_empty() {
            if requested.len() > 128
                || !requested
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(Status::invalid_argument("invalid execution id"));
            }
            return Ok(requested.into());
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| Status::internal("secure randomness unavailable"))?;
        Ok(format!("exec-{:x}", u128::from_be_bytes(random)))
    }

    /// Serves one authenticated host tunnel as an interactive guest shell.
    /// The TCP listener itself is guest-loopback only; the host reaches it
    /// exclusively through the boot-nonce-authenticated `Dial` RPC.
    #[cfg(unix)]
    pub async fn serve_terminal(&self, socket: TcpStream) -> Result<(), Status> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| Status::internal("secure randomness unavailable"))?;
        let id = format!("terminal-{:x}", u128::from_be_bytes(random));
        let cwd = self.sandbox.cwd_fd("/workspace/home")?;
        let identity = (self.identity)()?;
        let uid = identity.uid;
        let gid = identity.gid;
        let groups = identity.groups;
        #[cfg(target_os = "macos")]
        let group_count = i32::try_from(groups.len())
            .map_err(|_| Status::failed_precondition("boxuser has too many groups"))?;
        {
            let mut registry = self
                .processes
                .lock()
                .map_err(|_| Status::internal("process registry lock"))?;
            registry.starting.insert(id.clone());
        }
        let mut reservation = StartReservation {
            id: id.clone(),
            registry: self.processes.clone(),
            idle: self.idle.clone(),
            armed: true,
        };

        let socket = socket
            .into_std()
            .map_err(|_| Status::internal("terminal socket conversion failed"))?;
        socket
            .set_nonblocking(false)
            .map_err(|_| Status::internal("terminal socket configuration failed"))?;
        let stdin = socket
            .try_clone()
            .map_err(|_| Status::internal("terminal input clone failed"))?;
        let stdout = socket
            .try_clone()
            .map_err(|_| Status::internal("terminal output clone failed"))?;
        let stderr = socket;
        // SAFETY: each `into_raw_fd` transfers one independently owned cloned
        // socket descriptor to `File`, which then transfers it to `Stdio`.
        let stdin = unsafe { File::from_raw_fd(stdin.into_raw_fd()) };
        let stdout = unsafe { File::from_raw_fd(stdout.into_raw_fd()) };
        let stderr = unsafe { File::from_raw_fd(stderr.into_raw_fd()) };
        let mut command = Command::new("/bin/sh");
        command
            .arg("-s")
            .kill_on_drop(true)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("LANG", "C.UTF-8")
            .env("HOME", "/home/boxuser")
            .env("USER", "boxuser")
            .stdin(std::process::Stdio::from(stdin))
            .stdout(std::process::Stdio::from(stdout))
            .stderr(std::process::Stdio::from(stderr));
        let drop_privileges = self.drop_privileges;
        unsafe {
            // SAFETY: all identity/group storage and cwd descriptor are owned
            // before fork; the closure invokes only allocation-free syscalls.
            command.pre_exec(move || {
                if libc::fchdir(cwd.as_raw_fd()) != 0 || libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if drop_privileges {
                    #[cfg(target_os = "macos")]
                    let setgroups_result = libc::setgroups(group_count, groups.as_ptr());
                    #[cfg(not(target_os = "macos"))]
                    let setgroups_result = libc::setgroups(groups.len(), groups.as_ptr());
                    if setgroups_result != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| Status::internal("terminal shell spawn failed"))?;
        let Some(pgid) = child.id().and_then(|pid| i32::try_from(pid).ok()) else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(Status::internal("terminal shell pid unavailable"));
        };
        {
            let mut registry = self
                .processes
                .lock()
                .map_err(|_| Status::internal("process registry lock"))?;
            registry.starting.remove(&id);
            registry.running.insert(id.clone(), pgid);
        }
        reservation.finish();
        let mut guard = RunningProcessGuard {
            id,
            pgid,
            registry: self.processes.clone(),
            idle: self.idle.clone(),
            armed: true,
        };
        let result = loop {
            match child.try_wait() {
                Ok(Some(_)) => break Ok(()),
                Ok(None) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(_) => break Err(Status::internal("terminal shell wait failed")),
            }
        };
        if result.is_err() {
            // SAFETY: pgid is a positive child pid registered after spawn.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
            let _ = child.wait().await;
        }
        guard.finish()?;
        result
    }

    #[cfg(unix)]
    async fn exec_streaming(&self, request: ExecRequest) -> Result<FrameStream, Status> {
        validate_exec_request(&request)?;
        if request.argv[0].is_empty() {
            return Err(Status::invalid_argument("argv must not be empty"));
        }
        let id = Self::execution_id(&request.execution_id)?;
        if let Some(frames) = self
            .processes
            .lock()
            .map_err(|_| Status::internal("process registry lock"))?
            .replay(&id, &request)?
        {
            return Ok(Box::pin(stream::iter(frames.into_iter().map(Ok))));
        }
        let cwd = if request.cwd.is_empty() {
            None
        } else {
            Some(self.sandbox.cwd_fd(&request.cwd)?)
        };
        let identity = (self.identity)()?;
        let uid = identity.uid;
        let gid = identity.gid;
        let groups = identity.groups;
        #[cfg(target_os = "macos")]
        let group_count = i32::try_from(groups.len())
            .map_err(|_| Status::failed_precondition("boxuser has too many groups"))?;
        validate_environment(&request.environment)?;
        {
            let mut registry = self
                .processes
                .lock()
                .map_err(|_| Status::internal("process registry lock"))?;
            if registry.starting.contains(&id) || registry.running.contains_key(&id) {
                return Err(Status::already_exists("execution id already active"));
            }
            registry.starting.insert(id.clone());
        }
        let mut reservation = StartReservation {
            id: id.clone(),
            registry: self.processes.clone(),
            idle: self.idle.clone(),
            armed: true,
        };
        let executable_snapshot = if is_allowed_absolute_harness_command(&request.argv[0]) {
            Some(self.sandbox.snapshot_executable(&request.argv[0])?)
        } else {
            None
        };
        let program = executable_snapshot
            .as_ref()
            .map(|snapshot| snapshot.path.clone())
            .unwrap_or_else(|| request.argv[0].clone());
        let mut command = Command::new(program);
        command
            .kill_on_drop(true)
            .env_clear()
            .envs(&request.environment)
            .args(&request.argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("LANG", "C.UTF-8")
            .env("HOME", "/home/boxuser")
            .env("USER", "boxuser");
        let drop_privileges = self.drop_privileges;
        unsafe {
            // SAFETY: the closure captures only owned descriptors and
            // preallocated numeric identity data. It invokes only syscalls in
            // the post-fork window and performs no allocation or NSS lookup.
            command.pre_exec(move || {
                if let Some(cwd) = &cwd
                    && libc::fchdir(cwd.as_raw_fd()) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if drop_privileges {
                    #[cfg(target_os = "macos")]
                    let setgroups_result = libc::setgroups(group_count, groups.as_ptr());
                    #[cfg(not(target_os = "macos"))]
                    let setgroups_result = libc::setgroups(groups.len(), groups.as_ptr());
                    if setgroups_result != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let spawned = command.spawn();
        let mut child = spawned.map_err(|_| Status::internal("exec spawn failed"))?;
        let Some(pgid) = child.id().and_then(|pid| i32::try_from(pid).ok()) else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(Status::internal("missing child pid"));
        };
        if pgid <= 0 {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(Status::internal("invalid child pid"));
        }
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Status::internal("stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Status::internal("stderr unavailable"))?;
        let stdout = match blocking_process_pipe(&stdout) {
            Ok(file) => file,
            Err(error) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
        };
        let stderr = match blocking_process_pipe(&stderr) {
            Ok(file) => file,
            Err(error) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
        };
        {
            let mut registry = self
                .processes
                .lock()
                .map_err(|_| Status::internal("process registry lock"))?;
            registry.starting.remove(&id);
            registry.running.insert(id.clone(), pgid);
        }
        reservation.finish();
        let mut running_guard = RunningProcessGuard {
            id: id.clone(),
            pgid,
            registry: self.processes.clone(),
            idle: self.idle.clone(),
            armed: true,
        };
        let max = usize::try_from(request.max_output_bytes)
            .ok()
            .filter(|value| *value > 0)
            .unwrap_or(MAX_EXEC_OUTPUT)
            .min(MAX_EXEC_OUTPUT);
        let timeout = Duration::from_millis(request.timeout_ms.clamp(1, MAX_EXEC_TIMEOUT_MS));
        let completed_request = request.clone();
        let completed_registry = self.processes.clone();
        let (frame_tx, frame_rx) = tokio::sync::mpsc::channel(16);
        let (pipe_tx, mut pipe_rx) = tokio::sync::mpsc::channel(16);
        std::thread::spawn({
            let pipe_tx = pipe_tx.clone();
            move || forward_process_pipe(stdout, true, pipe_tx)
        });
        std::thread::spawn(move || forward_process_pipe(stderr, false, pipe_tx));
        tokio::spawn(async move {
            // Keep the protected linked snapshot alive until the interpreter or
            // executable has fully exited. This is required for script
            // interpreters that reopen argv[0] after the spawn handshake.
            let _executable_snapshot = executable_snapshot;
            let deadline = tokio::time::Instant::now() + timeout;
            let mut sequence = 0u64;
            let mut stdout_bytes = 0usize;
            let mut stderr_bytes = 0usize;
            let mut stdout_done = false;
            let mut stderr_done = false;
            let mut status = None;
            let mut receiver_open = true;
            let mut failure = None;
            let mut completed_frames = Vec::new();
            while failure.is_none() && (status.is_none() || !stdout_done || !stderr_done) {
                if status.is_none() {
                    match child.try_wait() {
                        Ok(Some(value)) => status = Some(value),
                        Ok(None) if tokio::time::Instant::now() >= deadline => {
                            failure = Some(Status::deadline_exceeded("exec timed out"));
                            continue;
                        }
                        Ok(None) => {}
                        Err(_) => {
                            failure = Some(Status::internal("exec wait failed"));
                            continue;
                        }
                    }
                }
                if status.is_some() && stdout_done && stderr_done {
                    break;
                }
                tokio::select! {
                    message = pipe_rx.recv(), if !stdout_done || !stderr_done => {
                        match message {
                            Some(ProcessPipe::Stdout(bytes)) => {
                                stdout_bytes = stdout_bytes.saturating_add(bytes.len());
                                if stdout_bytes > max {
                                    failure = Some(Status::resource_exhausted("exec output exceeds limit"));
                                } else {
                                    let frame = ExecFrame {
                                        sequence,
                                        stdout: bytes,
                                        stderr: Vec::new(),
                                        exit_code: 0,
                                        exited: false,
                                        execution_id: id.clone(),
                                    };
                                    completed_frames.push(frame.clone());
                                    if receiver_open {
                                        receiver_open = frame_tx.send(Ok(frame)).await.is_ok();
                                    }
                                    sequence = sequence.saturating_add(1);
                                }
                            }
                            Some(ProcessPipe::Stderr(bytes)) => {
                                stderr_bytes = stderr_bytes.saturating_add(bytes.len());
                                if stderr_bytes > max {
                                    failure = Some(Status::resource_exhausted("exec output exceeds limit"));
                                } else {
                                    let frame = ExecFrame {
                                        sequence,
                                        stdout: Vec::new(),
                                        stderr: bytes,
                                        exit_code: 0,
                                        exited: false,
                                        execution_id: id.clone(),
                                    };
                                    completed_frames.push(frame.clone());
                                    if receiver_open {
                                        receiver_open = frame_tx.send(Ok(frame)).await.is_ok();
                                    }
                                    sequence = sequence.saturating_add(1);
                                }
                            }
                            Some(ProcessPipe::StdoutEof) => stdout_done = true,
                            Some(ProcessPipe::StderrEof) => stderr_done = true,
                            Some(ProcessPipe::Error(error)) => failure = Some(error),
                            None => {
                                stdout_done = true;
                                stderr_done = true;
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(2)), if status.is_none() => {}
                }
            }
            if let Some(error) = failure {
                // SAFETY: pgid is a positive direct child pid registered after spawn.
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
                let _ = child.wait().await;
                let _ = running_guard.finish();
                if receiver_open {
                    let _ = frame_tx.send(Err(error)).await;
                }
                return;
            }
            let status = status.expect("loop exits only after child status");
            let terminal = ExecFrame {
                sequence,
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: status.code().unwrap_or(-1),
                exited: true,
                execution_id: id.clone(),
            };
            completed_frames.push(terminal.clone());
            if receiver_open {
                let _ = frame_tx.send(Ok(terminal)).await;
            }
            let _ = running_guard.finish();
            if let Ok(mut registry) = completed_registry.lock() {
                registry.record(id, completed_request, completed_frames);
            }
        });
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(
            frame_rx,
        )))
    }
}

#[cfg(unix)]
enum ProcessPipe {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    StdoutEof,
    StderrEof,
    Error(Status),
}

#[cfg(unix)]
fn blocking_process_pipe(pipe: &impl AsRawFd) -> Result<File, Status> {
    // SAFETY: pipe is a live child pipe descriptor; dup creates an independently
    // owned descriptor referring to the same pipe endpoint.
    let descriptor = unsafe { libc::dup(pipe.as_raw_fd()) };
    if descriptor < 0 {
        return Err(Status::internal("process pipe duplication failed"));
    }
    // Tokio configures child pipes as nonblocking. Dedicated reader threads use
    // blocking reads and forward bounded chunks to the async process supervisor.
    // SAFETY: descriptor is live and fcntl does not retain pointers.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0
    {
        // SAFETY: ownership has not transferred to File on this failure path.
        unsafe { libc::close(descriptor) };
        return Err(Status::internal("process pipe configuration failed"));
    }
    // SAFETY: dup returned a uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn forward_process_pipe(
    mut reader: File,
    stdout: bool,
    sender: tokio::sync::mpsc::Sender<ProcessPipe>,
) {
    let mut buffer = vec![0u8; EXEC_FRAME_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = sender.blocking_send(if stdout {
                    ProcessPipe::StdoutEof
                } else {
                    ProcessPipe::StderrEof
                });
                return;
            }
            Ok(read) => {
                let message = if stdout {
                    ProcessPipe::Stdout(buffer[..read].to_vec())
                } else {
                    ProcessPipe::Stderr(buffer[..read].to_vec())
                };
                if sender.blocking_send(message).is_err() {
                    return;
                }
            }
            Err(_) => {
                let _ = sender.blocking_send(ProcessPipe::Error(Status::internal(if stdout {
                    "stdout read failed"
                } else {
                    "stderr read failed"
                })));
                return;
            }
        }
    }
}
#[cfg(unix)]
struct UserIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

#[cfg(all(unix, target_os = "macos"))]
fn supplementary_groups(name: &CString, gid: libc::gid_t) -> Result<Vec<libc::gid_t>, Status> {
    let base_gid =
        i32::try_from(gid).map_err(|_| Status::failed_precondition("boxuser gid is invalid"))?;
    let mut count: libc::c_int = 16;
    let mut raw = vec![base_gid; count as usize];
    loop {
        let mut required = count;
        // SAFETY: the C string and writable group array remain live for the call.
        let found =
            unsafe { libc::getgrouplist(name.as_ptr(), base_gid, raw.as_mut_ptr(), &mut required) };
        if found >= 0 {
            raw.truncate(
                usize::try_from(required)
                    .map_err(|_| Status::failed_precondition("boxuser groups are invalid"))?,
            );
            return raw
                .into_iter()
                .map(|group| {
                    libc::gid_t::try_from(group)
                        .map_err(|_| Status::failed_precondition("boxuser group is invalid"))
                })
                .collect();
        }
        let required = usize::try_from(required)
            .ok()
            .filter(|required| *required > raw.len())
            .ok_or_else(|| Status::failed_precondition("boxuser groups are invalid"))?;
        raw.resize(required, base_gid);
        count = i32::try_from(required)
            .map_err(|_| Status::failed_precondition("boxuser has too many groups"))?;
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn supplementary_groups(name: &CString, gid: libc::gid_t) -> Result<Vec<libc::gid_t>, Status> {
    let mut count: libc::c_int = 16;
    let mut groups = vec![gid; count as usize];
    loop {
        let mut required = count;
        // SAFETY: the C string and writable group array remain live for the call.
        let found =
            unsafe { libc::getgrouplist(name.as_ptr(), gid, groups.as_mut_ptr(), &mut required) };
        if found >= 0 {
            groups.truncate(
                usize::try_from(required)
                    .map_err(|_| Status::failed_precondition("boxuser groups are invalid"))?,
            );
            return Ok(groups);
        }
        let required = usize::try_from(required)
            .ok()
            .filter(|required| *required > groups.len())
            .ok_or_else(|| Status::failed_precondition("boxuser groups are invalid"))?;
        groups.resize(required, gid);
        count = i32::try_from(required)
            .map_err(|_| Status::failed_precondition("boxuser has too many groups"))?;
    }
}

#[cfg(unix)]
fn boxuser_identity() -> Result<UserIdentity, Status> {
    let name = CString::new("boxuser").expect("constant user name has no NUL");
    // NSS implementations may use shared process state. Resolve the complete
    // identity in the parent with the reentrant API, before `Command::spawn`
    // forks and enters the async-signal-safe-only pre-exec window.
    // SAFETY: sysconf reads an immutable process configuration value and has
    // no pointer or lifetime preconditions.
    let configured = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let buffer_len = usize::try_from(configured)
        .ok()
        .filter(|length| *length > 0)
        .unwrap_or(16 * 1024)
        .clamp(1024, 1024 * 1024);
    let mut buffer = vec![0_u8; buffer_len];
    // SAFETY: zero is a valid initial bit pattern for `passwd`; getpwnam_r
    // initializes it before the result pointer is consumed.
    let mut password: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    // SAFETY: all pointers refer to live, correctly sized writable storage for
    // the duration of this reentrant lookup.
    let lookup = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut password,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if lookup != 0 || result.is_null() {
        return Err(Status::failed_precondition("boxuser is required"));
    }
    let groups = supplementary_groups(&name, password.pw_gid)?;
    Ok(UserIdentity {
        uid: password.pw_uid,
        gid: password.pw_gid,
        groups,
    })
}

#[cfg(all(test, unix))]
fn current_user_identity() -> Result<UserIdentity, Status> {
    // SAFETY: these no-argument identity queries have no preconditions.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    Ok(UserIdentity {
        uid,
        gid,
        groups: vec![gid],
    })
}

#[cfg(all(unix, not(test)))]
fn boxuser_ids() -> Result<(u32, u32), Status> {
    let identity = boxuser_identity()?;
    Ok((identity.uid, identity.gid))
}

#[cfg(not(test))]
fn file_owner_ids() -> Result<(u32, u32), Status> {
    boxuser_ids()
}

#[cfg(test)]
fn file_owner_ids() -> Result<(u32, u32), Status> {
    // SAFETY: these no-argument identity queries have no preconditions.
    Ok(unsafe { (libc::geteuid(), libc::getegid()) })
}
#[cfg(unix)]
#[async_trait]
impl ProcessExecutor for UnixProcessExecutor {
    async fn exec(&self, request: ExecRequest) -> Result<Vec<ExecFrame>, Status> {
        validate_exec_request(&request)?;
        if request.argv[0].is_empty() {
            return Err(Status::invalid_argument("argv must not be empty"));
        }
        let id = Self::execution_id(&request.execution_id)?;
        if let Some(frames) = self
            .processes
            .lock()
            .map_err(|_| Status::internal("process registry lock"))?
            .replay(&id, &request)?
        {
            return Ok(frames);
        }
        let cwd = if request.cwd.is_empty() {
            None
        } else {
            Some(self.sandbox.cwd_fd(&request.cwd)?)
        };
        let identity = (self.identity)()?;
        let uid = identity.uid;
        let gid = identity.gid;
        let groups = identity.groups;
        #[cfg(target_os = "macos")]
        let group_count = i32::try_from(groups.len())
            .map_err(|_| Status::failed_precondition("boxuser has too many groups"))?;
        validate_environment(&request.environment)?;
        {
            let mut registry = self
                .processes
                .lock()
                .map_err(|_| Status::internal("process registry lock"))?;
            if registry.starting.contains(&id) || registry.running.contains_key(&id) {
                return Err(Status::already_exists("execution id already active"));
            }
            registry.starting.insert(id.clone());
        }
        let mut reservation = StartReservation {
            id: id.clone(),
            registry: self.processes.clone(),
            idle: self.idle.clone(),
            armed: true,
        };
        let executable_snapshot = if is_allowed_absolute_harness_command(&request.argv[0]) {
            Some(self.sandbox.snapshot_executable(&request.argv[0])?)
        } else {
            None
        };
        let program = executable_snapshot
            .as_ref()
            .map(|snapshot| snapshot.path.clone())
            .unwrap_or_else(|| request.argv[0].clone());
        let mut command = Command::new(program);
        command
            .kill_on_drop(true)
            .env_clear()
            .envs(&request.environment)
            .args(&request.argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("LANG", "C.UTF-8")
            .env("HOME", "/home/boxuser")
            .env("USER", "boxuser");
        let drop_privileges = self.drop_privileges;
        unsafe {
            // SAFETY: the closure captures only owned descriptors and
            // preallocated numeric identity data. After fork it invokes only
            // async-signal-safe syscalls and performs no NSS lookup, heap
            // allocation, locking, or formatting.
            command.pre_exec(move || {
                if let Some(cwd) = &cwd
                    && libc::fchdir(cwd.as_raw_fd()) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                };
                if drop_privileges {
                    #[cfg(target_os = "macos")]
                    let setgroups_result = libc::setgroups(group_count, groups.as_ptr());
                    #[cfg(not(target_os = "macos"))]
                    let setgroups_result = libc::setgroups(groups.len(), groups.as_ptr());
                    if setgroups_result != 0 {
                        return Err(std::io::Error::last_os_error());
                    };
                    if libc::setgid(gid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    };
                    if libc::setuid(uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    };
                }
                Ok(())
            });
        }
        let spawned = command.spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(_) => {
                return Err(Status::internal("exec spawn failed"));
            }
        };
        let Some(pgid) = child.id().and_then(|pid| i32::try_from(pid).ok()) else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(Status::internal("missing child pid"));
        };
        if pgid <= 0 {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(Status::internal("invalid child pid"));
        }
        {
            let mut registry = self
                .processes
                .lock()
                .map_err(|_| Status::internal("process registry lock"))?;
            registry.starting.remove(&id);
            registry.running.insert(id.clone(), pgid);
        }
        reservation.finish();
        let mut running_guard = RunningProcessGuard {
            id: id.clone(),
            pgid,
            registry: self.processes.clone(),
            idle: self.idle.clone(),
            armed: true,
        };
        let max = usize::try_from(request.max_output_bytes)
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or(MAX_EXEC_OUTPUT)
            .min(MAX_EXEC_OUTPUT);
        let outcome = async {
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| Status::internal("stdout unavailable"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| Status::internal("stderr unavailable"))?;
            let stdout_reader = tokio::spawn(read_limited(stdout, max, "stdout read failed"));
            let stderr_reader = tokio::spawn(read_limited(stderr, max, "stderr read failed"));
            let timeout = Duration::from_millis(request.timeout_ms.clamp(1, MAX_EXEC_TIMEOUT_MS));
            // Poll `waitpid(WNOHANG)` through `try_wait` instead of depending
            // on a process-wide SIGCHLD registration. The guest PID 1 may set
            // or inherit SIGCHLD handling before the Tokio runtime starts, and
            // on macOS a fork+pre_exec child can otherwise already be a zombie
            // before Tokio's readiness watcher observes it.
            let deadline = tokio::time::Instant::now() + timeout;
            let status = loop {
                // Check the kernel first. If the runtime thread was starved
                // across the deadline but the child is already reaped, report
                // its real result instead of manufacturing a timeout.
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if tokio::time::Instant::now() >= deadline => {
                        break Err(Status::deadline_exceeded("exec timed out"));
                    }
                    Ok(None) => tokio::time::sleep(Duration::from_millis(2)).await,
                    Err(_) => break Err(Status::internal("exec wait failed")),
                }
            };
            if status.is_err() {
                // SAFETY: pgid is a positive child pid registered only after spawn.
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
                let _ = child.wait().await;
            }
            let (stdout_result, stderr_result) = tokio::join!(stdout_reader, stderr_reader);
            let status = status?;
            let out = stdout_result.map_err(|_| Status::internal("stdout task failed"))??;
            let err = stderr_result.map_err(|_| Status::internal("stderr task failed"))??;
            Ok(vec![ExecFrame {
                sequence: 0,
                stdout: out,
                stderr: err,
                exit_code: status.code().unwrap_or(-1),
                exited: true,
                execution_id: id.clone(),
            }])
        }
        .await;
        if outcome.is_err() {
            // SAFETY: pgid is positive; ESRCH for an exited group is harmless.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
            let _ = child.wait().await;
        }
        running_guard.finish()?;
        if let Ok(frames) = &outcome {
            self.processes
                .lock()
                .map_err(|_| Status::internal("process registry lock"))?
                .record(id, request, frames.clone());
        }
        outcome
    }
    async fn exec_stream(&self, request: ExecRequest) -> Result<FrameStream, Status> {
        self.exec_streaming(request).await
    }
    async fn cancel(&self, id: &str) -> Result<bool, Status> {
        let pgid = self
            .processes
            .lock()
            .map_err(|_| Status::internal("process registry lock"))?
            .running
            .get(id)
            .copied();
        let Some(pgid) = pgid.filter(|pgid| *pgid > 0) else {
            return Ok(false);
        };
        unsafe { libc::kill(-pgid, libc::SIGTERM) };
        tokio::time::sleep(self.grace).await;
        if self
            .processes
            .lock()
            .map_err(|_| Status::internal("process registry lock"))?
            .running
            .contains_key(id)
        {
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
        let reaped = async {
            loop {
                let notified = self.idle.notified();
                if !self
                    .processes
                    .lock()
                    .map_err(|_| Status::internal("process registry lock"))?
                    .running
                    .contains_key(id)
                {
                    return Ok::<(), Status>(());
                }
                notified.await;
            }
        };
        tokio::time::timeout(self.grace, reaped)
            .await
            .map_err(|_| Status::deadline_exceeded("cancelled process was not reaped"))??;
        Ok(true)
    }
    async fn wait_idle(&self, deadline: Duration) -> Result<bool, Status> {
        let pending = async {
            loop {
                if self
                    .processes
                    .lock()
                    .map_err(|_| Status::internal("process registry lock"))?
                    .is_idle()
                {
                    return Ok(true);
                }
                self.idle.notified().await;
            }
        };
        match tokio::time::timeout(deadline, pending).await {
            Ok(value) => value,
            Err(_) => Ok(false),
        }
    }
}
#[cfg(not(unix))]
#[async_trait]
impl ProcessExecutor for UnixProcessExecutor {
    async fn exec(&self, _: ExecRequest) -> Result<Vec<ExecFrame>, Status> {
        Err(Status::unimplemented("feature_not_supported"))
    }
    async fn cancel(&self, _: &str) -> Result<bool, Status> {
        Err(Status::unimplemented("feature_not_supported"))
    }
}

#[derive(Clone)]
pub struct AgentIdentity {
    pub box_id: String,
    pub boot_nonce: Vec<u8>,
    pub runtime: String,
    pub arch: String,
    pub agent_version: String,
    pub capabilities: Vec<String>,
}
impl AgentIdentity {
    fn handshake(&self) -> Handshake {
        Handshake {
            protocol_version: PROTOCOL_VERSION,
            box_id: self.box_id.clone(),
            boot_nonce: self.boot_nonce.clone(),
            runtime: self.runtime.clone(),
            arch: self.arch.clone(),
            agent_version: self.agent_version.clone(),
            capabilities: self.capabilities.clone(),
        }
    }
    fn verify(&self, got: Option<Handshake>) -> Result<(), Status> {
        let Some(g) = got else {
            return Err(Status::invalid_argument("missing handshake"));
        };
        if self.boot_nonce.len() != NONCE_LEN {
            return Err(Status::failed_precondition("invalid configured boot nonce"));
        }
        if g.protocol_version != PROTOCOL_VERSION {
            return Err(Status::failed_precondition("protocol version mismatch"));
        };
        let equal = (g.box_id.as_bytes().ct_eq(self.box_id.as_bytes())
            & g.boot_nonce.ct_eq(self.boot_nonce.as_slice())
            & g.runtime.as_bytes().ct_eq(self.runtime.as_bytes())
            & g.arch.as_bytes().ct_eq(self.arch.as_bytes()))
        .unwrap_u8()
            == 1;
        if !equal {
            return Err(Status::unauthenticated("handshake mismatch"));
        };
        Ok(())
    }
    fn verify_metadata<T>(&self, r: &Request<T>) -> Result<(), Status> {
        let received = r
            .metadata()
            .get("x-boxd-boot-nonce")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("missing agent nonce"))?;
        let expected = self
            .boot_nonce
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if received.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
            return Err(Status::unauthenticated("agent nonce mismatch"));
        };
        Ok(())
    }
}

pub struct GuestAgent {
    identity: AgentIdentity,
    sandbox: FileSandbox,
    executor: Arc<dyn ProcessExecutor>,
    browser: Arc<dyn BrowserBackend>,
    admission: Arc<AdmissionGate>,
    quiesce_lock: tokio::sync::Mutex<()>,
    shutdown: Notify,
}

struct AdmissionState {
    accepting: bool,
    active: usize,
}

struct AdmissionGate {
    state: Mutex<AdmissionState>,
    idle: Notify,
}

struct ActiveOperation {
    gate: Arc<AdmissionGate>,
}

impl Drop for ActiveOperation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.state.lock() {
            state.active = state.active.saturating_sub(1);
            if state.active == 0 {
                self.gate.idle.notify_waiters();
            }
        }
    }
}

impl AdmissionGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(AdmissionState {
                accepting: true,
                active: 0,
            }),
            idle: Notify::new(),
        }
    }

    fn admit(self: &Arc<Self>) -> Result<ActiveOperation, Status> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Status::internal("admission lock"))?;
        if !state.accepting {
            return Err(Status::failed_precondition("agent is quiesced"));
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| Status::resource_exhausted("too many active operations"))?;
        Ok(ActiveOperation { gate: self.clone() })
    }

    fn close(&self) -> Result<bool, Status> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Status::internal("admission lock"))?;
        let was_accepting = state.accepting;
        state.accepting = false;
        Ok(was_accepting)
    }

    fn reopen(&self) -> Result<(), Status> {
        self.state
            .lock()
            .map_err(|_| Status::internal("admission lock"))?
            .accepting = true;
        Ok(())
    }

    async fn wait_idle(&self) -> Result<(), Status> {
        loop {
            let notified = self.idle.notified();
            if self
                .state
                .lock()
                .map_err(|_| Status::internal("admission lock"))?
                .active
                == 0
            {
                return Ok(());
            }
            notified.await;
        }
    }
}
impl GuestAgent {
    pub fn new(
        identity: AgentIdentity,
        sandbox: FileSandbox,
        executor: Arc<dyn ProcessExecutor>,
    ) -> Self {
        Self {
            identity,
            sandbox,
            executor,
            browser: Arc::new(UnavailableBrowserBackend),
            admission: Arc::new(AdmissionGate::new()),
            quiesce_lock: tokio::sync::Mutex::new(()),
            shutdown: Notify::new(),
        }
    }
    pub fn with_browser_backend(mut self, browser: Arc<dyn BrowserBackend>) -> Self {
        self.browser = browser;
        self
    }
    pub async fn wait_shutdown(&self) {
        self.shutdown.notified().await
    }
    fn authenticated<T>(&self, r: &Request<T>) -> Result<(), Status> {
        self.identity.verify_metadata(r)
    }
    async fn quiesce_now(&self) -> Result<(), Status> {
        let _transition = self.quiesce_lock.lock().await;
        let was_accepting = self.admission.close()?;
        let drain = async {
            self.admission.wait_idle().await?;
            if self.executor.wait_idle(Duration::from_secs(10)).await? {
                self.sandbox.sync_filesystems()
            } else {
                Err(Status::failed_precondition(
                    "agent did not quiesce before deadline",
                ))
            }
        };
        match tokio::time::timeout(Duration::from_secs(10), drain).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                if was_accepting {
                    self.admission.reopen()?;
                }
                Err(error)
            }
            Err(_) => {
                if was_accepting {
                    self.admission.reopen()?;
                }
                Err(Status::failed_precondition(
                    "agent did not quiesce before deadline",
                ))
            }
        }
    }

    async fn write_frames<S>(&self, stream: S) -> Result<WriteFileResponse, Status>
    where
        S: Stream<Item = Result<WriteFileFrame, Status>> + Send,
    {
        let _active = self.admission.admit()?;
        tokio::pin!(stream);
        let (mut path, mut data, mut frames, mut eof) = (None, Vec::new(), 0usize, false);
        while let Some(f) = stream.next().await.transpose()? {
            frames += 1;
            if frames > MAX_WRITE_FRAMES {
                return Err(Status::resource_exhausted("too many write frames"));
            };
            if path.as_ref().is_some_and(|p: &String| p != &f.path) {
                return Err(Status::invalid_argument("mixed paths"));
            };
            if eof {
                return Err(Status::invalid_argument("frames after eof"));
            };
            if f.data.len() > FILE_FRAME_BYTES {
                return Err(Status::resource_exhausted("write frame exceeds limit"));
            }
            if data.len().saturating_add(f.data.len()) > MAX_FILE_BYTES {
                return Err(Status::resource_exhausted("file exceeds agent limit"));
            };
            path = Some(f.path);
            data.extend_from_slice(&f.data);
            eof = f.eof;
        }
        if !eof {
            return Err(Status::invalid_argument("write EOF required"));
        };
        let path = path.ok_or_else(|| Status::invalid_argument("empty write"))?;
        self.sandbox.atomic_write(&path, &data)?;
        Ok(WriteFileResponse {
            bytes_written: data.len() as u64,
        })
    }
}

#[tonic::async_trait]
impl box_agent_v1_server::BoxAgentV1 for GuestAgent {
    type ExecStream = FrameStream;
    type ReadFileStream = ByteStream;
    type GitStream = FrameStream;
    type RunHarnessStream = HarnessStream;
    type DialStream = TunnelStream;
    type BrowserStream = BrowserStream;
    type StatsStream = StatsStream;
    async fn health(&self, r: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        self.authenticated(&r)?;
        self.identity.verify(r.get_ref().handshake.clone())?;
        Ok(Response::new(HealthResponse {
            handshake: Some(self.identity.handshake()),
        }))
    }
    async fn exec(&self, r: Request<ExecRequest>) -> Result<Response<Self::ExecStream>, Status> {
        self.authenticated(&r)?;
        let _active = self.admission.admit()?;
        let frames = chunk_exec_frames(self.executor.exec(r.into_inner()).await?);
        Ok(Response::new(Box::pin(stream::iter(
            frames.into_iter().map(Ok),
        ))))
    }
    async fn cancel(&self, r: Request<CancelRequest>) -> Result<Response<CancelResponse>, Status> {
        self.authenticated(&r)?;
        let id = r.into_inner().execution_id;
        if id.is_empty() {
            return Err(Status::invalid_argument("execution id required"));
        };
        Ok(Response::new(CancelResponse {
            cancelled: self.executor.cancel(&id).await?,
        }))
    }
    async fn read_file(
        &self,
        r: Request<ReadFileRequest>,
    ) -> Result<Response<Self::ReadFileStream>, Status> {
        self.authenticated(&r)?;
        let bytes = self.sandbox.read(&r.into_inner().path)?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Status::resource_exhausted("file exceeds agent limit"));
        }
        let mut frames = Vec::with_capacity(bytes.len().div_ceil(FILE_FRAME_BYTES).max(1));
        if bytes.is_empty() {
            frames.push(Ok(BytesFrame {
                sequence: 0,
                data: Vec::new(),
                eof: true,
            }));
        } else {
            let frame_count = bytes.len().div_ceil(FILE_FRAME_BYTES);
            for (index, data) in bytes.chunks(FILE_FRAME_BYTES).enumerate() {
                frames.push(Ok(BytesFrame {
                    sequence: index as u64,
                    data: data.to_vec(),
                    eof: index + 1 == frame_count,
                }));
            }
        }
        Ok(Response::new(Box::pin(stream::iter(frames))))
    }
    async fn write_file(
        &self,
        r: Request<tonic::Streaming<WriteFileFrame>>,
    ) -> Result<Response<WriteFileResponse>, Status> {
        self.authenticated(&r)?;
        Ok(Response::new(self.write_frames(r.into_inner()).await?))
    }
    async fn list_files(
        &self,
        r: Request<ListFilesRequest>,
    ) -> Result<Response<ListFilesResponse>, Status> {
        self.authenticated(&r)?;
        let entries = self.sandbox.list(&r.into_inner().path)?;
        if entries.len() > MAX_LIST_ENTRIES {
            return Err(Status::resource_exhausted("directory entry limit exceeded"));
        }
        let encoded_bytes = entries.iter().try_fold(0usize, |total, entry| {
            total
                .checked_add(entry.path.len())
                .and_then(|value| value.checked_add(32))
                .ok_or_else(|| Status::resource_exhausted("directory listing size overflow"))
        })?;
        if encoded_bytes > MAX_LIST_ENCODED_BYTES {
            return Err(Status::resource_exhausted(
                "directory listing size limit exceeded",
            ));
        }
        Ok(Response::new(ListFilesResponse { entries }))
    }
    async fn quiesce(
        &self,
        r: Request<QuiesceRequest>,
    ) -> Result<Response<QuiesceResponse>, Status> {
        self.authenticated(&r)?;
        self.quiesce_now().await?;
        Ok(Response::new(QuiesceResponse { quiesced: true }))
    }
    async fn shutdown(
        &self,
        r: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        self.authenticated(&r)?;
        self.quiesce_now().await?;
        self.shutdown.notify_waiters();
        Ok(Response::new(ShutdownResponse { accepted: true }))
    }
    async fn git(&self, r: Request<GitRequest>) -> Result<Response<Self::ExecStream>, Status> {
        self.authenticated(&r)?;
        let _active = self.admission.admit()?;
        let request = r.into_inner();
        if request.args.is_empty() {
            return Err(Status::invalid_argument("git args required"));
        }
        let mut argv = Vec::with_capacity(request.args.len() + 1);
        argv.push("git".into());
        argv.extend(request.args);
        let request = ExecRequest {
            argv,
            cwd: request.cwd,
            execution_id: request.execution_id,
            timeout_ms: request.timeout_ms,
            max_output_bytes: request.max_output_bytes,
            environment: request.environment,
        };
        validate_exec_request(&request)?;
        let frames = chunk_exec_frames(self.executor.exec(request).await?);
        Ok(Response::new(Box::pin(stream::iter(
            frames.into_iter().map(Ok),
        ))))
    }
    async fn run_harness(
        &self,
        r: Request<RunHarnessRequest>,
    ) -> Result<Response<Self::RunHarnessStream>, Status> {
        self.authenticated(&r)?;
        let active = self.admission.admit()?;
        validate_harness_request(r.get_ref())?;
        let request = harness_exec_request(r.into_inner());
        let execution_id = request.execution_id.clone();
        let frames = self.executor.exec_stream(request).await?;
        Ok(Response::new(live_harness_stream(
            self.executor.clone(),
            execution_id,
            frames,
            active,
        )))
    }
    async fn install_skill(
        &self,
        r: Request<InstallSkillRequest>,
    ) -> Result<Response<SkillMutationResponse>, Status> {
        self.authenticated(&r)?;
        let _active = self.admission.admit()?;
        let request = r.into_inner();
        if request.skill_id.is_empty() || request.skill_id.len() > 384 {
            return Err(Status::invalid_argument("invalid skill id"));
        }
        Ok(Response::new(SkillMutationResponse {
            changed: self.sandbox.install_skill(&request.name, &request.files)?,
        }))
    }
    async fn remove_skill(
        &self,
        r: Request<RemoveSkillRequest>,
    ) -> Result<Response<SkillMutationResponse>, Status> {
        self.authenticated(&r)?;
        let _active = self.admission.admit()?;
        Ok(Response::new(SkillMutationResponse {
            changed: self.sandbox.remove_skill(&r.into_inner().name)?,
        }))
    }
    async fn dial(
        &self,
        r: Request<tonic::Streaming<TunnelFrame>>,
    ) -> Result<Response<Self::DialStream>, Status> {
        self.authenticated(&r)?;
        let active = self.admission.admit()?;
        let mut inbound = r.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("tunnel port frame is required"))?;
        if first.port == 0
            || first.port > u32::from(u16::MAX)
            || first.port == AGENT_CONTROL_PORT
            || !first.data.is_empty()
            || first.eof
        {
            return Err(Status::invalid_argument("invalid tunnel port frame"));
        }
        let port = u16::try_from(first.port)
            .map_err(|_| Status::invalid_argument("invalid tunnel port"))?;
        let socket = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("guest port connect timeout"))?
        .map_err(|_| Status::unavailable("guest port is unavailable"))?;
        socket
            .set_nodelay(true)
            .map_err(|_| Status::internal("tunnel socket configuration failed"))?;
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            let _active = active;
            let (mut reader, mut writer) = socket.into_split();
            let output = sender.clone();
            let upstream = async move {
                while let Some(frame) = inbound.message().await? {
                    if frame.port != 0 || frame.data.len() > MAX_TUNNEL_FRAME_BYTES {
                        return Err(Status::invalid_argument("invalid tunnel data frame"));
                    }
                    if !frame.data.is_empty() {
                        writer
                            .write_all(&frame.data)
                            .await
                            .map_err(|_| Status::unavailable("guest tunnel write failed"))?;
                    }
                    if frame.eof {
                        writer
                            .shutdown()
                            .await
                            .map_err(|_| Status::unavailable("guest tunnel shutdown failed"))?;
                        return Ok::<(), Status>(());
                    }
                }
                writer
                    .shutdown()
                    .await
                    .map_err(|_| Status::unavailable("guest tunnel shutdown failed"))
            };
            let downstream = async move {
                let mut buffer = vec![0_u8; 64 * 1024];
                loop {
                    let count = reader
                        .read(&mut buffer)
                        .await
                        .map_err(|_| Status::unavailable("guest tunnel read failed"))?;
                    let eof = count == 0;
                    output
                        .send(Ok(TunnelFrame {
                            data: buffer[..count].to_vec(),
                            port: 0,
                            eof,
                        }))
                        .await
                        .map_err(|_| Status::cancelled("tunnel client disconnected"))?;
                    if eof {
                        return Ok::<(), Status>(());
                    }
                }
            };
            let (upstream, downstream) = tokio::join!(upstream, downstream);
            if let Err(error) = upstream.and(downstream) {
                let _ = sender.send(Err(error)).await;
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(receiver),
        )))
    }
    async fn browser(
        &self,
        r: Request<BrowserRequest>,
    ) -> Result<Response<Self::BrowserStream>, Status> {
        self.authenticated(&r)?;
        let _active = self.admission.admit()?;
        let request = r.into_inner();
        validate_browser_request(&request)?;
        let frames = self.browser.execute(request).await?;
        validate_browser_frames(&frames)?;
        Ok(Response::new(Box::pin(stream::iter(
            frames.into_iter().map(Ok),
        ))))
    }
    async fn stats(&self, r: Request<StatsRequest>) -> Result<Response<Self::StatsStream>, Status> {
        self.authenticated(&r)?;
        Err(Status::unimplemented("feature_not_supported"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use box_agent_v1_server::BoxAgentV1;
    use std::fs;

    fn sandbox() -> (tempfile::TempDir, FileSandbox) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("workspace")).unwrap();
        fs::create_dir(dir.path().join("home")).unwrap();
        let sandbox =
            FileSandbox::new(dir.path().join("workspace"), dir.path().join("home")).unwrap();
        (dir, sandbox)
    }
    fn identity() -> AgentIdentity {
        AgentIdentity {
            box_id: "box".into(),
            boot_nonce: vec![7; NONCE_LEN],
            runtime: "node".into(),
            arch: "aarch64".into(),
            agent_version: "test".into(),
            capabilities: vec![],
        }
    }
    fn authenticated<T>(value: T) -> Request<T> {
        let mut request = Request::new(value);
        request.metadata_mut().insert(
            "x-boxd-boot-nonce",
            "0707070707070707070707070707070707070707070707070707070707070707"
                .parse()
                .unwrap(),
        );
        request
    }

    fn assert_registry_idle(executor: &UnixProcessExecutor) {
        let registry = executor.processes.lock().unwrap();
        assert!(registry.starting.is_empty());
        assert!(registry.running.is_empty());
        assert!(registry.running.values().all(|pgid| *pgid > 0));
    }

    struct FixtureBrowserBackend;

    #[async_trait]
    impl BrowserBackend for FixtureBrowserBackend {
        async fn execute(&self, request: BrowserRequest) -> Result<Vec<BrowserFrame>, Status> {
            Ok(vec![BrowserFrame {
                sequence: 0,
                json_payload: serde_json::json!({
                    "operation": request.operation,
                    "tab_id": request.tab_id,
                })
                .to_string(),
                data: Vec::new(),
                eof: true,
            }])
        }
    }

    #[tokio::test]
    async fn browser_rpc_authenticates_validates_and_forwards_typed_frames() {
        let (_dir, sandbox) = sandbox();
        let agent = GuestAgent::new(identity(), sandbox, Arc::new(FakeExecutor::default()))
            .with_browser_backend(Arc::new(FixtureBrowserBackend));
        let response = BoxAgentV1::browser(
            &agent,
            authenticated(BrowserRequest {
                operation: "content".into(),
                tab_id: "tab_fixture".into(),
                url: String::new(),
                wait_until: String::new(),
                timeout_ms: 0,
                full_page: false,
                json_payload: String::new(),
            }),
        )
        .await
        .unwrap();
        let frames = response
            .into_inner()
            .collect::<Vec<Result<BrowserFrame, Status>>>()
            .await;
        assert_eq!(frames.len(), 1);
        let frame = frames[0].as_ref().unwrap();
        assert!(frame.eof);
        assert!(frame.json_payload.contains("tab_fixture"));

        let connect = BoxAgentV1::browser(
            &agent,
            authenticated(BrowserRequest {
                operation: "connect".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .collect::<Vec<Result<BrowserFrame, Status>>>()
        .await;
        assert_eq!(connect.len(), 1);
        assert!(
            connect[0]
                .as_ref()
                .unwrap()
                .json_payload
                .contains("connect")
        );
        let screencast = BoxAgentV1::browser(
            &agent,
            authenticated(BrowserRequest {
                operation: "screencast".into(),
                tab_id: "tab_fixture".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .collect::<Vec<Result<BrowserFrame, Status>>>()
        .await;
        assert_eq!(screencast.len(), 1);
        assert!(
            screencast[0]
                .as_ref()
                .unwrap()
                .json_payload
                .contains("screencast")
        );

        let recording = BoxAgentV1::browser(
            &agent,
            authenticated(BrowserRequest {
                operation: "recording_target".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .collect::<Vec<Result<BrowserFrame, Status>>>()
        .await;
        assert_eq!(recording.len(), 1);
        assert!(
            recording[0]
                .as_ref()
                .unwrap()
                .json_payload
                .contains("recording_target")
        );

        let error = match BoxAgentV1::browser(
            &agent,
            authenticated(BrowserRequest {
                operation: "unknown".into(),
                ..Default::default()
            }),
        )
        .await
        {
            Ok(_) => panic!("unsupported browser operation was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::Unimplemented);
    }

    #[test]
    fn nofollow_paths_reject_symlink_and_write_is_atomic() {
        let (dir, sandbox) = sandbox();
        sandbox.atomic_write("safe", b"ok").unwrap();
        assert_eq!(sandbox.read("safe").unwrap(), b"ok");
        sandbox.atomic_write("/workspace/sdk.txt", b"sdk").unwrap();
        assert_eq!(sandbox.read("/workspace/sdk.txt").unwrap(), b"sdk");
        let first_mtime = sandbox
            .list("/workspace")
            .unwrap()
            .into_iter()
            .find(|entry| entry.path == "sdk.txt")
            .unwrap()
            .modified_at_unix_millis;
        assert!(first_mtime > 0);
        std::thread::sleep(Duration::from_millis(5));
        sandbox
            .atomic_write("/workspace/sdk.txt", b"updated")
            .unwrap();
        let second_mtime = sandbox
            .list("/workspace")
            .unwrap()
            .into_iter()
            .find(|entry| entry.path == "sdk.txt")
            .unwrap()
            .modified_at_unix_millis;
        assert!(second_mtime > first_mtime);
        assert!(sandbox.cwd_fd("/workspace").is_ok());
        assert!(sandbox.read("/workspace-escape/sdk.txt").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path(), dir.path().join("workspace/link")).unwrap();
            assert!(sandbox.read("link/Cargo.toml").is_err());
            assert!(sandbox.atomic_write("link/pwned", b"no").is_err());
        }
        assert!(sandbox.atomic_write("../no", b"no").is_err());
    }

    #[test]
    fn sandbox_root_symlink_is_rejected_at_descriptor_acquisition() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("real-workspace")).unwrap();
        fs::create_dir(dir.path().join("home")).unwrap();
        symlink(
            dir.path().join("real-workspace"),
            dir.path().join("workspace"),
        )
        .unwrap();
        assert!(FileSandbox::new(dir.path().join("workspace"), dir.path().join("home")).is_err());
    }

    #[test]
    fn sandbox_filesystem_sync_uses_retained_root_capabilities() {
        let (dir, sandbox) = sandbox();
        std::fs::write(dir.path().join("workspace/sync-fixture"), b"persisted").unwrap();
        sandbox.sync_filesystems().unwrap();
        assert_eq!(
            sandbox.read("/workspace/sync-fixture").unwrap(),
            b"persisted"
        );
    }

    #[test]
    fn concurrent_directory_lists_have_independent_offsets_and_complete_results() {
        let (_dir, sandbox) = sandbox();
        for index in 0..200 {
            sandbox
                .atomic_write(&format!("entry-{index:03}"), b"value")
                .unwrap();
        }
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let handles = (0..8)
            .map(|_| {
                let sandbox = sandbox.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    sandbox.list("/workspace").unwrap()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for handle in handles {
            let entries = handle.join().unwrap();
            assert_eq!(entries.len(), 200);
            assert_eq!(entries.first().unwrap().path, "entry-000");
            assert_eq!(entries.last().unwrap().path, "entry-199");
        }
    }

    #[test]
    fn sdk_workspace_is_created_idempotently_and_is_writable() {
        let (dir, sandbox) = sandbox();
        sandbox.ensure_sdk_workspace().unwrap();
        sandbox.ensure_sdk_workspace().unwrap();
        assert!(dir.path().join("workspace/home").is_dir());
        sandbox
            .atomic_write("/workspace/home/sdk.txt", b"sdk")
            .unwrap();
        assert_eq!(sandbox.read("/workspace/home/sdk.txt").unwrap(), b"sdk");
    }

    #[test]
    fn skills_install_replace_remove_atomically_under_agents_root() {
        let (dir, sandbox) = sandbox();
        let initial = vec![
            SkillFile {
                path: "SKILL.md".into(),
                content: b"---\nname: safe-skill\n---\ninitial".to_vec(),
            },
            SkillFile {
                path: "references/guide.md".into(),
                content: b"guide".to_vec(),
            },
        ];
        assert!(sandbox.install_skill("safe-skill", &initial).unwrap());
        let installed = dir.path().join("home/.agents/skills/safe-skill");
        assert_eq!(
            fs::read(installed.join("references/guide.md")).unwrap(),
            b"guide"
        );

        let replacement = vec![SkillFile {
            path: "SKILL.md".into(),
            content: b"---\nname: safe-skill\n---\nreplacement".to_vec(),
        }];
        assert!(sandbox.install_skill("safe-skill", &replacement).unwrap());
        assert_eq!(
            fs::read(installed.join("SKILL.md")).unwrap(),
            b"---\nname: safe-skill\n---\nreplacement"
        );
        assert!(!installed.join("references").exists());
        assert!(sandbox.remove_skill("safe-skill").unwrap());
        assert!(!installed.exists());
        assert!(!sandbox.remove_skill("safe-skill").unwrap());
    }

    #[test]
    fn skills_reject_unsafe_names_paths_duplicates_and_missing_manifest() {
        let (_dir, sandbox) = sandbox();
        let manifest = SkillFile {
            path: "SKILL.md".into(),
            content: b"safe".to_vec(),
        };
        assert!(
            sandbox
                .install_skill("../escape", std::slice::from_ref(&manifest))
                .is_err()
        );
        assert!(
            sandbox
                .install_skill(
                    "safe-skill",
                    &[
                        manifest.clone(),
                        SkillFile {
                            path: "../escape".into(),
                            content: b"no".to_vec(),
                        },
                    ],
                )
                .is_err()
        );
        assert!(
            sandbox
                .install_skill("safe-skill", &[manifest.clone(), manifest])
                .is_err()
        );
        assert!(
            sandbox
                .install_skill(
                    "safe-skill",
                    &[SkillFile {
                        path: "README.md".into(),
                        content: b"missing".to_vec(),
                    }],
                )
                .is_err()
        );
    }
    #[tokio::test]
    async fn rpc_requires_metadata() {
        let (_dir, sandbox) = sandbox();
        let agent = GuestAgent::new(identity(), sandbox, Arc::new(FakeExecutor::default()));
        assert_eq!(
            agent
                .list_files(Request::new(ListFilesRequest { path: "x".into() }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        let health = HealthRequest {
            handshake: Some(identity().handshake()),
        };
        assert!(agent.health(authenticated(health)).await.is_ok());
    }

    #[tokio::test]
    async fn git_rpc_prepends_fixed_binary_and_preserves_bounded_request() {
        let (_dir, sandbox) = sandbox();
        sandbox.ensure_sdk_workspace().unwrap();
        let executor = Arc::new(FakeExecutor::default());
        executor.frames.lock().unwrap().push(ExecFrame {
            execution_id: "git-1".into(),
            exited: true,
            ..Default::default()
        });
        let agent = GuestAgent::new(identity(), sandbox, executor.clone());
        let response = agent
            .git(authenticated(GitRequest {
                execution_id: "git-1".into(),
                args: vec!["status".into(), "--short".into()],
                cwd: "/workspace/home/repo".into(),
                environment: HashMap::new(),
                timeout_ms: 30_000,
                max_output_bytes: 4096,
            }))
            .await
            .unwrap();
        assert_eq!(
            futures_util::StreamExt::count(response.into_inner()).await,
            1
        );
        let requests = executor.requests.lock().unwrap();
        assert_eq!(requests[0].argv, ["git", "status", "--short"]);
        assert_eq!(requests[0].cwd, "/workspace/home/repo");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_git_rpc_executes_real_git_as_current_test_user() {
        let (_dir, sandbox) = sandbox();
        sandbox.ensure_sdk_workspace().unwrap();
        let executor = Arc::new(UnixProcessExecutor::new_for_current_user(sandbox.clone()));
        let agent = GuestAgent::new(identity(), sandbox, executor);
        let mut stream = agent
            .git(authenticated(GitRequest {
                execution_id: "git-real".into(),
                args: vec!["--version".into()],
                cwd: "/workspace/home".into(),
                environment: HashMap::new(),
                timeout_ms: 30_000,
                max_output_bytes: 64 * 1024,
            }))
            .await
            .unwrap()
            .into_inner();
        let mut stdout = Vec::new();
        let mut exit = None;
        while let Some(frame) = stream.next().await {
            let frame = frame.unwrap();
            stdout.extend(frame.stdout);
            if frame.exited {
                exit = Some(frame.exit_code);
            }
        }
        assert_eq!(exit, Some(0));
        assert!(
            String::from_utf8(stdout)
                .unwrap()
                .starts_with("git version ")
        );
    }

    fn harness_request() -> RunHarnessRequest {
        RunHarnessRequest {
            execution_id: "run-1".into(),
            command: "fixture-harness".into(),
            args: vec!["--flag".into(), "value".into()],
            prompt: "hello".into(),
            model: "custom".into(),
            session_id: "session-1".into(),
            cwd: "/workspace/home".into(),
            environment: HashMap::from([("TOKEN".into(), "guest-secret".into())]),
            timeout_ms: 30_000,
            max_output_bytes: 4_096,
        }
    }

    #[tokio::test]
    async fn run_harness_builds_pinned_argv_and_parses_strict_events() {
        let (_dir, sandbox) = sandbox();
        sandbox.ensure_sdk_workspace().unwrap();
        let executor = Arc::new(FakeExecutor::default());
        executor.frames.lock().unwrap().push(ExecFrame {
            sequence: 0,
            stdout: concat!(
                "event: text\n",
                "data: {\"text\":\"hello\"}\n\n",
                "event: done\n",
                "data: {\"output\":\"hello\",\"input_tokens\":1}\n\n"
            )
            .as_bytes()
            .to_vec(),
            stderr: b"diagnostic only".to_vec(),
            exit_code: 0,
            exited: true,
            execution_id: "run-1".into(),
        });
        let agent = GuestAgent::new(identity(), sandbox, executor.clone());
        let response = agent
            .run_harness(authenticated(harness_request()))
            .await
            .unwrap();
        let events = response
            .into_inner()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[0].event_type, "text");
        assert!(!events[0].terminal);
        assert_eq!(events[1].sequence, 1);
        assert_eq!(events[1].event_type, "stderr");
        assert_eq!(events[1].stderr, b"diagnostic only");
        assert_eq!(events[2].sequence, 2);
        assert_eq!(events[2].event_type, "done");
        assert!(events[2].terminal);
        assert_eq!(events[2].execution_id, "run-1");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&events[2].payload_json).unwrap(),
            serde_json::json!({"output": "hello", "input_tokens": 1})
        );

        let requests = executor.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].argv,
            vec![
                "fixture-harness",
                "--flag",
                "value",
                "-p",
                "hello",
                "--model",
                "custom",
                "--stream",
                "--session",
                "session-1",
            ]
        );
        assert_eq!(requests[0].cwd, "/workspace/home");
        assert_eq!(requests[0].environment["TOKEN"], "guest-secret");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_harness_emits_text_before_process_exit_and_reaps_after_terminal() {
        let (_dir, sandbox) = sandbox();
        sandbox.ensure_sdk_workspace().unwrap();
        let executor = Arc::new(UnixProcessExecutor::new_for_current_user(sandbox.clone()));
        let agent = GuestAgent::new(identity(), sandbox, executor.clone());
        let mut request = harness_request();
        request.command = "sh".into();
        request.args = vec![
            "-c".into(),
            concat!(
                "/usr/bin/printf 'event: text\\ndata: {\"text\":\"early\"}\\n\\n'; ",
                "/bin/sleep 1; ",
                "/usr/bin/printf 'diagnostic from harness' >&2; ",
                "/bin/sleep 1; ",
                "/usr/bin/printf 'event: done\\ndata: {\"output\":\"early\"}\\n\\n'"
            )
            .into(),
            "harness-fixture".into(),
        ];
        let mut events = agent
            .run_harness(authenticated(request))
            .await
            .unwrap()
            .into_inner();
        let first = tokio::time::timeout(Duration::from_secs(10), events.next())
            .await
            .expect("first harness event must arrive before the child exits")
            .unwrap()
            .unwrap();
        assert_eq!(first.event_type, "text");
        assert!(!first.terminal);
        assert!(
            executor
                .processes
                .lock()
                .unwrap()
                .running
                .contains_key("run-1")
        );
        let stderr = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stderr.event_type, "stderr");
        assert_eq!(stderr.stderr, b"diagnostic from harness");
        assert!(stderr.payload_json.is_empty());
        let terminal = events.next().await.unwrap().unwrap();
        assert_eq!(terminal.event_type, "done");
        assert!(terminal.terminal);
        assert!(events.next().await.is_none());
        assert!(
            executor
                .wait_idle(Duration::from_millis(100))
                .await
                .unwrap()
        );
        assert_registry_idle(&executor);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_harness_executes_descriptor_pinned_absolute_command_and_rejects_links() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let (dir, sandbox) = sandbox();
        sandbox.ensure_sdk_workspace().unwrap();
        let command = dir.path().join("workspace/home/absolute-harness");
        fs::write(
            &command,
            concat!(
                "#!/bin/sh\n",
                "printf 'event: text\\ndata: {\"text\":\"absolute\"}\\n\\n'\n",
                "printf 'event: done\\ndata: {\"output\":\"absolute\"}\\n\\n'\n",
            ),
        )
        .unwrap();
        fs::set_permissions(&command, fs::Permissions::from_mode(0o755)).unwrap();
        let executor = Arc::new(UnixProcessExecutor::new_for_current_user(sandbox.clone()));
        let agent = GuestAgent::new(identity(), sandbox, executor.clone());
        let mut request = harness_request();
        request.command = "/workspace/home/absolute-harness".into();
        request.args.clear();
        let events = agent
            .run_harness(authenticated(request))
            .await
            .unwrap()
            .into_inner()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(events[0].event_type, "text");
        assert_eq!(events.last().unwrap().event_type, "done");
        assert_registry_idle(&executor);

        symlink("/bin/sh", dir.path().join("workspace/home/link-harness")).unwrap();
        let mut linked = harness_request();
        linked.execution_id = "run-link".into();
        linked.command = "/workspace/home/link-harness".into();
        assert!(agent.run_harness(authenticated(linked)).await.is_err());

        let mut outside = harness_request();
        outside.execution_id = "run-outside".into();
        outside.command = "/usr/local/bin/harness".into();
        let error = match agent.run_harness(authenticated(outside)).await {
            Ok(_) => panic!("outside harness unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn harness_parser_rejects_missing_duplicate_or_unsuccessful_terminal() {
        let frame = |stdout: &str, exit_code| ExecFrame {
            sequence: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_code,
            exited: true,
            execution_id: "run-1".into(),
        };
        assert_eq!(
            parse_harness_stdout(
                "run-1",
                vec![frame("event: text\ndata: {\"text\":\"x\"}\n\n", 0)]
            )
            .unwrap_err()
            .code(),
            tonic::Code::DataLoss
        );
        assert_eq!(
            parse_harness_stdout(
                "run-1",
                vec![frame(
                    concat!(
                        "event: done\n",
                        "data: {\"output\":\"x\"}\n\n",
                        "event: text\n",
                        "data: {\"text\":\"late\"}\n\n"
                    ),
                    0,
                )]
            )
            .unwrap_err()
            .code(),
            tonic::Code::DataLoss
        );
        assert_eq!(
            parse_harness_stdout(
                "run-1",
                vec![frame("event: done\ndata: {\"output\":\"x\"}\n\n", 7,)]
            )
            .unwrap_err()
            .code(),
            tonic::Code::FailedPrecondition
        );
        assert!(
            parse_harness_stdout(
                "run-1",
                vec![frame("event: error\ndata: {\"error\":\"boom\"}\n\n", 7)]
            )
            .is_ok()
        );
    }

    #[test]
    fn harness_command_allows_only_path_lookup_or_two_absolute_roots() {
        let mut request = harness_request();
        request.command = "/tmp/unsafe".into();
        assert_eq!(
            validate_harness_request(&request).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        request.command = "relative/tool".into();
        assert_eq!(
            validate_harness_request(&request).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        request.command = "/workspace/home/bin/harness".into();
        assert!(validate_harness_request(&request).is_ok());
        request.command = "/home/boxuser/bin/harness".into();
        assert!(validate_harness_request(&request).is_ok());
    }

    #[tokio::test]
    async fn quiesce_atomically_drains_admitted_write_and_rejects_new_mutations() {
        let (_dir, sandbox) = sandbox();
        let agent = Arc::new(GuestAgent::new(
            identity(),
            sandbox,
            Arc::new(FakeExecutor::default()),
        ));
        let stream_polled = Arc::new(tokio::sync::Barrier::new(2));
        let release_stream = Arc::new(tokio::sync::Barrier::new(2));
        let write = {
            let agent = agent.clone();
            let stream_polled = stream_polled.clone();
            let release_stream = release_stream.clone();
            tokio::spawn(async move {
                let frames = stream::once(async move {
                    stream_polled.wait().await;
                    release_stream.wait().await;
                    Ok(WriteFileFrame {
                        path: "/workspace/drained".into(),
                        data: b"complete".to_vec(),
                        eof: true,
                    })
                });
                agent.write_frames(frames).await
            })
        };
        stream_polled.wait().await;
        let quiesce = {
            let agent = agent.clone();
            tokio::spawn(async move { agent.quiesce_now().await })
        };
        for _ in 0..100 {
            if !agent.admission.state.lock().unwrap().accepting {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!agent.admission.state.lock().unwrap().accepting);
        assert!(!quiesce.is_finished());

        let rejected_write = agent
            .write_frames(stream::iter(vec![Ok(WriteFileFrame {
                path: "/workspace/rejected".into(),
                data: b"no".to_vec(),
                eof: true,
            })]))
            .await
            .unwrap_err();
        assert_eq!(rejected_write.code(), tonic::Code::FailedPrecondition);
        let rejected_exec = BoxAgentV1::exec(
            agent.as_ref(),
            authenticated(ExecRequest {
                argv: vec!["/bin/true".into()],
                cwd: String::new(),
                execution_id: "rejected".into(),
                timeout_ms: 1_000,
                max_output_bytes: 1_024,
                environment: HashMap::new(),
            }),
        )
        .await;
        let rejected_exec = match rejected_exec {
            Ok(_) => panic!("quiesced exec was accepted"),
            Err(error) => error,
        };
        assert_eq!(rejected_exec.code(), tonic::Code::FailedPrecondition);

        release_stream.wait().await;
        assert_eq!(write.await.unwrap().unwrap().bytes_written, 8);
        quiesce.await.unwrap().unwrap();
        assert_eq!(
            agent.sandbox.read("/workspace/drained").unwrap(),
            b"complete"
        );
        assert!(agent.sandbox.read("/workspace/rejected").is_err());
    }

    #[tokio::test]
    async fn failed_quiesce_reopens_mutation_admission() {
        let (_dir, sandbox) = sandbox();
        let agent = GuestAgent::new(identity(), sandbox, Arc::new(FailingIdleExecutor));
        assert_eq!(
            agent.quiesce_now().await.unwrap_err().code(),
            tonic::Code::Internal
        );
        let write = agent
            .write_frames(stream::iter(vec![Ok(WriteFileFrame {
                path: "/workspace/after-failure".into(),
                data: b"accepted".to_vec(),
                eof: true,
            })]))
            .await
            .unwrap();
        assert_eq!(write.bytes_written, 8);
    }
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_runs_direct_argv_and_reports_nonzero() {
        let (_dir, sandbox) = sandbox();
        let executor = UnixProcessExecutor::new_for_current_user(sandbox);
        let result = executor
            .exec(ExecRequest {
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf out; printf err >&2; exit 7".into(),
                ],
                cwd: "".into(),
                execution_id: "real-test".into(),
                timeout_ms: 10_000,
                max_output_bytes: 1024,
                environment: HashMap::new(),
            })
            .await
            .unwrap();
        assert_eq!(result[0].stdout, b"out");
        assert_eq!(result[0].stderr, b"err");
        assert_eq!(result[0].exit_code, 7);
        assert_eq!(result[0].execution_id, "real-test");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_replays_completed_execution_id_without_reexecuting() {
        let (dir, sandbox) = sandbox();
        let executor = UnixProcessExecutor::new_for_current_user(sandbox);
        let marker = dir.path().join("execution-marker");
        let request = ExecRequest {
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf x >> \"$MARKER\"; cat \"$MARKER\"".into(),
            ],
            cwd: String::new(),
            execution_id: "schedule-replay-fixture".into(),
            timeout_ms: 10_000,
            max_output_bytes: 1_024,
            environment: HashMap::from([("MARKER".into(), marker.to_string_lossy().into_owned())]),
        };

        let first = executor.exec(request.clone()).await.unwrap();
        let replay = executor.exec(request.clone()).await.unwrap();
        assert_eq!(first, replay);
        assert_eq!(fs::read(&marker).unwrap(), b"x");

        let mut conflicting = request;
        conflicting.argv = vec!["/bin/true".into()];
        let error = executor.exec(conflicting).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::AlreadyExists);
        assert_eq!(fs::read(&marker).unwrap(), b"x");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_streaming_executor_replays_completed_execution_without_reexecuting() {
        let (dir, sandbox) = sandbox();
        let executor = UnixProcessExecutor::new_for_current_user(sandbox);
        let marker = dir.path().join("streaming-execution-marker");
        let request = ExecRequest {
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf x >> \"$MARKER\"; cat \"$MARKER\"".into(),
            ],
            cwd: String::new(),
            execution_id: "schedule-prompt-replay-fixture".into(),
            timeout_ms: 10_000,
            max_output_bytes: 1_024,
            environment: HashMap::from([("MARKER".into(), marker.to_string_lossy().into_owned())]),
        };

        let first = executor
            .exec_stream(request.clone())
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let replay = executor
            .exec_stream(request.clone())
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(fs::read(&marker).unwrap(), b"x");

        let mut conflicting = request;
        conflicting.argv = vec!["/bin/true".into()];
        let error = match executor.exec_stream(conflicting).await {
            Ok(_) => panic!("conflicting streaming replay unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::AlreadyExists);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_terminal_shell_is_bidirectional_and_reaped() {
        let (_dir, sandbox) = sandbox();
        sandbox.ensure_sdk_workspace().unwrap();
        let executor = Arc::new(UnixProcessExecutor::new_for_current_user(sandbox));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = {
            let executor = Arc::clone(&executor);
            tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                executor.serve_terminal(socket).await.unwrap();
            })
        };
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"printf 'terminal-fixture\\n'; exit\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();
        assert!(String::from_utf8_lossy(&output).contains("terminal-fixture"));
        assert_registry_idle(&executor);
    }
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_clears_agent_environment() {
        // SAFETY: this test owns process environment access and does not run in parallel with another env mutator.
        unsafe {
            std::env::set_var("BOXD_BOOT_NONCE_HEX", "must-not-reach-child");
        }
        let (_dir, sandbox) = sandbox();
        let executor = UnixProcessExecutor::new_for_current_user(sandbox);
        let result = executor
            .exec(ExecRequest {
                argv: vec!["/usr/bin/env".into()],
                cwd: "".into(),
                execution_id: "env-test".into(),
                timeout_ms: 10_000,
                max_output_bytes: 4096,
                environment: HashMap::from([
                    ("CUSTOM_TOKEN".into(), "visible".into()),
                    ("PATH".into(), "/unsafe".into()),
                    ("HOME".into(), "/unsafe".into()),
                ]),
            })
            .await
            .unwrap();
        let environment = String::from_utf8(result[0].stdout.clone()).unwrap();
        assert!(!environment.contains("BOXD_BOOT_NONCE_HEX"));
        assert!(environment.contains("CUSTOM_TOKEN=visible"));
        assert!(environment.contains("HOME=/home/boxuser"));
        assert!(
            environment
                .contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        );
        // SAFETY: paired with the setup above in this test.
        unsafe {
            std::env::remove_var("BOXD_BOOT_NONCE_HEX");
        }
    }

    #[test]
    fn exec_environment_rejects_invalid_names_nul_count_and_size() {
        assert!(validate_environment(&HashMap::from([("GOOD_1".into(), "ok".into())])).is_ok());
        for name in ["", "1BAD", "BAD-NAME"] {
            assert_eq!(
                validate_environment(&HashMap::from([(name.into(), "x".into())]))
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        assert!(validate_environment(&HashMap::from([("BAD".into(), "x\0y".into())])).is_err());
        let too_many = (0..=MAX_ENV_VARS)
            .map(|n| (format!("V{n}"), "x".into()))
            .collect();
        assert!(validate_environment(&too_many).is_err());
        assert!(
            validate_environment(&HashMap::from([(
                "BIG".into(),
                "x".repeat(MAX_ENV_TOTAL_BYTES)
            )]))
            .is_err()
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_enforces_timeout() {
        let (_dir, sandbox) = sandbox();
        let executor = UnixProcessExecutor::new_for_current_user(sandbox);
        let error = executor
            .exec(ExecRequest {
                argv: vec!["/bin/sh".into(), "-c".into(), "sleep 2".into()],
                cwd: "".into(),
                execution_id: "timeout-test".into(),
                timeout_ms: 10,
                max_output_bytes: 1024,
                environment: HashMap::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert_registry_idle(&executor);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_preflight_failure_never_registers_or_cancels_placeholder() {
        let (_dir, sandbox) = sandbox();
        let executor = UnixProcessExecutor::new_for_current_user(sandbox);
        let error = executor
            .exec(ExecRequest {
                argv: vec!["/bin/true".into()],
                cwd: "/workspace/missing".into(),
                execution_id: "invalid-folder".into(),
                timeout_ms: 10_000,
                max_output_bytes: 1024,
                environment: HashMap::new(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error.code(),
            tonic::Code::InvalidArgument | tonic::Code::PermissionDenied
        ));
        assert!(!executor.cancel("invalid-folder").await.unwrap());
        assert!(executor.wait_idle(Duration::from_millis(10)).await.unwrap());
        assert_registry_idle(&executor);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_output_limit_cleans_registry_and_reaps_child() {
        let (_dir, sandbox) = sandbox();
        let executor = UnixProcessExecutor::new_for_current_user(sandbox);
        let error = executor
            .exec(ExecRequest {
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf 0123456789abcdef".into(),
                ],
                cwd: "".into(),
                execution_id: "output-limit".into(),
                timeout_ms: 10_000,
                max_output_bytes: 4,
                environment: HashMap::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert!(!executor.cancel("output-limit").await.unwrap());
        assert!(executor.wait_idle(Duration::from_millis(10)).await.unwrap());
        assert_registry_idle(&executor);
    }
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_cancels_process_group() {
        let (_dir, sandbox) = sandbox();
        let mut executor = UnixProcessExecutor::new_for_current_user(sandbox);
        executor.grace = Duration::from_millis(10);
        let executor = Arc::new(executor);
        let running = {
            let executor = executor.clone();
            tokio::spawn(async move {
                executor
                    .exec(ExecRequest {
                        argv: vec!["/bin/sh".into(), "-c".into(), "sleep 10".into()],
                        cwd: "".into(),
                        execution_id: "cancel-test".into(),
                        timeout_ms: 20_000,
                        max_output_bytes: 1024,
                        environment: HashMap::new(),
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(executor.cancel("cancel-test").await.unwrap());
        assert!(running.await.unwrap().is_ok());
        assert!(executor.wait_idle(Duration::from_millis(10)).await.unwrap());
        assert_registry_idle(&executor);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_rejects_concurrent_duplicate_execution_id() {
        let (_dir, sandbox) = sandbox();
        let mut executor = UnixProcessExecutor::new_for_current_user(sandbox);
        executor.grace = Duration::from_millis(10);
        let executor = Arc::new(executor);
        let running = {
            let executor = executor.clone();
            tokio::spawn(async move {
                executor
                    .exec(ExecRequest {
                        argv: vec!["/bin/sh".into(), "-c".into(), "sleep 10".into()],
                        cwd: "".into(),
                        execution_id: "duplicate".into(),
                        timeout_ms: 20_000,
                        max_output_bytes: 1024,
                        environment: HashMap::new(),
                    })
                    .await
            })
        };
        for _ in 0..100 {
            if executor
                .processes
                .lock()
                .unwrap()
                .running
                .contains_key("duplicate")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            executor
                .processes
                .lock()
                .unwrap()
                .running
                .contains_key("duplicate")
        );
        let duplicate = executor
            .exec(ExecRequest {
                argv: vec!["/bin/true".into()],
                cwd: "".into(),
                execution_id: "duplicate".into(),
                timeout_ms: 1_000,
                max_output_bytes: 1024,
                environment: HashMap::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(duplicate.code(), tonic::Code::AlreadyExists);
        assert!(executor.cancel("duplicate").await.unwrap());
        assert!(running.await.unwrap().is_ok());
        assert_registry_idle(&executor);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn unix_executor_aborted_future_drops_registry_guard() {
        let (_dir, sandbox) = sandbox();
        let executor = Arc::new(UnixProcessExecutor::new_for_current_user(sandbox));
        let running = {
            let executor = executor.clone();
            tokio::spawn(async move {
                executor
                    .exec(ExecRequest {
                        argv: vec!["/bin/sh".into(), "-c".into(), "sleep 10".into()],
                        cwd: "".into(),
                        execution_id: "aborted".into(),
                        timeout_ms: 20_000,
                        max_output_bytes: 1024,
                        environment: HashMap::new(),
                    })
                    .await
            })
        };
        for _ in 0..100 {
            if executor
                .processes
                .lock()
                .unwrap()
                .running
                .contains_key("aborted")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());
        assert!(executor.wait_idle(Duration::from_millis(50)).await.unwrap());
        assert!(!executor.cancel("aborted").await.unwrap());
        assert_registry_idle(&executor);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn real_tonic_transport_roundtrips_file_larger_than_default_four_mib() {
        let (_dir, sandbox) = sandbox();
        let agent = Arc::new(GuestAgent::new(
            identity(),
            sandbox,
            Arc::new(FakeExecutor::default()),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_agent = agent.clone();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    box_agent_v1_server::BoxAgentV1Server::from_arc(server_agent)
                        .max_decoding_message_size(2 * 1024 * 1024)
                        .max_encoding_message_size(2 * 1024 * 1024),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = box_agent_v1_client::BoxAgentV1Client::new(channel)
            .max_decoding_message_size(2 * 1024 * 1024)
            .max_encoding_message_size(2 * 1024 * 1024);
        let bytes = vec![0x5a; 5 * 1024 * 1024 + 17];
        let frame_count = bytes.len().div_ceil(FILE_FRAME_BYTES);
        let frames = bytes
            .chunks(FILE_FRAME_BYTES)
            .enumerate()
            .map(|(index, data)| WriteFileFrame {
                path: "/workspace/large.bin".into(),
                data: data.to_vec(),
                eof: index + 1 == frame_count,
            })
            .collect::<Vec<_>>();
        client
            .write_file(authenticated(tokio_stream::iter(frames)))
            .await
            .unwrap();
        let mut stream = client
            .read_file(authenticated(ReadFileRequest {
                path: "/workspace/large.bin".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        let mut received = Vec::new();
        let mut eof = false;
        while let Some(frame) = stream.message().await.unwrap() {
            assert!(frame.data.len() <= FILE_FRAME_BYTES);
            assert!(!eof);
            received.extend_from_slice(&frame.data);
            eof = frame.eof;
        }
        assert!(eof);
        assert_eq!(received, bytes);
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn real_tonic_dial_bridges_only_an_explicit_guest_loopback_port() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            socket.write_all(b"echo:").await.unwrap();
            socket.write_all(&request).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let (_dir, sandbox) = sandbox();
        let agent = Arc::new(GuestAgent::new(
            identity(),
            sandbox,
            Arc::new(FakeExecutor::default()),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    box_agent_v1_server::BoxAgentV1Server::from_arc(agent)
                        .max_decoding_message_size(2 * 1024 * 1024)
                        .max_encoding_message_size(2 * 1024 * 1024),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = box_agent_v1_client::BoxAgentV1Client::new(channel);
        let frames = vec![
            TunnelFrame {
                data: Vec::new(),
                port: u32::from(target_port),
                eof: false,
            },
            TunnelFrame {
                data: b"preview".to_vec(),
                port: 0,
                eof: true,
            },
        ];
        let mut tunnel = client
            .dial(authenticated(tokio_stream::iter(frames)))
            .await
            .unwrap()
            .into_inner();
        let mut received = Vec::new();
        let mut eof = false;
        while let Some(frame) = tunnel.message().await.unwrap() {
            assert_eq!(frame.port, 0);
            received.extend_from_slice(&frame.data);
            eof = frame.eof;
        }
        assert!(eof);
        assert_eq!(received, b"echo:preview");
        echo.await.unwrap();
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn real_tonic_exec_chunks_interleaved_outputs_below_transport_cap() {
        let (_dir, sandbox) = sandbox();
        let executor = Arc::new(FakeExecutor::default());
        *executor.frames.lock().unwrap() = vec![ExecFrame {
            sequence: 0,
            stdout: vec![b'o'; 3 * 1024 * 1024 + 7],
            stderr: vec![b'e'; 3 * 1024 * 1024 + 11],
            exit_code: 9,
            exited: true,
            execution_id: "large-exec".into(),
        }];
        let agent = Arc::new(GuestAgent::new(identity(), sandbox, executor));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    box_agent_v1_server::BoxAgentV1Server::from_arc(agent)
                        .max_decoding_message_size(2 * 1024 * 1024)
                        .max_encoding_message_size(2 * 1024 * 1024),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = box_agent_v1_client::BoxAgentV1Client::new(channel)
            .max_decoding_message_size(2 * 1024 * 1024)
            .max_encoding_message_size(2 * 1024 * 1024);
        let mut stream = client
            .exec(authenticated(ExecRequest {
                argv: vec!["true".into()],
                execution_id: "large-exec".into(),
                max_output_bytes: 8 * 1024 * 1024,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        let mut sequence = 0;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = None;
        while let Some(frame) = stream.message().await.unwrap() {
            assert_eq!(frame.sequence, sequence);
            assert!(frame.stdout.len().max(frame.stderr.len()) <= EXEC_FRAME_BYTES);
            sequence += 1;
            stdout.extend(frame.stdout);
            stderr.extend(frame.stderr);
            if frame.exited {
                exit = Some(frame.exit_code);
            }
        }
        assert_eq!(stdout, vec![b'o'; 3 * 1024 * 1024 + 7]);
        assert_eq!(stderr, vec![b'e'; 3 * 1024 * 1024 + 11]);
        assert_eq!(exit, Some(9));
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }
}
