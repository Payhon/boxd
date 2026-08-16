use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    os::unix::process::CommandExt,
    os::unix::{ffi::OsStrExt, fs::DirBuilderExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use box_agent_proto::v1::{BrowserFrame, BrowserRequest};
use box_egress::{EgressDecision, evaluate_tcp_connect};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{net::lookup_host, sync::Mutex, time::timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tonic::Status;
use url::Url;

use crate::{BrowserBackend, boxuser_identity};

const START_TIMEOUT: Duration = Duration::from_secs(15);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const FRAME_BYTES: usize = 512 * 1024;
const MAX_CONTENT_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_AGENT_TEXT_BYTES: usize = 1024 * 1024;
const MAX_AGENT_ELEMENTS: usize = 512;

/// Guest-only Chromium/CDP adapter. Chromium listens on loopback and target IDs
/// are translated to random opaque IDs before crossing the agent boundary.
pub struct ChromiumBrowserBackend {
    executable: PathBuf,
    state: Mutex<Option<ChromiumSession>>,
}

struct ChromiumSession {
    child: Child,
    profile: PathBuf,
    origin: String,
    port: u16,
    browser_websocket_path: String,
    client: reqwest::Client,
    opaque_to_target: HashMap<String, String>,
    active_opaque: Option<String>,
}

struct ProfileGuard(Option<PathBuf>);

impl ProfileGuard {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn keep(mut self) -> PathBuf {
        self.0.take().expect("profile guard always owns a path")
    }
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ChromeTarget {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(rename = "webSocketDebuggerUrl", default)]
    websocket_url: String,
}

impl ChromiumBrowserBackend {
    pub fn new(executable: impl Into<PathBuf>) -> Result<Self, Status> {
        let executable = executable.into();
        if !executable.is_absolute() || !executable.is_file() {
            return Err(Status::failed_precondition(
                "configured Chromium executable is unavailable",
            ));
        }
        Ok(Self {
            executable,
            state: Mutex::new(None),
        })
    }

    async fn session<'a>(
        &'a self,
        state: &'a mut Option<ChromiumSession>,
    ) -> Result<&'a mut ChromiumSession, Status> {
        let exited = match state.as_mut() {
            Some(session) => session
                .child
                .try_wait()
                .map_err(|_| Status::unavailable("failed to inspect Chromium process"))?
                .is_some(),
            None => true,
        };
        if exited {
            if let Some(mut previous) = state.take() {
                terminate_chromium(&mut previous.child);
                let _ = tokio::fs::remove_dir_all(previous.profile).await;
            }
            *state = Some(self.launch().await?);
        }
        state
            .as_mut()
            .ok_or_else(|| Status::unavailable("Chromium session is unavailable"))
    }

    async fn launch(&self) -> Result<ChromiumSession, Status> {
        let profile = private_profile_dir()?;
        let profile_guard = ProfileGuard::new(profile.clone());
        let stderr_path = profile.join("chromium.stderr");
        let stderr = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&stderr_path)
            .map_err(|_| Status::unavailable("failed to create Chromium diagnostics"))?;
        // The agent is PID 1/root so it can safely service the guest, but the
        // browser must run as the unprivileged boxuser and must not inherit the
        // boot nonce or other agent-only identity environment.
        let identity = if unsafe { libc::geteuid() } == 0 {
            Some(boxuser_identity()?)
        } else {
            None
        };
        if let Some(identity) = &identity {
            let profile_path = std::ffi::CString::new(profile.as_os_str().as_bytes())
                .map_err(|_| Status::unavailable("Chromium profile path is invalid"))?;
            // SAFETY: profile_path is a live NUL-terminated path to the newly
            // created private directory; uid/gid were resolved in the parent.
            if unsafe { libc::chown(profile_path.as_ptr(), identity.uid, identity.gid) } != 0 {
                return Err(Status::unavailable(
                    "failed to assign Chromium profile ownership",
                ));
            }
        }
        let working_directory = if Path::new("/workspace/home").is_dir() {
            Path::new("/workspace/home")
        } else {
            profile.as_path()
        };
        let child_home = identity
            .as_ref()
            .map(|_| std::ffi::OsString::from("/home/boxuser"))
            .or_else(|| std::env::var_os("HOME"))
            .unwrap_or_else(|| profile.as_os_str().to_owned());
        let child_user = identity
            .as_ref()
            .map(|_| std::ffi::OsString::from("boxuser"))
            .or_else(|| std::env::var_os("USER"))
            .unwrap_or_else(|| std::ffi::OsString::from("boxuser"));
        #[cfg(target_os = "macos")]
        let group_count = identity
            .as_ref()
            .map(|identity| i32::try_from(identity.groups.len()))
            .transpose()
            .map_err(|_| Status::failed_precondition("boxuser has too many groups"))?
            .unwrap_or(0);
        let mut command = Command::new(&self.executable);
        if identity.is_some() {
            command.env_clear();
        }
        command
            .env("HOME", child_home)
            .env("USER", child_user)
            .env("LANG", "C.UTF-8")
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("TMPDIR", "/tmp")
            .current_dir(working_directory)
            .args([
                "--headless=new",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                "--disable-background-networking",
                "--disable-breakpad",
                "--disable-component-update",
                "--disable-crash-reporter",
                "--disable-default-apps",
                "--disable-dev-shm-usage",
                "--disable-sync",
                "--metrics-recording-only",
                "--no-default-browser-check",
                "--no-first-run",
            ])
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        // SAFETY: the closure performs only allocation-free libc syscalls in
        // the post-fork child. Identity/group storage is resolved in the
        // parent before spawn and moved into the closure.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(identity) = &identity {
                    #[cfg(target_os = "macos")]
                    let setgroups_result = libc::setgroups(group_count, identity.groups.as_ptr());
                    #[cfg(not(target_os = "macos"))]
                    let setgroups_result =
                        libc::setgroups(identity.groups.len(), identity.groups.as_ptr());
                    if setgroups_result != 0
                        || libc::setgid(identity.gid) != 0
                        || libc::setuid(identity.uid) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| Status::unavailable("failed to start Chromium"))?;
        let port_file = profile.join("DevToolsActivePort");
        let deadline = Instant::now() + START_TIMEOUT;
        let (port, browser_websocket_path) = loop {
            let child_status = match child.try_wait() {
                Ok(status) => status,
                Err(_) => {
                    terminate_chromium(&mut child);
                    return Err(Status::unavailable("failed to inspect Chromium startup"));
                }
            };
            if let Some(status) = child_status {
                terminate_chromium(&mut child);
                report_test_startup_diagnostics(&stderr_path).await;
                let _ = tokio::fs::remove_dir_all(&profile).await;
                return Err(Status::unavailable(format!(
                    "Chromium exited during startup with {status}"
                )));
            }
            if let Ok(contents) = tokio::fs::read_to_string(&port_file).await {
                let mut lines = contents.lines();
                if let (Some(raw_port), Some(path)) = (lines.next(), lines.next())
                    && lines.next().is_none()
                    && let Ok(port) = raw_port.parse::<u16>()
                    && port != 0
                    && valid_browser_websocket_path(path)
                {
                    break (port, path.to_owned());
                }
            }
            if Instant::now() >= deadline {
                terminate_chromium(&mut child);
                report_test_startup_diagnostics(&stderr_path).await;
                let _ = tokio::fs::remove_dir_all(&profile).await;
                return Err(Status::deadline_exceeded("Chromium startup timed out"));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let client = match reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(_) => {
                terminate_chromium(&mut child);
                return Err(Status::unavailable("failed to initialize Chromium client"));
            }
        };
        Ok(ChromiumSession {
            child,
            profile: profile_guard.keep(),
            origin: format!("http://127.0.0.1:{port}"),
            port,
            browser_websocket_path,
            client,
            opaque_to_target: HashMap::new(),
            active_opaque: None,
        })
    }
}

async fn report_test_startup_diagnostics(path: &Path) {
    #[cfg(test)]
    {
        if let Ok(mut contents) = tokio::fs::read_to_string(path).await {
            contents.truncate(contents.len().min(4 * 1024));
            eprintln!("Chromium startup diagnostics: {contents}");
        }
        if let Some(parent) = path.parent() {
            let entries = std::fs::read_dir(parent)
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .collect::<Vec<_>>();
            eprintln!("Chromium startup profile entries: {entries:?}");
        }
    }
    #[cfg(not(test))]
    let _ = path;
}

impl Drop for ChromiumBrowserBackend {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.try_lock()
            && let Some(mut session) = state.take()
        {
            terminate_chromium(&mut session.child);
            let _ = std::fs::remove_dir_all(session.profile);
        }
    }
}

#[async_trait]
impl BrowserBackend for ChromiumBrowserBackend {
    async fn execute(&self, request: BrowserRequest) -> Result<Vec<BrowserFrame>, Status> {
        let mut state = self.state.lock().await;
        let session = self.session(&mut state).await?;
        match request.operation.as_str() {
            "create_tab" => {
                validate_navigation(&request.url).await?;
                let target = session.create_target().await?;
                if let Err(error) = navigate(
                    &target.websocket_url,
                    &request.url,
                    &request.wait_until,
                    request.timeout_ms,
                )
                .await
                {
                    let _ = session.close_target(&target.id).await;
                    return Err(error);
                }
                let target = session.target(&target.id).await?;
                let opaque = session.opaque_for(&target.id);
                session.active_opaque = Some(opaque.clone());
                json_frame(json!({"id": opaque, "url": target.url, "title": target.title}))
            }
            "list_tabs" => {
                let targets = session.sync_tabs().await?;
                let tabs = targets
                    .into_iter()
                    .map(|target| {
                        let opaque = session.opaque_for(&target.id);
                        json!({"id": opaque, "url": target.url, "title": target.title})
                    })
                    .collect::<Vec<_>>();
                json_frame(json!({"tabs": tabs}))
            }
            "close_tab" => {
                let target_id = session.target_id(&request.tab_id)?.to_owned();
                session.close_target(&target_id).await?;
                session.opaque_to_target.remove(&request.tab_id);
                if session.active_opaque.as_deref() == Some(request.tab_id.as_str()) {
                    session.active_opaque = None;
                }
                json_frame(json!({}))
            }
            "goto" => {
                session.active_opaque = Some(request.tab_id.clone());
                validate_navigation(&request.url).await?;
                let target = session.target_for_opaque(&request.tab_id).await?;
                navigate(
                    &target.websocket_url,
                    &request.url,
                    "load",
                    request.timeout_ms,
                )
                .await?;
                json_frame(page_content(&target.websocket_url).await?)
            }
            "content" => {
                session.active_opaque = Some(request.tab_id.clone());
                let target = session.target_for_opaque(&request.tab_id).await?;
                json_frame(page_content(&target.websocket_url).await?)
            }
            "screenshot" => {
                session.active_opaque = Some(request.tab_id.clone());
                let target = session.target_for_opaque(&request.tab_id).await?;
                binary_frames(capture_screenshot(&target.websocket_url, request.full_page).await?)
            }
            "connect" => json_frame(json!({
                "port": session.port,
                "websocket_path": session.browser_websocket_path,
            })),
            "screencast" => {
                session.active_opaque = Some(request.tab_id.clone());
                let target = session.target_for_opaque(&request.tab_id).await?;
                let websocket_path = target_websocket_path(&target.websocket_url, session.port)?;
                json_frame(json!({
                    "port": session.port,
                    "websocket_path": websocket_path,
                }))
            }
            "recording_target" => {
                let targets = session.sync_tabs().await?;
                if session
                    .active_opaque
                    .as_ref()
                    .is_none_or(|opaque| !session.opaque_to_target.contains_key(opaque))
                {
                    let target = targets
                        .first()
                        .ok_or_else(|| Status::failed_precondition("browser has no open tab"))?;
                    session.active_opaque = Some(session.opaque_for(&target.id));
                }
                let opaque = session
                    .active_opaque
                    .clone()
                    .ok_or_else(|| Status::failed_precondition("browser has no active tab"))?;
                let target = session.target_for_opaque(&opaque).await?;
                let websocket_path = target_websocket_path(&target.websocket_url, session.port)?;
                json_frame(json!({
                    "port": session.port,
                    "websocket_path": websocket_path,
                    "tab_id": opaque,
                    "title": target.title,
                    "url": target.url,
                }))
            }
            "snapshot" => {
                session.active_opaque = Some(request.tab_id.clone());
                let target = session.target_for_opaque(&request.tab_id).await?;
                json_frame(agent_snapshot(&target.websocket_url).await?)
            }
            "perform" => {
                session.active_opaque = Some(request.tab_id.clone());
                let target = session.target_for_opaque(&request.tab_id).await?;
                let action: BrowserAction = serde_json::from_str(&request.json_payload)
                    .map_err(|_| Status::invalid_argument("invalid browser action"))?;
                perform_browser_action(&target.websocket_url, action).await?;
                json_frame(json!({"success": true}))
            }
            _ => Err(Status::unimplemented("feature_not_supported")),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserAction {
    method: String,
    #[serde(default)]
    selector: String,
    #[serde(default)]
    arguments: Vec<String>,
}

fn target_websocket_path(raw: &str, expected_port: u16) -> Result<String, Status> {
    let parsed = Url::parse(raw)
        .map_err(|_| Status::data_loss("Chromium target websocket URL is invalid"))?;
    let path = parsed.path();
    if parsed.scheme() != "ws"
        || parsed.host_str() != Some("127.0.0.1")
        || parsed.port() != Some(expected_port)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || path.len() > 512
        || !path.starts_with("/devtools/page/")
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'?' && byte != b'#')
    {
        return Err(Status::data_loss(
            "Chromium target websocket URL is invalid",
        ));
    }
    Ok(path.to_owned())
}

fn valid_browser_websocket_path(path: &str) -> bool {
    path.len() <= 512
        && path.starts_with("/devtools/browser/")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'?' && byte != b'#')
}

impl ChromiumSession {
    async fn targets(&self) -> Result<Vec<ChromeTarget>, Status> {
        let response = self
            .client
            .get(format!("{}/json/list", self.origin))
            .send()
            .await
            .map_err(|_| Status::unavailable("Chromium target query failed"))?;
        if !response.status().is_success() {
            return Err(Status::unavailable("Chromium target query failed"));
        }
        response
            .json::<Vec<ChromeTarget>>()
            .await
            .map_err(|_| Status::data_loss("Chromium target response is invalid"))
    }

    async fn sync_tabs(&mut self) -> Result<Vec<ChromeTarget>, Status> {
        let targets = self
            .targets()
            .await?
            .into_iter()
            .filter(|target| target.kind == "page" && !target.websocket_url.is_empty())
            .collect::<Vec<_>>();
        let existing = targets
            .iter()
            .map(|target| target.id.as_str())
            .collect::<HashSet<_>>();
        self.opaque_to_target
            .retain(|_, target_id| existing.contains(target_id.as_str()));
        Ok(targets)
    }

    async fn create_target(&mut self) -> Result<ChromeTarget, Status> {
        let response = self
            .client
            .put(format!("{}/json/new?about:blank", self.origin))
            .send()
            .await
            .map_err(|_| Status::unavailable("Chromium tab creation failed"))?;
        if !response.status().is_success() {
            return Err(Status::unavailable("Chromium tab creation failed"));
        }
        response
            .json()
            .await
            .map_err(|_| Status::data_loss("Chromium tab response is invalid"))
    }

    async fn close_target(&self, target_id: &str) -> Result<(), Status> {
        let response = self
            .client
            .get(format!("{}/json/close/{target_id}", self.origin))
            .send()
            .await
            .map_err(|_| Status::unavailable("Chromium tab close failed"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Status::not_found("browser tab not found"))
        }
    }

    async fn target(&self, target_id: &str) -> Result<ChromeTarget, Status> {
        self.targets()
            .await?
            .into_iter()
            .find(|target| target.id == target_id && target.kind == "page")
            .ok_or_else(|| Status::not_found("browser tab not found"))
    }

    async fn target_for_opaque(&self, opaque: &str) -> Result<ChromeTarget, Status> {
        self.target(self.target_id(opaque)?).await
    }

    fn target_id(&self, opaque: &str) -> Result<&str, Status> {
        self.opaque_to_target
            .get(opaque)
            .map(String::as_str)
            .ok_or_else(|| Status::not_found("browser tab not found"))
    }

    fn opaque_for(&mut self, target_id: &str) -> String {
        if let Some((opaque, _)) = self
            .opaque_to_target
            .iter()
            .find(|(_, mapped)| mapped.as_str() == target_id)
        {
            return opaque.clone();
        }
        let opaque = random_id("tab_");
        self.opaque_to_target
            .insert(opaque.clone(), target_id.to_owned());
        opaque
    }
}

async fn validate_navigation(raw: &str) -> Result<(), Status> {
    // `about:blank` is Chromium's inert, network-free document and is useful
    // for callers that populate a page through the authenticated CDP tunnel.
    // No other non-HTTP scheme is accepted.
    if raw == "about:blank" {
        return Ok(());
    }
    let parsed = Url::parse(raw).map_err(|_| Status::invalid_argument("invalid browser URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Status::invalid_argument(
            "browser URL must be an unauthenticated HTTP(S) URL",
        ));
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| Status::invalid_argument("browser URL has no valid port"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| Status::invalid_argument("browser URL has no host"))?;
    let addresses = lookup_host((host, port))
        .await
        .map_err(|_| Status::unavailable("browser DNS resolution failed"))?
        .map(|socket| socket.ip())
        .collect::<Vec<_>>();
    validate_resolved_addresses(port, &addresses)
}

fn validate_resolved_addresses(port: u16, addresses: &[IpAddr]) -> Result<(), Status> {
    // The Phase-1 packet plane is IPv4-only. Ignore native IPv6 answers here,
    // while requiring every connectable IPv4 answer to pass the exact TCP
    // policy. The packet plane repeats the check on the numeric destination.
    let ipv4 = addresses.iter().filter_map(|address| match address {
        IpAddr::V4(address) => Some(IpAddr::V4(*address)),
        IpAddr::V6(address) => address.to_ipv4_mapped().map(IpAddr::V4),
    });
    let decisions = ipv4
        .map(|address| evaluate_tcp_connect(address, port))
        .collect::<Vec<_>>();
    if decisions.is_empty()
        || decisions
            .iter()
            .any(|decision| *decision != EgressDecision::Allow)
    {
        return Err(Status::permission_denied(
            "browser navigation is blocked by egress policy",
        ));
    }
    Ok(())
}

async fn navigate(
    websocket_url: &str,
    url: &str,
    wait_until: &str,
    timeout_ms: u64,
) -> Result<(), Status> {
    let timeout_ms = if timeout_ms == 0 { 30_000 } else { timeout_ms };
    let wait = Duration::from_millis(timeout_ms.min(2_147_000_000));
    timeout(wait, async {
        let (mut socket, _) = connect_async(websocket_url)
            .await
            .map_err(|_| Status::unavailable("Chromium CDP connection failed"))?;
        send_cdp(&mut socket, 1, "Page.enable", json!({})).await?;
        wait_cdp_response(&mut socket, 1).await?;
        send_cdp(
            &mut socket,
            2,
            "Page.setLifecycleEventsEnabled",
            json!({"enabled": true}),
        )
        .await?;
        wait_cdp_response(&mut socket, 2).await?;
        send_cdp(&mut socket, 3, "Page.navigate", json!({"url": url})).await?;
        let response = wait_cdp_response(&mut socket, 3).await?;
        if response
            .get("errorText")
            .and_then(Value::as_str)
            .is_some_and(|error| !error.is_empty())
        {
            return Err(Status::unavailable("Chromium navigation failed"));
        }
        let wanted = match wait_until {
            "domcontentloaded" => "DOMContentLoaded",
            "networkidle" => "networkIdle",
            _ => "load",
        };
        if wanted != "networkIdle" {
            drop(socket);
            loop {
                let result = cdp_call(
                    websocket_url,
                    "Runtime.evaluate",
                    json!({"expression":"document.readyState","returnByValue":true}),
                )
                .await?;
                let ready_state = result.pointer("/result/value").and_then(Value::as_str);
                let ready = if wanted == "DOMContentLoaded" {
                    matches!(ready_state, Some("interactive" | "complete"))
                } else {
                    ready_state == Some("complete")
                };
                if ready {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        while let Some(message) = socket.next().await {
            let message = message.map_err(|_| Status::unavailable("Chromium CDP stream failed"))?;
            let Some(text) = message.to_text().ok() else {
                continue;
            };
            let event: Value = serde_json::from_str(text)
                .map_err(|_| Status::data_loss("Chromium CDP event is invalid"))?;
            trace_cdp("navigation", &event);
            let lifecycle = event
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if lifecycle == wanted {
                return Ok(());
            }
        }
        Err(Status::unavailable("Chromium CDP stream closed"))
    })
    .await
    .map_err(|_| Status::deadline_exceeded("Chromium navigation timed out"))?
}

async fn page_content(websocket_url: &str) -> Result<Value, Status> {
    let expression = format!(
        r#"(() => ({{title: document.title || '', url: location.href, text: (document.body?.innerText || '').slice(0, {MAX_CONTENT_TEXT_BYTES}), links: Array.from(document.links).slice(0, 4096).map(link => ({{text: (link.innerText || '').slice(0, 4096), href: link.href || ''}}))}}))()"#
    );
    let result = cdp_call(
        websocket_url,
        "Runtime.evaluate",
        json!({"expression": expression, "returnByValue": true, "awaitPromise": true}),
    )
    .await?;
    result
        .pointer("/result/value")
        .cloned()
        .ok_or_else(|| Status::data_loss("Chromium content response is invalid"))
}

async fn agent_snapshot(websocket_url: &str) -> Result<Value, Status> {
    let expression = format!(
        r#"(() => {{
          const selectorFor = (element) => {{
            if (element.id) return '#' + CSS.escape(element.id);
            const testId = element.getAttribute('data-testid');
            if (testId) return '[data-testid="' + CSS.escape(testId) + '"]';
            const parts = [];
            let current = element;
            while (current && current.nodeType === Node.ELEMENT_NODE && parts.length < 12) {{
              let part = current.tagName.toLowerCase();
              const parent = current.parentElement;
              if (parent) {{
                const same = Array.from(parent.children).filter((child) => child.tagName === current.tagName);
                if (same.length > 1) part += ':nth-of-type(' + (same.indexOf(current) + 1) + ')';
              }}
              parts.unshift(part);
              if (current === document.body) break;
              current = parent;
            }}
            return parts.join(' > ');
          }};
          const candidates = Array.from(document.querySelectorAll('a,button,input,textarea,select,[role="button"],[role="link"],[contenteditable="true"],[tabindex]'));
          const elements = [];
          for (const element of candidates) {{
            if (elements.length >= {MAX_AGENT_ELEMENTS}) break;
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            if (rect.width <= 0 || rect.height <= 0 || style.visibility === 'hidden' || style.display === 'none') continue;
            const description = (element.getAttribute('aria-label') || element.getAttribute('placeholder') || element.getAttribute('title') || element.innerText || element.textContent || '').trim().slice(0, 1024);
            const selector = selectorFor(element);
            if (!selector) continue;
            elements.push({{
              selector,
              description,
              tag: element.tagName.toLowerCase(),
              role: element.getAttribute('role') || '',
              type: element.getAttribute('type') || '',
              url: element instanceof HTMLAnchorElement ? element.href : undefined
            }});
          }}
          return {{
            title: document.title || '',
            url: location.href,
            text: (document.body?.innerText || '').slice(0, {MAX_AGENT_TEXT_BYTES}),
            elements
          }};
        }})()"#
    );
    let result = cdp_call(
        websocket_url,
        "Runtime.evaluate",
        json!({"expression": expression, "returnByValue": true, "awaitPromise": true}),
    )
    .await?;
    result
        .pointer("/result/value")
        .cloned()
        .ok_or_else(|| Status::data_loss("Chromium agent snapshot is invalid"))
}

async fn perform_browser_action(websocket_url: &str, action: BrowserAction) -> Result<(), Status> {
    if action.method.len() > 32
        || action.selector.len() > 8 * 1024
        || action.arguments.len() > 8
        || action.arguments.iter().any(|value| value.len() > 16 * 1024)
    {
        return Err(Status::invalid_argument("browser action exceeds limit"));
    }
    if action.method == "navigate" {
        let url = action
            .arguments
            .first()
            .ok_or_else(|| Status::invalid_argument("navigate requires a URL"))?;
        validate_navigation(url).await?;
        return navigate(websocket_url, url, "load", 60_000).await;
    }
    if action.method == "wait" {
        let millis = action
            .arguments
            .first()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(250)
            .min(5_000);
        tokio::time::sleep(Duration::from_millis(millis)).await;
        return Ok(());
    }
    if !matches!(
        action.method.as_str(),
        "click" | "fill" | "press" | "select" | "scroll"
    ) || (action.method != "scroll" && action.selector.is_empty())
    {
        return Err(Status::invalid_argument("unsupported browser action"));
    }
    let action = serde_json::to_string(&json!({
        "method": action.method,
        "selector": action.selector,
        "arguments": action.arguments,
    }))
    .map_err(|_| Status::invalid_argument("browser action is invalid"))?;
    let expression = format!(
        r#"(() => {{
          const action = {action};
          if (action.method === 'scroll') {{
            const x = Number(action.arguments[0] || 0);
            const y = Number(action.arguments[1] || 600);
            window.scrollBy({{left: x, top: y, behavior: 'instant'}});
            return {{ok: true}};
          }}
          const element = document.querySelector(action.selector);
          if (!element) return {{ok: false, error: 'target_not_found'}};
          element.scrollIntoView({{block: 'center', inline: 'center'}});
          element.focus();
          if (action.method === 'click') element.click();
          if (action.method === 'fill') {{
            const value = String(action.arguments[0] || '');
            const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), 'value')?.set;
            if (setter) setter.call(element, value); else element.value = value;
            element.dispatchEvent(new InputEvent('input', {{bubbles: true, inputType: 'insertText', data: value}}));
            element.dispatchEvent(new Event('change', {{bubbles: true}}));
          }}
          if (action.method === 'select') {{
            element.value = String(action.arguments[0] || '');
            element.dispatchEvent(new Event('change', {{bubbles: true}}));
          }}
          if (action.method === 'press') {{
            const key = String(action.arguments[0] || 'Enter');
            element.dispatchEvent(new KeyboardEvent('keydown', {{key, bubbles: true}}));
            element.dispatchEvent(new KeyboardEvent('keyup', {{key, bubbles: true}}));
            if (key === 'Enter' && element.form) element.form.requestSubmit?.();
          }}
          return {{ok: true}};
        }})()"#
    );
    let result = cdp_call(
        websocket_url,
        "Runtime.evaluate",
        json!({"expression": expression, "returnByValue": true, "awaitPromise": true}),
    )
    .await?;
    if result.pointer("/result/value/ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(Status::not_found("browser action target not found"))
    }
}

async fn capture_screenshot(websocket_url: &str, full_page: bool) -> Result<Vec<u8>, Status> {
    let mut params = json!({"format": "png", "fromSurface": true});
    if full_page {
        let metrics = cdp_call(websocket_url, "Page.getLayoutMetrics", json!({})).await?;
        let size = metrics
            .get("cssContentSize")
            .or_else(|| metrics.get("contentSize"))
            .ok_or_else(|| Status::data_loss("Chromium layout response is invalid"))?;
        let width = size.get("width").and_then(Value::as_f64).unwrap_or(0.0);
        let height = size.get("height").and_then(Value::as_f64).unwrap_or(0.0);
        if width <= 0.0 || height <= 0.0 || width * height > 268_435_456.0 {
            return Err(Status::resource_exhausted(
                "browser screenshot dimensions exceed limit",
            ));
        }
        params["captureBeyondViewport"] = Value::Bool(true);
        params["clip"] = json!({"x": 0, "y": 0, "width": width, "height": height, "scale": 1});
    }
    let result = cdp_call(websocket_url, "Page.captureScreenshot", params).await?;
    let encoded = result
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| Status::data_loss("Chromium screenshot response is invalid"))?;
    BASE64
        .decode(encoded)
        .map_err(|_| Status::data_loss("Chromium screenshot payload is invalid"))
}

async fn cdp_call(websocket_url: &str, method: &str, params: Value) -> Result<Value, Status> {
    timeout(COMMAND_TIMEOUT, async {
        let (mut socket, _) = connect_async(websocket_url)
            .await
            .map_err(|_| Status::unavailable("Chromium CDP connection failed"))?;
        send_cdp(&mut socket, 1, method, params).await?;
        wait_cdp_response(&mut socket, 1).await
    })
    .await
    .map_err(|_| Status::deadline_exceeded("Chromium CDP command timed out"))?
}

async fn send_cdp<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
    id: u64,
    method: &str,
    params: Value,
) -> Result<(), Status>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    socket
        .send(Message::Text(
            json!({"id": id, "method": method, "params": params})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|_| Status::unavailable("Chromium CDP send failed"))
}

async fn wait_cdp_response<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
    wanted_id: u64,
) -> Result<Value, Status>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(message) = socket.next().await {
        let message = message.map_err(|_| Status::unavailable("Chromium CDP stream failed"))?;
        let Some(text) = message.to_text().ok() else {
            continue;
        };
        let response: Value = serde_json::from_str(text)
            .map_err(|_| Status::data_loss("Chromium CDP response is invalid"))?;
        trace_cdp("command", &response);
        if response.get("id").and_then(Value::as_u64) == Some(wanted_id) {
            if response.get("error").is_some() {
                return Err(Status::unavailable("Chromium CDP command failed"));
            }
            return response
                .get("result")
                .cloned()
                .ok_or_else(|| Status::data_loss("Chromium CDP result is missing"));
        }
    }
    Err(Status::unavailable("Chromium CDP stream closed"))
}

fn trace_cdp(scope: &str, value: &Value) {
    #[cfg(debug_assertions)]
    if std::env::var_os("BOXD_BROWSER_TRACE").is_some() {
        eprintln!(
            "browser CDP {scope}: id={:?} method={:?} error={}",
            value.get("id").and_then(Value::as_u64),
            value.get("method").and_then(Value::as_str),
            value.get("error").is_some()
        );
    }
    #[cfg(not(debug_assertions))]
    let _ = (scope, value);
}

fn json_frame(value: Value) -> Result<Vec<BrowserFrame>, Status> {
    let payload = serde_json::to_string(&value)
        .map_err(|_| Status::internal("failed to encode browser response"))?;
    if payload.len() > 16 * 1024 * 1024 {
        return Err(Status::resource_exhausted(
            "browser JSON response exceeds size limit",
        ));
    }
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let mut end = (offset + FRAME_BYTES).min(payload.len());
        while end > offset && !payload.is_char_boundary(end) {
            end -= 1;
        }
        if end == offset {
            return Err(Status::internal("failed to split browser JSON response"));
        }
        frames.push(BrowserFrame {
            sequence: frames.len() as u64,
            json_payload: payload[offset..end].to_owned(),
            data: Vec::new(),
            eof: end == payload.len(),
        });
        offset = end;
    }
    Ok(frames)
}

fn binary_frames(bytes: Vec<u8>) -> Result<Vec<BrowserFrame>, Status> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
        return Err(Status::resource_exhausted(
            "browser screenshot exceeds size limit",
        ));
    }
    let chunks = bytes.chunks(FRAME_BYTES).collect::<Vec<_>>();
    Ok(chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| BrowserFrame {
            sequence: index as u64,
            json_payload: String::new(),
            data: chunk.to_vec(),
            eof: index + 1 == chunks.len(),
        })
        .collect())
}

fn private_profile_dir() -> Result<PathBuf, Status> {
    let path = Path::new("/tmp").join(random_id("boxd-chromium-"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| Status::unavailable("failed to create Chromium profile"))?;
    Ok(path)
}

fn terminate_chromium(child: &mut Child) {
    if let Ok(process_group) = i32::try_from(child.id()) {
        // SAFETY: the child established a distinct process group before exec;
        // a negative PID targets only that group. ESRCH is an idempotent exit.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).expect("OS randomness is required for browser identities");
    let mut value = String::with_capacity(prefix.len() + bytes.len() * 2);
    value.push_str(prefix);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn browser_websocket_path_is_absolute_bounded_and_header_safe() {
        assert!(valid_browser_websocket_path(
            "/devtools/browser/019ff-browser"
        ));
        for invalid in [
            "devtools/browser/id",
            "/devtools/page/id",
            "/devtools/browser/id?ticket=secret",
            "/devtools/browser/id#fragment",
            "/devtools/browser/id\nheader",
        ] {
            assert!(!valid_browser_websocket_path(invalid), "{invalid:?}");
        }
        assert!(!valid_browser_websocket_path(&format!(
            "/devtools/browser/{}",
            "a".repeat(513)
        )));
    }

    #[test]
    fn screencast_target_path_is_loopback_port_bound_and_header_safe() {
        assert_eq!(
            target_websocket_path("ws://127.0.0.1:37777/devtools/page/opaque", 37_777).unwrap(),
            "/devtools/page/opaque"
        );
        for invalid in [
            "ws://127.0.0.1:37778/devtools/page/opaque",
            "ws://localhost:37777/devtools/page/opaque",
            "wss://127.0.0.1:37777/devtools/page/opaque",
            "ws://127.0.0.1:37777/devtools/browser/opaque",
            "ws://127.0.0.1:37777/devtools/page/opaque?secret=value",
        ] {
            assert!(target_websocket_path(invalid, 37_777).is_err(), "{invalid}");
        }
    }

    #[test]
    fn browser_navigation_reuses_restricted_default_policy() {
        assert!(
            validate_resolved_addresses(443, &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
                .is_ok()
        );
        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert!(validate_resolved_addresses(443, &[address]).is_err());
        }
        assert!(
            validate_resolved_addresses(8080, &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
                .is_err()
        );
    }

    #[tokio::test]
    async fn browser_navigation_allows_only_the_inert_about_blank_document() {
        validate_navigation("about:blank").await.unwrap();
        for invalid in ["about:srcdoc", "about:blank#fragment", "file:///etc/passwd"] {
            assert!(validate_navigation(invalid).await.is_err(), "{invalid}");
        }
    }

    #[test]
    fn browser_frames_are_bounded_and_opaque_ids_are_random() {
        let first = random_id("tab_");
        let second = random_id("tab_");
        assert!(first.starts_with("tab_"));
        assert_ne!(first, second);
        let frames = binary_frames(vec![7; FRAME_BYTES + 1]).unwrap();
        assert_eq!(frames.len(), 2);
        assert!(!frames[0].eof);
        assert!(frames[1].eof);
    }

    #[test]
    fn browser_json_frames_preserve_utf8_across_transport_boundaries() {
        let text = "界".repeat(FRAME_BYTES / 2);
        let frames = json_frame(json!({"text": text})).unwrap();
        assert!(frames.len() > 1);
        assert!(
            frames
                .iter()
                .all(|frame| frame.json_payload.len() <= FRAME_BYTES)
        );
        assert!(frames[..frames.len() - 1].iter().all(|frame| !frame.eof));
        assert!(frames.last().unwrap().eof);
        let payload = frames
            .into_iter()
            .map(|frame| frame.json_payload)
            .collect::<String>();
        let decoded: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            decoded["text"].as_str().unwrap().chars().count(),
            FRAME_BYTES / 2
        );
    }
}
