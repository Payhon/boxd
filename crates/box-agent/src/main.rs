//! PID 1 entrypoint baked into a runtime bundle.  The worker maps vsock port
//! 18080 to the host-owned agent socket; this process never opens TCP.
#[cfg(unix)]
use box_agent::{
    AgentIdentity, ChromiumBrowserBackend, FileSandbox, GuestAgent, UnixProcessExecutor,
};
#[cfg(unix)]
use box_agent_proto::v1::box_agent_v1_server::BoxAgentV1Server;
#[cfg(unix)]
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

#[cfg(unix)]
fn configure_resolver(path: &Path, network_mode: &str) -> Result<(), Box<dyn std::error::Error>> {
    let contents = match network_mode {
        "restricted-default" => "nameserver 192.0.2.1\noptions attempts:2 timeout:1\n",
        "deny-all" => "options attempts:1 timeout:1\n",
        _ => return Err("BOXD_NETWORK_MODE is invalid".into()),
    };
    let parent = path.parent().ok_or("resolver path has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("resolver parent must be a real directory".into());
    }
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| "OS randomness is unavailable")?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = parent.join(format!(".boxd-resolv-{}-{}", std::process::id(), suffix));
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
struct VsockIo(tokio_vsock::VsockStream);
#[cfg(unix)]
impl tonic::transport::server::Connected for VsockIo {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}
#[cfg(unix)]
impl tokio::io::AsyncRead for VsockIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}
#[cfg(unix)]
impl tokio::io::AsyncWrite for VsockIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, data)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(unix)]
fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("BOOT_NONCE_HEX has odd length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| "BOOT_NONCE_HEX is not hexadecimal".into())
        })
        .collect()
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::stream;
    use std::{env, path::PathBuf, sync::Arc};
    use tokio::net::TcpListener;
    use tokio_vsock::{VsockAddr, VsockListener};
    use tonic::transport::Server;
    use zeroize::Zeroizing;

    // Git invokes this same immutable guest binary through GIT_ASKPASS.  The
    // credential exists only in the child environment; it never enters argv,
    // a remote URL, the guest filesystem, or the long-running agent state.
    if let Ok(token) = env::var("BOXD_GIT_ASKPASS_TOKEN") {
        let token = Zeroizing::new(token);
        let prompt = env::args().nth(1).unwrap_or_default().to_ascii_lowercase();
        if prompt.contains("username") {
            println!("x-access-token");
        } else {
            println!("{}", token.as_str());
        }
        return Ok(());
    }

    let nonce = hex_decode(&env::var("BOXD_BOOT_NONCE_HEX")?)?;
    if nonce.len() != 32 {
        return Err("BOOT_NONCE_HEX must encode exactly 32 bytes".into());
    }
    let workspace =
        PathBuf::from(env::var("BOXD_WORKSPACE").unwrap_or_else(|_| "/workspace".into()));
    let home = PathBuf::from(env::var("BOXD_HOME").unwrap_or_else(|_| "/home/boxuser".into()));
    let sandbox = FileSandbox::new(workspace, home)?;
    sandbox.ensure_sdk_workspace()?;
    configure_resolver(
        Path::new("/etc/resolv.conf"),
        &env::var("BOXD_NETWORK_MODE").unwrap_or_else(|_| "deny-all".into()),
    )?;
    let executor = Arc::new(UnixProcessExecutor::new(sandbox.clone()));
    let browser_enabled = env::var("BOXD_BROWSER_ENABLED").as_deref() == Ok("1");
    let browser_backend = if browser_enabled {
        let executable = ["/usr/bin/chromium", "/usr/bin/chromium-browser"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .ok_or("browser box requires Chromium in the runtime bundle")?;
        Some(Arc::new(ChromiumBrowserBackend::new(executable)?))
    } else {
        None
    };
    let mut capabilities = vec![
        "exec".into(),
        "files".into(),
        "skills".into(),
        "terminal".into(),
    ];
    if browser_backend.is_some() {
        capabilities.push("browser-cdp-v1".into());
    }
    let mut agent = GuestAgent::new(
        AgentIdentity {
            box_id: env::var("BOXD_BOX_ID")?,
            boot_nonce: nonce,
            runtime: env::var("BOXD_RUNTIME").unwrap_or_else(|_| "unknown".into()),
            arch: env::consts::ARCH.into(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
            capabilities,
        },
        sandbox,
        executor.clone(),
    );
    if let Some(browser_backend) = browser_backend {
        agent = agent.with_browser_backend(browser_backend);
    }
    let agent = Arc::new(agent);
    let listener = VsockListener::bind(VsockAddr::new(libc::VMADDR_CID_ANY, 18_080))?;
    let incoming = stream::unfold(listener, |listener| async move {
        Some((
            listener.accept().await.map(|(stream, _)| VsockIo(stream)),
            listener,
        ))
    });
    let terminal_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 18_081)).await?;
    let terminal_executor = Arc::clone(&executor);
    let terminal_shutdown = Arc::clone(&agent);
    let terminal_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = terminal_listener.accept() => match accepted {
                    Ok((socket, _)) => {
                        let executor = Arc::clone(&terminal_executor);
                        tokio::spawn(async move {
                            if let Err(error) = executor.serve_terminal(socket).await {
                                eprintln!("box-agent terminal closed: {error}");
                            }
                        });
                    }
                    Err(_) => break,
                },
                () = terminal_shutdown.wait_shutdown() => break,
            }
        }
    });
    let shutdown_agent = Arc::clone(&agent);
    let result = Server::builder()
        .add_service(
            BoxAgentV1Server::from_arc(agent.clone())
                .max_decoding_message_size(2 * 1024 * 1024)
                .max_encoding_message_size(2 * 1024 * 1024),
        )
        .serve_with_incoming_shutdown(
            incoming,
            async move { shutdown_agent.wait_shutdown().await },
        )
        .await;
    terminal_task.abort();
    let _ = terminal_task.await;
    if let Err(error) = result {
        eprintln!("box-agent transport terminated: {error}");
        return Err(error.into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("box-agent requires Unix virtio-vsock");
    std::process::exit(1);
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn resolver_configuration_is_atomic_and_does_not_follow_existing_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let etc = directory.path().join("etc");
        fs::create_dir(&etc).unwrap();
        let outside = directory.path().join("outside");
        fs::write(&outside, "unchanged").unwrap();
        let resolver = etc.join("resolv.conf");
        symlink(&outside, &resolver).unwrap();

        configure_resolver(&resolver, "restricted-default").unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "unchanged");
        assert_eq!(
            fs::read_to_string(&resolver).unwrap(),
            "nameserver 192.0.2.1\noptions attempts:2 timeout:1\n"
        );
        assert!(
            !fs::symlink_metadata(&resolver)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_dir(&etc).unwrap().count(),
            1,
            "temporary resolver file leaked"
        );
    }

    #[test]
    fn resolver_configuration_rejects_unknown_network_mode() {
        let directory = tempfile::tempdir().unwrap();
        let resolver = directory.path().join("resolv.conf");
        assert!(configure_resolver(&resolver, "allow-everything").is_err());
        assert!(!resolver.exists());
    }
}
