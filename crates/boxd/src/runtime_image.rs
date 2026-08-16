use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use box_image::{
    ImportLimits, ImportSource, ImportedBundle, RuntimeBundleManager, TrustedEd25519Keys,
};
use reqwest::{StatusCode, Url, blocking::Client, redirect::Policy};

use crate::config::AppConfig;

const DOWNLOAD_LIMIT_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(4 * 60);

pub fn import(config: &AppConfig, bundle: &Path) -> Result<(), String> {
    let source = if bundle.is_dir() {
        ImportSource::Directory(bundle.to_path_buf())
    } else {
        ImportSource::Archive(bundle.to_path_buf())
    };
    let imported = configured_manager(config)?
        .import_with_policy(source, None, Some(std::env::consts::ARCH))
        .map_err(|error| format!("runtime import failed: {error}"))?;
    println!(
        "runtime={} version={} arch={} sha256={} already_present={}",
        imported.manifest.runtime,
        imported.manifest.runtime_version,
        imported.manifest.arch,
        imported.rootfs_sha256,
        imported.already_present
    );
    Ok(())
}

pub fn pull(config: &AppConfig, name: &str) -> Result<(), String> {
    let manager = configured_manager(config)?;
    let imported = pull_verified(
        &config.runtime.bundle_registry,
        &config.storage.data_dir.join("run"),
        &manager,
        name,
        std::env::consts::ARCH,
    )?;
    println!(
        "runtime={} version={} arch={} sha256={} already_present={}",
        imported.manifest.runtime,
        imported.manifest.runtime_version,
        imported.manifest.arch,
        imported.rootfs_sha256,
        imported.already_present
    );
    Ok(())
}

pub(crate) fn pull_verified(
    registry: &str,
    run_dir: &Path,
    manager: &RuntimeBundleManager,
    name: &str,
    arch: &str,
) -> Result<ImportedBundle, String> {
    fetch_and_import(registry, run_dir, name, arch, download, |path| {
        manager
            .import_with_policy(
                ImportSource::Archive(path.to_path_buf()),
                Some(name),
                Some(arch),
            )
            .map_err(|error| format!("runtime pull failed verification: {error}"))
    })
}

fn fetch_and_import<T>(
    registry: &str,
    run_dir: &Path,
    name: &str,
    arch: &str,
    fetch: impl FnOnce(&Url, &mut File) -> Result<(), String>,
    import: impl FnOnce(&Path) -> Result<T, String>,
) -> Result<T, String> {
    validate_runtime_name(name)?;
    let mut url = Url::parse(registry)
        .map_err(|_| "runtime.bundle_registry is not a valid URL".to_string())?;
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    validate_runtime_name(arch)?;
    url = url
        .join(&format!("box-runtime-{name}-{arch}.tar.zst"))
        .map_err(|_| "could not build runtime bundle URL".to_string())?;
    if url.scheme() != "https" && !is_loopback_url(&url) {
        return Err(
            "runtime bundle downloads require HTTPS (HTTP is allowed only for loopback tests)"
                .into(),
        );
    }

    fs::create_dir_all(run_dir)
        .map_err(|error| format!("cannot create runtime download directory: {error}"))?;
    let mut temporary = TemporaryDownload::create(run_dir)?;
    fetch(&url, temporary.file_mut())?;
    temporary
        .file_mut()
        .sync_all()
        .map_err(|error| format!("cannot sync runtime download: {error}"))?;

    import(&temporary.path)
}

pub(crate) fn configured_manager(config: &AppConfig) -> Result<RuntimeBundleManager, String> {
    let mut keys = BTreeMap::new();
    for (key_id, encoded) in &config.runtime.trusted_signing_keys {
        let key = BASE64
            .decode(encoded)
            .map_err(|_| format!("trusted runtime key '{key_id}' is not valid base64"))?;
        if key.len() != 32 {
            return Err(format!(
                "trusted runtime key '{key_id}' must decode to 32 bytes"
            ));
        }
        keys.insert(key_id.clone(), key);
    }
    if keys.is_empty() {
        return Err("no runtime.trusted_signing_keys are configured".into());
    }
    Ok(RuntimeBundleManager::new(
        &config.storage.images_dir,
        &config.storage.boxes_dir,
        &config.storage.snapshots_dir,
        TrustedEd25519Keys::new(keys),
        ImportLimits::default(),
    ))
}

fn download(url: &Url, output: &mut File) -> Result<(), String> {
    download_with_timeout(url, output, HTTP_TOTAL_TIMEOUT)
}

fn download_with_timeout(
    url: &Url,
    output: &mut File,
    total_timeout: Duration,
) -> Result<(), String> {
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        // The service owns a five-minute creation deadline. Keep the complete
        // HTTP exchange strictly below it so verification/import retains time
        // to finish and publish atomically.
        .timeout(total_timeout)
        .build()
        .map_err(|error| format!("cannot create runtime HTTP client: {error}"))?;
    let mut response = client
        .get(url.clone())
        .send()
        .map_err(|error| format!("runtime download failed: {error}"))?;
    if response.status() != StatusCode::OK {
        return Err(format!(
            "runtime registry returned HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > DOWNLOAD_LIMIT_BYTES)
    {
        return Err("runtime download exceeds the configured limit".into());
    }
    let mut total = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = response
            .read(&mut buffer)
            .map_err(|error| format!("runtime download read failed: {error}"))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| "runtime download size overflow".to_string())?;
        if total > DOWNLOAD_LIMIT_BYTES {
            return Err("runtime download exceeds the configured limit".into());
        }
        output
            .write_all(&buffer[..count])
            .map_err(|error| format!("runtime download write failed: {error}"))?;
    }
    Ok(())
}

fn validate_runtime_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("runtime name must be 1..=64 ASCII alphanumeric, '-' or '_' characters".into());
    }
    Ok(())
}

fn is_loopback_url(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

struct TemporaryDownload {
    path: PathBuf,
    file: File,
}

impl TemporaryDownload {
    fn create(directory: &Path) -> Result<Self, String> {
        for attempt in 0..32_u32 {
            let path = directory.join(format!(
                ".runtime-download-{}-{}-{}.tmp",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |value| value.as_nanos()),
                attempt
            ));
            match OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("cannot create runtime download: {error}")),
            }
        }
        Err("cannot allocate unique runtime download path".into())
    }

    fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl Drop for TemporaryDownload {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn runtime_names_and_loopback_transport_are_strict() {
        assert!(validate_runtime_name("node-alpine").is_ok());
        assert!(validate_runtime_name("../node").is_err());
        assert!(is_loopback_url(
            &Url::parse("http://127.0.0.1:8000/x").unwrap()
        ));
        assert!(!is_loopback_url(
            &Url::parse("http://example.com/x").unwrap()
        ));
    }

    #[test]
    fn missing_trust_root_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.storage.images_dir = temp.path().join("images");
        config.storage.boxes_dir = temp.path().join("boxes");
        assert!(
            configured_manager(&config)
                .err()
                .expect("missing trust root")
                .contains("trusted_signing_keys")
        );
    }

    #[test]
    fn failed_download_removes_private_temporary_file() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        let error = fetch_and_import(
            "http://127.0.0.1:7331/runtimes",
            &run,
            "node",
            "aarch64",
            |url, output| {
                assert!(url.path().ends_with("/box-runtime-node-aarch64.tar.zst"));
                output.write_all(b"partial").unwrap();
                Err("injected download failure".into())
            },
            |_path| -> Result<(), String> { panic!("failed download must not be imported") },
        )
        .expect_err("download failure");
        assert!(error.contains("injected download failure"));
        assert_eq!(fs::read_dir(run).unwrap().count(), 0);
    }

    #[test]
    fn slow_http_response_obeys_total_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
                .unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut output = temp.reopen().unwrap();
        let error = download_with_timeout(
            &Url::parse(&format!("http://{address}/bundle")).unwrap(),
            &mut output,
            Duration::from_millis(50),
        )
        .expect_err("slow response must time out");
        assert!(error.contains("runtime download read failed"));
        server.join().unwrap();
        assert!(HTTP_TOTAL_TIMEOUT < Duration::from_secs(5 * 60));
    }
}
