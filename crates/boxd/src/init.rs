use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use box_auth::BootstrapService;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config;

pub async fn run(target: &Path) -> Result<(), String> {
    initialize(target)?;
    let outcome = match bootstrap(target).await {
        Ok(outcome) => outcome,
        Err(error) => {
            cleanup_published(target);
            return Err(error);
        }
    };
    println!("created {}", target.display());
    println!("administrator={}", outcome.username);
    println!("compat_api_key={}", outcome.api_key().expose());
    println!("The compatibility API key is shown once; store it securely.");
    Ok(())
}

fn initialize(target: &Path) -> Result<(), String> {
    if target.exists() {
        return Err(format!("拒绝覆盖已有配置: {}", target.display()));
    }
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("无法创建配置目录: {error}"))?;
    let data_target = parent.join("data");
    if data_target.exists() {
        return Err(format!(
            "拒绝复用或覆盖已有 data 目录: {}",
            data_target.display()
        ));
    }

    let staging = staging_path(parent);
    fs::create_dir(&staging).map_err(|error| format!("无法创建 init staging: {error}"))?;
    let result = stage_and_publish(target, &data_target, &staging);
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    let _ = fs::remove_dir(&staging);
    Ok(())
}

async fn bootstrap(target: &Path) -> Result<box_auth::BootstrapResult, String> {
    let loaded = config::load(Some(target), &config::CliOverrides::default())?;
    config::validate(&loaded)?;
    let password = Zeroizing::new(
        std::env::var(&loaded.auth.bootstrap_admin_password_env).map_err(|_| {
            format!(
                "required administrator password environment variable '{}' is not set",
                loaded.auth.bootstrap_admin_password_env
            )
        })?,
    );
    let master_key_raw =
        Zeroizing::new(std::env::var(&loaded.auth.master_key_env).map_err(|_| {
            format!(
                "required master-key environment variable '{}' is not set",
                loaded.auth.master_key_env
            )
        })?);
    let master_key = decode_master_key(&master_key_raw)?;
    let url = config::resolved_database_url(target, &loaded.database.url)?;
    let database = box_db::connect(&url, loaded.database.max_connections)
        .await
        .map_err(|error| format!("database bootstrap connection failed: {error}"))?;
    box_db::migrate(&database)
        .await
        .map_err(|error| format!("database migration failed: {error}"))?;
    BootstrapService::new(database, derive_key(&master_key, b"boxd-api-key-hmac-v1"))
        .map_err(|error| format!("authentication bootstrap failed: {error}"))?
        .initialize(
            "local",
            &loaded.auth.bootstrap_admin_user,
            &password,
            unix_millis(),
        )
        .await
        .map_err(|error| format!("authentication bootstrap failed: {error}"))
}

pub(crate) fn derive_key(master: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(master);
    digest.finalize().into()
}

pub(crate) fn decode_master_key(value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let decoded = if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        hex::decode(value).map_err(|_| "BOXD master key is not valid hexadecimal".to_string())?
    } else {
        BASE64
            .decode(value)
            .map_err(|_| "BOXD master key must be 64 hex characters or base64".to_string())?
    };
    if decoded.len() != 32 {
        return Err("BOXD master key must decode to exactly 32 bytes".into());
    }
    Ok(Zeroizing::new(decoded))
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn cleanup_published(target: &Path) {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _ = fs::remove_file(target);
    let _ = fs::remove_dir_all(parent.join("data"));
}

fn stage_and_publish(target: &Path, data_target: &Path, staging: &Path) -> Result<(), String> {
    let staged_config = staging.join("boxd.toml");
    let staged_data = staging.join("data");
    fs::create_dir(&staged_data).map_err(|error| format!("无法创建 staged data: {error}"))?;
    for name in [
        "images",
        "boxes",
        "snapshots",
        "recordings",
        "run",
        "embedded",
    ] {
        fs::create_dir(staged_data.join(name))
            .map_err(|error| format!("无法创建 staged data/{name}: {error}"))?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged_config)
        .map_err(|error| format!("无法创建 staged 配置: {error}"))?;
    file.write_all(config::EXAMPLE.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("无法写入 staged 配置: {error}"))?;

    fs::rename(&staged_data, data_target)
        .map_err(|error| format!("无法原子发布 data 目录: {error}"))?;
    if let Err(error) = fs::hard_link(&staged_config, target) {
        let cleanup = fs::remove_dir_all(data_target);
        return match cleanup {
            Ok(()) => Err(format!("拒绝覆盖已有配置或无法原子发布配置: {error}")),
            Err(cleanup_error) => Err(format!(
                "配置发布失败 ({error})，且新建 data 目录清理失败 ({cleanup_error})"
            )),
        };
    }
    fs::remove_file(&staged_config)
        .map_err(|error| format!("配置已发布但 staged link 清理失败: {error}"))?;
    Ok(())
}

fn staging_path(parent: &Path) -> PathBuf {
    parent.join(format!(
        ".boxd-init-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: configuration and init environment tests share the serial lock.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: configuration and init environment tests share the serial lock.
            unsafe {
                if let Some(value) = &self.previous {
                    std::env::set_var(self.key, value);
                } else {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn creates_filesystem_once_without_a_fake_bootstrap_token() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("boxd.toml");
        initialize(&target).expect("init");
        assert!(temp.path().join("data/images").is_dir());
        let config = fs::read_to_string(&target).expect("config");
        assert!(!config.contains("bootstrap_token"));
        assert!(
            initialize(&target)
                .expect_err("refuse")
                .contains("拒绝覆盖")
        );
    }

    #[test]
    fn preexisting_data_causes_clean_failure_without_config_or_staging() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("data")).expect("existing data");
        let target = temp.path().join("boxd.toml");
        assert!(
            initialize(&target)
                .expect_err("refuse data")
                .contains("拒绝复用")
        );
        assert!(!target.exists());
        assert!(
            fs::read_dir(temp.path())
                .expect("parent entries")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".boxd-init-"))
        );
    }

    #[tokio::test]
    #[serial]
    async fn real_bootstrap_is_persisted_once_without_plaintext() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("boxd.toml");
        let password = "correct horse battery staple";
        let master = "1111111111111111111111111111111111111111111111111111111111111111";
        let _password = EnvGuard::set("BOXD_ADMIN_PASSWORD", password);
        let _master = EnvGuard::set("BOXD_MASTER_KEY", master);
        run(&target).await.expect("bootstrap");
        assert!(target.is_file());
        assert!(temp.path().join("data/boxd.sqlite3").is_file());
        let config = fs::read_to_string(&target).expect("config");
        assert!(!config.contains(password));
        assert!(!config.contains(master));
        let database = fs::read(temp.path().join("data/boxd.sqlite3")).expect("database");
        assert!(
            !database
                .windows(password.len())
                .any(|value| value == password.as_bytes())
        );
        assert!(
            !database
                .windows(master.len())
                .any(|value| value == master.as_bytes())
        );
        assert!(
            run(&target)
                .await
                .expect_err("second init")
                .contains("拒绝覆盖")
        );
    }

    #[tokio::test]
    #[serial]
    async fn missing_bootstrap_secret_removes_new_filesystem() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("boxd.toml");
        let _password = EnvGuard::set("BOXD_ADMIN_PASSWORD", "correct horse battery staple");
        let previous = std::env::var_os("BOXD_MASTER_KEY");
        // SAFETY: configuration and init environment tests share the serial lock.
        unsafe { std::env::remove_var("BOXD_MASTER_KEY") };
        let error = run(&target).await.expect_err("missing key");
        // SAFETY: configuration and init environment tests share the serial lock.
        unsafe {
            if let Some(value) = previous {
                std::env::set_var("BOXD_MASTER_KEY", value);
            }
        }
        assert!(error.contains("BOXD_MASTER_KEY"));
        assert!(!target.exists());
        assert!(!temp.path().join("data").exists());
    }
}
