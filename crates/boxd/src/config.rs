use std::path::{Path, PathBuf};

use box_egress::{AddressClass, classify_address};
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use url::Url;

pub const LIBKRUN_VERSION: &str = "1.19.4";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub version: u32,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub runtime: RuntimeConfig,
    pub resources: ResourcesConfig,
    pub network: NetworkConfig,
    pub preview: PreviewConfig,
    pub console: ConsoleConfig,
    pub observability: ObservabilityConfig,
    pub models: ModelsConfig,
    pub recording: BrowserRecordingConfig,
    pub quotas: QuotasConfig,
    pub features: FeaturesConfig,
}

macro_rules! config_struct {
    ($name:ident { $($field:ident : $type:ty = $value:expr),+ $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $type),+ }
        impl Default for $name { fn default() -> Self { Self { $($field: $value),+ } } }
    };
}

config_struct!(ServerConfig {
    listen: String = "127.0.0.1:7331".into(), public_url: String = "http://127.0.0.1:7331".into(),
    graceful_shutdown_seconds: u64 = 30, request_body_limit_mb: u64 = 128, trusted_proxies: Vec<String> = vec![]
});
config_struct!(DatabaseConfig {
    url: String = "sqlite://./data/boxd.sqlite3?mode=rwc".into(),
    auto_migrate: bool = true,
    max_connections: u32 = 10,
    min_connections: u32 = 0,
    connect_timeout_seconds: u64 = 10
});
config_struct!(AuthConfig {
    enabled: bool = true,
    bootstrap_admin_user: String = "admin".into(),
    bootstrap_admin_password_env: String = "BOXD_ADMIN_PASSWORD".into(),
    master_key_env: String = "BOXD_MASTER_KEY".into(),
    api_key_header: String = "X-Box-Api-Key".into(),
    session_ttl_seconds: u64 = 43200
});
config_struct!(StorageConfig {
    data_dir: PathBuf = PathBuf::from("./data"),
    images_dir: PathBuf = PathBuf::from("./data/images"),
    boxes_dir: PathBuf = PathBuf::from("./data/boxes"),
    snapshots_dir: PathBuf = PathBuf::from("./data/snapshots"),
    recordings_dir: PathBuf = PathBuf::from("./data/recordings"),
    minimum_free_gib: u64 = 10
});
config_struct!(RuntimeConfig {
    driver: String = "libkrun".into(),
    libkrun_version: String = LIBKRUN_VERSION.into(),
    bundle_registry: String = "https://releases.example.com/boxd/runtimes".into(),
    auto_pull: bool = false,
    verify_signatures: bool = true,
    trusted_signing_keys: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new(),
    agent_vsock_port: u16 = 18080,
    boot_timeout_seconds: u64 = 30,
    shutdown_timeout_seconds: u64 = 10
});
config_struct!(ResourceProfile {
    vcpus: u32 = 2,
    memory_mib: u64 = 4096
});
config_struct!(ResourcesConfig {
    max_running_boxes: u32 = 4, max_total_memory_mib: u64 = 16384, max_total_vcpus: u32 = 8, default_disk_gib: u64 = 20,
    profiles: std::collections::BTreeMap<String, ResourceProfile> = default_profiles()
});
config_struct!(NetworkConfig {
    default_policy: String = "restricted-default".into(),
    dns_servers: Vec<String> = vec!["1.1.1.1".into()],
    dns_over_https_name: String = String::new(),
    allow_private_cidrs: bool = false
});
config_struct!(PreviewConfig {
    mode: String = "path".into(),
    base_url: String = "http://127.0.0.1:7331".into(),
    path_prefix: String = "/p".into(),
    wildcard_domain: String = String::new()
});
config_struct!(ConsoleConfig {
    enabled: bool = true,
    base_path: String = "/console".into()
});
config_struct!(ObservabilityConfig {
    log_format: String = "pretty".into(),
    log_level: String = "info".into(),
    metrics_enabled: bool = true,
    metrics_path: String = "/metrics".into(),
    otlp_endpoint: String = String::new(),
    otlp_timeout_seconds: u64 = 5
});
config_struct!(ModelProviderConfig {
    kind: String = "openai".into(),
    base_url: String = String::new(),
    api_key_env: String = String::new()
});
config_struct!(ModelsConfig {
    default_model: String = "anthropic/claude-sonnet-4-5".into(),
    providers: std::collections::BTreeMap<String, ModelProviderConfig> = default_model_providers()
});
config_struct!(BrowserRecordingConfig {
    ffmpeg_path: String = "ffmpeg".into(),
    max_file_mib: u64 = 512,
    tenant_max_gib: u64 = 10
});
config_struct!(QuotasConfig {
    api_key_requests_per_minute: u32 = 600,
    api_key_request_burst: u32 = 100,
    api_key_traffic_mib_per_minute: u64 = 1024,
    api_key_traffic_burst_mib: u64 = 256,
    max_tracked_api_keys: usize = 10_000,
    idle_entry_ttl_seconds: u64 = 900,
    tenant_max_boxes: u32 = 4,
    tenant_max_disk_gib: u64 = 80,
    tenant_max_concurrent_runs: u32 = 4
});
config_struct!(FeaturesConfig {
    browser: bool = false,
    schedules: bool = false,
    custom_network_policy: bool = false,
    attach_headers: bool = false
});

fn default_profiles() -> std::collections::BTreeMap<String, ResourceProfile> {
    [
        ("small".into(), ResourceProfile::default()),
        (
            "medium".into(),
            ResourceProfile {
                vcpus: 4,
                memory_mib: 8192,
            },
        ),
        (
            "large".into(),
            ResourceProfile {
                vcpus: 8,
                memory_mib: 16384,
            },
        ),
    ]
    .into()
}

fn default_model_providers() -> std::collections::BTreeMap<String, ModelProviderConfig> {
    [
        (
            "anthropic".into(),
            ModelProviderConfig {
                kind: "anthropic".into(),
                base_url: "https://api.anthropic.com".into(),
                api_key_env: "ANTHROPIC_API_KEY".into(),
            },
        ),
        (
            "openai".into(),
            ModelProviderConfig {
                kind: "openai".into(),
                base_url: "https://api.openai.com/v1".into(),
                api_key_env: "OPENAI_API_KEY".into(),
            },
        ),
        (
            "openrouter".into(),
            ModelProviderConfig {
                kind: "openai".into(),
                base_url: "https://openrouter.ai/api/v1".into(),
                api_key_env: "OPENROUTER_API_KEY".into(),
            },
        ),
        (
            "vercel".into(),
            ModelProviderConfig {
                kind: "openai".into(),
                base_url: "https://ai-gateway.vercel.sh/v1".into(),
                api_key_env: "AI_GATEWAY_API_KEY".into(),
            },
        ),
    ]
    .into()
}
impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: 1,
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            auth: AuthConfig::default(),
            storage: StorageConfig::default(),
            runtime: RuntimeConfig::default(),
            resources: ResourcesConfig::default(),
            network: NetworkConfig::default(),
            preview: PreviewConfig::default(),
            console: ConsoleConfig::default(),
            observability: ObservabilityConfig::default(),
            models: ModelsConfig::default(),
            recording: BrowserRecordingConfig::default(),
            quotas: QuotasConfig::default(),
            features: FeaturesConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CliOverrides {
    pub listen: Option<String>,
    pub public_url: Option<String>,
    pub database_url: Option<String>,
    pub data_dir: Option<PathBuf>,
}

pub fn load(path: Option<&Path>, overrides: &CliOverrides) -> Result<AppConfig, String> {
    let mut figment = Figment::from(Serialized::defaults(AppConfig::default()));
    if let Some(path) = path {
        figment = figment.merge(Toml::file(path));
    }
    let mut config: AppConfig = figment
        .merge(Env::prefixed("BOXD__").split("__"))
        .extract()
        .map_err(|e| format!("配置解析失败: {e}"))?;
    if let Some(value) = &overrides.listen {
        config.server.listen.clone_from(value);
    }
    if let Some(value) = &overrides.public_url {
        config.server.public_url.clone_from(value);
        if config.preview.mode == "path" {
            config.preview.base_url.clone_from(value);
        }
    }
    if let Some(value) = &overrides.database_url {
        config.database.url.clone_from(value);
    }
    if let Some(value) = &overrides.data_dir {
        config.storage.data_dir.clone_from(value);
        config.storage.images_dir = value.join("images");
        config.storage.boxes_dir = value.join("boxes");
        config.storage.snapshots_dir = value.join("snapshots");
        config.storage.recordings_dir = value.join("recordings");
    }
    Ok(config)
}

/// Resolves a relative SQLite URL against the configuration file rather than
/// the caller's current working directory. Other database URLs are unchanged.
pub fn resolved_database_url(config_path: &Path, url: &str) -> Result<String, String> {
    if !url.starts_with("sqlite:") || url.starts_with("sqlite::memory:") {
        return Ok(url.to_owned());
    }
    let (base, query) = url
        .split_once('?')
        .map_or((url, None), |(base, query)| (base, Some(query)));
    let raw = base
        .strip_prefix("sqlite://")
        .or_else(|| base.strip_prefix("sqlite:"))
        .ok_or_else(|| "invalid SQLite URL".to_string())?;
    let raw_path = PathBuf::from(raw);
    let path = if raw_path.is_absolute() {
        raw_path
    } else {
        config_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .join(raw_path)
    };
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|error| format!("cannot resolve current directory: {error}"))?
            .join(path)
    };
    let absolute = lexical_absolute(&absolute)?;
    let mut resolved = format!("sqlite://{}", absolute.display());
    if let Some(query) = query {
        resolved.push('?');
        resolved.push_str(query);
    }
    Ok(resolved)
}

/// Resolves every relative storage path against the directory containing the
/// configuration file. This keeps `serve`, `doctor`, and runtime management
/// independent from the caller's current working directory.
pub fn resolve_storage_paths(config_path: &Path, config: &mut AppConfig) -> Result<(), String> {
    let base = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = if base.is_absolute() {
        base.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("cannot resolve current directory: {error}"))?
            .join(base)
    };
    fn resolve(base: &Path, path: &Path) -> Result<PathBuf, String> {
        if path.is_absolute() {
            lexical_absolute(path)
        } else {
            lexical_absolute(&base.join(path))
        }
    }
    config.storage.data_dir = resolve(&base, &config.storage.data_dir)?;
    config.storage.images_dir = resolve(&base, &config.storage.images_dir)?;
    config.storage.boxes_dir = resolve(&base, &config.storage.boxes_dir)?;
    config.storage.snapshots_dir = resolve(&base, &config.storage.snapshots_dir)?;
    config.storage.recordings_dir = resolve(&base, &config.storage.recordings_dir)?;
    config.database.url = resolved_database_url(config_path, &config.database.url)?;
    Ok(())
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, String> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err("path must be absolute before lexical normalization".into());
    }
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => result.push(prefix.as_os_str()),
            Component::RootDir => result.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    return Err("path escapes filesystem root".into());
                }
            }
            Component::Normal(value) => result.push(value),
        }
    }
    Ok(result)
}

pub fn validate(config: &AppConfig) -> Result<Vec<String>, String> {
    if config.version != 1 {
        return Err("version 必须为 1".into());
    }
    validate_listen(&config.server.listen)?;
    let public = parse_http_url("server.public_url", &config.server.public_url)?;
    let preview = parse_http_url("preview.base_url", &config.preview.base_url)?;
    let listen_port = config
        .server
        .listen
        .parse::<std::net::SocketAddr>()
        .map_err(|_| "server.listen 必须为 host:port（例如 127.0.0.1:7331）")?
        .port();
    if public.port_or_known_default() != Some(listen_port) {
        return Err("server.public_url 的端口必须与 server.listen 一致".into());
    }
    if public.origin() != preview.origin() && config.preview.mode == "path" {
        return Err("preview.mode=path 时 preview.base_url 必须与 server.public_url 同源".into());
    }
    if !config.preview.path_prefix.starts_with('/') {
        return Err("preview.path_prefix 必须以 / 开头".into());
    }
    if config.preview.mode != "path" || !config.preview.wildcard_domain.is_empty() {
        return Err(
            "feature_not_supported: Phase 1 仅支持 preview.mode=path 且 wildcard_domain 必须为空"
                .into(),
        );
    }
    if !config.database.url.starts_with("sqlite:")
        && !config.database.url.starts_with("postgres:")
        && !config.database.url.starts_with("mysql:")
    {
        return Err("database.url 必须是 sqlite:, postgres: 或 mysql: URL".into());
    }
    if config.runtime.driver != "libkrun" || config.runtime.libkrun_version != LIBKRUN_VERSION {
        return Err(format!(
            "runtime.driver 必须为 libkrun 且 runtime.libkrun_version 必须为 {LIBKRUN_VERSION}"
        ));
    }
    let bundle_registry =
        parse_http_url("runtime.bundle_registry", &config.runtime.bundle_registry)?;
    if !config.runtime.verify_signatures {
        return Err("runtime.verify_signatures 必须为 true；不支持跳过运行时签名验证".into());
    }
    for (key_id, encoded_key) in &config.runtime.trusted_signing_keys {
        if key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || encoded_key.is_empty()
        {
            return Err("runtime.trusted_signing_keys 包含无效 key id 或空公钥".into());
        }
    }
    if config.runtime.auto_pull && config.runtime.trusted_signing_keys.is_empty() {
        return Err(
            "runtime.auto_pull=true requires at least one runtime.trusted_signing_keys entry"
                .into(),
        );
    }
    if config.runtime.auto_pull
        && bundle_registry.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("example.com")
                || host.to_ascii_lowercase().ends_with(".example.com")
        })
    {
        return Err(
            "runtime.auto_pull=true cannot use the placeholder example.com bundle registry; configure a real trusted registry"
                .into(),
        );
    }
    if config.server.graceful_shutdown_seconds == 0
        || config.server.request_body_limit_mb == 0
        || config.database.connect_timeout_seconds == 0
        || config.auth.session_ttl_seconds == 0
        || config.runtime.boot_timeout_seconds == 0
        || config.runtime.shutdown_timeout_seconds == 0
    {
        return Err("server/database/auth/runtime 的 limit/timeout/TTL 必须大于 0".into());
    }
    if !config.server.trusted_proxies.is_empty() {
        return Err(
            "feature_not_supported: Phase 1 不使用 proxy-derived client identity，server.trusted_proxies 必须为空"
                .into(),
        );
    }
    if config.auth.api_key_header != "X-Box-Api-Key" {
        return Err("auth.api_key_header 必须固定为 X-Box-Api-Key".into());
    }
    if config.database.min_connections != 0 || config.database.connect_timeout_seconds != 10 {
        return Err(
            "database.min_connections 必须为 0 且 database.connect_timeout_seconds 必须为 10；Phase 1 production adapter 尚未接线其他值"
                .into(),
        );
    }
    if config.runtime.shutdown_timeout_seconds != 10 {
        return Err(
            "runtime.shutdown_timeout_seconds 必须为 10；Phase 1 lifecycle 使用固定十秒 shutdown budget"
                .into(),
        );
    }
    if config.database.max_connections == 0
        || config.database.min_connections > config.database.max_connections
    {
        return Err("database 连接数必须满足 0 <= min_connections <= max_connections 且 max_connections > 0".into());
    }
    if u32::from(config.runtime.agent_vsock_port) != box_runtime::AGENT_VSOCK_PORT {
        return Err(format!(
            "runtime.agent_vsock_port 必须固定为 {}；Phase 1 worker 不支持其他端口",
            box_runtime::AGENT_VSOCK_PORT
        ));
    }
    if config.resources.max_running_boxes == 0
        || config.resources.max_total_memory_mib == 0
        || config.resources.max_total_vcpus == 0
    {
        return Err("resources 上限必须大于 0".into());
    }
    for (name, profile) in &config.resources.profiles {
        if profile.vcpus == 0
            || profile.memory_mib == 0
            || profile.vcpus > config.resources.max_total_vcpus
            || profile.memory_mib > config.resources.max_total_memory_mib
        {
            return Err(format!("resources.profiles.{name} 超出资源上限或为零"));
        }
    }
    for path in [
        &config.storage.data_dir,
        &config.storage.images_dir,
        &config.storage.boxes_dir,
        &config.storage.snapshots_dir,
        &config.storage.recordings_dir,
    ] {
        if path.as_os_str().is_empty() {
            return Err("storage 路径不能为空".into());
        }
    }
    for (name, path) in [
        ("images_dir", &config.storage.images_dir),
        ("boxes_dir", &config.storage.boxes_dir),
        ("snapshots_dir", &config.storage.snapshots_dir),
        ("recordings_dir", &config.storage.recordings_dir),
    ] {
        if !path.starts_with(&config.storage.data_dir) {
            return Err(format!(
                "storage.{name} 必须位于 storage.data_dir 内；当前为 {}",
                path.display()
            ));
        }
    }
    if config.storage.minimum_free_gib == 0 || config.resources.default_disk_gib == 0 {
        return Err("storage.minimum_free_gib 和 resources.default_disk_gib 必须大于 0".into());
    }
    for required in ["small", "medium", "large"] {
        if !config.resources.profiles.contains_key(required) {
            return Err(format!("resources.profiles 缺少必需的 {required} profile"));
        }
    }
    match config.network.default_policy.as_str() {
        "deny-all"
            if !config.network.dns_servers.is_empty()
                || !config.network.dns_over_https_name.is_empty() =>
        {
            return Err(
                "deny-all 模式不提供 guest DNS，network.dns_servers 与 dns_over_https_name 必须为空"
                    .into(),
            );
        }
        "deny-all" => {}
        "restricted-default" => {
            if !(1..=3).contains(&config.network.dns_servers.len()) {
                return Err("restricted-default 要求配置 1 至 3 个公网 IPv4 DNS resolver".into());
            }
            let mut unique = std::collections::BTreeSet::new();
            for raw in &config.network.dns_servers {
                let address = raw.parse::<Ipv4Addr>().map_err(|_| {
                    "restricted-default DNS resolver 必须是数值公网 IPv4 地址".to_owned()
                })?;
                if classify_address(IpAddr::V4(address)) != AddressClass::PublicUnicast
                    || !unique.insert(address)
                {
                    return Err("restricted-default DNS resolver 必须唯一且属于公网 IPv4".into());
                }
            }
            if !config.network.dns_over_https_name.is_empty()
                && !valid_dns_authority(&config.network.dns_over_https_name)
            {
                return Err(
                    "network.dns_over_https_name 必须是规范的小写 ASCII hostname；TLS 连接仅使用 dns_servers 中的固定 IP"
                        .into(),
                );
            }
        }
        _ => {
            return Err("network.default_policy 必须为 deny-all 或 restricted-default".into());
        }
    }
    if config.network.allow_private_cidrs {
        return Err(
            "feature_not_supported: deny-all 模式不允许 private CIDR，network.allow_private_cidrs 必须为 false"
                .into(),
        );
    }
    if !config.console.base_path.starts_with('/')
        || !config.observability.metrics_path.starts_with('/')
    {
        return Err("console.base_path 和 observability.metrics_path 必须以 / 开头".into());
    }
    if config.console.base_path != "/console" {
        return Err("feature_not_supported: Phase 1 console.base_path 必须为 /console".into());
    }
    if !matches!(config.observability.log_format.as_str(), "pretty" | "json") {
        return Err("observability.log_format 必须为 pretty 或 json".into());
    }
    if !(1..=60).contains(&config.observability.otlp_timeout_seconds) {
        return Err("observability.otlp_timeout_seconds 必须介于 1 到 60 秒".into());
    }
    if !config.observability.otlp_endpoint.is_empty() {
        let endpoint = Url::parse(&config.observability.otlp_endpoint)
            .map_err(|_| "observability.otlp_endpoint 必须是有效的 HTTP(S) URL")?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(
                "observability.otlp_endpoint 仅支持不含凭据、query 或 fragment 的 HTTP(S) URL"
                    .into(),
            );
        }
    }
    if config.models.providers.is_empty() || config.models.providers.len() > 16 {
        return Err("models.providers 必须包含 1 至 16 个 provider".into());
    }
    let (default_provider, default_model) = config
        .models
        .default_model
        .split_once('/')
        .ok_or_else(|| "models.default_model 必须使用 provider/model 格式".to_string())?;
    if default_model.is_empty() || !config.models.providers.contains_key(default_provider) {
        return Err("models.default_model 引用了未知 provider 或空模型".into());
    }
    for (name, provider) in &config.models.providers {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !matches!(provider.kind.as_str(), "openai" | "anthropic")
        {
            return Err(format!("models.providers.{name} 名称或 kind 无效"));
        }
        let endpoint = Url::parse(&provider.base_url)
            .map_err(|_| format!("models.providers.{name}.base_url 必须是有效 HTTP(S) URL"))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(format!(
                "models.providers.{name}.base_url 不得包含凭据、query 或 fragment"
            ));
        }
        let mut env_bytes = provider.api_key_env.bytes();
        if provider.api_key_env.len() > 128
            || !env_bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
            || !env_bytes
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!(
                "models.providers.{name}.api_key_env 必须是大写 POSIX 环境变量名"
            ));
        }
    }
    let ffmpeg = &config.recording.ffmpeg_path;
    if ffmpeg.is_empty()
        || ffmpeg.len() > 4_096
        || (!Path::new(ffmpeg).is_absolute()
            && (ffmpeg.contains('/') || ffmpeg.contains('\\') || ffmpeg == "." || ffmpeg == ".."))
        || config.recording.max_file_mib == 0
        || config.recording.max_file_mib > 16 * 1024
        || config.recording.tenant_max_gib == 0
        || config.recording.tenant_max_gib > 1024 * 1024
    {
        return Err("recording.ffmpeg_path 或 recording 配额无效".into());
    }
    if config.quotas.api_key_requests_per_minute == 0
        || config.quotas.api_key_request_burst == 0
        || config.quotas.api_key_traffic_mib_per_minute == 0
        || config.quotas.api_key_traffic_burst_mib == 0
        || config.quotas.max_tracked_api_keys == 0
        || config.quotas.idle_entry_ttl_seconds == 0
        || config.quotas.tenant_max_boxes == 0
        || config.quotas.tenant_max_disk_gib == 0
        || config.quotas.tenant_max_concurrent_runs == 0
    {
        return Err("quotas 的 request rate、burst、tracked keys 和 idle TTL 必须大于 0".into());
    }
    if config.quotas.api_key_request_burst > config.quotas.api_key_requests_per_minute
        || config.quotas.api_key_traffic_burst_mib > config.quotas.api_key_traffic_mib_per_minute
        || config.quotas.api_key_requests_per_minute > 1_000_000
        || config.quotas.api_key_traffic_mib_per_minute > 1_000_000
        || config.quotas.max_tracked_api_keys > 1_000_000
        || config.quotas.idle_entry_ttl_seconds > 86_400
        || config.quotas.tenant_max_boxes > 100_000
        || config.quotas.tenant_max_disk_gib > 1_000_000
        || config.quotas.tenant_max_concurrent_runs > 100_000
    {
        return Err("quotas 配置超出支持范围".into());
    }
    let mut warnings = Vec::new();
    if config.database.url.starts_with("sqlite:") {
        warnings.push("SQLite 模式仅支持一个 active control-plane 进程".into());
    }
    Ok(warnings)
}

fn valid_dns_authority(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}
fn validate_listen(value: &str) -> Result<(), String> {
    value
        .parse::<std::net::SocketAddr>()
        .map(|_| ())
        .map_err(|_| "server.listen 必须为 host:port（例如 127.0.0.1:7331）".into())
}
fn parse_http_url(name: &str, value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| format!("{name} 必须是完整 HTTP(S) URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(format!("{name} 必须是完整 HTTP(S) URL"));
    }
    Ok(url)
}

pub const EXAMPLE: &str = include_str!("../../../config/boxd.example.toml");

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
            // SAFETY: every test that loads configuration uses the same serial_test lock.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: every test that loads configuration uses the same serial_test lock.
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
    #[serial]
    fn example_round_trips_and_validates() {
        let path = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(path.path(), EXAMPLE).expect("write example");
        let config = load(Some(path.path()), &CliOverrides::default()).expect("load example");
        validate(&config).expect("validate example");
        assert_eq!(config.runtime.libkrun_version, LIBKRUN_VERSION);
        let encoded = serde_json::to_value(&config).expect("serialize config");
        let decoded: AppConfig = serde_json::from_value(encoded).expect("deserialize config");
        assert_eq!(decoded.server.listen, config.server.listen);
        assert_eq!(decoded.resources.profiles.len(), 3);
        assert_eq!(decoded.quotas.api_key_requests_per_minute, 600);
    }

    #[test]
    fn request_quota_configuration_is_bounded_and_never_silently_disabled() {
        let mut config = AppConfig::default();
        config.quotas.api_key_requests_per_minute = 0;
        assert!(validate(&config).unwrap_err().contains("quotas"));
        config.quotas.api_key_requests_per_minute = 60;
        config.quotas.api_key_request_burst = 61;
        assert!(validate(&config).unwrap_err().contains("quotas"));
    }
    #[test]
    fn otlp_configuration_is_explicit_and_rejects_unsafe_urls() {
        let mut config = AppConfig::default();
        validate(&config).expect("empty endpoint disables OTLP");
        config.observability.otlp_endpoint = "https://collector.example.test/v1/traces".into();
        validate(&config).expect("valid OTLP HTTP endpoint");
        config.observability.otlp_endpoint =
            "https://token@collector.example.test/v1/traces".into();
        assert!(validate(&config).unwrap_err().contains("otlp_endpoint"));
        config.observability.otlp_endpoint = String::new();
        config.observability.otlp_timeout_seconds = 0;
        assert!(
            validate(&config)
                .unwrap_err()
                .contains("otlp_timeout_seconds")
        );
    }
    #[test]
    #[serial]
    fn secret_values_are_not_configuration_fields() {
        let debug = format!("{:?}", AppConfig::default());
        assert!(debug.contains("BOXD_ADMIN_PASSWORD"));
        assert!(!debug.contains("super-secret"));
    }
    #[test]
    #[serial]
    fn environment_overrides_toml_without_reading_secret_env_value() {
        let path = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(path.path(), EXAMPLE).expect("write example");
        let _environment = EnvGuard::set("BOXD__SERVER__LISTEN", "127.0.0.1:7444");
        let config =
            load(Some(path.path()), &CliOverrides::default()).expect("load overridden config");
        assert_eq!(config.server.listen, "127.0.0.1:7444");
    }
    #[test]
    #[serial]
    fn cli_overrides_environment_and_toml() {
        let path = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(path.path(), EXAMPLE).expect("write example");
        let key = "BOXD__SERVER__LISTEN";
        let _environment = EnvGuard::set(key, "127.0.0.1:7444");
        let overrides = CliOverrides {
            listen: Some("127.0.0.1:7555".into()),
            public_url: Some("http://127.0.0.1:7555".into()),
            database_url: Some("sqlite://override.sqlite3?mode=rwc".into()),
            data_dir: Some(PathBuf::from("./override-data")),
        };
        let config = load(Some(path.path()), &overrides).expect("load overridden config");
        assert_eq!(config.server.listen, "127.0.0.1:7555");
        assert_eq!(config.server.public_url, "http://127.0.0.1:7555");
        assert_eq!(config.preview.base_url, "http://127.0.0.1:7555");
        assert_eq!(config.database.url, "sqlite://override.sqlite3?mode=rwc");
        assert_eq!(config.storage.data_dir, PathBuf::from("./override-data"));
        assert_eq!(
            config.storage.images_dir,
            PathBuf::from("./override-data/images")
        );
    }

    #[test]
    fn browser_feature_is_supported_in_phase_three() {
        let mut config = AppConfig::default();
        config.features.browser = true;
        validate(&config).expect("browser must be accepted in Phase 3");
    }

    #[test]
    fn phase_four_accepts_custom_network_policy_and_attach_headers() {
        let mut config = AppConfig::default();
        config.features.custom_network_policy = true;
        validate(&config).expect("custom network policy is wired in Phase 4");

        config.features.attach_headers = true;
        validate(&config).expect("attach_headers is wired in Phase 4");
    }

    #[test]
    fn auto_pull_requires_real_registry_and_trust_root() {
        let mut config = AppConfig::default();
        config.runtime.auto_pull = true;
        let error = validate(&config).expect_err("empty trust root must fail");
        assert!(error.contains("trusted_signing_keys"));

        config
            .runtime
            .trusted_signing_keys
            .insert("release".into(), "not-empty".into());
        let error = validate(&config).expect_err("placeholder registry must fail");
        assert!(error.contains("example.com"));
    }

    #[test]
    fn fixed_worker_network_contract_rejects_ignored_configuration() {
        let mut config = AppConfig::default();
        config.runtime.agent_vsock_port = (box_runtime::AGENT_VSOCK_PORT + 1) as u16;
        assert!(
            validate(&config)
                .expect_err("alternate worker port")
                .contains("agent_vsock_port")
        );

        let mut config = AppConfig::default();
        config.network.dns_servers.push("1.1.1.1".into());
        assert!(
            validate(&config)
                .expect_err("duplicate resolver")
                .contains("resolver")
        );

        let mut config = AppConfig::default();
        config.network.dns_servers = vec!["169.254.169.254".into()];
        assert!(
            validate(&config)
                .expect_err("metadata resolver")
                .contains("公网 IPv4")
        );

        let mut config = AppConfig::default();
        config.network.default_policy = "deny-all".into();
        assert!(
            validate(&config)
                .expect_err("deny-all DNS")
                .contains("dns_servers")
        );

        let mut config = AppConfig::default();
        config.network.allow_private_cidrs = true;
        assert!(
            validate(&config)
                .expect_err("deny-all private cidrs")
                .contains("allow_private_cidrs")
        );
    }

    #[test]
    fn phase_one_rejects_control_plane_settings_not_wired_by_adapters() {
        let mut config = AppConfig::default();
        config.server.trusted_proxies.push("127.0.0.1".into());
        assert!(
            validate(&config)
                .expect_err("trusted proxy")
                .contains("trusted_proxies")
        );

        let mut config = AppConfig::default();
        config.auth.api_key_header = "Authorization".into();
        assert!(
            validate(&config)
                .expect_err("alternate API key header")
                .contains("api_key_header")
        );

        let mut config = AppConfig::default();
        config.database.min_connections = 1;
        assert!(
            validate(&config)
                .expect_err("minimum connections not wired")
                .contains("min_connections")
        );

        let mut config = AppConfig::default();
        config.database.connect_timeout_seconds = 11;
        assert!(
            validate(&config)
                .expect_err("database timeout not wired")
                .contains("connect_timeout_seconds")
        );

        let mut config = AppConfig::default();
        config.runtime.shutdown_timeout_seconds = 11;
        assert!(
            validate(&config)
                .expect_err("runtime shutdown timeout not wired")
                .contains("shutdown_timeout_seconds")
        );
    }

    #[test]
    fn relative_sqlite_url_is_bound_to_config_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let config_path = root.path().join("config/boxd.toml");
        let resolved = resolved_database_url(&config_path, "sqlite://./data/boxd.sqlite3?mode=rwc")
            .expect("resolve");
        assert_eq!(
            resolved,
            format!(
                "sqlite://{}?mode=rwc",
                root.path().join("config/data/boxd.sqlite3").display()
            )
        );
    }

    #[test]
    fn all_relative_storage_paths_are_bound_to_config_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let config_path = root.path().join("config/boxd.toml");
        let mut config = AppConfig::default();
        resolve_storage_paths(&config_path, &mut config).expect("resolve storage");
        let base = root.path().join("config");
        assert_eq!(config.storage.data_dir, base.join("data"));
        assert_eq!(config.storage.images_dir, base.join("data/images"));
        assert_eq!(config.storage.boxes_dir, base.join("data/boxes"));
        assert_eq!(
            config.database.url,
            format!(
                "sqlite://{}?mode=rwc",
                base.join("data/boxd.sqlite3").display()
            )
        );
    }
}
