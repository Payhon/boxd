use std::{sync::Arc, time::Duration};

use box_api::{ApiState, AuditEvent, AuditLogEntry, AuditSink};
use box_auth::{CompatibilityApiKeyAuthenticator, SessionManager};
use box_core::NetworkPolicy;
use box_db::{
    AccountSecretStore, ApiKeyStore, AuditRecord, AuditStore, BrowserRecordingStore, PreviewStore,
    RunStore, SeaRepository, SecretStore, SkillStore, SnapshotStore,
};
use box_observability::{MetricsRegistry, Telemetry};
use box_preview::{PreviewSigningKey, PreviewTokenCodec};
use box_secrets::{MasterKeySource, SecretError};
use box_service::{
    BoxService, BoxServiceDependencies, BrowserRecordingLimits, PersistentAccountSecretStore,
    PersistentSecretStore, PreviewGateway, TenantQuotaLimits, TonicAgentHostClient,
};
use salvo::{
    Router, Server,
    conn::{Listener, TcpListener},
    prelude::{Response, Text},
};
use zeroize::Zeroizing;

use crate::{
    admin_auth::LocalAdminLogin,
    config::AppConfig,
    console, embedded_runtime, github, init,
    model_provider::HttpBrowserModelProvider,
    recording::FfmpegRecordingStorage,
    request_quota::ApiKeyRequestQuota,
    runtime_host::{HostAdmission, RuntimeHost},
    runtime_image, skill_catalog,
};

pub async fn serve(config: AppConfig) -> Result<(), String> {
    if !config.auth.enabled {
        return Err("auth.enabled=false is not supported for a listening Phase 1 server".into());
    }
    let _tracing = crate::observability::initialize(&config.observability)?;
    let telemetry = Arc::new(MetricsRegistry::default());
    for path in [
        &config.storage.data_dir,
        &config.storage.images_dir,
        &config.storage.boxes_dir,
        &config.storage.snapshots_dir,
        &config.storage.recordings_dir,
        &config.storage.data_dir.join("run"),
    ] {
        std::fs::create_dir_all(path).map_err(|error| {
            format!(
                "cannot create storage directory {}: {error}",
                path.display()
            )
        })?;
    }
    let assets = embedded_runtime::install(&config.storage.data_dir)?;
    let identity = box_runtime::LibraryIdentity {
        tag: box_runtime_libkrun::LIBKRUN_TAG.into(),
        commit: box_runtime_libkrun::LIBKRUN_COMMIT.into(),
        header_sha256: box_runtime_libkrun::LIBKRUN_HEADER_SHA256.into(),
        artifact_sha256: embedded_runtime::LIBKRUN_SHA256.into(),
    };
    let firmware_identity = box_runtime::FirmwareIdentity {
        version: "5".into(),
        soname: if cfg!(target_os = "macos") {
            "libkrunfw.5.dylib"
        } else {
            "libkrunfw.so.5"
        }
        .into(),
        artifact_sha256: embedded_runtime::LIBKRUNFW_SHA256.into(),
    };
    let capabilities = box_runtime_libkrun::probe_library(
        &assets.libkrun,
        &identity,
        &assets.libkrunfw,
        &firmware_identity,
    )
    .map_err(|error| format!("embedded libkrun readiness probe failed: {error}"))?;

    let master_raw = Zeroizing::new(std::env::var(&config.auth.master_key_env).map_err(|_| {
        format!(
            "required master-key environment variable '{}' is not set",
            config.auth.master_key_env
        )
    })?);
    let master = init::decode_master_key(&master_raw)?;
    let master_source = Arc::new(StaticMasterKey(master.clone()));
    let database = box_db::connect(&config.database.url, config.database.max_connections)
        .await
        .map_err(|error| format!("database connection failed: {error}"))?;
    if config.database.auto_migrate {
        box_db::guarded_migrate(&database, &config.storage.data_dir)
            .await
            .map_err(|error| format!("database migration failed: {error}"))?;
    }

    let manager = Arc::new(runtime_image::configured_manager(&config)?);
    let admission = Arc::new(
        HostAdmission::new(&config)
            .map_err(|error| error.to_string())?
            .with_telemetry(telemetry.clone()),
    );
    let host = Arc::new(
        RuntimeHost::new(&config, manager, assets, capabilities)
            .map_err(|error| error.to_string())?
            .with_telemetry(telemetry.clone()),
    );
    let repository = Arc::new(SeaRepository::new(database.clone()));
    let persistent_secrets = Arc::new(PersistentSecretStore::new(SecretStore::new(
        database.clone(),
    )));
    let persistent_account_secrets = Arc::new(PersistentAccountSecretStore::new(
        AccountSecretStore::new(database.clone()),
    ));
    let agent = Arc::new(TonicAgentHostClient::new(
        Arc::clone(&host),
        16 * 1024 * 1024,
        Duration::from_secs(1),
        Duration::from_secs(config.runtime.boot_timeout_seconds),
    ));
    let preview_key = init::derive_key(&master, b"boxd-preview-signing-v1");
    let preview_tokens = PreviewTokenCodec::new(
        PreviewSigningKey::from_slice(&preview_key)
            .map_err(|error| format!("preview signing key initialization failed: {error}"))?,
    );
    let preview_base_url = format!(
        "{}{}",
        config.preview.base_url.trim_end_matches('/'),
        config.preview.path_prefix
    );
    let api_key_pepper = init::derive_key(&master, b"boxd-api-key-hmac-v1");
    let api_keys = ApiKeyStore::new(database.clone(), api_key_pepper)
        .map_err(|error| format!("API key store initialization failed: {error}"))?;
    let disk_bytes_per_box = config
        .resources
        .default_disk_gib
        .checked_mul(1024 * 1024 * 1024)
        .ok_or_else(|| "resources.default_disk_gib is too large".to_string())?;
    let tenant_max_disk_bytes = config
        .quotas
        .tenant_max_disk_gib
        .checked_mul(1024 * 1024 * 1024)
        .ok_or_else(|| "quotas.tenant_max_disk_gib is too large".to_string())?;
    let browser_models = Arc::new(HttpBrowserModelProvider::new(&config.models)?);
    let service = BoxService::new(BoxServiceDependencies {
        boxes: repository.clone(),
        runs: Arc::new(RunStore::new(database.clone())),
        images: host.clone(),
        runtime: host.clone(),
        agent,
        secrets: persistent_secrets,
        account_secrets: persistent_account_secrets,
        master_keys: master_source,
        admission,
    })
    .with_browser_model_provider(browser_models)
    .with_telemetry(telemetry.clone())
    .with_tenant_quotas(TenantQuotaLimits {
        max_boxes: config.quotas.tenant_max_boxes,
        max_disk_bytes: tenant_max_disk_bytes,
        disk_bytes_per_box,
        max_concurrent_runs: config.quotas.tenant_max_concurrent_runs,
    })
    .with_agent_timeout(Duration::from_secs(config.runtime.boot_timeout_seconds))
    .with_git_hosting(Arc::new(github::GitHubApi::new()?))
    .with_webhook_delivery(Arc::new(crate::webhook::WebhookClient::new()))
    .with_snapshot_repository(Arc::new(SnapshotStore::new(database.clone())))
    .with_skills(
        Arc::new(SkillStore::new(database.clone())),
        Arc::new(skill_catalog::Context7Catalog::new()?),
    )
    .with_admin_api_keys(Arc::new(api_keys.clone()))
    .with_preview(
        Arc::new(PreviewStore::new(database.clone())),
        preview_tokens,
        preview_base_url,
    )
    .map_err(|error| format!("preview service initialization failed: {error}"))?
    .with_network_policy_features(
        if config.network.default_policy == "restricted-default" {
            NetworkPolicy::RestrictedDefault
        } else {
            NetworkPolicy::DenyAll
        },
        config.network.default_policy == "restricted-default",
        config.features.custom_network_policy,
    )
    .with_attach_headers(config.features.attach_headers);
    let service = if config.features.schedules {
        service.with_schedule_repository(repository)
    } else {
        service
    };
    let service = if config.features.browser {
        let max_file_bytes = config
            .recording
            .max_file_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| "recording.max_file_mib is too large".to_string())?;
        let storage = Arc::new(FfmpegRecordingStorage::new(
            &config.storage.recordings_dir,
            &config.recording.ffmpeg_path,
            max_file_bytes,
        )?);
        let tenant_max_bytes = config
            .recording
            .tenant_max_gib
            .checked_mul(1024 * 1024 * 1024)
            .ok_or_else(|| "recording.tenant_max_gib is too large".to_string())?;
        service
            .with_browser_recording(
                Arc::new(BrowserRecordingStore::new(database.clone())),
                storage,
            )
            .with_browser_recording_limits(BrowserRecordingLimits {
                max_file_bytes,
                tenant_max_bytes,
            })
    } else {
        service
    };
    let service = Arc::new(service);
    service
        .reconcile_startup(&[])
        .await
        .map_err(|error| format!("startup reconciliation failed: {error}"))?;

    let session_pepper = init::derive_key(&master, b"boxd-admin-session-hmac-v1");
    let authenticator = Arc::new(CompatibilityApiKeyAuthenticator::new(api_keys));
    let sessions = Arc::new(
        SessionManager::new(database.clone(), session_pepper)
            .map_err(|error| format!("session manager initialization failed: {error}"))?,
    );
    let admin_login = Arc::new(LocalAdminLogin::new(
        Arc::clone(&sessions),
        config.auth.session_ttl_seconds,
    )?);
    let body_limit_bytes = usize::try_from(config.server.request_body_limit_mb)
        .ok()
        .and_then(|value| value.checked_mul(1024 * 1024))
        .ok_or_else(|| "server.request_body_limit_mb is too large".to_string())?;
    let state = ApiState {
        authenticator,
        sessions,
        admin_login,
        services: service.clone(),
        audit: Arc::new(DatabaseAuditSink(AuditStore::new(database))),
        request_quota: Arc::new(ApiKeyRequestQuota::new(&config.quotas)),
        telemetry: telemetry.clone(),
        body_limit_bytes,
    };
    let mut router = Router::new();
    if config.console.enabled {
        router = router.push(
            Router::with_path(format!(
                "{}/{{**path}}",
                config.console.base_path.trim_matches('/')
            ))
            .get(console::embedded_console),
        );
    }
    if config.observability.metrics_enabled {
        router = router.push(
            Router::with_path(config.observability.metrics_path.trim_start_matches('/'))
                .get(MetricsHandler(telemetry.clone())),
        );
    }
    let preview_gateway: Arc<dyn PreviewGateway> = service.clone();
    router = router.push(
        Router::with_path(format!(
            "{}/{{token}}/{{**path}}",
            config.preview.path_prefix.trim_matches('/')
        ))
        .goal(
            crate::preview_proxy::PreviewProxy::new(preview_gateway)
                .with_telemetry(telemetry.clone()),
        ),
    );
    router = router.push(box_api::build_router(state));

    let expiry_service = Arc::clone(&service);
    let expiry = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            if let Err(error) = expiry_service
                .expire_due(box_core::UtcEpochMillis::from_millis(now))
                .await
            {
                tracing::error!(%error, "ephemeral box expiry tick failed");
            }
            if let Err(error) = expiry_service
                .expire_previews(box_core::UtcEpochMillis::from_millis(now))
                .await
            {
                tracing::error!(%error, "preview expiry tick failed");
            }
            if let Err(error) = expiry_service
                .expire_browser_recordings(box_core::UtcEpochMillis::from_millis(now), 32)
                .await
            {
                tracing::error!(code = error.code, "browser recording expiry tick failed");
            }
            if let Err(error) = expiry_service.retry_failed_deletes_tick(8).await {
                tracing::error!(%error, "failed delete retry tick failed");
            }
            if let Err(error) = expiry_service.retry_webhook_deliveries_tick(8).await {
                tracing::error!(code = error.code, "webhook delivery retry tick failed");
            }
        }
    });
    let heartbeat_service = Arc::clone(&service);
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Creation and startup reconciliation already perform an authenticated
        // health check, so the periodic monitor starts after one full interval.
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = heartbeat_service.heartbeat_tick().await {
                tracing::error!(%error, "agent heartbeat recovery tick failed");
            }
        }
    });
    let scheduler = config.features.schedules.then(|| {
        let scheduler_service = Arc::clone(&service);
        let scheduler_telemetry = telemetry.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let scheduled_at = interval.tick().await;
                scheduler_telemetry.set_scheduler_lag(
                    tokio::time::Instant::now().saturating_duration_since(scheduled_at),
                );
                if let Err(error) = scheduler_service.schedule_tick().await {
                    tracing::error!(code = error.code, %error, "schedule tick failed");
                }
            }
        })
    });

    let acceptor = TcpListener::new(config.server.listen.clone())
        .try_bind()
        .await
        .map_err(|error| format!("cannot bind {}: {error}", config.server.listen))?;
    let server = Server::new(acceptor);
    let handle = server.handle();
    let shutdown_timeout = Duration::from_secs(config.server.graceful_shutdown_seconds);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            handle.stop_graceful(shutdown_timeout);
        }
    });
    tracing::info!(listen = %config.server.listen, "boxd control plane listening");
    let result = server
        .try_serve(router)
        .await
        .map_err(|error| format!("server failed: {error}"));
    expiry.abort();
    heartbeat.abort();
    if let Some(scheduler) = scheduler {
        scheduler.abort();
    }
    if let Err(error) = service.shutdown_creations(shutdown_timeout).await {
        tracing::error!(%error, "creation supervisor shutdown failed");
        return Err(format!("creation supervisor shutdown failed: {error}"));
    }
    if let Err(error) = service.shutdown_runtime_boxes().await {
        tracing::error!(%error, "runtime shutdown failed");
        return Err(format!("runtime shutdown failed: {error}"));
    }
    result
}

struct MetricsHandler(Arc<MetricsRegistry>);

#[async_trait::async_trait]
impl salvo::Handler for MetricsHandler {
    async fn handle(
        &self,
        _: &mut salvo::Request,
        _: &mut salvo::Depot,
        response: &mut Response,
        _: &mut salvo::FlowCtrl,
    ) {
        response.render(Text::Plain(self.0.render_prometheus()));
    }
}

struct DatabaseAuditSink(AuditStore);

#[async_trait::async_trait]
impl AuditSink for DatabaseAuditSink {
    async fn record(&self, event: AuditEvent) -> Result<(), box_core::DomainError> {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        self.0
            .append(&AuditRecord {
                id: uuid::Uuid::now_v7().to_string(),
                context: event.context,
                actor: event.actor.into(),
                action: event.action,
                resource: event.resource,
                request_id: Some(event.request_id),
                ip: event.ip,
                metadata: serde_json::json!({
                    "status_code": event.status_code,
                    "succeeded": event.succeeded,
                }),
                created_at,
            })
            .await
    }

    async fn list(
        &self,
        context: box_core::AccountContext,
        limit: u64,
    ) -> Result<Vec<AuditLogEntry>, box_core::DomainError> {
        self.0.list(context, limit).await.map(|records| {
            records
                .into_iter()
                .map(|record| AuditLogEntry {
                    id: record.id,
                    actor: record.actor,
                    action: record.action,
                    resource: record.resource,
                    request_id: record.request_id,
                    ip: record.ip,
                    status_code: record
                        .metadata
                        .get("status_code")
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|value| u16::try_from(value).ok())
                        .unwrap_or(0),
                    succeeded: record
                        .metadata
                        .get("succeeded")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                    created_at: record.created_at,
                })
                .collect()
        })
    }
}

struct StaticMasterKey(Zeroizing<Vec<u8>>);

impl MasterKeySource for StaticMasterKey {
    fn master_key(&self) -> Result<Vec<u8>, SecretError> {
        Ok(self.0.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pepper_domains_are_distinct_and_deterministic() {
        let master = [7_u8; 32];
        assert_eq!(
            init::derive_key(&master, b"a"),
            init::derive_key(&master, b"a")
        );
        assert_ne!(
            init::derive_key(&master, b"a"),
            init::derive_key(&master, b"b")
        );
    }
}
