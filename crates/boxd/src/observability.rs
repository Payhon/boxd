use std::time::Duration;

use opentelemetry::{global, trace::TracerProvider as _};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::ObservabilityConfig;

pub struct TracingGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take()
            && let Err(error) = provider.shutdown()
        {
            eprintln!("boxd: OpenTelemetry shutdown failed: {error}");
        }
    }
}

pub fn initialize(config: &ObservabilityConfig) -> Result<TracingGuard, String> {
    global::set_text_map_propagator(TraceContextPropagator::new());

    let provider = build_provider(config)?;

    let format_layer = if config.log_format == "json" {
        tracing_subscriber::fmt::layer()
            .json()
            .with_target(false)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer().with_target(false).boxed()
    };
    let otlp_layer = provider.as_ref().map(|provider| {
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("boxd"))
            .boxed()
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_new(config.log_level.clone())
                .map_err(|error| format!("invalid observability.log_level: {error}"))?,
        )
        .with(format_layer)
        .with(otlp_layer)
        .try_init()
        .map_err(|error| format!("cannot initialize tracing subscriber: {error}"))?;

    Ok(TracingGuard { provider })
}

fn build_provider(config: &ObservabilityConfig) -> Result<Option<SdkTracerProvider>, String> {
    if config.otlp_endpoint.is_empty() {
        return Ok(None);
    }
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(config.otlp_endpoint.clone())
        .with_timeout(Duration::from_secs(config.otlp_timeout_seconds))
        .build()
        .map_err(|error| format!("cannot configure OTLP trace exporter: {error}"))?;
    Ok(Some(
        SdkTracerProvider::builder()
            .with_resource(Resource::builder().with_service_name("boxd").build())
            .with_batch_exporter(exporter)
            .build(),
    ))
}

#[cfg(test)]
mod tests {
    use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn otlp_http_exporter_emits_protobuf_to_configured_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind OTLP fixture");
        let address = listener.local_addr().expect("fixture address");
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept OTLP request");
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 8 * 1024];
            loop {
                let count = stream.read(&mut buffer).await.expect("read OTLP request");
                assert_ne!(count, 0, "OTLP request ended before headers");
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let header_end = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("header delimiter")
                + 4;
            let headers = String::from_utf8(bytes[..header_end].to_vec()).expect("HTTP headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
                .expect("content-length header");
            while bytes.len() < header_end + content_length {
                let count = stream.read(&mut buffer).await.expect("read OTLP body");
                assert_ne!(count, 0, "OTLP request ended before body");
                bytes.extend_from_slice(&buffer[..count]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .expect("respond to exporter");
            assert!(headers.starts_with("POST /v1/traces HTTP/1.1"));
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("content-type: application/x-protobuf")
            );
            assert!(content_length > 0);
        });

        let config = ObservabilityConfig {
            otlp_endpoint: format!("http://{address}/v1/traces"),
            otlp_timeout_seconds: 2,
            ..ObservabilityConfig::default()
        };
        let provider = build_provider(&config)
            .expect("build OTLP provider")
            .expect("enabled provider");
        let tracer = provider.tracer("boxd-test");
        let mut span = tracer.start("phase3.otlp.fixture");
        span.end();
        tokio::task::spawn_blocking(move || provider.shutdown())
            .await
            .expect("shutdown task")
            .expect("flush OTLP spans");
        tokio::time::timeout(Duration::from_secs(3), receiver)
            .await
            .expect("OTLP fixture timeout")
            .expect("OTLP fixture task");
    }
}
