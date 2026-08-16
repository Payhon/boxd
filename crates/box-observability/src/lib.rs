//! Low-cardinality, dependency-free Prometheus metrics shared by host crates.
//!
//! Labels are closed enums supplied by trusted adapters. Tenant, box, request,
//! path, and secret values are deliberately absent from this boundary.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{
        Mutex,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HttpSurface {
    Compatibility,
    Admin,
    Health,
    Metrics,
    OpenApi,
    Other,
}

impl HttpSurface {
    const fn label(self) -> &'static str {
        match self {
            Self::Compatibility => "compatibility",
            Self::Admin => "admin",
            Self::Health => "health",
            Self::Metrics => "metrics",
            Self::OpenApi => "openapi",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct HttpAggregate {
    requests: u64,
    duration_micros: u64,
}

pub trait Telemetry: Send + Sync {
    fn record_http(&self, surface: HttpSurface, status: u16, elapsed: Duration);
    fn set_active_boxes(&self, value: i64);
    fn record_vm_boot(&self, elapsed: Duration, succeeded: bool);
    fn record_run(&self, elapsed: Duration, succeeded: bool);
    fn add_sse_clients(&self, delta: i64);
    fn record_guest_rpc_error(&self);
    fn set_scheduler_lag(&self, lag: Duration);
    fn set_disk_bytes(&self, value: u64);
    fn add_preview_traffic(&self, bytes: u64);
    fn record_runtime_pull(&self, elapsed: Duration, succeeded: bool);
    fn record_browser_command(&self, elapsed: Duration, succeeded: bool);
}

#[derive(Default)]
pub struct NoopTelemetry;

impl Telemetry for NoopTelemetry {
    fn record_http(&self, _: HttpSurface, _: u16, _: Duration) {}
    fn set_active_boxes(&self, _: i64) {}
    fn record_vm_boot(&self, _: Duration, _: bool) {}
    fn record_run(&self, _: Duration, _: bool) {}
    fn add_sse_clients(&self, _: i64) {}
    fn record_guest_rpc_error(&self) {}
    fn set_scheduler_lag(&self, _: Duration) {}
    fn set_disk_bytes(&self, _: u64) {}
    fn add_preview_traffic(&self, _: u64) {}
    fn record_runtime_pull(&self, _: Duration, _: bool) {}
    fn record_browser_command(&self, _: Duration, _: bool) {}
}

#[derive(Default)]
pub struct MetricsRegistry {
    http: Mutex<BTreeMap<(HttpSurface, u16), HttpAggregate>>,
    active_boxes: AtomicI64,
    vm_boot_count: AtomicU64,
    vm_boot_failures: AtomicU64,
    vm_boot_micros: AtomicU64,
    run_count: AtomicU64,
    run_failures: AtomicU64,
    run_micros: AtomicU64,
    sse_clients: AtomicI64,
    guest_rpc_errors: AtomicU64,
    scheduler_lag_millis: AtomicU64,
    disk_bytes: AtomicU64,
    preview_traffic_bytes: AtomicU64,
    runtime_pull_count: AtomicU64,
    runtime_pull_failures: AtomicU64,
    runtime_pull_micros: AtomicU64,
    browser_command_count: AtomicU64,
    browser_command_failures: AtomicU64,
    browser_command_micros: AtomicU64,
}

impl MetricsRegistry {
    pub fn render_prometheus(&self) -> String {
        let mut output = String::from("# TYPE boxd_up gauge\nboxd_up 1\n");
        output.push_str("# TYPE boxd_http_requests_total counter\n");
        output.push_str("# TYPE boxd_http_request_duration_seconds summary\n");
        for ((surface, status), aggregate) in self
            .http
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
        {
            let labels = format!("surface=\"{}\",status=\"{}\"", surface.label(), status);
            let _ = writeln!(
                output,
                "boxd_http_requests_total{{{labels}}} {}",
                aggregate.requests
            );
            let _ = writeln!(
                output,
                "boxd_http_request_duration_seconds_sum{{{labels}}} {:.6}",
                aggregate.duration_micros as f64 / 1_000_000.0
            );
            let _ = writeln!(
                output,
                "boxd_http_request_duration_seconds_count{{{labels}}} {}",
                aggregate.requests
            );
        }
        gauge(
            &mut output,
            "boxd_active_boxes",
            self.active_boxes.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_vm_boot_total",
            self.vm_boot_count.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_vm_boot_failures_total",
            self.vm_boot_failures.load(Ordering::Relaxed),
        );
        seconds_sum(
            &mut output,
            "boxd_vm_boot_duration_seconds",
            self.vm_boot_micros.load(Ordering::Relaxed),
            self.vm_boot_count.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_runs_total",
            self.run_count.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_run_failures_total",
            self.run_failures.load(Ordering::Relaxed),
        );
        seconds_sum(
            &mut output,
            "boxd_run_duration_seconds",
            self.run_micros.load(Ordering::Relaxed),
            self.run_count.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "boxd_sse_clients",
            self.sse_clients.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_guest_rpc_errors_total",
            self.guest_rpc_errors.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "boxd_scheduler_lag_milliseconds",
            self.scheduler_lag_millis.load(Ordering::Relaxed) as i64,
        );
        gauge(
            &mut output,
            "boxd_disk_bytes",
            self.disk_bytes.load(Ordering::Relaxed) as i64,
        );
        counter(
            &mut output,
            "boxd_preview_traffic_bytes_total",
            self.preview_traffic_bytes.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_runtime_image_pulls_total",
            self.runtime_pull_count.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_runtime_image_pull_failures_total",
            self.runtime_pull_failures.load(Ordering::Relaxed),
        );
        seconds_sum(
            &mut output,
            "boxd_runtime_image_pull_duration_seconds",
            self.runtime_pull_micros.load(Ordering::Relaxed),
            self.runtime_pull_count.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_browser_commands_total",
            self.browser_command_count.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "boxd_browser_command_failures_total",
            self.browser_command_failures.load(Ordering::Relaxed),
        );
        seconds_sum(
            &mut output,
            "boxd_browser_command_duration_seconds",
            self.browser_command_micros.load(Ordering::Relaxed),
            self.browser_command_count.load(Ordering::Relaxed),
        );
        output
    }
}

impl Telemetry for MetricsRegistry {
    fn record_http(&self, surface: HttpSurface, status: u16, elapsed: Duration) {
        let mut metrics = self.http.lock().unwrap_or_else(|error| error.into_inner());
        let aggregate = metrics.entry((surface, status)).or_default();
        aggregate.requests = aggregate.requests.saturating_add(1);
        aggregate.duration_micros = aggregate
            .duration_micros
            .saturating_add(elapsed.as_micros().min(u128::from(u64::MAX)) as u64);
    }

    fn set_active_boxes(&self, value: i64) {
        self.active_boxes.store(value.max(0), Ordering::Relaxed);
    }

    fn record_vm_boot(&self, elapsed: Duration, succeeded: bool) {
        observe(
            &self.vm_boot_count,
            &self.vm_boot_failures,
            &self.vm_boot_micros,
            elapsed,
            succeeded,
        );
    }

    fn record_run(&self, elapsed: Duration, succeeded: bool) {
        observe(
            &self.run_count,
            &self.run_failures,
            &self.run_micros,
            elapsed,
            succeeded,
        );
    }

    fn add_sse_clients(&self, delta: i64) {
        saturating_add_gauge(&self.sse_clients, delta);
    }

    fn record_guest_rpc_error(&self) {
        self.guest_rpc_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn set_scheduler_lag(&self, lag: Duration) {
        self.scheduler_lag_millis.store(
            lag.as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }

    fn set_disk_bytes(&self, value: u64) {
        self.disk_bytes.store(value, Ordering::Relaxed);
    }

    fn add_preview_traffic(&self, bytes: u64) {
        self.preview_traffic_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_runtime_pull(&self, elapsed: Duration, succeeded: bool) {
        observe(
            &self.runtime_pull_count,
            &self.runtime_pull_failures,
            &self.runtime_pull_micros,
            elapsed,
            succeeded,
        );
    }

    fn record_browser_command(&self, elapsed: Duration, succeeded: bool) {
        observe(
            &self.browser_command_count,
            &self.browser_command_failures,
            &self.browser_command_micros,
            elapsed,
            succeeded,
        );
    }
}

fn observe(
    count: &AtomicU64,
    failures: &AtomicU64,
    micros: &AtomicU64,
    elapsed: Duration,
    succeeded: bool,
) {
    count.fetch_add(1, Ordering::Relaxed);
    if !succeeded {
        failures.fetch_add(1, Ordering::Relaxed);
    }
    micros.fetch_add(
        elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
}

fn saturating_add_gauge(gauge: &AtomicI64, delta: i64) {
    let _ = gauge.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(delta).max(0))
    });
}

fn counter(output: &mut String, name: &str, value: u64) {
    let _ = writeln!(output, "# TYPE {name} counter");
    let _ = writeln!(output, "{name} {value}");
}

fn gauge(output: &mut String, name: &str, value: i64) {
    let _ = writeln!(output, "# TYPE {name} gauge");
    let _ = writeln!(output, "{name} {value}");
}

fn seconds_sum(output: &mut String, name: &str, micros: u64, count: u64) {
    let _ = writeln!(output, "# TYPE {name} summary");
    let _ = writeln!(output, "{name}_sum {:.6}", micros as f64 / 1_000_000.0);
    let _ = writeln!(output, "{name}_count {count}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_output_has_closed_labels_and_real_aggregates() {
        let metrics = MetricsRegistry::default();
        metrics.record_http(HttpSurface::Compatibility, 429, Duration::from_millis(25));
        metrics.record_vm_boot(Duration::from_secs(2), false);
        metrics.add_sse_clients(1);
        metrics.add_sse_clients(-2);
        metrics.add_preview_traffic(512);
        let output = metrics.render_prometheus();
        assert!(
            output.contains("boxd_http_requests_total{surface=\"compatibility\",status=\"429\"} 1")
        );
        assert!(output.contains("boxd_http_request_duration_seconds_sum{surface=\"compatibility\",status=\"429\"} 0.025000"));
        assert!(output.contains("boxd_vm_boot_failures_total 1"));
        assert!(output.contains("boxd_sse_clients 0"));
        assert!(output.contains("boxd_preview_traffic_bytes_total 512"));
        assert!(!output.contains("tenant"));
    }
}
