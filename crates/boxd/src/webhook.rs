use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use box_core::{DomainError, DomainErrorKind};
use box_egress::{EgressDecision, evaluate_tcp_connect};
use box_service::{WebhookDelivery, WebhookDeliveryRequest};
use reqwest::{
    Url,
    header::{HeaderMap, HeaderName, HeaderValue},
};

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct WebhookClient;

impl WebhookClient {
    pub fn new() -> Self {
        Self
    }
}

fn policy_error() -> DomainError {
    DomainError::validation("webhook URL is not allowed")
}

fn delivery_error() -> DomainError {
    DomainError {
        kind: DomainErrorKind::Unavailable,
        code: "webhook_delivery_failed",
        message: "webhook delivery failed".into(),
    }
}

fn parse_target(raw: &str) -> box_core::Result<(Url, String, u16)> {
    let url = Url::parse(raw).map_err(|_| policy_error())?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(policy_error());
    }
    let host = url.host_str().ok_or_else(policy_error)?.to_owned();
    let port = url.port_or_known_default().ok_or_else(policy_error)?;
    if !matches!((url.scheme(), port), ("http", 80) | ("https", 443)) {
        return Err(policy_error());
    }
    Ok((url, host, port))
}

fn custom_headers(
    values: &std::collections::BTreeMap<String, String>,
    run_id: &str,
) -> box_core::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| policy_error())?;
        if matches!(
            name.as_str(),
            "host"
                | "content-type"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "upgrade"
                | "x-boxd-webhook-id"
        ) {
            return Err(policy_error());
        }
        let value = HeaderValue::from_str(value).map_err(|_| policy_error())?;
        headers.insert(name, value);
    }
    headers.insert(
        HeaderName::from_static("x-boxd-webhook-id"),
        HeaderValue::from_str(run_id).map_err(|_| policy_error())?,
    );
    Ok(headers)
}

async fn resolve_public_target(
    host: &str,
    port: u16,
) -> box_core::Result<Vec<std::net::SocketAddr>> {
    let addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![std::net::SocketAddr::new(address, port)]
    } else {
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| delivery_error())?
        .map_err(|_| delivery_error())?
        .collect::<Vec<_>>()
    };
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| evaluate_tcp_connect(address.ip(), port) != EgressDecision::Allow)
    {
        return Err(policy_error());
    }
    Ok(addresses)
}

#[async_trait]
impl WebhookDelivery for WebhookClient {
    async fn deliver(&self, request: WebhookDeliveryRequest) -> box_core::Result<()> {
        let (url, host, port) = parse_target(&request.url)?;
        let addresses = resolve_public_target(&host, port).await?;
        let mut builder = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(DELIVERY_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if host.parse::<IpAddr>().is_err() {
            builder = builder.resolve(&host, addresses[0]);
        }
        let client = builder.build().map_err(|_| delivery_error())?;
        let response = client
            .post(url)
            .headers(custom_headers(
                &request.headers,
                &request.run_id.to_string(),
            )?)
            .json(&request.payload)
            .send()
            .await
            .map_err(|_| delivery_error())?;
        if !response.status().is_success() {
            return Err(delivery_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_url_policy_rejects_unsafe_targets_and_headers() {
        for url in [
            "file:///tmp/hook",
            "http://1.1.1.1:8080/hook",
            "https://user:secret@1.1.1.1/hook",
            "https://1.1.1.1/hook#fragment",
        ] {
            assert!(parse_target(url).is_err(), "{url}");
        }
        for url in [
            "http://127.0.0.1/hook",
            "http://169.254.169.254/latest",
            "http://10.0.0.1/hook",
        ] {
            let (_, host, port) = parse_target(url).expect("valid URL shape");
            let address = host.parse::<IpAddr>().unwrap();
            assert_ne!(
                evaluate_tcp_connect(address, port),
                EgressDecision::Allow,
                "{url}"
            );
        }
        let (_, host, port) = parse_target("https://1.1.1.1/hook?token=opaque").unwrap();
        assert_eq!(host, "1.1.1.1");
        assert_eq!(port, 443);
        assert_eq!(
            evaluate_tcp_connect(host.parse().unwrap(), port),
            EgressDecision::Allow
        );

        for name in [
            "Host",
            "Content-Type",
            "Keep-Alive",
            "Proxy-Authorization",
            "TE",
            "Trailer",
        ] {
            let forbidden = std::collections::BTreeMap::from([(name.into(), "attacker".into())]);
            assert!(custom_headers(&forbidden, "run").is_err(), "{name}");
        }
    }
}
