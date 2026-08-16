use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use box_core::{DomainError, DomainErrorKind};
use box_service::{BrowserModelProvider, BrowserModelRequest, BrowserModelResponse};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::config::{ModelProviderConfig, ModelsConfig};

const MAX_MODEL_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 3;

#[derive(Clone)]
pub struct HttpBrowserModelProvider {
    client: Client,
    providers: Arc<BTreeMap<String, ModelProviderConfig>>,
}

impl HttpBrowserModelProvider {
    pub fn new(config: &ModelsConfig) -> Result<Self, String> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("browser model HTTP client initialization failed: {error}"))?;
        Ok(Self {
            client,
            providers: Arc::new(config.providers.clone()),
        })
    }

    async fn complete_openai(
        &self,
        provider: &ModelProviderConfig,
        model: &str,
        api_key: &str,
        request: &BrowserModelRequest,
    ) -> box_core::Result<BrowserModelResponse> {
        let schema = request
            .schema
            .clone()
            .unwrap_or_else(|| json!({"type":"object"}));
        let body = json!({
            "model": model,
            "messages": [
                {"role":"system","content":request.system},
                {"role":"user","content":request.prompt}
            ],
            "response_format": {
                "type":"json_schema",
                "json_schema":{"name":"boxd_browser_result","strict":false,"schema":schema}
            }
        });
        let endpoint = format!(
            "{}/chat/completions",
            provider.base_url.trim_end_matches('/')
        );
        let payload = self
            .post_json(&endpoint, api_key, None, body, request.timeout)
            .await?;
        let content = payload
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| unavailable("browser model response content is missing"))?;
        let output = serde_json::from_str(content)
            .map_err(|_| unavailable("browser model response is not valid JSON"))?;
        Ok(BrowserModelResponse {
            output,
            input_tokens: payload
                .pointer("/usage/prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: payload
                .pointer("/usage/completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }

    async fn complete_anthropic(
        &self,
        provider: &ModelProviderConfig,
        model: &str,
        api_key: &str,
        request: &BrowserModelRequest,
    ) -> box_core::Result<BrowserModelResponse> {
        let schema = request
            .schema
            .clone()
            .unwrap_or_else(|| json!({"type":"object"}));
        let body = json!({
            "model": model,
            "max_tokens": 4096,
            "system": request.system,
            "messages":[{"role":"user","content":request.prompt}],
            "tools":[{
                "name":"boxd_browser_result",
                "description":"Return the structured browser operation result",
                "input_schema":schema
            }],
            "tool_choice":{"type":"tool","name":"boxd_browser_result"}
        });
        let endpoint = format!("{}/v1/messages", provider.base_url.trim_end_matches('/'));
        let payload = self
            .post_json(
                &endpoint,
                api_key,
                Some(("anthropic-version", "2023-06-01")),
                body,
                request.timeout,
            )
            .await?;
        let output = payload
            .get("content")
            .and_then(Value::as_array)
            .and_then(|content| {
                content.iter().find_map(|part| {
                    (part.get("type").and_then(Value::as_str) == Some("tool_use")
                        && part.get("name").and_then(Value::as_str) == Some("boxd_browser_result"))
                    .then(|| part.get("input").cloned())
                    .flatten()
                })
            })
            .ok_or_else(|| unavailable("browser model tool result is missing"))?;
        Ok(BrowserModelResponse {
            output,
            input_tokens: payload
                .pointer("/usage/input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: payload
                .pointer("/usage/output_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }

    async fn post_json(
        &self,
        endpoint: &str,
        api_key: &str,
        extra_header: Option<(&'static str, &'static str)>,
        body: Value,
        timeout: Duration,
    ) -> box_core::Result<Value> {
        for attempt in 0..MAX_ATTEMPTS {
            let mut request = self
                .client
                .post(endpoint)
                .timeout(timeout)
                .bearer_auth(api_key)
                .json(&body);
            if let Some((name, value)) = extra_header {
                request = request.header(name, value).header("x-api-key", api_key);
            }
            let response = request
                .send()
                .await
                .map_err(|_| unavailable("browser model request failed"))?;
            let status = response.status();
            if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                && attempt + 1 < MAX_ATTEMPTS
            {
                tokio::time::sleep(Duration::from_millis(100 * (1_u64 << attempt))).await;
                continue;
            }
            if !status.is_success() {
                return Err(
                    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                        DomainError::state_conflict("browser model credential was rejected")
                    } else {
                        unavailable("browser model provider rejected the request")
                    },
                );
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_MODEL_RESPONSE_BYTES)
            {
                return Err(unavailable("browser model response exceeds limit"));
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|_| unavailable("browser model response read failed"))?;
            if bytes.len() as u64 > MAX_MODEL_RESPONSE_BYTES {
                return Err(unavailable("browser model response exceeds limit"));
            }
            return serde_json::from_slice(&bytes)
                .map_err(|_| unavailable("browser model provider returned invalid JSON"));
        }
        Err(unavailable("browser model retry budget exhausted"))
    }
}

#[async_trait]
impl BrowserModelProvider for HttpBrowserModelProvider {
    async fn complete(
        &self,
        mut request: BrowserModelRequest,
    ) -> box_core::Result<BrowserModelResponse> {
        let (provider_name, model) = request
            .model
            .split_once('/')
            .filter(|(provider, model)| !provider.is_empty() && !model.is_empty())
            .ok_or_else(|| {
                DomainError::validation("browser model must use provider/model format")
            })?;
        let provider = self
            .providers
            .get(provider_name)
            .ok_or_else(|| DomainError::feature_not_supported("browser model provider"))?;
        let api_key = Zeroizing::new(
            request
                .environment
                .remove(&provider.api_key_env)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    DomainError::state_conflict("browser model credential is not configured")
                })?,
        );
        match provider.kind.as_str() {
            "openai" => {
                self.complete_openai(provider, model, api_key.as_str(), &request)
                    .await
            }
            "anthropic" => {
                self.complete_anthropic(provider, model, api_key.as_str(), &request)
                    .await
            }
            _ => Err(DomainError::feature_not_supported(
                "browser model provider kind",
            )),
        }
    }
}

fn unavailable(message: impl Into<String>) -> DomainError {
    DomainError {
        kind: DomainErrorKind::Unavailable,
        code: "service_unavailable",
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn fixture_server(response_body: Value) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let expected = loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap();
                break header_end + 4 + content_length;
            };
            while request.len() < expected {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
            }
            let body = response_body.to_string();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            request
        });
        (format!("http://{address}"), task)
    }

    fn config(name: &str, kind: &str, base_url: String, key_env: &str) -> ModelsConfig {
        ModelsConfig {
            default_model: format!("{name}/fixture"),
            providers: [(
                name.into(),
                ModelProviderConfig {
                    kind: kind.into(),
                    base_url,
                    api_key_env: key_env.into(),
                },
            )]
            .into(),
        }
    }

    fn request(model: &str, key_env: &str) -> BrowserModelRequest {
        BrowserModelRequest {
            model: model.into(),
            system: "system fixture".into(),
            prompt: "prompt fixture".into(),
            schema: Some(json!({"type":"object"})),
            environment: [(key_env.into(), "fixture-secret".into())].into(),
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn openai_compatible_provider_sends_bounded_structured_request() {
        let (base_url, server) = fixture_server(json!({
            "choices":[{"message":{"content":"{\"ok\":true}"}}],
            "usage":{"prompt_tokens":7,"completion_tokens":3}
        }))
        .await;
        let provider = HttpBrowserModelProvider::new(&config(
            "fixture",
            "openai",
            base_url,
            "FIXTURE_API_KEY",
        ))
        .unwrap();
        let response = provider
            .complete(request("fixture/model", "FIXTURE_API_KEY"))
            .await
            .unwrap();
        assert_eq!(response.output, json!({"ok":true}));
        assert_eq!((response.input_tokens, response.output_tokens), (7, 3));
        let request = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(request.starts_with("POST /chat/completions HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-secret")
        );
        assert!(request.contains("\"response_format\""));
    }

    #[tokio::test]
    async fn anthropic_provider_uses_forced_tool_and_redacts_failures() {
        let (base_url, server) = fixture_server(json!({
            "content":[{"type":"tool_use","name":"boxd_browser_result","input":{"ok":true}}],
            "usage":{"input_tokens":5,"output_tokens":2}
        }))
        .await;
        let config = config("anthropic", "anthropic", base_url, "ANTHROPIC_API_KEY");
        let provider = HttpBrowserModelProvider::new(&config).unwrap();
        let response = provider
            .complete(request("anthropic/model", "ANTHROPIC_API_KEY"))
            .await
            .unwrap();
        assert_eq!(response.output, json!({"ok":true}));
        let wire = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(wire.starts_with("POST /v1/messages HTTP/1.1"));
        assert!(
            wire.to_ascii_lowercase()
                .contains("x-api-key: fixture-secret")
        );
        assert!(wire.contains("\"tool_choice\""));

        let mut missing = request("anthropic/model", "UNRELATED_KEY");
        missing
            .environment
            .insert("UNRELATED_KEY".into(), "do-not-leak".into());
        let error = match provider.complete(missing).await {
            Ok(_) => panic!("missing browser credential unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(!error.to_string().contains("do-not-leak"));
        assert_eq!(error.code, "state_conflict");
    }
}
