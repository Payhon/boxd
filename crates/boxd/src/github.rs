use std::time::Duration;

use async_trait::async_trait;
use box_api::PullRequest;
use box_core::{DomainError, DomainErrorKind};
use box_service::{GitHosting, GitHubCredential, GitHubPullRequestInput};
use serde::{Deserialize, Serialize};

pub struct GitHubApi {
    client: reqwest::Client,
    base_url: reqwest::Url,
}

impl GitHubApi {
    pub fn new() -> Result<Self, String> {
        Self::with_base("https://api.github.com/")
    }

    fn with_base(base_url: &str) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("GitHub API client construction failed: {error}"))?;
        let base_url = reqwest::Url::parse(base_url)
            .map_err(|error| format!("GitHub API base URL is invalid: {error}"))?;
        Ok(Self { client, base_url })
    }
}

#[derive(Serialize)]
struct CreatePullRequest<'a> {
    title: &'a str,
    body: Option<&'a str>,
    base: &'a str,
    head: &'a str,
}

#[derive(Deserialize)]
struct PullRequestResponse {
    html_url: String,
    number: u64,
    title: String,
    base: PullRequestBase,
}

#[derive(Deserialize)]
struct PullRequestBase {
    #[serde(rename = "ref")]
    reference: String,
}

fn github_error(message: impl Into<String>) -> DomainError {
    DomainError {
        kind: DomainErrorKind::Unavailable,
        code: "git_provider_unavailable",
        message: message.into(),
    }
}

#[async_trait]
impl GitHosting for GitHubApi {
    async fn create_pull_request(
        &self,
        credential: GitHubCredential,
        input: GitHubPullRequestInput,
    ) -> box_core::Result<PullRequest> {
        let path = format!("repos/{}/{}/pulls", input.owner, input.repository);
        let url = self
            .base_url
            .join(&path)
            .map_err(|_| github_error("GitHub pull request URL construction failed"))?;
        let response = self
            .client
            .post(url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "boxd")
            .bearer_auth(credential.expose())
            .json(&CreatePullRequest {
                title: &input.title,
                body: input.body.as_deref(),
                base: &input.base,
                head: &input.head,
            })
            .send()
            .await
            .map_err(|_| github_error("GitHub pull request request failed"))?;
        if !response.status().is_success() {
            return Err(github_error(format!(
                "GitHub pull request failed with HTTP {}",
                response.status().as_u16()
            )));
        }
        let response: PullRequestResponse = response
            .json()
            .await
            .map_err(|_| github_error("GitHub pull request response was invalid"))?;
        Ok(PullRequest {
            url: response.html_url,
            number: response.number,
            title: response.title,
            base: response.base.reference,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn loopback_adapter_uses_bearer_header_and_pinned_json_shape() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&chunk[..count]);
                let text = String::from_utf8_lossy(&request);
                let Some(header_end) = text.find("\r\n\r\n") else {
                    continue;
                };
                let length = text[..header_end]
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap();
                if request.len() >= header_end + 4 + length {
                    break;
                }
            }
            let text = String::from_utf8(request).unwrap();
            assert!(text.starts_with("POST /repos/example/repository/pulls HTTP/1.1\r\n"));
            assert!(
                text.to_ascii_lowercase()
                    .contains("authorization: bearer fixture-provider-token\r\n")
            );
            assert!(
                text.contains(r#"{"title":"title","body":"body","base":"main","head":"feature"}"#)
            );
            let body = r#"{"html_url":"https://github.com/example/repository/pull/42","number":42,"title":"title","base":{"ref":"main"}}"#;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let client = GitHubApi::with_base(&format!("http://{address}/")).unwrap();
        let result = client
            .create_pull_request(
                GitHubCredential::new("fixture-provider-token".into()).unwrap(),
                GitHubPullRequestInput {
                    owner: "example".into(),
                    repository: "repository".into(),
                    title: "title".into(),
                    body: Some("body".into()),
                    base: "main".into(),
                    head: "feature".into(),
                },
            )
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(result.number, 42);
        assert_eq!(result.base, "main");
    }
}
