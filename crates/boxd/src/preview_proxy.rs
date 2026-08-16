use std::sync::Arc;

use box_core::{DomainError, DomainErrorKind};
use box_observability::{NoopTelemetry, Telemetry};
use box_service::PreviewGateway;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use salvo::{
    Depot, FlowCtrl, Handler, Request, Response, async_trait,
    conn::SocketAddr,
    http::{HeaderMap, HeaderValue, ReqBody, ResBody, StatusCode, header},
    writing::Text,
};
use tokio::io::copy_bidirectional;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

#[derive(Clone)]
pub struct PreviewProxy {
    gateway: Arc<dyn PreviewGateway>,
    telemetry: Arc<dyn Telemetry>,
}

impl PreviewProxy {
    pub fn new(gateway: Arc<dyn PreviewGateway>) -> Self {
        Self {
            gateway,
            telemetry: Arc::new(NoopTelemetry),
        }
    }

    pub fn with_telemetry(mut self, telemetry: Arc<dyn Telemetry>) -> Self {
        self.telemetry = telemetry;
        self
    }
}

#[async_trait]
impl Handler for PreviewProxy {
    async fn handle(&self, req: &mut Request, _: &mut Depot, res: &mut Response, _: &mut FlowCtrl) {
        if let Err(error) = self.proxy(req, res).await {
            render_error(res, error);
        }
    }
}

impl PreviewProxy {
    async fn proxy(&self, req: &mut Request, res: &mut Response) -> Result<(), DomainError> {
        let request_bytes = content_length(req.headers());
        let route_token = req.param::<String>("token").ok_or_else(not_found)?;
        let tail = req.param::<String>("path").unwrap_or_default();
        validate_path(&tail)?;
        let authorization = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let opened = self
            .gateway
            .open_preview(&route_token, authorization.as_deref())
            .await?;

        let is_upgrade = header_contains_token(req, header::CONNECTION, "upgrade")
            && req
                .headers()
                .get(header::UPGRADE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        let request_upgrade = if is_upgrade {
            req.extensions_mut().remove::<OnUpgrade>()
        } else {
            None
        };
        let original_host = req
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let original_host = original_host
            .parse::<hyper::http::uri::Authority>()
            .map_err(|_| DomainError::validation("invalid preview Host header"))?
            .to_string();
        let remote_ip = match req.remote_addr() {
            SocketAddr::IPv4(address) => Some(address.ip().to_string()),
            SocketAddr::IPv6(address) => Some(address.ip().to_string()),
            _ => None,
        };
        let proto = if req.scheme().as_str() == "https" {
            "https"
        } else {
            "http"
        };
        let query = req
            .uri()
            .query()
            .map(|value| format!("?{value}"))
            .unwrap_or_default();
        let target = format!("/{}{query}", tail.trim_start_matches('/'));
        *req.uri_mut() = target
            .parse()
            .map_err(|_| DomainError::validation("invalid preview request path"))?;
        req.headers_mut().remove(header::AUTHORIZATION);
        let connection_headers = connection_header_names(req);
        for name in HOP_BY_HOP {
            req.headers_mut().remove(*name);
        }
        for name in connection_headers {
            if !is_upgrade || name != header::UPGRADE {
                req.headers_mut().remove(name);
            }
        }
        if !is_upgrade {
            req.headers_mut().remove(header::UPGRADE);
        } else {
            req.headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        }
        overwrite_header(req, header::HOST, &format!("127.0.0.1:{}", opened.port))?;
        overwrite_header(req, "x-forwarded-host", &original_host)?;
        overwrite_header(req, "x-forwarded-proto", proto)?;
        overwrite_header(req, "x-forwarded-prefix", "/")?;
        req.headers_mut().remove("x-forwarded-for");
        if let Some(remote_ip) = remote_ip {
            overwrite_header(req, "x-forwarded-for", &remote_ip)?;
        }
        overwrite_header(
            req,
            "forwarded",
            &format!("proto={proto};host=\"{original_host}\""),
        )?;

        let request = req
            .strip_to_hyper::<ReqBody>()
            .map_err(|error| proxy_error(format!("preview request conversion failed: {error}")))?;
        let io = TokioIo::new(opened.tunnel);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| proxy_error(format!("preview HTTP handshake failed: {error}")))?;
        tokio::spawn(async move {
            if let Err(error) = connection.with_upgrades().await {
                tracing::debug!(%error, "preview HTTP connection closed");
            }
        });
        let mut response = sender
            .send_request(request)
            .await
            .map_err(|error| proxy_error(format!("preview upstream request failed: {error}")))?;
        let response_bytes = content_length(response.headers());

        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            if !is_upgrade
                || response
                    .headers()
                    .get(header::UPGRADE)
                    .and_then(|value| value.to_str().ok())
                    .is_none_or(|value| !value.eq_ignore_ascii_case("websocket"))
            {
                return Err(proxy_error("preview upstream returned an invalid upgrade"));
            }
            let Some(request_upgrade) = request_upgrade else {
                return Err(proxy_error(
                    "preview upgrade is missing the client transport",
                ));
            };
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            let telemetry = Arc::clone(&self.telemetry);
            tokio::spawn(async move {
                let (Ok(client), Ok(upstream)) = (request_upgrade.await, upstream_upgrade.await)
                else {
                    return;
                };
                let mut client = TokioIo::new(client);
                let mut upstream = TokioIo::new(upstream);
                match copy_bidirectional(&mut client, &mut upstream).await {
                    Ok((client_to_upstream, upstream_to_client)) => telemetry
                        .add_preview_traffic(client_to_upstream.saturating_add(upstream_to_client)),
                    Err(error) => tracing::debug!(%error, "preview upgraded stream closed"),
                }
            });
        } else {
            let response_connection_headers = response
                .headers()
                .get(header::CONNECTION)
                .and_then(|value| value.to_str().ok())
                .map(|value| {
                    value
                        .split(',')
                        .filter_map(|name| name.trim().parse::<header::HeaderName>().ok())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            for name in HOP_BY_HOP {
                response.headers_mut().remove(*name);
            }
            response.headers_mut().remove(header::UPGRADE);
            for name in response_connection_headers {
                response.headers_mut().remove(name);
            }
        }
        self.telemetry
            .add_preview_traffic(request_bytes.saturating_add(response_bytes));
        res.merge_hyper(response.map(ResBody::Hyper));
        Ok(())
    }
}

fn content_length(headers: &HeaderMap) -> u64 {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn header_contains_token(req: &Request, name: header::HeaderName, expected: &str) -> bool {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
}

fn connection_header_names(req: &Request) -> Vec<header::HeaderName> {
    req.headers()
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .filter_map(|name| name.trim().parse::<header::HeaderName>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn overwrite_header(
    req: &mut Request,
    name: impl header::IntoHeaderName,
    value: &str,
) -> Result<(), DomainError> {
    let value = HeaderValue::from_str(value)
        .map_err(|_| DomainError::validation("invalid preview forwarding header"))?;
    req.headers_mut().insert(name, value);
    Ok(())
}

fn validate_path(path: &str) -> Result<(), DomainError> {
    if path.len() > 8 * 1024
        || path.split(['/', '\\']).any(|segment| segment == "..")
        || path.as_bytes().windows(3).any(|window| {
            window[0] == b'%'
                && matches!(
                    window[1..],
                    [b'2', b'e' | b'E'] | [b'2', b'f' | b'F'] | [b'2', b'5'] | [b'5', b'c' | b'C']
                )
        })
    {
        return Err(DomainError::validation("invalid preview request path"));
    }
    Ok(())
}

fn not_found() -> DomainError {
    DomainError {
        kind: DomainErrorKind::NotFound,
        code: "not_found",
        message: "preview route not found".into(),
    }
}

fn proxy_error(message: impl Into<String>) -> DomainError {
    DomainError {
        kind: DomainErrorKind::Unavailable,
        code: "preview_unavailable",
        message: message.into(),
    }
}

fn render_error(res: &mut Response, error: DomainError) {
    let status = match error.kind {
        DomainErrorKind::Validation => StatusCode::BAD_REQUEST,
        DomainErrorKind::Ownership => StatusCode::UNAUTHORIZED,
        DomainErrorKind::NotFound => StatusCode::NOT_FOUND,
        DomainErrorKind::FeatureNotSupported => StatusCode::NOT_IMPLEMENTED,
        DomainErrorKind::Unavailable | DomainErrorKind::Capacity => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_GATEWAY,
    };
    if status == StatusCode::UNAUTHORIZED {
        res.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"boxd-preview\", Basic realm=\"boxd-preview\""),
        );
    }
    res.status_code(status);
    res.render(Text::Plain(if status.is_server_error() {
        "preview unavailable"
    } else if status == StatusCode::UNAUTHORIZED {
        "preview authorization required"
    } else {
        "preview not found"
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use box_service::{AgentTunnelStream, OpenedPreviewTunnel};
    use salvo::{
        Router, Server,
        conn::{Acceptor, Listener, TcpListener},
        server::ServerHandle,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    enum Mode {
        Http(std::sync::Mutex<Option<oneshot::Sender<String>>>),
        WebSocket,
    }

    struct Gateway(Mode);

    #[async_trait]
    impl PreviewGateway for Gateway {
        async fn open_preview(
            &self,
            route_token: &str,
            authorization: Option<&str>,
        ) -> box_core::Result<OpenedPreviewTunnel> {
            if route_token != "route" {
                return Err(not_found());
            }
            if authorization == Some("Bearer wrong") {
                return Err(DomainError {
                    kind: DomainErrorKind::Ownership,
                    code: "preview_unauthorized",
                    message: "unauthorized".into(),
                });
            }
            let (client, mut server) = tokio::io::duplex(2 * 1024 * 1024);
            match &self.0 {
                Mode::Http(sender) => {
                    let sender = sender.lock().unwrap().take();
                    tokio::spawn(async move {
                        let mut request = Vec::new();
                        let mut buffer = [0_u8; 1024];
                        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                            let read = server.read(&mut buffer).await.unwrap();
                            if read == 0 {
                                break;
                            }
                            request.extend_from_slice(&buffer[..read]);
                        }
                        let request = String::from_utf8(request).unwrap();
                        if let Some(sender) = sender {
                            let _ = sender.send(request);
                        }
                        server
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\npreview-body",
                            )
                            .await
                            .unwrap();
                    });
                }
                Mode::WebSocket => {
                    tokio::spawn(async move {
                        let request = read_headers(&mut server).await;
                        assert!(request.to_ascii_lowercase().contains("upgrade: websocket"));
                        server.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
                        let payload = read_websocket_frame(&mut server, true).await;
                        write_websocket_frame(&mut server, &payload, false).await;
                    });
                }
            }
            Ok(OpenedPreviewTunnel {
                tunnel: Box::new(client) as AgentTunnelStream,
                port: 3_000,
            })
        }
    }

    async fn serve(gateway: Arc<dyn PreviewGateway>) -> (std::net::SocketAddr, ServerHandle) {
        let acceptor = TcpListener::new("127.0.0.1:0").bind().await;
        let address = acceptor.holdings()[0]
            .local_addr
            .clone()
            .into_std()
            .unwrap();
        let server = Server::new(acceptor);
        let handle = server.handle();
        tokio::spawn(
            server.serve(Router::with_path("p/{token}/{**path}").goal(PreviewProxy::new(gateway))),
        );
        (address, handle)
    }

    async fn read_headers(stream: &mut tokio::io::DuplexStream) -> String {
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            request.push(byte[0]);
        }
        String::from_utf8(request).unwrap()
    }

    async fn read_websocket_frame<R: tokio::io::AsyncRead + Unpin>(
        stream: &mut R,
        expect_mask: bool,
    ) -> Vec<u8> {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0] & 0x0f, 2);
        assert_eq!(header[1] & 0x80 != 0, expect_mask);
        let length = match header[1] & 0x7f {
            value @ 0..=125 => u64::from(value),
            126 => {
                let mut length = [0_u8; 2];
                stream.read_exact(&mut length).await.unwrap();
                u64::from(u16::from_be_bytes(length))
            }
            127 => {
                let mut length = [0_u8; 8];
                stream.read_exact(&mut length).await.unwrap();
                u64::from_be_bytes(length)
            }
            _ => unreachable!(),
        };
        let mut mask = [0_u8; 4];
        if expect_mask {
            stream.read_exact(&mut mask).await.unwrap();
        }
        let mut payload = vec![0; usize::try_from(length).unwrap()];
        stream.read_exact(&mut payload).await.unwrap();
        if expect_mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % mask.len()];
            }
        }
        payload
    }

    async fn write_websocket_frame<W: tokio::io::AsyncWrite + Unpin>(
        stream: &mut W,
        payload: &[u8],
        mask: bool,
    ) {
        let mut header = vec![0x82, 127 | if mask { 0x80 } else { 0 }];
        header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        let mask_key = [1_u8, 2, 3, 4];
        if mask {
            header.extend_from_slice(&mask_key);
        }
        stream.write_all(&header).await.unwrap();
        if mask {
            let payload = payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask_key[index % mask_key.len()])
                .collect::<Vec<_>>();
            stream.write_all(&payload).await.unwrap();
        } else {
            stream.write_all(payload).await.unwrap();
        }
    }

    #[test]
    fn rejects_ambiguous_paths_and_accepts_normal_nested_paths() {
        assert!(validate_path("assets/app.js").is_ok());
        assert!(validate_path("../secret").is_err());
        assert!(validate_path("%2e%2e/secret").is_err());
        assert!(validate_path("safe/%2Fescape").is_err());
    }

    #[tokio::test]
    async fn proxies_streaming_http_and_overwrites_untrusted_forwarding_headers() {
        let (send, receive) = oneshot::channel();
        let (address, handle) = serve(Arc::new(Gateway(Mode::Http(std::sync::Mutex::new(Some(
            send,
        ))))))
        .await;
        let response = reqwest::Client::new()
            .get(format!("http://{address}/p/route/nested?a=1"))
            .header("authorization", "Bearer preview-secret")
            .header("x-forwarded-host", "attacker.invalid")
            .header("forwarded", "for=attacker.invalid")
            .header("connection", "keep-alive, x-spoof")
            .header("x-spoof", "smuggled")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "preview-body");
        let request = receive.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /nested?a=1 http/1.1\r\n"));
        assert!(request.contains("host: 127.0.0.1:3000\r\n"));
        assert!(request.contains(&format!("x-forwarded-host: {address}\r\n")));
        assert!(request.contains(&format!("forwarded: proto=http;host=\"{address}\"\r\n")));
        assert!(!request.contains("preview-secret"));
        assert!(!request.contains("attacker.invalid"));
        assert!(!request.contains("smuggled"));
        handle.stop_graceful(None);
    }

    #[tokio::test]
    async fn websocket_upgrade_is_bidirectional_and_bounded_by_transport_backpressure() {
        let (address, handle) = serve(Arc::new(Gateway(Mode::WebSocket))).await;
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket.write_all(format!("GET /p/route/socket HTTP/1.1\r\nHost: {address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
            response.push(byte[0]);
        }
        assert!(
            String::from_utf8(response)
                .unwrap()
                .starts_with("HTTP/1.1 101")
        );
        let payload = vec![42_u8; 512 * 1024];
        write_websocket_frame(&mut socket, &payload, true).await;
        assert_eq!(read_websocket_frame(&mut socket, false).await, payload);
        handle.stop_graceful(None);
    }

    #[tokio::test]
    async fn invalid_route_is_404_and_wrong_preview_credential_is_401() {
        let (address, handle) = serve(Arc::new(Gateway(Mode::WebSocket))).await;
        let invalid = reqwest::get(format!("http://{address}/p/invalid/"))
            .await
            .unwrap();
        assert_eq!(invalid.status(), reqwest::StatusCode::NOT_FOUND);
        let wrong = reqwest::Client::new()
            .get(format!("http://{address}/p/route/"))
            .header("authorization", "Bearer wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(wrong.headers().contains_key("www-authenticate"));
        handle.stop_graceful(None);
    }
}
