# box-egress-http

Phase 4 `attach_headers` 的安全组件。它提供：

- canonical exact / `*.` host pattern 和最具体规则选择；
- header name/value 边界、禁止 framing 与 hop-by-hop header、secret 脱敏；
- 严格、有界的 HTTP/1.1 request-head transformer；
- 可持久化的 per-Box CA、重启恢复校验、动态 SNI leaf certificate；
- 只协商 `http/1.1`、使用 WebPKI 验证上游证书的单请求 async TLS MITM bridge。

数据面接入顺序固定为：先解析 DNS，并按 network policy 对域名和每个解析 IP
再次判定；再连接已批准的 numeric `SocketAddr`；最后将连接后的 transport 和 guest
侧 `DuplexStream` 交给
`Http1TlsMitmProxy::proxy_single_http1_tls_connection_for_allowed_hostnames`。该方法从
guest ClientHello 读取实际 SNI，并要求它属于同一 numeric address 对应的
`AllowedHostnames`，随后才用该 SNI 验证上游证书并绑定 HTTP `Host`。plain HTTP 使用
`Http1AttachHeadersProxy::proxy_single_http1_connection`，从请求 `Host` 获取实际主机并
执行相同的 allowlist 检查。该 crate 不解析或执行 DNS，也不决定 tenant/Box policy。

当前 async bridge 有意只支持一个 HTTP/1.1 request/response exchange 和无 body 或
`Content-Length` body。它拒绝 chunked request，不支持 keep-alive 多请求、Upgrade、
HTTP/2，也不负责把 CA 安装到 guest trust store。因此，在数据面和 guest CA 生命周期
闭环前，不得据此把 HTTPS `attach_headers` capability 标记为完成。
