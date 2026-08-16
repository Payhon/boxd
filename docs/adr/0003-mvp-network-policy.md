# ADR-0003：MVP network policy 的显式子集

- Status: Accepted

## Context

稳定 libkrun 没有完整的逐域名网络策略接口。若接收复杂规则后静默忽略，会造成错误的兼容和安全承诺。

## Decision

- 目标 MVP `network_policy` 支持受限默认 egress 策略与 `deny-all`。
- 受限默认策略只允许 DNS、HTTP/HTTPS 出站，并拒绝宿主控制 API、云 metadata、loopback、link-local 与配置的私有 CIDR；DNS 结果必须再次经过 CIDR 检查。
- domain、CIDR、port 的 allow/deny 规则在固定完整实现（网络 hook 补丁或用户态 virtio-net/proxy）前一律返回 HTTP 501，错误为 `feature_not_supported`；不得接受后忽略。
- HTTPS `attach_headers` 在具备受控 MITM/自签 CA 的透明 egress proxy 前返回 HTTP 501 `feature_not_supported`。

当前 Phase 1 runtime 同时实现真实 `deny-all` virtio-net blackhole 与受限默认
用户态数据面。部署默认 `network.default_policy = "restricted-default"`；SDK create
省略 `network_policy` 时返回兼容 wire 的 `allow-all`，但实际只开放受控 DNS 与 public
IPv4 TCP 80/443。蓝图中的完整/custom network policy 仍属于 Phase 4。

## Consequences

当前默认能力已具备真实隔离；完整 custom network policy 和 HTTPS
`attach_headers` 仍属于 Phase 4 生产加固门禁并返回 501。

## Verification

实施后执行：

```sh
rg -n 'feature_not_supported|deny-all|attach_headers|network_policy' crates compat docs
npm --prefix compat/upstash-box-0.6.3 test -- --grep 'network|attach headers'
```

兼容 handler、create 校验和 contract runner 已存在；macOS HVF 已验收受限默认、
`deny-all`、daemon restart 与 unsupported policy 的 501。Linux KVM 仍需同等证据。

## Related

- [API compatibility](../api-compatibility.md)
- [Implementation status](../implementation-status.md)
