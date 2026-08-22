# ADR-0007：Phase 4 custom network policy 数据面

- Status: Accepted
- Supersedes: ADR-0003 中 custom network policy 返回 501 的临时边界

## Context

`@upstash/box@0.6.3` 的 custom policy 只包含 `allowedDomains`、
`allowedCidrs`、`deniedCidrs`，没有 port 字段。接受这些规则后只保存、不在 DNS 与
实际连接上执行，会形成安全上的“接受即忽略”。

## Decision

- custom policy 由 typed DTO、domain model、repository、worker wire 和 host-owned
  virtio-net egress proxy 贯通；未启用 `[features].custom_network_policy` 时返回 501。
- 域名规范化为小写 ASCII，允许 exact name 与单层 `*.` wildcard；CIDR 必须是
  canonical network address。全部规则合计最多 64 条，重复和非法输入 fail closed。
- 数据面只开放 public IPv4 TCP 80/443。UDP/QUIC、ICMP、IPv6 egress 和入站端口
  不在当前兼容承诺中；IPv6 CIDR 输入明确返回 501，不保存不可达规则。
- DNS answer 先经过 domain、CIDR 与 special/private address 判定。允许结果写入有界、
  短 TTL 的 hostname-to-IP lease；每次 numeric connect 再执行 CIDR 和 lease 判定。
- `deniedCidrs` 优先级高于任何 allow；loopback、link-local、private、metadata、
  multicast、reserved 等地址永久拒绝，不能由 allow 规则覆盖。
- `PUT /v2/box/{box_id}/config/network-policy` 只允许 idle/paused Box；策略变更通过
  optimistic version 保存并重启数据面，失败走 reconciliation，不允许热改一半状态。
- `boxes.network_policy` 使用跨 SQLite/PostgreSQL/MySQL 的 TEXT 列；m0010 将已有
  PostgreSQL/MySQL `VARCHAR(32)` 升级为 TEXT，避免长 custom JSON 截断。
- wildcard/domain allow 只授权经 boxd resolver 得到的目标 IP lease。共享 IP 并不授权
  其他 hostname；HTTPS 层还必须把 SNI/Host 与策略重新绑定。`attach_headers` 完整
  数据面未就绪时继续返回 501。

## Consequences

custom policy 的控制面和 host egress 判定可以由 hermetic tests 验证，但 Phase 4 完成
仍要求同一 commit 的 macOS HVF 与 Linux KVM 真实 smoke/e2e evidence。普通 hosted
CI、fake runtime 或仅 repository round-trip 不能替代平台验收。

## Verification

```sh
cargo test -p box-core
cargo test -p box-egress
cargo test -p box-runtime
cargo test -p box-runtime-libkrun
cargo test -p box-service custom_network_policy
cargo test -p box-api network_policy
```

## Related

- [ADR-0003](0003-mvp-network-policy.md)
- [Phase 4 implementation plan](../phase4-implementation-plan.md)
- [Implementation status](../implementation-status.md)
