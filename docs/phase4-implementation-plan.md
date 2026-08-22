# Phase 4 implementation plan

本文只记录可执行范围和验收证据。Phase 4 完成前，boxd 仍是
`@upstash/box@0.6.3` 的兼容子集；mock capture、未认证 401、普通 hosted CI、
ad-hoc codesign 或本地 fake runtime 都不能代替真实发布门禁。

## 冻结范围

唯一 wire contract 是 `@upstash/box@0.6.3`、commit
`677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`：

- `networkPolicy.mode` 只接受 `allow-all`、`deny-all` 或 `custom`；
- custom 规则只包含 `allowedDomains`、`allowedCidrs`、`deniedCidrs`；
- `attachHeaders` 是 `Record<host-pattern, Record<header-name, header-value>>`，只写；
- SDK 的 PUT wire 使用 `allowed_domains`、`allowed_cidrs`、`denied_cidrs`；
- 不增加 SDK 没有的 port 字段。数据面继续只支持 TCP 80/443；UDP/QUIC、ICMP、
  IPv6 egress 和入站端口映射不属于本 Phase 的兼容承诺；IPv6 CIDR 输入返回
  501 `feature_not_supported`，不得保存后静默不生效。

`attach_headers` 必须在透明 egress proxy 内真正修改 HTTP/HTTPS 请求；仅校验、
持久化或把值传入 guest 均不算实现。HTTPS 使用 per-tenant/per-Box 受控 CA 和透明
TLS proxy，CA 私钥与 header value 加密持久化，日志、审计、diagnostics、API response
和 evidence 一律不得回显。任一策略版本、secret、CA、proxy 或 worker wire 不一致时
fail closed。

## 纵向切片

### P4.1 完整 network policy

- typed DTO、域名/CIDR canonicalization、去重、数量和长度上限；
- `deny-all`、当前受限 `allow-all` 与 custom 的 domain/CIDR evaluator；
- create、GET response、PUT `/config/network-policy`、tenant repository、migration、
  optimistic version、restart reconciliation、worker wire；
- DNS answer 与每次 numeric connect 都重新判定，禁止 metadata/private/link-local/
  loopback/reserved，deny 优先于 allow，解析或状态异常一律拒绝；
- macOS HVF 与 Linux KVM 使用同一真实 egress smoke。

### P4.2 HTTPS `attach_headers`

- host pattern 只接受精确 DNS name 或单层 `*.` wildcard，最具体规则优先；
- 禁止 `Host`、`Content-Length`、`Transfer-Encoding`、`Connection`、
  `Proxy-Connection`、`Keep-Alive`、`Upgrade` 及其他 hop-by-hop header；
- header values 使用 tenant/account/Box/rule AAD 的 AEAD secret store；
- HTTP parser 有界、拒绝歧义 framing；HTTPS 由透明 TLS proxy 终止并重新连接目标，
  校验目标证书，不允许降级或 redirect 绕过策略；
- guest trust bootstrap 只安装该 Box 对应 CA，删除/轮换/重启可恢复且不残留；
- 完整实现以前继续返回 501，capabilities 不提前声明。

### P4.3 authenticated differential

- 全部 78 server contracts / 82 public cases 只能经 pinned SDK 分别请求 official 与
  boxd，比较 status、关键 headers、canonical JSON 与 SSE/stream；
- runner 将 case 分类为 `read_only`、`sandbox_mutating`、
  `externally_mutating`、`cost_incurring`，后两类必须显式 opt-in 和预算；
- 每个 mutating case 有 `finally` cleanup，official/local 使用不同 credential 与资源
  前缀，artifact 只保存脱敏 hash；
- 缺 official credential、browser/runtime、外部 provider 或 cleanup 失败时结果必须是
  `blocked`/`failed`，不得记为 passed。

### P4.4 fuzz / security / load / recovery

- fuzz：API JSON、network policy、HTTP/SSE parser、archive bundle、path resolution；
- security：tenant/account 越权、SSRF/DNS rebinding、secret redaction、path/symlink race、
  archive bomb、preview takeover、quota/resource exhaustion、runtime replacement；
- load：1/4/16/64 Boxes 的 exec/SSE/browser/preview 混合负载，记录 P50/P95/P99、
  error rate、CPU/RSS/FD/disk ceiling；
- recovery：graceful stop、SIGTERM、worker SIGKILL、daemon restart、disk full、runtime
  pull interruption、SQLite backup/restore 与 migration journal；
- fake/local harness 只证明 harness；最终 runtime 场景分别要求 macOS HVF 与 Linux KVM。

### P4.5 release hardening

- 统一 release manifest 绑定 version、commit、target、boxd/libkrun/libkrunfw/runtime
  bundle/SBOM/licenses/SHA256SUMS、toolchain、builder 与 provenance；
- release SBOM 覆盖 Rust workspace、embedded console、embedded native libraries 和
  runtime bundle，并执行 dependency/vulnerability/license gate；
- macOS 主程序与解出的 dylib 使用同一 Team ID、hardened runtime、Developer ID、
  notarization、stapling，并在 Apple Silicon 真机执行 HVF boot；
- Linux x86_64/aarch64 固定 glibc baseline、签名/校验策略，在真实 KVM+cgroup v2
  runner 执行 lifecycle/restart；
- 提供 systemd/launchd 定义；启动前 SQLite backup + migration journal；migration
  only-forward，旧二进制只在声明的 schema compatibility window 内回滚；runtime
  bundle 按 content hash 并存，运行中 Box 不原地换包。

## 统一 evidence

每个 suite 输出 `boxd-phase4-evidence-v1` JSON，至少包含 commit、platform、toolchain、
输入 artifact hash、case id、expected、observed、artifact hash、external requirements、
secret scan 和 `pass|fail|blocked` 总结。仓库中的示例/fixture 不得伪装成真实运行证据。

## 完成门禁

只有以下项目全部有当前 commit 的可复核 evidence，才能把 capability phase 改成
`phase_4_complete` 或发布 1.0/“完全兼容”：

- compatibility manifest 78/78 implemented，82/82 public cases 已映射；
- pinned SDK contract suite 100%，所有 SSE/stream byte fixtures 通过；
- authenticated official/local differential 全量通过且 cleanup 完成；
- macOS Apple Silicon HVF 与 Linux x86_64/aarch64 KVM smoke/e2e 通过；
- 不存在接受参数但忽略的路径，未知 route fail closed；
- custom network policy 和 HTTPS `attach_headers` 的安全矩阵通过；
- fuzz/security/load/recovery 门禁与 release integrity 门禁通过；
- 文档已知差异为 0。

外部凭据或硬件缺失时，继续实施可 hermetic 的代码与 harness，但 Phase 4 状态保持
未完成，并在 evidence 中明确 `blocked` 的具体输入。
