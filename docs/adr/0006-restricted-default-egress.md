# ADR-0006：Phase 1 受限默认 egress 的用户态数据面

- Status: Accepted

## Context

Phase 1 默认网络只允许 DNS 与 TCP 80/443 出站，并必须阻断宿主控制 API、云
metadata、loopback、link-local、multicast、unspecified、reserved 和私有网段；
DNS 结果与实际连接目标都要分类，以抵抗 DNS rebinding。

libkrun v1.19.4 在没有 virtio-net 时自动启用 TSI。TSI 不提供逐目标过滤 hook，
不能实现该策略。`HTTP_PROXY`、guest 环境变量或 guest 防火墙也不是安全边界：
恶意 guest 可绕过它们直接建 socket。macOS 本机没有可依赖的 `passt`，而交付约束
是单一 `boxd` 可执行文件。

已冻结的可用边界是 `krun_add_net_unixstream`：libkrun 与代理通过 Unix stream
传递 4-byte big-endian length 加一帧 Ethernet II。当前 `deny-all` blackhole 已证明
显式添加 virtio-net 会禁止 TSI。

## Decision boundary

受限默认 egress 使用每 Box、由 host worker 拥有的用户态网络代理，并继续通过
`krun_add_net_unixstream` 接入。代理或 framing 线程退出时，Box 网络必须立即
fail-closed；不得回退到 TSI。

候选依赖审计已拒绝 `netstack-smoltcp 0.2.4`：它包含没有 Future `Send` 约束的
`unsafe impl Send`，并在关键路径使用无界 channel。底层 `smoltcp 0.12.0` 仅保留为
有条件候选：必须关闭默认 feature、自建有界 adapter，且不得启用 raw socket/TUN/BPF
等 platform PHY。完整证据见
[dependency audit](../egress-dependency-audit.md)。

`smoltcp` 支持 macOS/aarch64，MSRV 低于 Rust 1.94，采用 0BSD；当前以关闭默认
feature 的精确版本加入独立 crate，并由自有固定容量 device 隔离。DHCP、DNS、
透明 TCP proxy、资源上限、协议审计、macOS HVF 与 daemon-restart 门禁均已完成，
因此采用该生产选型。外部 `gvproxy` 仅作互操作参考，不是生产必需安装项。

冻结的数据流：

1. control plane 为 Box 选择 `deny-all` 或 `restricted-default`；省略 SDK policy 时
   选择后者，显式 deny-all 保持原语义；custom 规则仍返回 501。
2. worker 在 VM entry 前创建 socketpair，启动同进程内代理并等待 ready；代理
   ready 后才把另一端交给 libkrun。
3. 代理只实现 guest DHCP、受控 DNS 与 TCP NAT。ICMP、raw IP、UDP（DNS 除外）、
   非 80/443 TCP、监听/端口映射和 IPv6（在完整实现前）均拒绝。
4. DNS 只把 A 查询转发到配置的数值 public IPv4 resolver；应答中的每个地址执行
   统一 IP 分类。AAAA 在本地返回事务绑定的 NODATA，因为数据面不支持 IPv6；不得
   静默丢弃而拖住双栈 resolver。拒绝结果不得写入可连接缓存。
5. 每次 TCP connect 使用 packet 的实际目标 IP 重新分类，不能只信 hostname、
   DNS 缓存或先前判定。目标必须为 public unicast，端口只能为 80/443。
6. host connect 使用数值 IP，避免第二次隐式 DNS。连接事件只记录 tenant、Box、
   目标类别、端口、允许/拒绝与原因；不记录 query/body、payload 或敏感 DNS label。

IP 分类覆盖 IPv4、IPv6 和 IPv4-mapped IPv6；拒绝 unspecified、RFC1918、CGNAT、
loopback、link-local、ULA、multicast、documentation/benchmark/reserved、metadata 和
配置私网。DNS 与 connect 必须调用同一个分类器。

代理有硬上限：Ethernet frame/length、DHCP/DNS message、DNS name/answer/TTL、并发
连接、每 Box 内存、每连接 buffer、connect/idle/total timeout、bytes/sec 与总
bytes。长度溢出、trailing frame、解析错误、半包超时、task panic 或代理退出均关闭
网络，不得继续宣称 ready。

## Non-goals

- custom domain/CIDR/port allow/deny；
- HTTPS `attach_headers` 或 TLS MITM；
- Preview/inbound port mapping；
- UDP/QUIC、ICMP、IPv6 egress（在单独完整设计和测试前）；
- 以 TSI、host routing/NAT、`HTTP_PROXY` 或 guest iptables 代替安全边界。

这些能力继续返回 HTTP 501 `feature_not_supported`。

## Required executable evidence

- 单元/属性测试：特殊 IPv4/IPv6 与 mapped 地址、DNS 压缩指针循环、malformed/
  truncated/oversized frame、资源上限和日志脱敏。
- L2 集成：DHCP、A/AAAA、HTTP 80、TLS 443、非 80/443、raw/UDP/ICMP；DNS 先
  public 后 private 的 rebinding；直接连 metadata/private/loopback；代理崩溃断网。
- macOS HVF：真实 guest public HTTP/HTTPS 成功，metadata/private/loopback 与非法
  端口失败；显式 deny-all 仍断网；daemon restart 后策略不漂移。
- Linux KVM：同一真实门禁，不以容器/TUN 替代 `/dev/kvm`。
- doctor/readiness：netstack 自检、资源上限和平台支持为 required，且不访问外网。

## Consequences

这不是配置补丁，而是新的安全关键数据面和跨 crate 契约。实施顺序为：

1. 审计并固定 netstack 依赖、版本、license 与 provenance；
2. 新建独立且无 libkrun FFI 的 egress crate，完成分类器与 L2 proxy；
3. 扩展 `NetworkPolicy`/`NetworkMode`/worker wire，接入生命周期和 watcher；
4. 更新 config、API response/capabilities、doctor/readiness；
5. 完成 macOS HVF 与 Linux KVM 门禁。

macOS 门禁已完成并把省略 SDK policy 的默认切换为 `restricted-default`；显式
`deny-all` 保持不变。Linux KVM 仍须执行同一门禁，不能由 macOS 结果代替。

## Related

- [ADR-0003](0003-mvp-network-policy.md)
- [Runtime worker protocol](../runtime-worker-protocol.md)
- [Phase 1 acceptance](../phase1-acceptance.md)
