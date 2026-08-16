# API compatibility

## Frozen source of truth

兼容基线固定为 `@upstash/box@0.6.3`，源码 commit `677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`。唯一的 DTO、路由、流式语义真相源是该 commit 的：

- `packages/sdk/src/client.ts`
- `packages/sdk/src/types.ts`
- `packages/sdk/src/custom-harness.ts`

兼容请求使用 `/v2/box`、`X-Box-Api-Key` 和 snake_case；管理 API 不在该前缀。不得凭印象新增或改变 DTO，必须先从 pinned SDK 提取 fixture。

## Contract runner priority

发布判断优先级如下（高者覆盖低者）：

1. pinned SDK 的公开调用及其 Node contract runner；
2. 固定输入/规范化响应/SSE 字节流 fixture；
3. 真实 SDK 指向本地 `baseUrl` 的 contract suite；
4. 与官方服务的 differential 样本（规范化 ID/time 后比较 status、headers、JSON/SSE）；
5. compatibility manifest、OpenAPI 与实现代码。

OpenAPI 不是唯一真相。任何新增兼容路由必须同时更新 manifest、OpenAPI 和 Node contract test；未知路由必须让 CI 失败。

## 69-call executable baseline

蓝图给出的 **69 个 SDK HTTP 调用点** 是早期估计，不是可以硬编码的目标数量。
对 pinned commit 的 AST 提取与 public-call runner 已把口径冻结为：86 个业务 HTTP
callsite、通过 6 条有来源证据的 poll/retry/contract-reuse 归一化规则得到 80 个 operation dispatch、77 个直接
`method + canonical path` 合同，以及 recording metadata 暴露的 1 个 playlist
response-linked 服务端合同，共 78 个服务端合同。

`compat/upstash-box-0.6.3/` 固定 npm lockfile、commit provenance、未修改的上游源码
快照、raw/route/type/stream manifest、协议 fixtures 和 capture runner。生成器使用
TypeScript AST，默认离线重新生成并与提交资产逐字节比较；禁止通过增删条目硬凑 69。

当前 capture runner 使用 hash-verified pinned source（包括 telemetry/version/index）
临时构建公开 SDK，执行 82 个公开 case，实际捕获 159 次 dispatch，覆盖 77 个直接合同；第 78 个 playlist 合同
由 recording metadata 的公开返回 URL 验证。该结果证明 Phase 0 线协议枚举完成，
不代表 boxd 服务端已经实现这些合同。

`files.download` 当前准确能力为单层目录下载。Pinned
`@upstash/box@0.6.3` 只创建顶层本地目标目录、跳过目录 entry，并直接写入
`dest/file.name`，因此无法安全还原嵌套树：保留相对路径会产生 `ENOENT`，扁平化
又会覆盖同名文件。boxd 检测到子目录时返回 HTTP 501
`feature_not_supported`，并在 capabilities 中报告
`nested_tree_download_upstash_box_0_6_3` 为 unsupported；可执行证据见
`compat/upstash-box-0.6.3/test/sdk-contract.test.mjs`。

Phase 3 的 schedule 与 Browser pinned surface 已实现：exec/prompt schedule CRUD、
pause/resume/delete、加密 webhook；tabs/goto/content/screenshot、
extract/observe/act/run、CDP connect、view-only screencast，以及 recording
start/stop/list/get/HLS/download。真实 macOS HVF runner 使用 hash-verified pinned SDK，
同时验证 graceful stop/restart 后的 Chromium 恢复和 schedule guest side effect 持久化。
`schedule_agent_options` 仍明确 501；Browser connect token 单次、短期且绑定
account/tenant/Box，不能作为通用 guest tunnel。完整证据见
[Phase 3 acceptance](phase3-acceptance.md)。

`preview` 当前按 pinned `PublicURL` DTO 实现：POST body 只接受 `port`、
`bearer_token`、`basic_auth`，后两者不可同时为真；create 可返回一次性 `token` 或
`username/password`，list 始终省略凭据，DELETE 按 port 幂等撤销。公开 URL 使用配置的
path-mode `/p/{opaque-token}/`，30 分钟后失效。HTTP/1.1 body 与 WebSocket Upgrade 经
guest agent 的 boot-nonce authenticated `Dial` 流式桥接；不是 host 直接连接 guest 或
暴露 vsock/control port。完整自定义域名/TLS 发行配置不由该兼容 DTO 承诺。

`skills` 当前按 pinned contract 实现：create 的 `skills` 可传
`owner/repo/skill` 或 Context7 project `owner/repo`；运行中 add 使用 JSON
`{"skill_id":"owner/repo/skill"}`，remove 使用保留 slash 的 path tail，list 读取
`BoxData.enabled_skills`。安装源必须存在于 Context7 scanner 结果中，并绑定 GitHub
完整 commit 与 package content SHA-256；控制面下载验证后才把有界文件包发送给 guest，
guest 本身不访问供应链网络。未扫描、source identity 漂移、非 regular file、路径攻击、
commit/digest 不一致均 fail-closed，不会把 branch 最新内容当作已绑定 skill。

`POST /v2/box/{box_id}/run` 当前实现 pinned webhook fire-and-forget shape。成功响应立即给出
`status=accepted` 与 durable `run_id`；custom harness 继续在 guest 内运行，terminal 状态与
events 先落库，再按 pinned `WebhookPayload` 投递。Webhook 配置只以 AEAD 密文保存，失败或
daemon restart 会按持久化指数退避重试，因此接收端必须以 `X-Boxd-Webhook-Id` 去重。投递端禁止系统代理、
redirect、非 80/443 端口及特殊地址；DNS 所有结果都须通过 public-unicast 检查，并把连接
固定到已检查地址。prompt files、response schema 和 agent options 因 pinned custom harness
没有 argv/协议映射而明确返回 501，不会静默忽略。

## Admin Console boundary

`/api/admin/v1` 不是 Upstash 兼容面。Console 仅使用 secure/HttpOnly/SameSite
会话 Cookie 和内存 CSRF token；`X-Box-Api-Key` 不会为管理路由授权。
Boxes、Runs、Snapshots 与 API Keys 的读写均绑定会话的 account/tenant。
兼容 API Key 明文只在创建响应中返回一次，list 只包含 ID、prefix、
scope 与时间元数据。Terminal ticket 不是长期凭据：它是 60 秒、单次消费、
绑定 account/tenant/Box 的 256-bit capability，且只能连接内部保留 terminal
port。浏览器端不持久 ticket、CSRF token 或 API Key 明文。

## Compatibility-subset declaration

在同时满足 manifest 100% implemented、SDK contract 100% 通过、双平台 smoke/e2e、无接受即忽略路径、全部 SSE/stream 字节 fixture 通过、已知差异为零之前，版本说明只能称为“兼容子集”。

未实现能力必须：

- 返回 HTTP 501，错误为 `feature_not_supported`；
- 在 `/api/admin/v1/capabilities` 报告为 `false`；
- 不得接受参数后忽略，也不得以 CRUD 可用宣称完全兼容。

目标 MVP network policy 包含受限默认 egress 与 `deny-all`；当前 SDK 省略 policy
时使用受限默认 DNS/HTTP(S)，显式 `deny-all` 保持全断，二者均有 macOS HVF 与
daemon-restart 证据。custom 规则和 HTTPS `attach_headers` 均属明确 501 子集边界，
见 [ADR-0003](adr/0003-mvp-network-policy.md)。Browser、recording 与完整网络
策略不属于 Phase 1。

## Verification

Phase 0 完成条件是 runner 能列出所有调用点并让未知路由导致 CI 失败。实施后最低命令为：

```sh
npm --prefix compat/upstash-box-0.6.3 test
rg -n '677ca0827a6f54bc328b4b3e97d32a7cc5ac1934|86|80|78|feature_not_supported' compat crates docs
```

这些命令现已可执行；每次变更都必须重新执行。官方服务目前只有无效 fixture key 的
只读 401 样本，authenticated/success differential 仍需测试账户，不能由 mock capture
代替。状态边界见 [implementation status](implementation-status.md)。
