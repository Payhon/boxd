# Implementation status

状态基于当前工作区的可执行证据，不把蓝图计划或历史产物记为当前完成项。

Legend: `[ ]` 未完成；`[x]` 已有可复核证据。

## Phase 0 — 契约冻结

- [x] 固定 SDK `@upstash/box@0.6.3` 与 commit `677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`。
- [x] 固定 libkrun、磁盘、network policy、单可执行文件与 SDK provenance ADR。
- [x] Rust 2024 workspace、fmt、clippy `-D warnings`、workspace tests。
- [x] TypeScript AST raw/route/type/stream manifest 与 hash/fresh-diff 门禁。
- [x] 86 callsites / 80 operations / 77 direct + 1 response-linked contracts。
- [x] 82 public SDK cases / 159 captured dispatches，逐项 case evidence。
- [x] DTO、错误、SSE、custom harness、exec/code stream fixtures 与 mutation tests。
- [x] 官方服务只读 401 differential 样本。

Phase 0 已完成。Authenticated success 与全量响应/SSE differential 仍属于
Phase 4 完全兼容门禁，不能由 mock capture 或 401 样本代替。

## Phase 1 — 可启动 MVP

- [x] config、`init`、`doctor`、migration、auth。
- [x] Salvo router、OpenAPI、SQLite、embedded console skeleton。
- [x] 每 Box worker、固定 libkrun v1.19.4、signed runtime pull/import、guest agent。
- [x] create/status/pause/resume/delete、TTL、持久 operation 与重启 reconciliation。
- [x] exec、Python/JavaScript/TypeScript code、env、labels。
- [x] file read/write/list/upload 与 flat/direct-folder download；nested tree download 明确 501。
- [x] macOS Apple Silicon `deny-all` HVF lifecycle + daemon-restart smoke。
- [x] macOS 受限默认 DNS/HTTP(S) egress + deny-all + daemon-restart smoke。
- [ ] Linux x86_64/aarch64 KVM lifecycle + daemon-restart smoke。
- [ ] 十 runtime × 目标架构的 signed bundle 真实执行矩阵。

因此本轮 **macOS 当前宿主机 Phase 1 验收已完成**：生命周期和受限默认网络基线
均有当前源码的真实 HVF/restart 证据。Linux KVM 与十 runtime × 目标架构矩阵作为
后续 TODO 保留，不阻断本轮 macOS 验收，也不据此宣称跨平台发布或十 runtime 已全量
验证。完整 custom network policy、HTTPS `attach_headers`、Browser 与 recording
属于后续阶段，不在本轮冒充实现。

### 当前证据

- macOS 26.4.1 arm64，`kern.hv_support=1`，doctor `overall=true`，所有 required checks pass。
- signed bundle：53,917,206 bytes，SHA-256
  `b1957bb7a26b5d12c77423e440c3577d48626be13fff1d43311702a4da835303`。
- 20 GiB rootfs SHA-256：
  `9f4bf99b7b69ea5565a1c73f90c7680e40aa5375dec5fe7639da0f4e949bacc2`。
- guest `box-agent` SHA-256：
  `784ff7f5b5ecf5aad86ce4fb5fd179cb79d20dfbe13d41141e3c43037a95d07c`。
- restricted-default ad-hoc entitlement-signed `boxd` SHA-256：
  `67e7ea0a58c740fcae76fdf368f75c9aa40441f21f618d0e405a85c6baacba2c`。
- SDK create 266,292 ms，初始 `creating`，133 polls；2,017 ms exec、TypeScript、
  init、mtime、pause/resume、5,242,897-byte binary roundtrip 均通过。
- 完整 daemon stop/restart 后 reconciliation、持久文件、post-restart exec、
  两 Box bulk delete 通过；daemon/worker/敏感临时数据已清理。
- Rust workspace 全门禁通过；compat 17/17；console Node 22.19.0
  lint/typecheck/6 tests/build 通过。

完整命令、签名边界与脱敏证据见 [Phase 1 acceptance](phase1-acceptance.md)
和 [phase1 evidence](phase1-evidence/)。

受限默认 egress 已通过同进程、每 Box 的有界 `box-egress` 数据面接入生产生命周期：
固定 DHCP、事务绑定 DNS、AAAA/NODATA、public IPv4 TCP 80/443、统一特殊地址分类、
重绑定阻断与实际目标二次判定均已落地；TSI、`HTTP_PROXY` 或 host NAT 均未作为
安全边界。可执行结果见 [ADR-0006](adr/0006-restricted-default-egress.md) 与
[Phase 1 acceptance](phase1-acceptance.md)。

Linux 原生门禁已有可执行的
[`phase1-linux-kvm-smoke.sh`](../scripts/phase1-linux-kvm-smoke.sh) 和手动
self-hosted workflow；它严格要求真实 `/dev/kvm`、cgroup v2 与 doctor required
checks，并按两组 lifecycle/restart 顺序释放 Box。当前机器不具备 `/dev/kvm`，所以
此入口仍是待执行门禁，不能勾选 Linux 验收项。

平台 gate 的 build/import/doctor/SDK 子进程现有显式进程组总超时；TERM grace 后
KILL，且 hermetic 测试证明忽略 TERM 的后代不会残留。Linux summary 会记录 source
gate 是否跳过，并绑定 kernel、libkrun/firmware、doctor 与四份 smoke evidence hash。

十 runtime 门禁已有
[`phase1-runtime-matrix-smoke.sh`](../scripts/phase1-runtime-matrix-smoke.sh)：输入必须
恰好包含当前架构的十个签名 bundle，逐 runtime 只保留一个 Box，执行语言探针、文件、
pause/resume、完整 daemon restart/reconcile/delete，并将 bundle/binary/SDK hash 写入
摘要。当前仅有 Node 22.16.0/aarch64 的真实 bundle，因此该门禁尚未执行，矩阵项仍不
勾选。

artifact 构建侧也已形成 fail-closed 入口：
[`build-runtime-bundle.sh`](../scripts/runtime/build-runtime-bundle.sh) 按 runtime、
Debian/Alpine、GNU/musl 与 aarch64/x86_64 构建单个签名 bundle；
[`build_runtime_matrix.py`](../scripts/runtime/build_runtime_matrix.py) 只接受恰好十种
runtime 的完整外部 pin 文档，串行构建后原子产生矩阵验收 manifest。metadata 与
release-pin hermetic tests 已通过。仓库没有为其余 runtime/arch 决定版本、不可变 OCI
digest、镜像内 license path 或 GNU/musl Rust builder digest；这些属于发行输入，不能
由实现代码猜测。因此构建/验收工具已就绪，但真实矩阵证据仍被外部 pin/asset 阻塞。

Linux 与双架构矩阵的后续执行条件、命令和验收产物统一记录在
[Linux validation TODO](linux-validation-todo.md)。

## Phase 2 — Agent 与开发工作流

- [x] run/SSE/cancel/logs/webhook/custom harness 的 pinned custom-harness 子集；
- [x] git、snapshot、startup、model；
- [x] skills；
- [x] preview 与 WebSocket bridge；
- [x] Console terminal、runs、snapshots、API keys。

Blueprint §22 定义的 **Phase 2 已完成**。实施顺序、禁区、逐切片验收和最终门禁见
[Phase 2 implementation plan](phase2-implementation-plan.md)。这只覆盖 §22 明确列出的
custom-harness Agent 与开发工作流；managed harness、prompt files、response schema 和
agent options 仍是显式 501 compatibility-subset 边界，不计为已实现，也不被用来虚构
完全 SDK 兼容。
当前增量已完成 tenant-scoped run/event persistence、SQLite restart replay、pinned
`GET /runs` history DTO、自定义 Agent 配置持久化、guest/host 实时 `RunHarness`、JSON
`POST /run/stream` SSE、scoped cancel、稳定 `<run_id>:<sequence>` 重连重放、keepalive 与
pinned `GET /logs` stderr 投影。run/event 均在发布前持久化，stderr 不进入协议 stdout，
断开客户端不会杀死 guest run；cancel 会等待后台 settlement，terminal 后重复调用幂等。
custom harness create 已接受 pinned SDK 的顶层 `agent/model/custom_runner` wire shape、
可选 `args` 和缺省 `box-sse-v1` protocol；两个允许 guest 根下的 absolute command 通过
no-follow descriptor 读取、root-owned 私有 snapshot 执行并在进程退出后清理，symlink 和
允许根外路径均拒绝。Webhook run 已闭环 pinned fire-and-forget 请求与 accepted 响应：
配置以 tenant/Box/run AAD 加密持久化，terminal 后投递固定 payload，失败和 daemon restart
按持久化指数退避有界重试，`X-Boxd-Webhook-Id` 提供接收方幂等键。生产投递禁代理/redirect并对全部 DNS
答案和实际连接执行 public-unicast/80/443 SSRF policy，日志不记录 URL、header 或响应体。
multipart/files、response schema 与 agent options 在 custom harness 没有可执行映射，仍明确
501；managed agent 也保持 501。
Pinned `PUT /config/model` 和 `PUT /config/custom-runner` 现已支持 custom-agent Box 的
Idle/Paused tenant-scoped 更新；配置写入沿用 SQLite repository，更新 model 不丢 runner，
更新 runner 不丢 model。Pinned `GET/PUT/DELETE /startup` 也已闭环：命令按 tenant/Box
加密持久化，GET 需要 `SecretsRead`，仅 keep-alive Idle Box 可更新；PUT 重置 durable
at-most-once init claim 并在下一次真实 guest boot 执行，DELETE 幂等清除。managed agent
仍明确 501。Git 已实现 pinned `/git/exec`、`/git/diff`、`/git/status`、
`/git/checkout`、`/git/commit`、`/git/clone`、`/git/push`、`/git/create-pr` 与 `/git-config`：专用 host/guest `Git` RPC、有界参数、固定 `git` argv、
SDK workspace cwd、tenant ownership、持久 global identity 与非零退出 fail-closed 已测试；
commit 的 add/author override/SHA 读取均不经过 shell。GitHub token 使用 tenant/Box AAD
加密仓储和 guest askpass 临时注入，clone/push 只允许干净的 HTTPS GitHub remote，禁用
credential helper/hooks，失败 clone 恢复原 token；create-pr 使用固定 GitHub API adapter、Bearer
header、无 redirect/30 秒 timeout，provider 响应严格投影 pinned `PullRequest` DTO。
Snapshot 已闭环 pinned create/list/delete/bulk-delete/from-snapshot：Idle Box 在租约内
quiesce/短暂停机，使用 descriptor-bound CoW/reflink 或 sparse copy 生成只读 snapshot
disk 并校验 SHA-256，随后恢复运行。Snapshot repository 全程带 account+tenant scope；
失败与 daemon 中断会持久结算并清理残盘。from-snapshot 将 source snapshot ID 和原
runtime bundle identity 持久到新 Box，启动恢复仍克隆同一 snapshot，不会静默使用
runtime base image。Preview 已实现 pinned create/list/delete、30 分钟 HMAC capability、
create-only Bearer/Basic credentials、轮换/撤销/tenant scope，以及 `/p/{token}` 到 guest
loopback 的 HTTP/1.1 streaming 与 WebSocket Upgrade bridge；agent control port 被固定拒绝，
外部认证和 forwarding headers 不会透传污染 guest。Rust workspace fmt/clippy/tests 与
pinned Node contract、86/80/77+1、82 cases/159 captures 已在本切片通过。

Skills 已实现 pinned create-time `skills` 与 `skills.add/remove/list`：服务端只接受
`owner/repo/skill` 或 create-time 的 `owner/repo` project，先从 Context7 scanner API
取得已扫描条目，再把 GitHub source commit 扩展为完整 40 hex SHA，按该 commit 下载
regular-file tree并计算 canonical content SHA-256。commit 与 digest 随 Box 以
account+tenant scope 持久化，daemon restart 按 pin 重新验证并安装，不会漂移到分支新内容。
guest 只接收 host 已解析的最多 128 files / 1 MiB package，使用 dirfd、`O_NOFOLLOW`、
随机 staging 与原子 rename 写入 `/home/boxuser/.agents/skills`；遍历、symlink、重复路径、
缺 `SKILL.md` 和 identity mismatch 均 fail-closed。capability 现为
`skills_context7_install_remove`，`skills` 不再列入 unsupported。本切片的
agent/proto/core/SQLite/service/Salvo/OpenAPI/pinned Node 回归均通过。

Console Phase 2 管理面已接到 tenant-scoped `/api/admin/v1`：Boxes、Runs、
Snapshots 和 API Keys 列表及其 pause/resume/delete/cancel/revoke 操作使用独立
HttpOnly 管理会话 + CSRF，不接受 `X-Box-Api-Key`。新 API Key 仅在
创建响应显示一次，服务端仅持久 HMAC。Terminal 先签发 60 秒、
32-byte 随机、account/tenant/Box 绑定的单用途 ticket，再经 WebSocket
双向桥接 guest `127.0.0.1:18081` 上由 boxuser 运行的行定向 shell。会话
全程持有 per-Box mutex 与可续租 DB lease；preview/control/terminal 保留端口
均不能被通用 tunnel 调用。剪贴板、文件上传和 PTY resize 未伪造为已实现。

Phase 2 最终门禁（2026-08-13）：Rust workspace fmt、全 targets/features clippy
`-D warnings` 与 workspace tests 全绿；API 22、service 58、boxd 50 tests；pinned
manifest 86/80/77+1、coverage 82/159、Node contract 18/18；Console Node 22.19.0
lint/typecheck、Vitest 9/9、build、Playwright 1/1 全绿。

## Phase 3 — 调度与 Browser

Blueprint §22 定义的 **Phase 3 已完成**：

- [x] exec/prompt schedule CRUD、UTC 五字段 cron、UUIDv7 identity、
  `schedule_id + scheduled_at` 幂等 occurrence、单 holder 条件租约和续租；
- [x] schedule webhook header 以 tenant/Box/schedule AAD 加密，投递采用固定
  idempotency header、SSRF 防护、持久退避重试；daemon restart 可恢复未结算 occurrence；
- [x] Box 删除同时清理 schedule，scheduler 会自动清除历史软删除 Box 的遗留行；
- [x] Console schedules tenant 管理面；
- [x] `browser:true` 生产 provisioning、guest Chromium、tabs/goto/content/screenshot；
- [x] extract/observe/act/run 的 provider adapter、严格结构化投影与 credential redaction；
- [x] 单用途短期 CDP ticket、view-only screencast、背压与断开清理；
- [x] recording start/stop/list/get、HLS playlist/segment、MP4 download、marker、
  crash finalize、retention 与 tenant/file quota；
- [x] API-key request/traffic token bucket、tenant Box/disk/concurrent-run quota 与稳定 429；
- [x] tenant-scoped durable mutation audit、Prometheus 指标、W3C trace context 和
  OTLP/HTTP protobuf export；
- [x] 同一 migration/repository suite 在 SQLite、PostgreSQL、MySQL 真实运行通过；
- [x] 当前源码 macOS Apple Silicon HVF + hash-verified pinned SDK 完整 lifecycle、
  graceful stop、daemon restart/reconciliation、持久 schedule side effect 与 bulk delete。

详细命令、artifact hash、真实 Browser/recording/OTLP/三数据库证据见
[Phase 3 acceptance](phase3-acceptance.md)。完整 custom network policy、HTTPS
`attach_headers`、全量 authenticated differential、安全/负载/发行加固仍属于 Phase 4；
Linux KVM 和十 runtime × 目标架构矩阵也仍是明确的平台 TODO，不能由本轮 macOS Node
Browser smoke 代替。

Phase 3 最终门禁（2026-08-16）：Rust workspace fmt、全 targets/features clippy
`-D warnings` 与 all-features workspace tests 全绿；pinned manifest
86/80/77+1、coverage 82/159、Node contract 20/20；Console Node 22.19.0
lint/typecheck、Vitest 11/11、production build、Playwright 1/1 全绿。

## Required evidence before checking items

| Area | Minimum evidence |
|---|---|
| SDK contract | pinned SDK runner、86/80/77+1、82 cases / 159 captures、未知调用失败 |
| 501 subset | HTTP 501 `feature_not_supported` fixture 与 capability false |
| libkrun worker | worker lifecycle tests、doctor、真实 HVF/KVM |
| disk | signed raw ext4 import、clone、checksum 与 guest capacity |
| platform | macOS Apple Silicon HVF 与 Linux native KVM 独立 smoke |
| security | secret redaction、no-follow path、tenant scope、cleanup evidence |

## Linked decisions

- [Architecture](architecture.md)
- [API compatibility](api-compatibility.md)
- [ADR-0001](adr/0001-libkrun-worker-lifecycle.md)
- [ADR-0002](adr/0002-raw-ext4-private-disks.md)
- [ADR-0003](adr/0003-mvp-network-policy.md)
- [ADR-0004](adr/0004-single-executable-runtime-bundles.md)
- [ADR-0005](adr/0005-pinned-sdk-source-baseline.md)
- [ADR-0006](adr/0006-restricted-default-egress.md)
