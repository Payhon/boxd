# Phase 2 implementation plan

状态：**已完成 blueprint §22 定义的 Phase 2 范围**。Phase 0/1 的当前 macOS 验收结论保持不变；Linux KVM 与
runtime matrix 继续按 [Linux validation TODO](linux-validation-todo.md) 独立跟踪。

Phase 2 只实现 blueprint §22 列出的 Agent 与开发工作流，不借机进入 schedules、
Browser/recording、完整 custom network policy、HTTPS `attach_headers`、生产计费或
Phase 4 全量 differential。

## 兼容真相源

- npm：`@upstash/box@0.6.3`；
- source commit：`677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`；
- route/type/stream manifest：`compat/upstash-box-0.6.3/`；
- SSE：`run_start/text/thinking/tool/tool_result/stats/done/error`；
- custom harness：`box-sse-v1`，argv 为
  `<command> <args...> -p <prompt> --model <model> --stream [--session <id>]`。

## Vertical slices

### P2-01 Run persistence and replay foundation

- [x] tenant-scoped `Run`/`RunEvent` domain 与 repository；
- [x] 单调 sequence、canonical JSON、状态转换和 terminal settlement；
- [x] `GET .../runs` 的 pinned `BoxRunData` newest-first DTO；
- [x] `GET .../logs` 的 pinned DTO 与 custom-harness stderr redacted log store；
- [x] SQLite restart 后 event replay；
- [x] account/box environment secret 精确值在事件落库和推流之前递归脱敏。

验收：同一 account 不同 tenant 不可见；重复 sequence 原子拒绝；terminal run
不可回退；重启后逐字节重放得到相同 SSE event/data。

### P2-02 Guest harness and HTTP run lifecycle

- [x] `RunHarness` protobuf、boot-nonce 鉴权、固定 argv 与严格 `box-sse-v1` 解析；
- [x] 实时 stdout 事件、进程注册、cancel/reap 与客户端断开后的 detached drain；
- [x] descriptor-safe absolute command；
- [x] stderr 独立于协议 stdout 传输，持久化为 `RunEvent::Stderr` 并投影 pinned logs DTO；
- [x] `POST .../run/stream` JSON prompt/folder、自定义 Agent 配置持久化、run/event 落库后推流；
- [x] `POST .../run/stream` 对 multipart/files、response schema 与 agent options
  严格识别并返回 501/capability false（完整兼容扩展，非 §22 custom-harness 验收项）；
- [x] `POST .../run` webhook fire-and-forget；
- [x] `POST .../runs/{run_id}/cancel`，tenant/run/box scope 与 TERM→KILL→reap；
- [x] SSE keepalive、no buffering/compression、断线 detached、`<run_id>:<sequence>` event-id replay；

验收：固定 SDK 的同步 run、stream、cancel、断线重连与 `box-sse-v1` byte fixtures
通过；客户端断开不自动杀 run。

当前增量边界：custom harness create 已按 pinned SDK 的顶层
`agent="custom"`、`model`、`custom_runner.command/args/protocol` wire shape 接入，缺省
protocol 固定为 `box-sse-v1`。PATH executable 直接按受控 PATH 执行；
`/workspace/home` 或 `/home/boxuser` 下的 absolute command 逐组件 `openat/O_NOFOLLOW`
打开，再复制到 root-owned、随机且不可修改的私有 executable snapshot，子进程结束后按
dirfd 清理。真实子进程测试覆盖 absolute script、末级 symlink 拒绝和允许根外拒绝。
guest 使用独立有界 pipe reader 实时产生 stdout frame，严格增量解析 `box-sse-v1`；
真实子进程测试证明首个 `text` 到达时进程仍在运行，
stderr 走独立内部 frame 且不污染协议事件，terminal 后才完成 reap。控制面先持久化
`run_start`/后续 event，再发布 HTTP SSE；客户端断开只关闭消费者，host/guest 继续
drain、settle run 并恢复 Box。`Last-Event-ID: <run_id>:<sequence>` 只重放同 tenant、同 box
的后续持久事件并跟随到 terminal；响应包含 15 秒 comment keepalive、`no-cache`、
`X-Accel-Buffering: no` 与 identity encoding。Pinned custom harness 只定义
command/args/prompt/model/session，没有 files、JSON schema 或 agent options 的 guest argv
映射；在默认/managed harness 落地前这三类参数继续明确返回 501，避免接受后忽略。
Webhook run 已按 pinned SDK 的 JSON wire shape 接通：响应立即返回
`{status:"accepted",run_id}`，后台继续 drain 同一持久 run，并在 terminal 后投递固定
`WebhookPayload`。Webhook URL/header 配置使用 tenant/Box/run AAD 的 XChaCha20-Poly1305
密文持久化；成功投递后删除，失败和 daemon restart 由有界 tick 重试，因此语义为
at-least-once。失败次数和下一次投递时间保存在同一 AEAD 密文中，以 1 秒起步、最长
1 小时的指数退避限制故障接收端压力；稳定 `X-Boxd-Webhook-Id: <run_id>` 让接收方去重。生产 adapter 禁止
代理和 redirect，只允许 HTTP(S) 80/443；DNS 的全部答案必须为 public unicast，实际连接
固定到已复核地址，loopback、私网、link-local、metadata、userinfo、fragment 与 hop-by-hop
header 均 fail-closed。URL、header value 和 response body 不进入日志。Pinned SDK vendored
contract、严格 Salvo DTO、加密持久重试和 SSRF policy tests 已覆盖。
重试测试会销毁原 `BoxService`，以同一 SQLite repositories 构造全新实例，证明
`attempts`、`next_attempt_at`、稳定幂等键与成功后的密文清理均跨 daemon 生命周期成立。

Multipart prompt files、response schema 与 agent options 在 pinned custom harness 的
`box-sse-v1` argv 中没有语义映射，当前仍逐项明确 501；managed/default harness 落地前
不得把它们物化后假装已由 Agent 消费。因此 P2-02 的 custom-harness/webhook 子集已闭环，
完整 managed Agent 子集仍未验收。Blueprint §22 对 Phase 2 的明确交付与验收只要求
custom harness、SSE/cancel/logs 及本页其余开发工作流；managed harness 与这三类专属
参数不作为 Phase 2 完成的伪前提，而作为 501 compatibility-subset 边界继续保留。

### P2-03 Development workflow

- [x] git clone/diff/status/commit/push/create-pr/exec/checkout 与 git-config；
- [x] snapshot create/list/delete/from-snapshot；
- [x] startup/model/custom-runner 的持久配置；
- [x] skills 安装、删除、持久列表与 create-time 配置；
- [x] snapshot quiesce、CoW/sparse-copy、checksum、幂等清理；
- [x] git token askpass 临时注入并清除 remote URL 凭据。

验收：pinned git/snapshot contract、snapshot clone、tenant/path/token-redaction tests
通过。

当前增量：pinned `GET/PUT/DELETE .../startup`、`PUT .../config/model` 与
`PUT .../config/custom-runner` 已接到
tenant-scoped 持久配置；只允许已有 custom-agent Box 在 Idle/Paused 状态更新，runner
继续复用 command/args/protocol 的严格校验，model 更新保留 runner，runner 更新保留
model。startup command 加密持久化，只允许 keep-alive Idle Box 更新；GET 使用
`SecretsRead`，PUT 将 durable init operation 重置为 Pending，并在下一次真实 guest boot
以 at-most-once claim 执行，DELETE 幂等清除。
Pinned `POST .../git/exec|commit|clone|push`、`GET .../git/diff|status`、
`POST .../git/checkout` 与 `PUT .../git-config` 已接通：host/guest 使用专用 `Git` RPC，只接受有界
argv，guest 固定补 `git` 可执行文件并在 SDK `/workspace/home[/folder]` cwd 下由 boxuser
执行；global user name/email 落在持久 home，非零退出不回显可能含凭据的 stderr。
commit 使用无 shell 的 `git add -A`、单次 author override、`rev-parse HEAD` 严格 SHA
校验。create/clone 提交的 GitHub token 以 tenant/Box AAD 加密持久化；clone/push 仅接受
不含 userinfo/query/fragment 的 `https://github.com/{owner}/{repo}`，固定关闭 credential
helper 与 hooks，并仅通过同一 immutable guest agent 的 `GIT_ASKPASS` 子进程环境临时注入
token，remote URL 和 argv 从不包含 token。失败 clone 会恢复先前密文。create-pr 通过
注入式 Git hosting port 调用固定 `api.github.com`，Bearer token 仅进入 HTTP header，adapter
禁止 redirect、限制 30 秒并且不回显 provider body；loopback 测试校验 pinned body 与响应 DTO。
Snapshot 已实现 pinned create/list/delete/bulk-delete/from-snapshot：创建时对 Idle Box
持租约并执行 quiesce、shutdown、短暂停机、descriptor-bound CoW/reflink 或 sparse copy、
全盘 SHA-256，再恢复原 Box。Snapshot、磁盘路径和 checksum 均 tenant-scoped 持久化；
失败结算为 `error`，daemon 启动会清理遗留 `creating` 磁盘。from-snapshot 将 source
snapshot ID 与原 runtime bundle identity 一并持久到新 Box，崩溃恢复继续克隆同一
snapshot，绝不退回 base image；原 snapshot 只读且删除幂等。

Skills 已实现 pinned `POST/DELETE .../config/skills` 与 `GET BoxData.enabled_skills`，
create-time 同时接受精确 `owner/repo/skill` 和 project `owner/repo`。Context7 adapter 只
消费 scanner API 已列出的 skill，随后从 GitHub exact commit 读取 regular-file tree；
完整 40 hex commit 与 canonical package SHA-256 持久化，重启恢复使用同一 pin。guest
通过 boot-nonce authenticated RPC 接收有界 package，在
`/home/boxuser/.agents/skills/{name}` 下使用 no-follow dirfd staging、fsync 和原子替换；
删除幂等。tenant 隔离、路径遍历、symlink、重复路径、missing manifest、content pin、
create/install/list/remove 与 pinned Node wire contract 均有测试。

### P2-04 Preview and terminal bridge

- [x] preview token repository、HMAC、30 分钟 TTL、轮换、撤销与过期清理；
- [x] `/p/{token}/{*path}` HTTP/1.1、WebSocket 与流式 bridge；
- [x] Host/Forwarded 覆盖、credential header 剥离、control/agent port 拒绝；
- [x] Console terminal 使用 60 秒、单用途、单 Box ticket。

验收：HTTP/WebSocket 背压、过期/重放/跨 tenant token、SSRF 端口矩阵通过。

当前增量：pinned `POST/GET/DELETE .../preview` 已接通严格 DTO；同一 Box/port
再次创建会原子轮换 capability。路由 token 是带服务端 HMAC 的 opaque capability，数据库
只存 domain-separated HMAC；Bearer/Basic 派生凭据只在 create 响应返回一次，list 不回显。
匿名、Bearer、Basic、篡改、过期、tenant 隔离与撤销均有测试，过期记录由有界 tick 清理。
guest `Dial` 每次 boot-nonce 鉴权，只连接 guest `127.0.0.1:<port>`，明确拒绝 0 和 agent
控制端口 18080；帧与队列均有上限。path-mode gateway 流式转发 HTTP/1.1 body，并对
WebSocket Upgrade 做协议一致性检查和双向背压复制；外部 `Authorization` 不传给 guest，
`Host`、`Forwarded`、`X-Forwarded-*` 覆盖而非信任客户端值，Connection 指定的 hop header
也会移除。真实 loopback HTTP 和 512 KiB WebSocket frame 测试已通过。

Console terminal 使用独立的 guest loopback port `18081`，不经过公开 preview
port。管理会话需先用 Cookie + CSRF 为指定 Idle Box 签发 32-byte OS
随机票据；票据 60 秒失效、原子单次消费并绑定 account/tenant/Box。
WebSocket 链路消费票据后持有 per-Box mutex 和 DB lease，把有界帧双向桥接到
boxuser 的 `/bin/sh -s`；cwd 固定 `/workspace/home`。当前为真实行定向 shell，
不冒充 PTY resize；剪贴板和文件上传权限未授予，UI 也不会发送对应操作。

### P2-05 Console surfaces and final gate

- [x] terminal、runs、snapshots、API keys 页面；
- [x] 管理 API 继续使用 cookie + CSRF，不复用 compatibility key；
- [x] destructive 操作显示 Box ID 并二次确认；
- [x] capability/OpenAPI/implementation status 同步更新。

验收：Console lint/typecheck/unit/build 与 Playwright 核心流；完整 Rust workspace、
pinned SDK route/type/stream contract 门禁全绿。

当前增量：`/api/admin/v1` 已有 tenant-scoped Boxes/Runs/Snapshots/API Keys
读面与 pause/resume/delete/cancel/revoke 写面。API Key 仅在创建响应返回一次
明文，数据库仅保存 HMAC 索引；列表不回显。Console Dashboard、Boxes、Runs、
Snapshots 和 Access 页使用真实管理 API，不用 compatibility key 或
`localStorage`。破坏性 Box 操作要求显式勾选并显示完整 Box ID。
Vitest 覆盖认证链、一次性凭据、确认和 terminal；Playwright 以真实 Chrome
执行登录、tenant 数据、API Key 一次显示与 Box 删除二次确认核心流。

## 每切片固定门禁

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace

cd compat/upstash-box-0.6.3
npm run check:manifest
npm run check:coverage
npm test
```

新增兼容路由必须同时更新 handler DTO/OpenAPI/contract test；尚未完成的 Phase 2
路由继续返回 HTTP 501 `feature_not_supported`，不得用占位 JSON 或 mock 事件标记为
implemented。

## Phase 2 completion evidence

2026-08-13 当前工作区的最终门禁：Rust workspace `fmt`、全 targets/features
`clippy -D warnings` 与全 workspace tests 通过；关键测试计数为 API 22、service 58、
boxd 50。Pinned SDK manifest 保持 86 raw callsites / 80 normalized dispatches /
77 direct + 1 response-linked contracts，coverage 为 82 public cases / 159 captured
dispatches，Node contract 18/18。Console 使用 Node 22.19.0，lint、typecheck、Vitest
9/9、production build 与 Playwright 1/1 均通过。

以上证明 blueprint §22 的 Phase 2 验收面完成，不等同于 Phase 3/4、Linux KVM、
十 runtime 矩阵或完全 SDK 兼容已经完成。
