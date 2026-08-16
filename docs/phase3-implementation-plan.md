# Phase 3 implementation plan

状态：**已完成并验收**。Phase 0–2 的既有验收结论保持不变；本阶段只实施 blueprint §22
定义的调度、Browser、配额/审计/可观测性和 PostgreSQL/MySQL repository suite，不进入
Phase 4 的完整 network policy、HTTPS `attach_headers`、全量 differential 或发行加固。

## 兼容真相源

- npm：`@upstash/box@0.6.3`；
- source commit：`677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`；
- schedule wire：`compat/upstash-box-0.6.3/upstream/client.ts` 的
  `_scheduleExec/_scheduleAgent/_scheduleList/_scheduleGet/_scheduleUpdate/
  _schedulePause/_scheduleResume/_scheduleDelete`；
- browser wire 与 DTO：同一 pinned `client.ts`、`types.ts` 和已提交 route/public capture
  fixtures。

## Vertical slices

### P3-01 Schedules

- [x] UTC 五字段 cron parser、next-fire 计算、UUIDv7 schedule identity 与状态模型；
- [x] tenant/account scoped repository port 与 `schedule_id + scheduled_at` 幂等键；
- [x] SQLite schedule repository CRUD、payload roundtrip 与跨 tenant 不可见测试；
- [x] pinned schedule HTTP DTO/route contract（缺失、`null`、空值语义）与 exec
  create/list/get/update/pause/resume/delete；prompt 请求保持明确 501；
- [x] webhook header 加密、URL SSRF policy 与结果投递；
- [x] durable due-claim、单 holder 条件租约、续租、同一 `scheduled_at` 重试键与条件结算；
- [x] exec run 触发与 last-run counters；
- [x] prompt run、加密 webhook 投递、daemon crash 恢复和 Console schedules surface；
- [x] Box 删除清理全部 schedule，历史软删除 Box 遗留行由 scheduler fail-closed 清除。

Exec 与 prompt schedule 均按 pinned DTO 实现。Webhook header 不进入
`payload_json`，只以 tenant/Box/schedule AAD 密文持久化；投递使用稳定幂等键、公共地址
SSRF policy 与持久退避重试。

验收：所有 pinned schedule public cases 走真实 API；同 tenant 单次触发、跨 tenant 不可见；
daemon restart 不重复同一 `scheduled_at`，暂停/恢复/删除与在途 run 行为确定。

### P3-02 Browser tabs and basic actions

- [x] browser domain/driver port、opaque tab ID、strict URL/wait/timeout DTO；
- [x] versioned guest Browser RPC envelope、nonce authentication、bounded ordered frames 与
  host Tonic adapter；
- [x] tabs/goto/content/screenshot 的 pinned HTTP decode 和 application lease/tenant boundary；
- [x] browser runtime bundle、guest Chromium production adapter 与 `browser:true` create；
- [x] tabs/goto/content/screenshot 真实 Chromium 执行；
- [x] URL scheme、metadata、loopback/link-local/private SSRF fail-closed；
- [x] pinned DTO、binary screenshot 和 tenant isolation fixtures。

生产 composition 通过 nonce-authenticated guest RPC 接入 Chromium；真实 HVF smoke
验证 Chrome 140、PNG screenshot、内容投影和 restart 后重新接管。

### P3-03 Browser actions and live connections

- [x] extract/observe/act/run；
- [x] connect 单用途短期 token；
- [x] screencast 帧率、分辨率、带宽、背压与 disconnect cleanup。

### P3-04 Recording

- [x] start/stop/list/get；
- [x] HLS playlist、分片、MP4/MPEG-TS download；
- [x] durable finalize/restart recovery、retention 与文件/tenant quota。

### P3-05 Quota, audit, metrics and database matrix

- [x] API key request/run/box/disk/traffic quota 与稳定 429；
- [x] create/delete/key/secret/policy/preview/browser 的结构化审计；
- [x] HTTP/VM/run/SSE/scheduler/browser/runtime 指标和 OTLP trace propagation；
- [x] 同一 repository suite 在 SQLite、PostgreSQL、MySQL 通过。

## 固定门禁

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace

npm --prefix compat/upstash-box-0.6.3 run check:manifest
npm --prefix compat/upstash-box-0.6.3 run check:coverage
npm --prefix compat/upstash-box-0.6.3 test

# Console 变更时使用 Node 22.x
npm --prefix web/console run lint
npm --prefix web/console run typecheck
npm --prefix web/console test -- --run
npm --prefix web/console run build
npm --prefix web/console run test:e2e
```

完成证据见 [Phase 3 acceptance](phase3-acceptance.md)。仍不在本阶段范围内的 managed
agent options、完整 custom network policy、HTTPS `attach_headers` 等继续返回 HTTP 501
`feature_not_supported`；仅有 schema、mock 或 capability 文案不得计为实现。
