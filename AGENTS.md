# boxd contributor instructions

- 默认使用中文沟通；命令、标识符和协议字段保持原样。
- 开始工作前完整阅读 `blueprint/boxd-development-blueprint.md`，它是产品、架构和验收基线。
- `/v2/box` 的唯一兼容真相源是 `@upstash/box@0.6.3`、commit `677ca0827a6f54bc328b4b3e97d32a7cc5ac1934` 的可执行契约；不得凭印象设计 DTO 或路由。
- Phase 0、Phase 1、Phase 2 和 Phase 3 已按当前文档口径验收；当前实施 Phase 4。按完整 network policy → HTTPS `attach_headers` → authenticated differential → fuzz/security/load/recovery → 签名、notarization、SBOM、升级/回滚演练的顺序交付；只有 blueprint §20.3 全部门禁通过后才能声明 1.0 或“完全兼容”。
- 未实现能力必须返回 501 `feature_not_supported`；不得接受参数后静默忽略，也不得用 mock 结果宣称能力已实现。
- Salvo handler 仅负责 DTO、鉴权、use case 调用和响应映射；不得直接访问 SeaORM、磁盘或 libkrun。
- libkrun 固定为 v1.19.4。unsafe FFI 只能位于 `box-runtime-libkrun`，VM 必须运行在 `boxd __vmm-worker` 子进程。
- 数据访问只能经过 repository/migration；domain 和业务代码不得依赖具体数据库方言。
- secret 类型必须脱敏，tenant/account 边界必须有测试。
- 不覆盖用户已有修改，不执行破坏性 Git 操作，不自动提交或推送。
- 每个可验收切片运行：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets --all-features -- -D warnings`、`cargo test --workspace`，以及对应 Node contract/前端测试。
