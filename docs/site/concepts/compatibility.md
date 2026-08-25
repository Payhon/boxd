# 兼容性与状态

## 固定基线

- npm package：`@upstash/box@0.6.3`；
- upstream commit：`677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`；
- libkrun：`v1.19.4`；
- compatibility prefix：`/v2/box`；
- auth header：`X-Box-Api-Key`。

## 当前完成度

| 阶段 | 状态 | 证据边界 |
| --- | --- | --- |
| Phase 0 契约冻结 | 完成 | manifest、fixtures、82 cases / 159 captures |
| Phase 1 可启动 MVP | macOS 完成 | Apple Silicon HVF；Linux KVM 与十 runtime 矩阵待验 |
| Phase 2 Agent/开发流 | 完成 | custom harness 子集、Git/Snapshot/Preview/Console |
| Phase 3 调度/Browser | 完成 | macOS Browser、recording、三数据库矩阵 |
| Phase 4 生产加固 | 进行中 | network/attach headers 已实现；外部 protected gates 尚未全通过 |

## “完全兼容”的门禁

只有以下条件同时满足，才会发布 1.0 或声明完全兼容：

1. compatibility manifest 100% implemented；
2. SDK contract suite 100% 通过；
3. macOS HVF 与 Linux KVM smoke/e2e 通过；
4. 不存在接受参数但忽略的路径；
5. SSE/stream 字节 fixture 全部通过；
6. 已知差异为 0；
7. authenticated differential、security/load/recovery、签名/notarization、SBOM 和升级回滚证据齐全。

当前版本必须描述为“兼容子集”。最新工程证据见仓库 [`docs/implementation-status.md`](https://github.com/Payhon/boxd/blob/main/docs/implementation-status.md)。
