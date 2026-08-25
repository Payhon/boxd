# 路线图

boxd 当前实施 Phase 4。路线图按发布门禁排序，而不是按页面数量或路由数量计完成度。

## 正在进行：Phase 4

- 完整 custom network policy 的双平台真实验证；
- HTTPS `attach_headers` 的受控 CA/egress 数据面真实验证；
- 带官方凭据的 authenticated differential；
- fuzz、security、load 与 daemon/native recovery；
- macOS Developer ID 签名、notarization 与 stapling；
- SBOM、provenance、升级/回滚演练；
- Linux KVM 与十 runtime × 目标架构矩阵。

## 1.0 标准

1.0 不由时间点自动触发。只有 blueprint §20.3 与 Phase 4 外部门禁全部通过、已知差异为 0，才会发布 1.0/完全兼容声明。

## 如何参与

- 平台维护者：提供受保护 macOS HVF / Linux KVM runner 证据；
- 安全研究者：审阅 egress、preview、path、secret 和 worker boundary；
- SDK 使用者：贡献 pinned public SDK 的真实最小复现；
- 文档贡献者：补齐不会越过实现状态的教程与排障材料。
