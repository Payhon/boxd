# Phase 1 evidence boundary

本目录保存的是可公开提交的**脱敏语义投影**，不是运行机上的原始 evidence byte
archive。真实 smoke 结束后，Box ID、临时路径、凭据、数据库、VM 磁盘和原始测试目录
已清理；保留的 JSON 仅包含验收结论、计数、时间、artifact identity 与非敏感结果。

因此必须区分两类 hash：

- `restart.json.lifecycle_evidence_sha256` 与当前 `lifecycle.json` 投影一致，可用于当前
  文件的交叉检查；
- `egress-restart.json.lifecycle_evidence_sha256` 是 restart 执行时读取的原始、含临时
  Box ID 的 lifecycle bytes SHA-256。当前 `egress-lifecycle.json` 已移除
  `restricted_box_id`/`deny_all_box_id` 并规范化格式，其 SHA-256 必然不同。原始文件已
  随敏感测试目录清理，不得把该 raw hash 重新解释为当前投影 hash。

[`manifest.json`](manifest.json) 固定当前五份投影的 SHA-256，并显式记录上述 raw→
redacted 边界。它证明仓库内 evidence 文件后续是否漂移，但不能替代原始运行机归档、
Developer ID/notarization 或 Linux KVM evidence。

macOS 通过结论还同时绑定：当次验收的 `box-agent` source hash、签名 Node runtime bundle、
rootfs、boxd、libkrun/firmware identity，以及 doctor/lifecycle/restart 的语义结果；详见
[Phase 1 acceptance](../phase1-acceptance.md)。后续源码演进不会把这份历史投影重写成
“当前源码”证据；当前源码的真实 HVF 身份以更新 phase 的 acceptance record 为准。
