# ADR-0005：pinned SDK 源码与 npm 发布包的兼容基线

- Status: Accepted

## Context

蓝图同时指定 `@upstash/box@0.6.3` 和源码 commit
`677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`。独立取证发现 npm
`0.6.3` 发布 tag 为 `69398b4`，而指定 commit 位于其后；虽然源码中的包版本仍为
`0.6.3`，指定 commit 已新增 recording download 等调用。因此两者不能被当作完全
相同的源码快照，蓝图中的 69 个调用点也不能作为硬编码数量。

## Decision

- 线协议以用户明确指定的 commit 为最终真相源；npm `0.6.3` 包用于运行公开 SDK
  contract runner，并单独固定其 integrity/shasum。
- compatibility 资产同时记录 npm artifact 与 pinned commit provenance，不以其中一个
  hash 冒充另一个。
- raw manifest 从 pinned `client.ts` 的业务 HTTP dispatch 生成：86 个 callsite。
  其中 3 个是 create/from-snapshot poll 或 run retry，另 3 个是 `cd`、skills list、
  labels list 对既有合同的复用；六条规则都保留 raw 证据与归一化原因，归一化后为 80 个
  operation dispatch。服务端合同为 77 个直接 `method + canonical path`，加上 SDK
  recording metadata 返回的 1 个 playlist URL 合同，共 78 个。生成器和 runner 必须
  双向验证这些口径，不能为了符合旧的 69 估计而增删条目。
- npm 包缺少而 pinned commit 新增的公开行为，contract runner 使用 pinned source
  构建出的 SDK 产物执行；若使用 npm artifact 执行，则明确标记其覆盖边界。
- SDK 与蓝图出现歧义时，保留可执行 fixture 和差异证据，再更新 manifest；不得凭
  文档表格猜测 DTO、method 或 path。

## Consequences

兼容测试需要维护两个相互关联但不同的来源证明，并明确 runner 使用的是哪一个 SDK
构建。数量可能随生成器修正而变化，但任何变化必须来自 pinned source diff，并让 CI
显示 source-only/manifest-only 差集。

## Verification

```sh
npm ci --prefix compat/upstash-box-0.6.3
npm run check:manifest --prefix compat/upstash-box-0.6.3
npm run check:coverage --prefix compat/upstash-box-0.6.3
npm test --prefix compat/upstash-box-0.6.3
```

验收输出必须同时报告 concrete dispatch、distinct contract、public SDK capture 三个
口径；不能只报告 JSON 条目数。

## Related

- [API compatibility](../api-compatibility.md)
- [Implementation status](../implementation-status.md)
