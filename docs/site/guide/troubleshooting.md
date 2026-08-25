# 故障排查

## `serve` 提示缺少 embedded release assets

原因：使用了裸 `cargo build --release -p boxd` 产物。它可用于测试 CLI，但不能加载真实 VMM。

处理：按 [从源码运行](./source-build) 提供六个 `BOXD_EMBEDDED_*` 变量重新构建。

## `doctor` 的 `overall` 为 false

不要绕过 doctor。逐项修复 JSON 中的 required check，常见原因包括：

- `kern.hv_support` 不为 `1`；
- 二进制缺失 `com.apple.security.hypervisor` entitlement；
- libkrun/libkrunfw hash 或签名不匹配；
- runtime bundle 未导入或 trust root 不匹配；
- data dir 空间不足；
- database migration 或 listen/public URL 不自洽。

## `/health/live` 正常但 `/health/ready` 失败

`live` 只证明事件循环可响应；`ready` 还检查数据库、data dir、VMM 资产和 runtime。以 `doctor --json` 的失败项为准。

## SDK 意外访问了其他服务

所有示例都要求显式设置：

```bash
export UPSTASH_BOX_BASE_URL=http://127.0.0.1:7331
export UPSTASH_BOX_API_KEY='<local key>'
```

如果 `UPSTASH_BOX_BASE_URL` 缺失，boxd 仓库示例会直接退出，避免误连其他 endpoint。

## 收到 `501 feature_not_supported`

这是预期的兼容边界，不应改成 200。查看 [错误与兼容边界](/api/errors) 以及 `/api/admin/v1/capabilities`。

## Node 版本告警或 Console 门禁异常

仓库 Console 与 pinned SDK 门禁使用 Node 22.x。不要用 Node 26 的结果替代既定门禁。
