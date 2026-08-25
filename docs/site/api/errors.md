# 错误与兼容边界

Compatibility API 错误至少包含稳定 code、人类可读 message 和 request id：

```json
{
  "error": "feature_not_supported",
  "message": "nested tree download is not supported",
  "request_id": "019..."
}
```

## 状态码

| Status | 含义 |
| --- | --- |
| `400` | DTO、字段、query 或配置 validation 失败 |
| `401` | API key/session 缺失或无效 |
| `403` | scope、tenant 或 network policy 拒绝 |
| `404` | 对象不存在，或当前 tenant 不可见 |
| `409` | Box/run/snapshot 状态冲突 |
| `413` | body/file 超限 |
| `422` | 宿主容量不足或资源请求不可满足 |
| `429` | API key 或 tenant quota 超限 |
| `500` | 未预期的内部错误 |
| `501` | 已知 contract，但当前能力未实现/未启用 |
| `503` | runtime、agent、database 或 readiness 暂不可用 |

## 为什么 501 很重要

boxd 不会接受未知/不支持参数后返回假成功。以下情况可能按当前部署返回 501：

- managed agent 与没有 custom harness 映射的 run options；
- run `files`、response `json_schema`、`agent_options` 组合；
- 无法保留嵌套目录语义的 tree download；
- 未启用 feature flag 的 custom network policy / `attach_headers`；
- 缺少对应 runtime feature 的 Browser 或 recording 能力。

## 兼容性声明

当前仓库固定了 86 callsites / 80 operations / 77 direct + 1 response-linked contracts，并维护 82 个公开 SDK cases 与 159 个 dispatch captures。这些数字证明 contract inventory 的覆盖，不等同于 Phase 4 的官方服务 authenticated differential、双平台真机和正式发行门禁已通过。

应用应读取 `/api/admin/v1/capabilities`，并把 501 当作能力协商结果，而不是重试型 5xx。
