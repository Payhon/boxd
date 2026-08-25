# Box 与生命周期

Box 是 boxd 的核心资源。创建请求先持久化状态，再启动独立 `boxd __vmm-worker` 和 microVM；非 ephemeral Box 通常先返回 `creating`，客户端轮询到 `idle` 或 `error`。

## 路由

| Method | Path | 说明 |
| --- | --- | --- |
| `POST` | `/v2/box` | 创建 Box |
| `GET` | `/v2/box` | 列出当前 tenant 的 Box |
| `DELETE` | `/v2/box` | 批量删除，body 为 `{ "ids": [...] }` |
| `GET` | `/v2/box/{box_id}` | 获取 Box |
| `GET` | `/v2/box/{box_id}/status` | 获取状态 |
| `POST` | `/v2/box/{box_id}/pause` | 持久化磁盘并停止 VM |
| `POST` | `/v2/box/{box_id}/resume` | 重启 VM 并完成 agent handshake |
| `DELETE` | `/v2/box/{box_id}` | 幂等删除 |
| `POST` | `/v2/box/from-snapshot` | 从不可变 Snapshot 创建 |

## 创建请求

直接 HTTP 示例：

```bash
curl --fail-with-body -X POST http://127.0.0.1:7331/v2/box \
  -H "X-Box-Api-Key: $UPSTASH_BOX_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "docs-example",
    "runtime": "node",
    "size": "small",
    "labels": ["docs"],
    "network_policy": { "mode": "deny-all" }
  }'
```

常用字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `runtime` | string | 目标 runtime；必须已有当前架构的签名 bundle |
| `size` | `small \| medium \| large` | 资源档位，资源不足返回 422，不静默缩水 |
| `name` | string? | 可读名称 |
| `labels` | string[]? | 最多 5 个，每个不超过 20 字符 |
| `keep_alive` | boolean? | 保持运行；与部分 pause/startup 语义有关 |
| `env_vars` | object? | 创建时环境变量，secret 按配置加密 |
| `browser` | boolean? | 请求 Browser runtime 能力 |
| `network_policy` | object? | `allow-all`、`deny-all` 或 feature-gated `custom` |
| `ephemeral` / `ttl` | boolean / integer? | 临时 Box 与生存时间，TTL 最大 259200 秒 |
| `snapshot_id` | string? | 从 Snapshot 创建时使用 |

未知字段会触发 validation error，不会被静默忽略。

## 响应核心字段

```json
{
  "id": "019...",
  "customer_id": "019...",
  "status": "creating",
  "name": "docs-example",
  "runtime": "node",
  "size": "small",
  "labels": ["docs"],
  "enabled_skills": [],
  "keep_alive": false,
  "ephemeral": false,
  "network_policy": { "mode": "deny-all" },
  "created_at": 1787000000,
  "updated_at": 1787000000
}
```

状态集合：`creating | idle | running | paused | error | deleted`。

## 配置子资源

| Method | Path | 说明 |
| --- | --- | --- |
| `GET/PUT/DELETE` | `/v2/box/{box_id}/startup` | init command |
| `PUT` | `/v2/box/{box_id}/config/model` | custom agent model |
| `PUT` | `/v2/box/{box_id}/config/custom-runner` | `box-sse-v1` custom runner |
| `PUT` | `/v2/box/{box_id}/config/network-policy` | 网络策略 |
| `POST/DELETE` | `/v2/box/{box_id}/config/labels[/{label}]` | label |
| `POST/DELETE` | `/v2/box/{box_id}/config/skills[/{skill_id...}]` | skill |
| `GET/PUT/DELETE` | `/v2/box/settings/env[/{key}]` | tenant stored env |

`attach_headers` 与完整 custom network policy 都受 feature flag 和 Phase 4 平台门禁约束。不要仅依据字段存在就认为当前部署已启用。
