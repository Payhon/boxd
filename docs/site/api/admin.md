# 管理 API

Admin API 服务嵌入式 Console。它与 compatibility API key 使用独立认证链，不应从普通应用直接复用。

## 登录与 CSRF

```bash
curl -i -c /tmp/boxd-cookie \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' \
  http://127.0.0.1:7331/api/admin/v1/auth/login
```

成功响应设置 secure/HttpOnly/SameSite 管理 session。后续请求使用 cookie，并在变更或受保护读取中携带 `X-CSRF-Token`。不要把 `X-Box-Api-Key` 当作管理 session。

## 核心路由

| Method | Path | 说明 |
| --- | --- | --- |
| `POST` | `/api/admin/v1/auth/login` | 创建 session |
| `POST` | `/api/admin/v1/auth/logout` | 销毁 session |
| `GET` | `/api/admin/v1/capabilities` | 当前部署能力标志 |
| `GET` | `/api/admin/v1/boxes` | tenant Box 列表 |
| `GET` | `/api/admin/v1/runs` | tenant run 列表 |
| `GET` | `/api/admin/v1/snapshots` | tenant Snapshot 列表 |
| `GET` | `/api/admin/v1/schedules` | tenant schedule 列表 |
| `GET/POST` | `/api/admin/v1/api-keys` | 列表/创建 API key |
| `DELETE` | `/api/admin/v1/api-keys/{id}` | revoke key |

API key 创建请求：

```json
{
  "scopes": ["boxes_read", "boxes_write", "runs_write"],
  "expires_at": null
}
```

可用 scope：`boxes_read`、`boxes_write`、`runs_write`、`secrets_read`、`admin`。明文 key 只在创建响应返回一次，服务端只持久 HMAC。

## 管理动作

- `POST /boxes/{box_id}/pause`
- `POST /boxes/{box_id}/resume`
- `DELETE /boxes/{box_id}`
- `POST /runs/{run_id}/cancel`
- `DELETE /snapshots/{snapshot_id}`
- `POST /schedules/{box_id}/{schedule_id}/pause|resume`
- `DELETE /schedules/{box_id}/{schedule_id}`

这些路径均位于 `/api/admin/v1` 下，要求 session 与 CSRF，并执行 tenant scope。

## Terminal ticket

`POST /api/admin/v1/boxes/{box_id}/terminal-ticket` 返回 60 秒、单用途 ticket 与 WebSocket URL。ticket 与 account/tenant/Box 绑定，使用后立即失效：

```json
{
  "ticket": "one-time-secret",
  "expires_at": 1787000060,
  "websocket_url": "/api/admin/v1/terminal?ticket=..."
}
```

不要记录 ticket，不要重放，也不要把通用 Preview token 用于 Terminal。
