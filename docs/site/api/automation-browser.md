# 调度、预览与 Browser

## Schedules

| Method | Path | 说明 |
| --- | --- | --- |
| `POST/GET` | `/v2/box/{box_id}/schedules` | 创建/列表 |
| `GET/PATCH/DELETE` | `/v2/box/{box_id}/schedules/{id}` | 单项操作 |
| `POST` | `/v2/box/{box_id}/schedules/{id}/pause` | 暂停 |
| `POST` | `/v2/box/{box_id}/schedules/{id}/resume` | 恢复 |

Exec schedule 示例：

```json
{
  "type": "exec",
  "cron": "0 * * * *",
  "command": ["/bin/sh", "-c", "date -u >> /workspace/home/hourly.log"],
  "folder": "/workspace/home",
  "timeout": 30000
}
```

cron 为五字段 UTC 表达式。occurrence identity 使用 `schedule_id + scheduled_at`，webhook 采用持久、at-least-once 语义，接收端应按 `X-Boxd-Webhook-Id` 去重。

## Preview

| Method | Path | 说明 |
| --- | --- | --- |
| `POST/GET` | `/v2/box/{box_id}/preview` | 创建/列出公开 URL |
| `DELETE` | `/v2/box/{box_id}/preview/{port}` | 撤销端口 URL |

Preview token 随机、带过期时间并与 Box/tenant 绑定。网关覆盖转发 header，不允许暴露 control/agent 保留端口。

## Browser

Browser Box 需要带 Chromium feature 的签名 runtime bundle。

| 能力 | 路由 |
| --- | --- |
| Tabs | `POST/GET /browser/tabs`、`DELETE /browser/tabs/{tab_id}` |
| Navigation | `POST /browser/goto` |
| Read | `GET /browser/content`、`GET /browser/screenshot` |
| Agent actions | `POST /browser/extract`、`observe`、`act`、`run` |
| Live access | `POST /browser/connect`、`screencast` |
| Recording | `POST/GET /browser/recordings`、`recordings/stop` |
| Media | playlist、segment、download endpoints |

以上路径均位于 `/v2/box/{box_id}` 下。

创建 tab：

```json
{
  "url": "https://example.com",
  "wait_until": "load",
  "timeout": 30000
}
```

导航复用 Box 网络策略，并阻断 `file:`、`chrome:`、metadata 与私网 SSRF。CDP/connect ticket 为短期、单 Box、单用途凭据；screencast 是 view-only，带背压与上限。
