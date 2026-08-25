# 执行与事件流

## Command 与 Code

| Method | Path | 响应 |
| --- | --- | --- |
| `POST` | `/v2/box/{box_id}/exec` | JSON `output/error/exit_code` |
| `POST` | `/v2/box/{box_id}/exec-stream` | stdout/stderr 原始字节 + SSE 终止帧 |
| `POST` | `/v2/box/{box_id}/code` | JSON `output/error/exit_code` |
| `POST` | `/v2/box/{box_id}/code-stream` | 原始输出 + SSE 终止帧 |

```bash
curl --fail-with-body -X POST \
  http://127.0.0.1:7331/v2/box/$BOX_ID/exec \
  -H "X-Box-Api-Key: $UPSTASH_BOX_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"command":["/bin/sh","-c","node --version && pwd"],"timeout":30000}'
```

`command` 是 argv 数组。服务端不会把任意数组重新拼成宿主 shell 命令；执行发生在 guest 中。

Code 请求：

```json
{
  "language": "javascript",
  "code": "console.log(JSON.stringify({ answer: 6 * 7 }))",
  "folder": "/workspace/home",
  "timeout": 30000
}
```

## Agent Run

| Method | Path | 说明 |
| --- | --- | --- |
| `POST` | `/v2/box/{box_id}/run` | fire-and-forget webhook run |
| `POST` | `/v2/box/{box_id}/run/stream` | Agent SSE |
| `POST` | `/v2/box/{box_id}/runs/{run_id}/cancel` | 取消 run |
| `GET` | `/v2/box/{box_id}/runs` | newest-first history |
| `GET` | `/v2/box/{box_id}/logs?limit=&source=` | 结构化日志 |

当前已实现的是固定 `box-sse-v1` custom harness 子集。`files`、`json_schema`、`agent_options` 和 managed agent 的未映射组合会返回 501。

## SSE 事件

`POST .../run/stream` 使用 `text/event-stream`，并关闭中间缓冲与压缩。核心事件：

| event | data |
| --- | --- |
| `run_start` | `{ "run_id": string }` |
| `text` / `thinking` | `{ "text": string }` |
| `tool` | `{ "tool_call_id", "name", "input" }` |
| `tool_result` | `{ "tool_call_id", "output" }` |
| `stats` | `{ "cpu_ns", "memory_peak_bytes" }` |
| `done` | output、tokens、cost、session id |
| `error` | `{ "error": string }` |

每个持久事件都有单调 sequence；断线不会自动取消 guest run。取消必须调用 cancel endpoint。

## Stream 字节边界

`exec-stream` 和 `code-stream` 不会把普通 stdout 包装成 `data:`。它们先原样输出 stdout/stderr，结尾追加：

```text
event: exit
data: {"exit_code":0,"cpu_ns":1234}
```

因此不要用只接受纯 SSE 的 parser 读取全部响应；公开 SDK 已实现相应 framing。
