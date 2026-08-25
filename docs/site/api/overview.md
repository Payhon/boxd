# API 总览

boxd 暴露三类 HTTP surface：

| Surface | 前缀 | 认证 | 面向对象 |
| --- | --- | --- | --- |
| Compatibility API | `/v2/box` | `X-Box-Api-Key` | `@upstash/box@0.6.3` 与直接 HTTP 客户端 |
| Admin API | `/api/admin/v1` | HttpOnly session cookie + CSRF | 嵌入式 Console 与管理员工具 |
| Operations | `/health/*`、`/metrics`、`/openapi.json` | 依部署策略 | 健康检查、监控和 API 探索 |

## 基础地址

本地默认：

```text
http://127.0.0.1:7331
```

所有 compatibility 请求都必须带 API key：

```bash
curl --fail-with-body \
  -H "X-Box-Api-Key: $UPSTASH_BOX_API_KEY" \
  http://127.0.0.1:7331/v2/box
```

## 推荐：使用公开 SDK

```bash
npm install @upstash/box@0.6.3
export UPSTASH_BOX_BASE_URL=http://127.0.0.1:7331
export UPSTASH_BOX_API_KEY='<local compatibility key>'
```

```js
import { Box } from '@upstash/box';

const box = await Box.create({
  runtime: 'node',
  size: 'small',
  networkPolicy: { mode: 'deny-all' },
  timeout: 300_000,
});

try {
  const result = await box.exec.command('node --version');
  console.log(result.stdout);
} finally {
  await box.delete();
}
```

## OpenAPI

运行中的服务在下列地址输出当前实现生成的 OpenAPI 文档：

```text
GET /openapi.json
```

OpenAPI 方便探索，但不是 `/v2/box` 的唯一兼容真相源。固定 SDK 的 contract fixtures、route/type/stream manifest 与差分门禁具有更高优先级。

## 请求约定

- compatibility API 使用 `snake_case` JSON 字段；
- SDK 本身会在 JavaScript 属性与 wire 字段之间转换；
- Box、Snapshot、Run 等 identity 使用不可猜测的 UUID 字符串；
- 时间按相应 SDK contract 返回 epoch seconds 或 milliseconds；
- SSE 与二进制响应不能按普通 JSON body 解析；
- secret 只在创建时展示一次，日志和错误中必须脱敏。

## 核心路由组

| 分组 | 能力 |
| --- | --- |
| Box | create/list/get/status/pause/resume/delete、startup、labels、env、skills |
| Execution | command/code、stream、run/SSE、cancel、logs |
| Development | files、Git、snapshot |
| Automation | schedules、preview、Browser、recording |

完整固定路由清单保存在仓库的 [`route-manifest.json`](https://github.com/Payhon/boxd/blob/main/compat/upstash-box-0.6.3/route-manifest.json)。
