# boxd Console（Phase 2 管理面）

React + TypeScript + Vite + Ant Design 的嵌入式控制台构建输入。Vite 的 `base` 固定为 `/console/`；Rust 静态资源层应把 `/console/{*path}` 的未知 SPA 路由回退到 `index.html`。

要求 Node.js 22，安装与验证：

```sh
npm ci
npm run lint
npm run typecheck
npm run test -- --run
npm run build
npm run test:e2e
```

控制台只允许调用 `/api/admin/v1`，请求始终携带 `credentials: 'include'`，并由调用方提供 CSRF token。它不使用 `/v2/box`、`X-Box-Api-Key` 或本地存储的凭据。

当前 Dashboard、Boxes、Runs、Snapshots 和 API Keys 页读取真实
`/api/admin/v1` 数据，并提供当前 Phase 2 支持的 pause/resume/delete/cancel/revoke
操作。Terminal 由管理会话签发 60 秒单用途 ticket，用 WebSocket 连接
guest 的 boxuser 行定向 shell；它不声称 PTY resize，也未授予剪贴板或文件
上传权限。删除 Box 必须二次确认目标 ID；新 API Key 明文只在内存
中展示一次。Schedules、System 中的后续阶段能力继续显式 unavailable。

`dist/` 是构建产物，不应提交；嵌入与 SPA fallback 由 Rust Phase 1 服务端实现，本目录不修改该接口。
