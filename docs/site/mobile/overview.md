# 移动端集成

boxd 当前没有发布独立的 iOS、Android 或 React Native SDK。移动端应通过自己的应用后端访问 boxd；本栏目提供可复制的 React Native 参考组件和 HTTP/SSE 接入模式，不把示例误写成已发布包。

## 推荐架构

```text
iOS / Android / React Native
          │ app session
          ▼
   Your application backend
          │ scoped boxd API key
          ▼
         boxd
          │
          ▼
      Linux microVM
```

为什么不建议 App 直连：

- compatibility API key 一旦打包到客户端就可被提取；
- Admin session、CSRF 和 Terminal ticket 面向受控 Console，不是公共移动鉴权；
- 应用后端可以做用户到 tenant/Box 的授权映射、quota 和审计；
- SSE reconnect、webhook 去重和后台任务更适合由服务端协调。

## 移动端常见页面

| 页面 | 使用的 boxd 能力 |
| --- | --- |
| Sandbox 列表 | `GET /v2/box` |
| Sandbox 详情 | get/status、pause/resume/delete |
| 执行面板 | exec/code 或 run/stream |
| 文件浏览器 | files read/list/write/upload |
| Run 时间线 | runs、logs、SSE event |
| Browser 预览 | signed preview URL 或受控 screencast |

## 接入步骤

1. 应用后端保存最小 scope 的 boxd API key；
2. 后端只暴露当前用户确实需要的业务操作；
3. 移动端使用自己的 access token 调用应用后端；
4. 后端把 Box identity 与 app user/tenant 绑定；
5. 长任务返回 app-level operation id，并通过 SSE/WebSocket/push 通知进度；
6. 任何 501 都转换为明确的“当前部署不支持”状态。

继续阅读 [React Native 接入](./react-native) 和 [参考组件与 API](./components)。
