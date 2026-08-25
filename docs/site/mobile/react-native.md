# React Native 接入

以下代码假设请求发往你的应用后端。后端再以 `X-Box-Api-Key` 调用 boxd；不要把 boxd key 写进 App。

## 最小 client

```ts
export type BoxStatus =
  | 'creating'
  | 'idle'
  | 'running'
  | 'paused'
  | 'error'
  | 'deleted';

export interface SandboxSummary {
  id: string;
  name?: string | null;
  runtime: string;
  size: 'small' | 'medium' | 'large';
  status: BoxStatus;
  labels: string[];
  createdAt: number;
  updatedAt: number;
}

export class SandboxApi {
  constructor(
    private readonly baseUrl: string,
    private readonly getAccessToken: () => Promise<string>,
  ) {}

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const token = await this.getAccessToken();
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        ...init?.headers,
      },
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new SandboxApiError(response.status, body.error, body.message);
    }
    return response.status === 204 ? (undefined as T) : response.json();
  }

  list() {
    return this.request<SandboxSummary[]>('/sandboxes');
  }

  pause(id: string) {
    return this.request<SandboxSummary>(`/sandboxes/${id}/pause`, { method: 'POST' });
  }

  resume(id: string) {
    return this.request<SandboxSummary>(`/sandboxes/${id}/resume`, { method: 'POST' });
  }
}

export class SandboxApiError extends Error {
  constructor(
    readonly status: number,
    readonly code?: string,
    message?: string,
  ) {
    super(message ?? `Sandbox request failed (${status})`);
  }
}
```
## Query 状态策略

- list/detail 前台页面可每 3–5 秒刷新；
- `creating`、`running` 等过渡态可缩短到 1–2 秒；
- App 进入后台后停止轮询，依赖 push 或返回前台 refresh；
- pause/resume/delete 使用 mutation lock，避免重复点击；
- 409 显示“状态已经变化”，刷新后重新判断；
- 501 显示能力缺失，不做指数重试。

## SSE

React Native 的内置 `fetch` 不保证所有版本都提供流式 `ReadableStream`。可选择：

1. 由应用后端把 boxd SSE 转换为 App 已有的 WebSocket；
2. 使用经过审阅的 EventSource polyfill；
3. 后台运行由后端接收，移动端轮询 operation/run history。

无论哪种方式，都应保存最后一个 event sequence/id，在重连时请求回放；组件 unmount 只断开订阅，不自动 cancel guest run。

## 错误映射

```ts
export function toUserMessage(error: unknown): string {
  if (!(error instanceof SandboxApiError)) return '网络连接失败，请稍后重试';
  if (error.status === 401) return '登录已失效，请重新登录';
  if (error.status === 409) return '沙盒状态已变化，正在刷新';
  if (error.status === 429) return '操作过于频繁，请稍后再试';
  if (error.code === 'feature_not_supported') return '当前服务暂不支持此功能';
  return error.message;
}
```
