# 认识 boxd

boxd 是一个用 Rust 构建的本地 Sandbox-as-a-Service 控制面。它面向需要在 macOS Apple Silicon 或原生 Linux KVM 上运行不可信、临时开发任务的开发者，并将公开的 `@upstash/box@0.6.3` API 作为兼容目标。

## 它解决什么问题

Agent、代码生成器、自动化测试和 Browser 工作流都需要一个可隔离、可重建、可清理的执行环境。直接在宿主机运行会把工作区、凭据和进程暴露给任务；传统容器又依赖共享内核和额外守护进程。

boxd 的选择是：一个本地控制面，一个 Box 对应一个 Linux microVM。

```text
@upstash/box SDK
        │
        ▼
   boxd HTTP API ─── SQLite / PostgreSQL / MySQL
        │
        ▼
boxd __vmm-worker
        │
        ▼
libkrun + HVF ─── Linux microVM ─── box-agent
```

## 适合的场景

- 在 Mac 上开发和调试使用 `@upstash/box` 的应用；
- 为 AI Agent 提供隔离的 command、code、files、Git 和 Browser 环境；
- 在提交云端前，重放生命周期、SSE、schedule、snapshot 和 preview 流程；
- 构建对数据位置和运行时资产有明确控制要求的本地工作流。

## 当前不是什么

- 不是已完成全部发布门禁的 1.0 产品；
- 不是 Intel Mac 或 Windows 虚拟化方案；
- 不是用 hosted CI 模拟出来的 Linux KVM 发行结论；
- 不是官方 Upstash 产品，也不代表 Upstash 的服务或商标；
- 不是可以缺少 libkrun/runtime bundle 仍返回假成功的 mock 服务。

## 设计原则

1. **契约先行**：兼容 DTO、method/path、query、header 和 stream 字节由固定 SDK 提取。
2. **明确降级**：未实现能力返回 `501 feature_not_supported`。
3. **最小信任**：secret 脱敏、tenant/account 边界、网络策略和 guest 路径都 fail closed。
4. **可恢复**：Box、run、schedule、snapshot 和 operation 状态可持久化并在 daemon 重启后协调。
5. **证据分层**：源码测试、hosted CI、macOS HVF、Linux KVM 和正式发行验收分别记录。

下一步先 [下载预编译二进制](./download)，再按 [5 分钟开始](./quick-start) 完成真实沙盒启动；只有贡献代码或审计发行输入时才需要 [从源码构建](./source-build)。
