# 安全模型

boxd 把 microVM 作为主要隔离边界，但不把“用了 VM”当作全部安全结论。

## 关键防线

- guest 默认以非 root `boxuser` 运行；
- rootfs 基础层只读，workspace 位于 Box 私盘；
- libkrun unsafe FFI 仅位于 `box-runtime-libkrun`；
- worker 使用最小环境、资源限制与独立工作目录；
- 网络默认阻断宿主控制 API、metadata、loopback/link-local/private CIDR；
- Preview 与 Terminal 使用短期、scope 绑定、可撤销 capability；
- runtime、agent、libkrun 与 firmware 使用 hash/signature 校验；
- secret 不进入 tracing、panic、SSE、snapshot metadata 或诊断包；
- tenant/account ownership 在 repository 与 API 层都验证。

## 需要持续验证的威胁

- 恶意 guest 逃逸或 VMM 漏洞；
- SSRF、DNS rebinding 与 metadata 访问；
- tenant 越权与 API key 泄漏；
- Preview/Terminal capability 接管；
- path traversal、symlink race 与 archive bomb；
- snapshot 残留与日志泄密；
- CPU、内存、PID、磁盘与流量耗尽；
- runtime 供应链替换。

发现安全问题请不要公开 issue，按 [安全报告流程](https://github.com/Payhon/boxd/blob/main/SECURITY.md) 联系维护者。
