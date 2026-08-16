# ADR-0001：固定 libkrun 与 worker 生命周期

- Status: Accepted

## Context

首发平台是 macOS 14+ Apple Silicon 与 Linux x86_64/aarch64 + KVM。稳定 VMM 接口必须可复现；同时 libkrun 的 `krun_start_enter()` 会接管执行，VM 停止时调用 `exit()`，不能驻留在控制面 API 进程中。

## Decision

- 固定 libkrun **v1.19.4**，生产 FFI 只使用该 tag 的 public C header，不跟随 `main` 或 `2.0` API。
- 所有 FFI 与 `unsafe` 集中在唯一的 `box-runtime-libkrun` crate；domain/API 不接触 libkrun 类型、REST socket、设备模型或快照类型。
- 每个活跃 Box 由同一可执行文件启动一个 `boxd __vmm-worker --spec-fd <fd>` 子进程。worker 负责加载库、VM 设备配置和启动；控制面保留业务状态、数据库和 guest RPC。
- worker 调用 `krun_start_enter()`；其退出原因通过退出码与控制管道返回 supervisor，而不是让 `boxd serve` 的生命周期受该调用支配。

## Consequences

控制面不会因单个 VM 正常退出而退出；每个 Box 有明确的故障与资源边界。代价是需要定义 worker spec、控制通道、重启 reconciliation 和平台适配测试。未来驱动可替换，但不得越过 `SandboxDriver` / `SandboxRuntime` 边界。

## Verification

实施后执行：

```sh
rg -n 'v1\\.19\\.4|krun_start_enter|__vmm-worker|box-runtime-libkrun' Cargo.toml crates docs
cargo test -p box-runtime-libkrun
boxd doctor --json
```

当前 Phase 0 仅冻结决策。workspace 已有可编译的 crate 与空 `boxd`
composition-root 骨架，但尚无 CLI、worker 或 libkrun FFI 行为。

## Related

- [Architecture](../architecture.md)
- [Implementation status](../implementation-status.md)
