# ADR-0004：单可执行文件边界与 runtime bundle

- Status: Accepted

## Context

部署交付是一个 `boxd` 可执行文件和一个 `boxd.toml`，但 Linux kernel、rootfs 与语言运行时若全部嵌入，会使发行物膨胀到数 GB。libkrun 官方交付又是动态库。

## Decision

- `boxd` 内嵌 console、migration、guest-agent bootstrap、license 和匹配平台 libkrun 动态库。
- 启动时对内嵌库做 SHA-256 校验，解出到受控数据目录后用 `libloading` 加载；正式发行校验签名。macOS 主程序与 dylib 必须使用同一签名身份并完成 notarization。
- runtime bundle（kernel/rootfs/语言运行时）不嵌入主程序：按需下载、校验、解压到 data dir，或通过 `boxd runtime import <bundle>` 离线导入。
- bundle 用 manifest、签名、checksum 和内容 hash 管理；运行中的 Box 固定原 hash，升级不得原地替换。

## Consequences

安装面保持单可执行文件边界，同时避免把运行时镜像伪装成二进制依赖。首次使用可能需要下载或显式导入；数据目录成为受控状态，而不是额外部署工件。

## Verification

实施后执行：

```sh
rg -n 'rust-embed|libloading|SHA-256|runtime import|manifest\\.sig|content hash' crates docs
boxd runtime import --help
boxd doctor --json
```

当前没有可执行的 runtime import、签名校验或发行构建。

## Related

- [Architecture](../architecture.md)
- [Implementation status](../implementation-status.md)
