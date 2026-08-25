# 系统架构

boxd 将 API 控制面、domain/use cases、repository、runtime supervisor 和 microVM worker 分层，避免 handler 直接访问数据库、磁盘或 FFI。

```text
SDK / Mobile backend / Console
             │
             ▼
 Salvo compatibility + Admin routers
             │
             ▼
      Domain / Use Cases
        │           │
        ▼           ▼
 SeaORM repos   Sandbox Supervisor
                    │
                    ▼
          boxd __vmm-worker process
                    │
                    ▼
        libkrun v1.19.4 + HVF/KVM
                    │
                    ▼
      private disk + box-agent + vsock
```

## 进程边界

每个活跃 Box 使用同一个可执行文件启动隐藏 worker 子进程。稳定版 `krun_start_enter()` 会消费配置并在 VM 停止时调用 `exit()`，因此 FFI 不能在长期 HTTP 进程中直接运行。

## 数据边界

- 默认 SQLite WAL；repository/migration 同时支持 PostgreSQL/MySQL；
- base runtime disk 永远只读，每个 Box 克隆独立 raw ext4 私盘；
- snapshot 使用 APFS clonefile/Linux reflink，缺失时退化为有界 sparse copy；
- secret 使用 AEAD，API key 只保存 HMAC 与前缀；
- guest 文件操作经 agent/私盘，不默认共享宿主目录。

## Runtime bundle

```text
box-runtime-node-arm64-<version>.tar.zst
├── manifest.json
├── manifest.sig
├── rootfs.raw
├── sbom.spdx.json
└── licenses/
```

控制面校验架构、agent protocol、checksum、签名与 trust root 后才导入。运行中的 Box 固定 bundle content hash，升级不会原地替换其基础镜像。
