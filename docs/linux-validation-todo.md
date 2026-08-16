# Linux validation TODO

状态：**TODO，尚未在原生 Linux KVM 宿主执行**。

当前 macOS Apple Silicon HVF 的 Phase 1 生命周期、重启恢复、受限默认 egress 与
`deny-all` 已完成真实验收。本文件只记录后续 Linux 与双架构 runtime matrix 工作；
在对应 evidence 生成前，不得把 hermetic tests、Docker Desktop 或 import 成功写成
Linux KVM/十 runtime 真机通过。

## 1. 原生 Linux KVM 平台验收

待执行目标：

- [ ] Linux x86_64：真实 `/dev/kvm` lifecycle + daemon restart。
- [ ] Linux aarch64：真实 `/dev/kvm` lifecycle + daemon restart。
- [ ] 两种架构均验证 cgroup v2 CPU/memory/PID enforcement。
- [ ] 两种架构均验证 seccomp policy v1、restricted-default egress 与 `deny-all`。

宿主必须满足：

- `/dev/kvm` 是当前 runner 可读写的字符设备；
- cgroup v2 已委派 `cpu`、`memory`、`pids` controllers；
- 提供与平台匹配的 libkrun `v1.19.4`、firmware ABI 5、SHA-256 和 license；
- 提供专用测试 `boxd.toml`、签名 Node runtime bundle、master key、admin password
  与一次性兼容 API key；
- 不复用生产数据库、数据目录、监听地址或凭据。

手动 self-hosted workflow：

```text
.github/workflows/phase1-linux-kvm.yml
```

GitHub-hosted Ubuntu 的源码、三数据库、SDK contract、Console 和 examples 门禁位于
`.github/workflows/linux-ci.yml`。它会在 push/PR 自动运行，但不能替代本节的原生
`/dev/kvm` 证据。self-hosted runner 注册、variables/secrets 和触发步骤见
[GitHub Actions Linux testing manual](manual/github-actions-linux-testing.md)。

直接执行入口及完整环境变量清单：

```sh
scripts/phase1-linux-kvm-smoke.sh --help
scripts/phase1-linux-kvm-smoke.sh
```

脚本会依次执行 Rust source gates、release build、runtime import、doctor、pinned SDK
lifecycle/restart、restricted-egress lifecycle/restart，并为每个外部阶段设置进程组硬
超时。任何阶段失败都不得生成成功 summary。

验收产物至少包括：

- `doctor.json`，`overall=true`，且 KVM/cgroup/seccomp required checks 为 pass；
- `lifecycle.json`、`restart.json`；
- `egress-lifecycle.json`、`egress-restart.json`；
- `linux-kvm-summary.json`，绑定 boxd、bundle、libkrun、firmware、kernel、SDK commit
  和上述 evidence SHA-256；
- daemon 停止后没有遗留 `boxd __vmm-worker`。

## 2. 十 runtime × 双架构矩阵

待执行目标：

- [ ] aarch64：`node/python/golang/ruby/rust` 及五个 `-alpine` bundle。
- [ ] x86_64：同一十 runtime bundle。
- [ ] 每个 runtime 真实完成语言探针、文件 roundtrip、pause/resume、daemon restart、
  reconciliation 与 delete。

每个架构先准备审核后的 `boxd-runtime-matrix-build-input-v1`：必须包含恰好十种
runtime 的完整 SemVer、immutable `tag@sha256` runtime/Rust builder、source user、
镜像内规范 license path、构建 epoch 和目标架构。仓库不会自动猜测版本或 digest。

```sh
python3 scripts/runtime/build_runtime_matrix.py \
  --input /absolute/reviewed-matrix-input.json \
  --validate-only

python3 scripts/runtime/build_runtime_matrix.py \
  --input /absolute/reviewed-matrix-input.json \
  --output-dir /absolute/new-bundle-directory \
  --matrix-manifest /absolute/new-runtime-matrix.json

scripts/phase1-runtime-matrix-smoke.sh --help
scripts/phase1-runtime-matrix-smoke.sh
```

成功产物 `runtime-matrix-summary.json` 必须列出十个 runtime，逐项绑定 bundle、
lifecycle、restart SHA-256，并绑定 doctor、matrix input、boxd 与 pinned SDK commit。

## 3. 完成后更新

Linux 真机执行完成后：

1. 将脱敏 evidence 复制到 `docs/phase1-evidence/linux-<arch>/`；
2. 在 `docs/phase1-acceptance.md` 记录宿主/kernel/KVM/libkrun/bundle/boxd hash；
3. 勾选 `docs/implementation-status.md` 对应 Linux 与 runtime matrix 项；
4. 重跑 Rust、pinned SDK、console、ShellCheck 与文档链接门禁；
5. 只有两种 Linux 架构和对应 runtime matrix 都有真实证据后，才宣称跨平台验收。
