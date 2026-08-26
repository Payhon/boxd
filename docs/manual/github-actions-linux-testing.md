# 使用 GitHub Actions 测试 boxd 的 Linux 路径

本文说明仓库内两类 Linux 流水线的用途、运行方式和证据边界。核心原则是：

- GitHub-hosted Ubuntu 适合源码、数据库和协议门禁；
- 真实 VM 沙盒验收必须运行在拥有原生 `/dev/kvm` 的 self-hosted Linux 主机；
- 没有 KVM runner 或签名 runtime 资产时，不把 queued、skipped、Docker 或单元测试
  写成 KVM 通过。

GitHub 会根据 `runs-on` 的标签组合选择 self-hosted runner。仓库使用默认的
`self-hosted`、`linux`、`x64`/`ARM64` 标签，并额外要求自定义标签
`boxd-kvm`。GitHub 官方说明见
[Using self-hosted runners in a workflow](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/use-in-a-workflow)
和
[Using labels with self-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/apply-labels)。

## 1. 自动运行的 hosted Linux 门禁

文件：`.github/workflows/linux-ci.yml`

触发条件：

- push；
- pull request；
- 手动 `workflow_dispatch`。

流水线固定使用 Ubuntu 24.04、Rust 1.94.0 和 Node 22，包含：

| Job | 检查内容 |
| --- | --- |
| `runtime-artifact-tools` | runtime 构建/验收脚本语法、Python 测试、Phase 1/3 smoke 入口和 ShellCheck |
| `rust` | `cargo fmt`、workspace 全 targets/features clippy、workspace tests |
| `database-matrix` | PostgreSQL 16、MySQL 8.4 migration up/down 与 portable repository matrix；SQLite 已在 workspace tests 中覆盖 |
| `pinned-sdk-contract` | `@upstash/box@0.6.3` manifest、coverage、可执行 contract tests |
| `embedded-console` | lint、typecheck、Vitest、production build 和 committed dist 一致性 |
| `sdk-examples` | `examples/` 锁文件安装和全部 `.mjs` 语法检查 |

首次 push 后查看：

```sh
gh run list --repo Payhon/boxd --workflow linux-ci.yml
gh run watch --repo Payhon/boxd <run-id>
```

也可手动触发：

```sh
gh workflow run linux-ci.yml --repo Payhon/boxd
```

这些 job 会真实运行 Linux-only 的 Rust 分支和外部 PostgreSQL/MySQL 容器，但 GitHub
hosted runner 是临时 VM，不能据此声称 boxd 已经完成 libkrun/KVM guest boot。

### 1.1 探测 GitHub-hosted runner 是否暴露 KVM

文件：`.github/workflows/phase4-hosted-kvm-probe.yml`

该手动/路径触发流水线分别在 `ubuntu-24.04` 和 `ubuntu-24.04-arm` 上运行隔离单测，
然后验证 `/dev/kvm` 是字符设备、能以 `O_RDWR` 打开，并且
`KVM_GET_API_VERSION` 返回 Linux KVM ABI 版本 `12`：

```sh
gh workflow run phase4-hosted-kvm-probe.yml --repo Payhon/boxd
gh run list --repo Payhon/boxd --workflow phase4-hosted-kvm-probe.yml
gh run watch --repo Payhon/boxd <run-id>
```

每个矩阵 job 都会上传 `phase4-hosted-kvm-probe-*` JSON artifact。`pass` 只证明
host KVM API 可访问；`blocked` 会以 exit 77 让对应 job 明确失败并记录原因。探针不加载
libkrun、不导入 runtime、不启动 boxd，也不替代下一节的 self-hosted guest smoke。

2026-08-22 对 commit `38788ce89f66d57f169c90f27627538ae81e504d` 的
[托管 runner 实测](https://github.com/Payhon/boxd/actions/runs/32574199144)为：

- `ubuntu-24.04` / `x86_64`：`/dev/kvm` 是字符设备，但 `O_RDWR` 返回
  `Permission denied`；
- `ubuntu-24.04-arm` / `aarch64`：`/dev/kvm` 不存在。

因此当前 GitHub-hosted 矩阵只能执行源码、协议、数据库与探针测试；真实 KVM guest
验收仍必须使用下一节的 `boxd-kvm` self-hosted runner。以后 runner 镜像能力可能变化，
应重新手动运行探针，以新的 JSON artifact 为准。

## 2. 准备原生 KVM self-hosted runner

文件：`.github/workflows/phase1-linux-kvm.yml`

推荐使用专用 Ubuntu 24.04 x86_64 或 aarch64 裸机/VM；如果 runner 自身是 VM，宿主
必须可靠地暴露 nested KVM。runner 账户至少需要：

```sh
test "$(uname -s)" = Linux
test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm
test -f /sys/fs/cgroup/cgroup.controllers
grep -qw cpu /sys/fs/cgroup/cgroup.controllers
grep -qw memory /sys/fs/cgroup/cgroup.controllers
grep -qw pids /sys/fs/cgroup/cgroup.controllers
```

还应安装 Git、curl、Python 3、ripgrep、Node/npm、Rustup，以及构建 libkrun 所需的
系统依赖。仓库使用 `actions/checkout@v5` 和 `actions/setup-node@v5`，self-hosted
runner 版本需不低于 `v2.327.1`。不要让该 runner 访问生产数据库或生产密钥。

在 GitHub 仓库的 `Settings -> Actions -> Runners -> New self-hosted runner` 按官方
命令注册。注册时添加自定义标签：

```sh
./config.sh \
  --url https://github.com/Payhon/boxd \
  --token '<short-lived registration token>' \
  --labels boxd-kvm
```

GitHub 会自动添加 `self-hosted`、`linux` 和架构标签。workflow 的 architecture 输入
必须和 runner 的 `x64` 或 `ARM64` 标签一致。

## 3. 配置专用测试资产

在 `Settings -> Secrets and variables -> Actions` 配置以下 repository variables：

| Variable | 内容 |
| --- | --- |
| `BOXD_KVM_CONFIG` | runner 上专用 `boxd.toml` 的绝对路径 |
| `BOXD_KVM_RUNTIME_BUNDLE` | 与 runner 架构匹配的签名 Node runtime bundle 绝对路径 |
| `BOXD_KVM_LIBKRUN_PATH` | 固定 libkrun v1.19.4 `.so` 绝对路径 |
| `BOXD_KVM_LIBKRUN_SHA256` | libkrun 64 位小写十六进制 SHA-256 |
| `BOXD_KVM_LIBKRUN_LICENSE_PATH` | libkrun license 绝对路径 |
| `BOXD_KVM_LIBKRUNFW_PATH` | firmware ABI 5 `.so` 绝对路径 |
| `BOXD_KVM_LIBKRUNFW_SHA256` | firmware 64 位小写十六进制 SHA-256 |
| `BOXD_KVM_LIBKRUNFW_LICENSE_PATH` | firmware license 绝对路径 |

再配置 repository secrets：

| Secret | 内容 |
| --- | --- |
| `BOXD_KVM_MASTER_KEY` | 专用测试环境的 32-byte master key（hex 或 base64） |
| `BOXD_KVM_ADMIN_PASSWORD` | 专用 bootstrap admin password |
| `BOXD_KVM_API_KEY` | 与该测试数据库匹配的一次性兼容 API key |

所有路径都必须是 runner 本地绝对路径、regular file 且不能是 symlink。workflow 不会
把 secret 写进 evidence，KVM 脚本也不会删除 runner-owned config、data 或 release
资产。仍应把 runner 视为持久敏感主机，定期轮换测试凭据。

完整 config、bundle 和 key 的生成方式见
[本地沙盒测试教程](boxd-local-sandbox-testing.md)；直接脚本帮助为：

```sh
scripts/phase1-linux-kvm-smoke.sh --help
```

## 4. 触发真实 KVM 门禁

hosted `linux-ci` 已通过后，可跳过重复的源码门禁：

```sh
gh workflow run phase1-linux-kvm.yml \
  --repo Payhon/boxd \
  -f architecture=x64 \
  -f skip_source_gates=true

gh run list --repo Payhon/boxd --workflow phase1-linux-kvm.yml
gh run watch --repo Payhon/boxd <run-id>
```

aarch64 runner 使用 `-f architecture=ARM64`。若没有同时匹配
`self-hosted + linux + boxd-kvm + architecture` 的在线 runner，job 会保持 queued，
这不是测试通过或失败。

脚本在构建前验证 `/dev/kvm`、cgroup v2 controllers、所有路径、SHA-256 和 loopback
监听地址；随后执行：

1. 可选 source gates；
2. 嵌入 libkrun/firmware 的 release build；
3. config validation、signed bundle import、`doctor --json`；
4. pinned SDK lifecycle、daemon restart、文件/exec/pause/resume/delete；
5. restricted-default egress lifecycle/restart；
6. worker 回收检查和脱敏 evidence 汇总。

无论成功或失败，workflow 都会上传 `phase1-linux-kvm-<run-id>-<attempt>` artifact。
成功的 `linux-kvm-summary.json` 会绑定 kernel、架构、boxd、runtime bundle、libkrun、
firmware、SDK commit 和每份 evidence 的 SHA-256。

## 5. 失败判定与清理

- preflight exit 77：平台没有可用 KVM/cgroup，不要重试成“偶发测试失败”；
- `doctor.overall=false`：按 required failed check 修 runner 或签名资产；
- job 一直 queued：检查 runner 在线状态和四个标签；
- `capacity_exceeded`：检查 runtime private disk 和 `minimum_free_gib`，不要绕过准入；
- smoke 失败后：先确认 workflow 已回收 owned daemon/worker，再删除该次 runner temp
  target/evidence；不要递归清理共享 runtime/config/data 目录。

Linux x86_64 和 aarch64 都产生真实 KVM evidence 后，才可更新
`docs/linux-validation-todo.md`、Phase acceptance 和 implementation status。十 runtime
矩阵仍须另外运行 `scripts/phase1-runtime-matrix-smoke.sh`，Node 单 runtime 通过不代表
矩阵完成。

## 6. Phase 4 的受保护 Linux 流水线

Phase 1 KVM smoke 通过后，Phase 4 还需要三类相互独立的 Linux 原生门禁：

- `phase4-authenticated-differential.yml`：当前提交构建出的本地 boxd 与官方服务执行
  78 contracts / 82 public cases 的 authenticated differential；
- `phase4-load-recovery.yml`：在专用 KVM runner 上执行 1/4/16/64 Box 负载矩阵；
- `phase4-native-recovery.yml`：执行 lifecycle、daemon restart、SIGTERM 与 SQLite
  integrity，并对尚无安全 fault fixture 的场景明确输出 blocked。

这些 workflow 都使用受保护 environment、一次一用的 runner-owned 路径和 hash-bound
输入，不能只靠 repository secrets 与 hosted Ubuntu 直接运行。完整配置、secret/variable
清单和触发命令见 [authenticated differential 手册](github-actions-phase4-differential.md)
与 [native recovery 手册](github-actions-phase4-recovery.md)。仓库没有匹配 runner 或外部
资产时，保持 queued/blocked 是正确结果，不等于 Phase 4 通过。

## 7. 发布二进制复用真实 KVM 门禁

`.github/workflows/release-binaries.yml` 在 tag 发布前分别调用同一个
`scripts/phase1-linux-kvm-smoke.sh` 验证 Linux x86_64 与 aarch64 binary。它额外要求
runner 标签 `boxd-release`、protected `release` environment 和目标专属发布资产；只有
两个架构都完成真实 guest lifecycle/restart/egress 后，publish job 才会创建可下载的
GitHub prerelease。变量、签名和 tag 说明见
[GitHub Actions 原生发布手册](github-actions-release.md)。
