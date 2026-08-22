# Phase 4 原生 recovery 手册

文件：`.github/workflows/phase4-native-recovery.yml`。

这是一个只允许手动 `workflow_dispatch` 的受保护 workflow。它不是 hosted CI，也不把
fixture、Docker、`virtualization=none` 或排队状态写成通过。job 必须同时匹配：

```text
self-hosted + linux|macos + boxd-recovery + x64|ARM64
```

Linux runner 必须提供可读写的 `/dev/kvm` 和 cgroup v2 的 `cpu`、`memory`、`pids`
controller；macOS runner 必须是 Apple Silicon，并且 `kern.hv_support=1`。当前 runner
只接受 Linux KVM 与 macOS aarch64 HVF；Windows、macOS Intel 和没有原生虚拟化的主机
会被拒绝，不能降级成假通过。

## 受保护环境配置

在 GitHub `Settings -> Environments` 创建 `phase4-native-recovery`，配置必需的审批者、
分支/标签保护和专用 self-hosted runner。只在这个 environment 提供下面的 variables 和
secrets；不要放进 repository-wide 默认变量。

| 类型 | 名称 | 内容 |
| --- | --- | --- |
| variable | `BOXD_RECOVERY_CONFIG` | runner 上专用 `boxd.toml` 的绝对路径 |
| variable | `BOXD_RECOVERY_RUNTIME_BUNDLE` | 与 runner 架构匹配、已独立验签的 runtime bundle 路径 |
| variable | `BOXD_RECOVERY_RELEASE_ARTIFACT` | 当前发行候选的 release manifest/checksum 或其他 regular-file artifact 路径 |
| variable | `BOXD_RECOVERY_LIBKRUN_PATH` | libkrun v1.19.4 路径 |
| variable | `BOXD_RECOVERY_LIBKRUN_SHA256` | libkrun 文件的 64 位小写 SHA-256，必须与 runner 文件匹配 |
| variable | `BOXD_RECOVERY_LIBKRUN_LICENSE_PATH` | libkrun license 路径 |
| variable | `BOXD_RECOVERY_LIBKRUNFW_PATH` | firmware ABI 5 路径 |
| variable | `BOXD_RECOVERY_LIBKRUNFW_SHA256` | firmware 文件的 64 位小写 SHA-256，必须与 runner 文件匹配 |
| variable | `BOXD_RECOVERY_LIBKRUNFW_LICENSE_PATH` | firmware license 路径 |
| secret | `BOXD_RECOVERY_MASTER_KEY` | 专用 recovery 数据库的 master key |
| secret | `BOXD_RECOVERY_ADMIN_PASSWORD` | 专用 recovery admin password |

所有 path 在 preflight 和 Python runner 中都必须是 single-link regular file，禁止
symlink；libkrun 与 firmware 还必须通过 protected SHA-256 变量的实际重算校验。
`BOXD_RECOVERY_RELEASE_ARTIFACT` 只作为被 hash 绑定的发行输入；本 workflow
不伪造签名、Developer ID、notarization 或 stapling，也不把存在一个文件误报成签名已验证。
签名/notarization gate 必须先在独立的 protected release workflow 完成。

## 实际执行和证据

runner 先校验 checkout 的 `HEAD == GITHUB_SHA`，执行 `npm ci`，再从当前 checkout 的
`compat/upstash-box-0.6.3` 调用 `build-pinned-sdk.mjs --json`。它强制 pinned source
commit `677ca0827a6f54bc328b4b3e97d32a7cc5ac1934`，把临时 entry 的 cleanup token 与
entry SHA 写入本次输入绑定，并在结束时只清理该 token 对应的目录。随后由同一个完整
`GITHUB_SHA` 构建 `boxd`，先复制 binary/runtime/release artifact 并计算 SHA，再让
`boxd init`、config validate、runtime import、doctor 和 daemon 全部执行已 hash-bind 的
binary/config/runtime 副本；SDK smoke 同样只执行已 hash-bind 的 SDK 副本。关键输入在
运行前后重复核对 hash，任何 TOCTOU 变化都会失败。构建 target、Cargo home、生成 config、
数据库、日志和 evidence 全部放在该次 `RUNNER_TEMP` 专用目录。它只回收自己启动的
daemon 及其 process group，不删除 runner 原有的 config、runtime、release artifact、
数据库或其他目录。

每次 run 先由当前 build 执行 `boxd init` 创建新的 disposable database/account，捕获
一次性 compatibility key 后立即将 init stdout 脱敏；key 只注入 pinned SDK 子进程，
不会进入 daemon 环境、日志或 evidence。最终 run config 从已 hash-bind 的 template
生成，并指向同一个 init data/SQLite 与动态 loopback 端口；整个 data 目录随本次
`RUNNER_TEMP` work 一起废弃。

可自动化且真实执行的场景包括：

- `graceful-stop`：pinned SDK lifecycle、真实 Box/worker 操作和 daemon 清理；
- `daemon-restart`：daemon 重启后读取之前持久化的 Box 状态、文件并执行命令；
- `sigterm`：真实 daemon 收到 SIGTERM 后退出；
- stopped daemon 后的 SQLite `PRAGMA integrity_check`、page count、私有 data tree 的
  路径逃逸/symlink/hardlink 检查。

以下场景目前明确记录为 `blocked`，不会被改写成 `pass`：worker SIGKILL、磁盘填满、
runtime pull 中断、SQLite backup/restore 和 migration journal 故障注入。原因是仓库尚无
隔离的 fault-injection 场景；对持久 runner 做任意 worker 注入、全盘压力或生产迁移
破坏不安全且不可复现。

上传目录只包含结构化 recovery input/case、`recovery-evidence.json` 和 hash summary，
不包含 config、secret、数据库原文、runtime bundle 或日志。`phase4-recovery-harness.py`
会重新打开 artifact 并校验 commit、platform、六个输入（实际执行的 boxd/runtime/config/
临时 pinned SDK/db/额外 release artifact）的 SHA-256 和每个 case artifact。case artifact
把实际执行的 `boxd` 与额外 release artifact 作为不同 input hash 交叉绑定；额外 artifact
不会被当作 daemon 的执行 binary。`phase4-evidence.py` 再校验闭合 evidence
schema。任何输入缺失、hash 不符、失败/blocked case 被宣称为 pass 或 evidence 缺失都会
使 job 失败。只要仍有 blocked 场景，workflow 以显式 blocked（exit 77）结束，绝不声明
Phase 4 recovery 已完成。

手动触发示例：

```sh
gh workflow run phase4-native-recovery.yml \
  --repo Payhon/boxd -f platform=linux -f architecture=x64 -f confirm_run=true
gh run watch --repo Payhon/boxd <run-id>
```

只有 evidence summary 为 `pass` 且所有 Phase 4 外部门禁另行满足时，才可在验收文档中
引用 native recovery 通过；当前默认结果包含 blocked 场景，因此不能单独宣称 Phase 4
或 1.0 完成。
