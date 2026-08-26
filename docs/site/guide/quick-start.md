# 5 分钟开始

这一页从已经下载好的 `boxd` 二进制开始，完成初始化、签名 runtime 导入和服务就绪检查。没有二进制时先按 [下载预编译二进制](./download) 选择宿主平台；普通用户不需要安装 Rust。

## 1. 确认宿主虚拟化

macOS 14+、Apple Silicon：

```bash
uname -s
uname -m
sw_vers -productVersion
sysctl -n kern.hv_support
```

预期依次看到 `Darwin`、`arm64`、不低于 14 的版本和 `1`。

Ubuntu 24.04 x86_64/aarch64：

```bash
uname -s
uname -m
test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm
cat /sys/fs/cgroup/cgroup.controllers
```

需要原生或可靠透传的 KVM，并委派 `cpu`、`memory`、`pids` cgroup v2 controllers。普通 GitHub-hosted runner 和未开启 nested virtualization 的云主机不满足真实 guest 要求。

## 2. 确认二进制

```bash
boxd --version
boxd --help
```

下载归档中的 `build-manifest.json` 会绑定 release version、Git commit、目标平台，以及内嵌 libkrun/firmware SHA-256。公开产物当前是 compatibility-subset prerelease，不是 1.0 声明。

## 3. 准备签名 runtime

预编译二进制只包含控制面、Console、固定 libkrun v1.19.4 与 firmware ABI 5。真实运行仍需要与宿主架构匹配的签名 runtime bundle及其 32-byte Ed25519 raw public key：

```bash
export BOXD_RUNTIME_BUNDLE=/absolute/path/box-runtime-node-<arch>-22.x.y.tar.zst
export BOXD_RUNTIME_KEY_ID=<reviewed-key-id>
export BOXD_RUNTIME_PUBLIC_KEY=<single-line-base64-public-key>
```

语言 rootfs、`box-agent` 和可选 Chromium 体积较大，因此不会塞进控制面归档。runtime 缺失、签名错误或架构不匹配都会 fail closed。

## 4. 初始化实例

```bash
umask 077
export BOXD_RUN_DIR="$HOME/.local/share/boxd"
export BOXD_CONFIG="$BOXD_RUN_DIR/boxd.toml"
mkdir -p "$BOXD_RUN_DIR"

export BOXD_ADMIN_PASSWORD='replace-with-a-local-password'
export BOXD_MASTER_KEY="$(openssl rand -hex 32)"
boxd init --config "$BOXD_CONFIG"
```

`init` 会在标准输出中只显示一次 compatibility API key。立即保存到密码管理器，不要写进配置、日志或 Git。

编辑配置中的 `[runtime]`，保留 `verify_signatures=true`，并把 `trusted_signing_keys` 设置为实际 key id 与公钥。不要继续使用示例 registry，也不要关闭签名验证。

## 5. 导入并诊断

```bash
boxd config validate -c "$BOXD_CONFIG"
boxd runtime import "$BOXD_RUNTIME_BUNDLE" -c "$BOXD_CONFIG"
boxd doctor --json -c "$BOXD_CONFIG"
```

只有 `doctor` 输出 `overall: true` 才继续。macOS 会检查 HVF entitlement 和 code signature；Linux 会检查 `/dev/kvm`、cgroup v2 与 seccomp enforcement。

## 6. 启动服务

```bash
boxd serve -c "$BOXD_CONFIG"
```

另开终端验证：

```bash
curl --fail http://127.0.0.1:7331/health/live
curl --fail http://127.0.0.1:7331/health/ready
```

然后打开 `http://127.0.0.1:7331/console`，或按 [API 概览](../api/overview) 使用固定 `@upstash/box@0.6.3` SDK。

需要从固定上游资产自行构建、做发行审计或开发贡献时，进入 [从源码构建](./source-build)。
