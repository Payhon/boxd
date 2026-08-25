# 从源码运行

本向导从“刚 clone 仓库”开始，最终目标是看到 `/health/ready` 返回 200，并通过公开 SDK 在真实 guest 中执行命令。

## 0. 获取源码并进入仓库

先确认当前机器是支持的 Apple Silicon Mac：

```bash
uname -s
uname -m
sw_vers -productVersion
sysctl -n kern.hv_support
```

预期依次为 `Darwin`、`arm64`、macOS 14 或更高版本，以及 `1`。然后安装基础工具并获取源码：

```bash
xcode-select --install
brew install rustup protobuf node@22 ffmpeg
rustup-init -y
source "$HOME/.cargo/env"

git clone https://github.com/Payhon/boxd.git
cd boxd
rustup show active-toolchain
node --version
```

仓库固定 Rust `1.94.0`，Console、示例和 compatibility contract 使用 Node 22.x。若 Xcode Command Line Tools 已安装，`xcode-select --install` 会提示已存在，可直接继续。

## 准备清单

- macOS 14+ / Apple Silicon / `kern.hv_support=1`；
- Rust 1.94.x、Node 22.x、Cargo、`ffmpeg`；
- 固定 libkrun v1.19.4 与匹配的 `libkrunfw.5.dylib`；
- 两个 dylib 的真实许可证文件；
- Node/aarch64 签名 runtime bundle；
- runtime bundle 对应的 32-byte Ed25519 raw public key；
- 至少 30 GiB 可用磁盘空间（默认 Box 私盘 20 GiB，另保留 10 GiB）。

:::info 为什么 runtime 不在 Git 仓库里？
语言运行时、Linux rootfs、agent 和可选 Chromium 会使产物达到数 GB。boxd 将控制面与 runtime bundle 分离，并要求 bundle 具备签名和 checksum。
:::

## 1. 准备并签名 libkrun 资产

```bash
export LIBKRUN_ARTIFACT=/absolute/path/libkrun.1.19.4.dylib
export LIBKRUNFW_ARTIFACT=/absolute/path/libkrunfw.5.dylib
export LIBKRUN_LICENSE=/absolute/path/libkrun-LICENSE
export LIBKRUNFW_LICENSE=/absolute/path/libkrunfw-LICENSE

codesign --force --sign - "$LIBKRUN_ARTIFACT"
codesign --force --sign - "$LIBKRUNFW_ARTIFACT"
codesign --verify --strict --verbose=2 "$LIBKRUN_ARTIFACT"
codesign --verify --strict --verbose=2 "$LIBKRUNFW_ARTIFACT"

export LIBKRUN_SHA256="$(shasum -a 256 "$LIBKRUN_ARTIFACT" | awk '{print $1}')"
export LIBKRUNFW_SHA256="$(shasum -a 256 "$LIBKRUNFW_ARTIFACT" | awk '{print $1}')"
```

必须先签名、再计算 SHA-256。

## 2. 构建带发行资产的 boxd

```bash
BOXD_EMBEDDED_LIBKRUN_PATH="$LIBKRUN_ARTIFACT" \
BOXD_EMBEDDED_LIBKRUN_SHA256="$LIBKRUN_SHA256" \
BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH="$LIBKRUN_LICENSE" \
BOXD_EMBEDDED_LIBKRUNFW_PATH="$LIBKRUNFW_ARTIFACT" \
BOXD_EMBEDDED_LIBKRUNFW_SHA256="$LIBKRUNFW_SHA256" \
BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH="$LIBKRUNFW_LICENSE" \
  cargo build --locked --release -p boxd
```

## 3. 添加本地 HVF entitlement

保存以下内容为 `/tmp/boxd-hvf.entitlements.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.hypervisor</key>
  <true/>
</dict>
</plist>
```

然后进行 ad-hoc 签名：

```bash
codesign --force --sign - \
  --entitlements /tmp/boxd-hvf.entitlements.plist \
  target/release/boxd
codesign --verify --deep --strict --verbose=2 target/release/boxd
codesign -d --entitlements :- target/release/boxd
```

本地验证不要增加 `--options runtime`。正式发行必须改用同一 Team ID、hardened runtime 与 notarization，不能把本段 ad-hoc 签名当成发行证据。

## 4. 初始化隔离实例

```bash
umask 077
export BOXD_RUN_DIR=/tmp/boxd-local
export BOXD_CONFIG="$BOXD_RUN_DIR/boxd.toml"
mkdir -p "$BOXD_RUN_DIR"

export BOXD_ADMIN_PASSWORD='replace-with-a-local-password'
export BOXD_MASTER_KEY="$(openssl rand -hex 32)"
target/release/boxd init --config "$BOXD_CONFIG"
```

`init` 会把 compatibility API key 打印一次。立即保存到密码管理器，不要提交到 Git，也不要写回配置文件。

## 5. 配置并导入 runtime

把真实 registry、trust root 和 data dir 写入刚生成的配置，然后验证：

```bash
target/release/boxd config validate -c "$BOXD_CONFIG"
target/release/boxd runtime import /absolute/path/box-runtime-node-aarch64-22.x.y.tar.zst \
  -c "$BOXD_CONFIG"
target/release/boxd doctor --json -c "$BOXD_CONFIG"
```

只有 `doctor` 输出 `overall: true` 才继续。

## 6. 启动服务

```bash
target/release/boxd serve -c "$BOXD_CONFIG"
```

另开一个终端：

```bash
curl --fail http://127.0.0.1:7331/health/live
curl --fail http://127.0.0.1:7331/health/ready
open http://127.0.0.1:7331/console
```

## 7. 用真实 SDK 验证

```bash
cd examples
npm ci
export UPSTASH_BOX_BASE_URL=http://127.0.0.1:7331
export UPSTASH_BOX_API_KEY='<init 输出的一次性 compatibility API key>'
npm run lifecycle
```

当 lifecycle 在 guest 内完成 command、code、file、label、pause/resume 并成功清理 Box，才证明“本机真实沙盒链路可用”。

更深的 runtime 构建、Browser bundle 与验收细节以仓库中的 [`docs/manual/boxd-local-sandbox-testing.md`](https://github.com/Payhon/boxd/blob/main/docs/manual/boxd-local-sandbox-testing.md) 为准。
