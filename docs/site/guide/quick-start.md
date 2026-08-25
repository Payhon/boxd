# 5 分钟开始

这一页帮助你在全新 Mac 上拉取仓库、验证工具链并构建控制面。它不会把“编译成功”写成“真实 microVM 已运行”；真实沙盒还需要下一页列出的固定发行资产。

## 1. 确认机器

首发宿主要求 macOS 14+、Apple Silicon，并启用 Hypervisor.framework：

```bash
uname -s
uname -m
sw_vers -productVersion
sysctl -n kern.hv_support
```

预期依次看到 `Darwin`、`arm64`、不低于 14 的版本，以及 `1`。

## 2. 安装基础工具

```bash
xcode-select --install
brew install rustup protobuf node@22 ffmpeg
rustup-init -y
source "$HOME/.cargo/env"
```

仓库固定 Rust `1.94.0`；Console 与 SDK contract 门禁使用 Node 22.x。

## 3. 获取源码

```bash
git clone https://github.com/Payhon/boxd.git
cd boxd
rustup show active-toolchain
node --version
```

## 4. 先验证源码

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

验证固定 SDK contract：

```bash
npm ci --prefix compat/upstash-box-0.6.3
npm run check:manifest --prefix compat/upstash-box-0.6.3
npm run check:coverage --prefix compat/upstash-box-0.6.3
npm test --prefix compat/upstash-box-0.6.3
```

## 5. 构建开发产物

```bash
cargo build --locked --release -p boxd
target/release/boxd --version
```

:::warning 这一步还不能启动真实 Box
不带六个 `BOXD_EMBEDDED_*` 构建变量的产物只能用于 CLI/config/源码验证。`serve` 会因缺少内嵌 libkrun 与 firmware 资产而明确失败。这是安全门禁，不是安装脚本故障。
:::

接下来进入 [从源码运行](./source-build)，准备 libkrun、签名 runtime bundle、配置与 API key。
