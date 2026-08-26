# 下载预编译二进制

boxd 的受保护发布流水线为三个原生目标生成可直接下载的预编译归档。你不需要在本机安装 Rust 或从源码编译：

| 宿主 | GitHub Release 资产 | 虚拟化要求 |
| --- | --- | --- |
| macOS 14+ / Apple Silicon | `boxd-<version>-darwin-arm64.zip` | `kern.hv_support=1` |
| Ubuntu 24.04 / x86_64 | `boxd-<version>-linux-x86_64.tar.gz` | 可读写的 `/dev/kvm` 与 cgroup v2 |
| Ubuntu 24.04 / aarch64 | `boxd-<version>-linux-aarch64.tar.gz` | 可读写的 `/dev/kvm` 与 cgroup v2 |

当前公开产物统一标记为 **prerelease**。它们面向已经理解当前兼容子集和 runtime 信任模型的测试用户，不代表 boxd 1.0、全量 `@upstash/box` 兼容或 Phase 4 全部门禁完成。

## 1. 从 GitHub 下载

先在 [GitHub Releases](https://github.com/Payhon/boxd/releases) 选择版本。以下示例把版本号替换为所选 tag（保留开头的 `v`）：

```bash
export BOXD_RELEASE=v0.0.0-preview.1
```

macOS Apple Silicon：

```bash
curl --fail --location --remote-name \
  "https://github.com/Payhon/boxd/releases/download/${BOXD_RELEASE}/boxd-${BOXD_RELEASE#v}-darwin-arm64.zip"
curl --fail --location --remote-name \
  "https://github.com/Payhon/boxd/releases/download/${BOXD_RELEASE}/SHA256SUMS"
shasum -a 256 -c SHA256SUMS --ignore-missing
unzip "boxd-${BOXD_RELEASE#v}-darwin-arm64.zip"
```

Linux 会自动选择支持的架构：

```bash
case "$(uname -m)" in
  x86_64) BOXD_TARGET=linux-x86_64 ;;
  aarch64|arm64) BOXD_TARGET=linux-aarch64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

curl --fail --location --remote-name \
  "https://github.com/Payhon/boxd/releases/download/${BOXD_RELEASE}/boxd-${BOXD_RELEASE#v}-${BOXD_TARGET}.tar.gz"
curl --fail --location --remote-name \
  "https://github.com/Payhon/boxd/releases/download/${BOXD_RELEASE}/SHA256SUMS"
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf "boxd-${BOXD_RELEASE#v}-${BOXD_TARGET}.tar.gz"
```

如果安装了 GitHub CLI，还可以验证 GitHub 生成的 build provenance：

```bash
gh attestation verify "boxd-${BOXD_RELEASE#v}-${BOXD_TARGET}.tar.gz" \
  --repo Payhon/boxd
```

## 2. 安装并检查

归档内包含 `bin/boxd`、示例配置、安装说明、服务定义、第三方许可证、`build-manifest.json` 和与 binary/内嵌资产哈希绑定的 SPDX 2.3 SBOM。将二进制复制到 PATH：

```bash
cd "boxd-${BOXD_RELEASE#v}-${BOXD_TARGET}"
sudo install -m 0755 bin/boxd /usr/local/bin/boxd
boxd --version
```

macOS 把上面的目录名改为 `boxd-${BOXD_RELEASE#v}-darwin-arm64`，并验证 Developer ID 签名与 notarization 结果：

```bash
codesign --verify --deep --strict --verbose=2 bin/boxd
spctl --assess --type execute --verbose=4 bin/boxd
sudo install -m 0755 bin/boxd /usr/local/bin/boxd
```

Linux 在初始化前还必须确认当前账户能访问 KVM：

```bash
test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm
test -f /sys/fs/cgroup/cgroup.controllers
```

GitHub-hosted Ubuntu 只能执行源码门禁，不能替代原生 KVM。发布流水线中的 Linux 归档只有在对应架构的 self-hosted runner 完成真实 guest lifecycle、restart 与 restricted-egress gate 后才会进入同一次 GitHub prerelease。

## 3. runtime bundle 仍需单独准备

预编译 `boxd` 已内嵌固定的 libkrun v1.19.4、firmware ABI 5 和许可证，但**不包含**数 GiB 的语言 rootfs、`box-agent` 或 Chromium。真实 Box 仍要求与宿主架构匹配、签名且受信任的 runtime bundle；缺少它时 `doctor` 或 import 会 fail closed，不会返回 mock 成功。

准备好 runtime bundle 与公钥后，继续 [5 分钟开始](./quick-start) 完成初始化、导入、`doctor` 和服务就绪检查。需要审计或自行重建发行输入时，再阅读 [从源码构建](./source-build)。
