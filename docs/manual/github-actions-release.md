# 使用 GitHub Actions 构建并发布原生二进制

`.github/workflows/release-binaries.yml` 为受保护的原生发布流水线。手动运行只上传保留 30 天的 Actions artifacts；推送 `v*` tag 时，三个原生目标全部成功后才创建 GitHub prerelease，并上传归档、`SHA256SUMS` 与 GitHub build provenance attestation。

当前产物是 compatibility-subset preview，不是 1.0 或 Phase 4 完成证据。发布归档内嵌 libkrun v1.19.4 和 firmware ABI 5，但不内嵌语言 runtime bundle。

## 1. Runner 拓扑

流水线要求三个隔离的 self-hosted runner：

| 目标 | 必须匹配的 labels | 额外要求 |
| --- | --- | --- |
| `darwin-arm64` | `self-hosted`, `macOS`, `ARM64`, `boxd-release` | macOS 14+、Developer ID 工具链、Apple Silicon |
| `linux-x86_64` | `self-hosted`, `linux`, `x64`, `boxd-kvm`, `boxd-release` | 原生可读写 `/dev/kvm`、cgroup v2 delegation |
| `linux-aarch64` | `self-hosted`, `linux`, `ARM64`, `boxd-kvm`, `boxd-release` | 原生可读写 `/dev/kvm`、cgroup v2 delegation |

三台 runner 都应专用于发布，不得复用生产数据库或生产密钥。为仓库创建名为 `release` 的 protected environment，限制可部署 branch/tag、要求人工 reviewer，并把以下 secrets/variables 放进该 environment。

## 2. 三平台固定资产

每个目标分别配置六个 environment variables；`<TARGET>` 取 `DARWIN_ARM64`、`LINUX_X86_64` 或 `LINUX_AARCH64`：

| Variable | 内容 |
| --- | --- |
| `BOXD_RELEASE_<TARGET>_LIBKRUN_PATH` | runner 本地固定 libkrun v1.19.4 regular file 绝对路径 |
| `BOXD_RELEASE_<TARGET>_LIBKRUN_SHA256` | 上述文件的 64 位小写 SHA-256 |
| `BOXD_RELEASE_<TARGET>_LIBKRUN_LICENSE_PATH` | runner 本地 libkrun license regular file |
| `BOXD_RELEASE_<TARGET>_LIBKRUNFW_PATH` | runner 本地 firmware ABI 5 regular file 绝对路径 |
| `BOXD_RELEASE_<TARGET>_LIBKRUNFW_SHA256` | 上述 firmware 的 64 位小写 SHA-256 |
| `BOXD_RELEASE_<TARGET>_LIBKRUNFW_LICENSE_PATH` | runner 本地 libkrunfw license regular file |

macOS 的两个 dylib 必须已使用与 `boxd` Developer ID 证书相同的 Team ID 签名。workflow 会分别执行 `codesign --verify` 并比较三个 TeamIdentifier；不同或为空都会停止发布。

## 3. Linux 真实 KVM 输入

两个 Linux 目标还需要目标专属 variables：

| Variable | 内容 |
| --- | --- |
| `BOXD_RELEASE_LINUX_X86_64_CONFIG` / `BOXD_RELEASE_LINUX_AARCH64_CONFIG` | runner 上的专用测试配置绝对路径 |
| `BOXD_RELEASE_LINUX_X86_64_RUNTIME_BUNDLE` / `BOXD_RELEASE_LINUX_AARCH64_RUNTIME_BUNDLE` | 与架构匹配的签名 Node runtime bundle |

再配置三项 environment secrets：

| Secret | 内容 |
| --- | --- |
| `BOXD_RELEASE_MASTER_KEY` | 专用测试实例的 32-byte master key |
| `BOXD_RELEASE_ADMIN_PASSWORD` | 专用 bootstrap admin password |
| `BOXD_RELEASE_API_KEY` | 与专用测试数据库匹配的 compatibility API key |

每个 Linux job 会调用 `scripts/phase1-linux-kvm-smoke.sh`，对当前 commit 构建出的同一个 binary 执行 runtime import、`doctor`、pinned SDK lifecycle、daemon restart 和 restricted-default egress；只有门禁成功后才打包。evidence 作为独立 Actions artifact 保留 30 天。

## 4. macOS Developer ID 与 notary secrets

| Secret | 内容 |
| --- | --- |
| `APPLE_CERTIFICATE_P12_BASE64` | Developer ID Application 证书与 private key 的 PKCS#12 文件 base64 |
| `APPLE_CERTIFICATE_PASSWORD` | PKCS#12 密码 |
| `APPLE_SIGNING_IDENTITY` | 完整 Developer ID Application identity |
| `APPLE_NOTARY_KEY_P8_BASE64` | App Store Connect API private key `.p8` 的 base64 |
| `APPLE_NOTARY_KEY_ID` | API key ID |
| `APPLE_NOTARY_ISSUER_ID` | API issuer UUID |

workflow 在临时 keychain 中导入证书，用 hardened runtime、timestamp 和 `release/macos/boxd.entitlements.plist` 签名二进制，然后将最终 ZIP 提交给 `xcrun notarytool --wait`。独立 CLI/ZIP 不能像 `.pkg` 或 `.dmg` 一样直接 staple；因此 blueprint 中的 production stapling gate 仍保持未完成，不能用 notarization 成功替代它。

## 5. 触发方式

先用手动运行验证三台 runner 和所有输入；它不会创建公开 release：

```bash
gh workflow run release-binaries.yml \
  --repo Payhon/boxd \
  -f version=0.0.0-preview.1
```

确认 artifacts、Linux evidence、macOS signing/notarization 后再创建 annotated tag：

```bash
git tag -a v0.0.0-preview.1 -m 'boxd 0.0.0 preview 1'
git push origin v0.0.0-preview.1
```

tag 名去掉开头 `v` 后必须是 SemVer。流水线把该值注入 `BOXD_BUILD_VERSION`，所以 `boxd --version`、OpenAPI version、归档名与 release tag 一致。任何一个目标 queued、blocked 或 failed 都不会执行 `publish` job。

完整归档结构由 `scripts/package-release.py` 确定性生成，并由 `tests/phase4/test_package_release.py` 验证。每个归档同时包含项目/内嵌资产许可证和绑定 boxd、Console、libkrun、libkrunfw 哈希的 SPDX 2.3 SBOM；它不虚构未随控制面归档发布的 runtime bundle。公开下载说明位于文档站的 [下载二进制](../site/guide/download.md) 页面。
