# boxd 本地编译、运行与人工沙盒测试教程

本文面向需要在本机直接启动 `boxd` 并人工验证沙盒功能的开发者。命令默认从
仓库根目录 `/Users/payhon/work2026/cms/boxd` 执行。

## 1. 当前功能是否可以正常使用

可以，但必须区分“源码/控制面可编译”和“真实 VM 沙盒可启动”。当前源码已经在
macOS Apple Silicon 上使用真实 HVF、libkrun v1.19.4、签名 Node/Browser runtime
bundle 和 pinned `@upstash/box@0.6.3` SDK 完成 Phase 3 验收，证明以下路径可工作：

- Box 异步创建、状态、暂停、恢复、删除、TTL 与 daemon restart reconciliation；
- command exec、JavaScript/TypeScript/Python code、环境变量、labels；
- 文件 read/write/list/upload、flat/direct-folder download；
- run/SSE/cancel/logs、custom harness、Git、snapshot、startup、skills、preview；
- Console 管理面与一次性 terminal ticket；
- exec/prompt schedule；
- Browser tabs、goto、content、screenshot、CDP、screencast、recording；
- quota、audit、Prometheus、OTLP；
- SQLite、PostgreSQL、MySQL repository/migration。

当前边界也必须保留：

- macOS 验收只证明 Apple Silicon HVF；Linux KVM 仍需在原生 KVM 主机执行门禁；
- 真实执行证据覆盖 Node/Browser bundle，不等于十种 runtime 均已发布和验收；
- nested tree download、managed agent options、完整 custom network policy、HTTPS
  `attach_headers` 等能力仍会明确返回 HTTP 501 `feature_not_supported`；
- 本地 ad-hoc 签名不是 Developer ID、Team ID、hardened runtime、notarization 或
  production release 证据。

因此，**只有 `boxd doctor --json` 的 `overall=true`、签名 runtime import 成功、
`/health/ready` 返回 200，并且 pinned SDK 在真实 guest 中执行成功后，才可以判断本机
沙盒功能正常**。

完整验收身份和边界见 [Phase 3 acceptance](../phase3-acceptance.md)。

## 2. 运行链路与必需资产

真实运行链路如下：

```text
@upstash/box SDK
        |
        v
boxd serve -> SQLite/PostgreSQL/MySQL + repository
        |
        v
当前 boxd __vmm-worker 子进程
        |
        v
内嵌 libkrun v1.19.4 + libkrunfw ABI 5
        |
        v
签名 runtime bundle -> Box 私有 20 GiB ext4 clone -> box-agent
```

`boxd` 可执行文件只内嵌 libkrun、firmware 和对应 license；语言 runtime、Linux
rootfs、`box-agent`、Chromium 等位于独立签名 bundle。缺少其中任一项时，控制面会
fail closed，不会启动伪 VM。

### macOS 人工测试前置条件

- macOS 14+、Apple Silicon，并且 `sysctl -n kern.hv_support` 输出 `1`；
- Rust 1.94.x、Cargo、Node 22.x；
- libkrun 固定 v1.19.4，以及匹配的 `libkrunfw.5.dylib`；
- 两个 dylib 的真实 license 文件；
- 签名 Node/aarch64 runtime bundle和对应 32-byte Ed25519 raw public key；
- `ffmpeg`（测试 Browser recording 时需要）；
- 默认一个 Box 需要 20 GiB private disk，并另外保留 10 GiB minimum free space；
- 端口 `7331` 未被占用。

先检查宿主机：

```sh
uname -s
uname -m
sw_vers -productVersion
sysctl -n kern.hv_support
rustc -Vv
node --version
ffmpeg -version | sed -n '1p'
df -h /tmp
```

期望平台为 `Darwin`、`arm64`，HVF 为 `1`。Console 构建和 pinned Node contract
要求 Node 22.x；不要用 Node 26 的结果替代门禁。

## 3. 构建可运行的 release `boxd`

### 3.1 不能只执行裸 `cargo build`

下面的命令只能生成适合单元测试、CLI help 和 config 检查的开发产物：

```sh
cargo build --release -p boxd
```

如果构建时没有提供六个 `BOXD_EMBEDDED_*` 变量，`serve` 会明确失败：

```text
this boxd build has no embedded libkrun/libkrunfw release assets; refusing to serve
```

### 3.2 准备并签名 libkrun 资产

先从固定 `v1.19.4`/commit
`728df8125077d0db44265f6e997c72b81b65c015` 构建或取得以下文件：

```sh
export LIBKRUN_ARTIFACT=/absolute/path/libkrun.1.19.4.dylib
export LIBKRUNFW_ARTIFACT=/absolute/path/libkrunfw.5.dylib
export LIBKRUN_LICENSE=/absolute/path/libkrun-LICENSE
export LIBKRUNFW_LICENSE=/absolute/path/libkrunfw-LICENSE
```

本地 ad-hoc 验收时，先签 dylib，再计算要嵌入的 hash：

```sh
codesign --force --sign - "$LIBKRUN_ARTIFACT"
codesign --force --sign - "$LIBKRUNFW_ARTIFACT"
codesign --verify --strict --verbose=2 "$LIBKRUN_ARTIFACT"
codesign --verify --strict --verbose=2 "$LIBKRUNFW_ARTIFACT"

export LIBKRUN_SHA256="$(shasum -a 256 "$LIBKRUN_ARTIFACT" | awk '{print $1}')"
export LIBKRUNFW_SHA256="$(shasum -a 256 "$LIBKRUNFW_ARTIFACT" | awk '{print $1}')"
```

必须在签名后计算 hash，否则 build-time hash 与 runtime 文件不一致。

### 3.3 将固定资产嵌入 `boxd`

```sh
BOXD_EMBEDDED_LIBKRUN_PATH="$LIBKRUN_ARTIFACT" \
BOXD_EMBEDDED_LIBKRUN_SHA256="$LIBKRUN_SHA256" \
BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH="$LIBKRUN_LICENSE" \
BOXD_EMBEDDED_LIBKRUNFW_PATH="$LIBKRUNFW_ARTIFACT" \
BOXD_EMBEDDED_LIBKRUNFW_SHA256="$LIBKRUNFW_SHA256" \
BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH="$LIBKRUNFW_LICENSE" \
  cargo build --locked --release -p boxd

file target/release/boxd
target/release/boxd --version
```

当前开发包版本会显示 `boxd 0.0.0`；它不是 production release version。

### 3.4 给 `boxd` 添加 HVF entitlement

创建仅用于本地测试的 entitlement 文件：

```sh
cat >/tmp/boxd-hvf.entitlements.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.hypervisor</key>
  <true/>
</dict>
</plist>
PLIST

codesign --force --sign - \
  --entitlements /tmp/boxd-hvf.entitlements.plist \
  target/release/boxd

codesign --verify --deep --strict --verbose=2 target/release/boxd
codesign -d --entitlements :- target/release/boxd
```

输出必须包含 `com.apple.security.hypervisor`。本地 ad-hoc 验收不要加入
`--options runtime`；否则 library validation 可能因 ad-hoc `boxd`、libkrun 和
firmware 没有相同 Team ID 而拒绝加载。正式发行应改用统一 Team ID 的完整签名流程，
不能沿用本段 ad-hoc 做法。

如果直接使用仓库里已有的 `target/release/boxd`，也必须重新执行 `codesign` 检查和
后面的 `doctor`；不要仅根据文件存在或文件大小判断它可运行。

## 4. 准备签名 runtime bundle

### 4.1 优先使用已审阅的 bundle

准备：

```sh
export BOXD_RUNTIME_BUNDLE=/absolute/path/box-runtime-node-aarch64-22.x.y.tar.zst
export BOXD_RUNTIME_PUBLIC_KEY_FILE=/absolute/path/<key-id>.public-key.base64
export BOXD_RUNTIME_KEY_ID=<key-id>
```

public-key 文件内容必须是 32-byte Ed25519 raw public key 的单行 base64，而不是 PEM。
bundle 内的 `manifest.json` 必须使用相同 `key_id`。`rootfs.raw` 的字节容量必须与
配置的 `resources.default_disk_gib` 完全一致；默认是 20 GiB。

### 4.2 没有 bundle 时自行构建

普通 Node 22/aarch64 bundle 的完整构建说明见
[Runtime artifact build](../runtime-artifact-build.md)。最小入口为：

```sh
scripts/runtime/build-node22-arm64-bundle.sh --help
```

该脚本要求 digest-pinned Node/Rust OCI image、外部 mode-0600 Ed25519 private key、
reviewed license、Docker、OpenSSL、Python、zstd 1.5.7 和已准备好的 Cargo registry
cache。它会生成：

```text
box-runtime-node-aarch64-<version>.tar.zst
box-runtime-node-aarch64-<version>.tar.zst.sha256
<key-id>.public-key.base64
```

这个基础脚本不自动替你选择 Browser 发行输入。要测试 Browser，bundle 的签名
manifest 必须包含 Browser feature，rootfs 内必须有经过审阅的 Chromium binary 和
license；可使用 `build-runtime-bundle.sh` 的
`BOXD_BROWSER_CHROMIUM_SOURCE`、`BOXD_BROWSER_CHROMIUM_VERSION` 和
`BOXD_BROWSER_LICENSE_FILE` 输入。只有 basic Node bundle 时，请先测试 exec/files，
不要把 Browser 创建失败误判为整个 sandbox 不可用。

## 5. 初始化独立测试实例

建议把人工测试数据放在仓库外，避免把 API key、数据库、私盘或 signing material
加入 Git：

```sh
umask 077
export BOXD_BIN=/Users/payhon/work2026/cms/boxd/target/release/boxd
export BOXD_RUN_DIR=/tmp/boxd-manual-test
export BOXD_CONFIG="$BOXD_RUN_DIR/boxd.toml"

test ! -e "$BOXD_RUN_DIR"
mkdir -p "$BOXD_RUN_DIR"

printf '请输入本地 admin 密码: ' >&2
read -r -s BOXD_ADMIN_PASSWORD
printf '\n' >&2
export BOXD_ADMIN_PASSWORD
export BOXD_MASTER_KEY="$(openssl rand -hex 32)"

"$BOXD_BIN" init --config "$BOXD_CONFIG"
```

`init` 会：

1. 原子创建 `boxd.toml` 和同目录 `data/`；
2. 创建 SQLite schema、admin 用户与一把 compatibility API key；
3. 在 stdout **只显示一次** `compat_api_key=...`。

立即把 API key 放入密码管理器或当前终端环境，不要写入配置、日志或 Git：

```sh
read -r -s UPSTASH_BOX_API_KEY
printf '\n' >&2
export UPSTASH_BOX_API_KEY
export UPSTASH_BOX_BASE_URL=http://127.0.0.1:7331
```

`BOXD_MASTER_KEY` 必须在后续每次 `serve` 时保持相同；丢失或更换会使已加密 secret
不可解密。`BOXD_ADMIN_PASSWORD` 只在初始化和人工登录时使用。

## 6. 配置 trust root 与功能开关

打开 `$BOXD_CONFIG`，将 `[runtime]` 中的 trust ring 改为实际 public key：

```toml
[runtime]
driver = "libkrun"
libkrun_version = "1.19.4"
bundle_registry = "https://your-real-registry.example/boxd/runtimes"
auto_pull = false
verify_signatures = true
trusted_signing_keys = { "<key-id>" = "<public-key.base64 的单行内容>" }
agent_vsock_port = 18080
boot_timeout_seconds = 30
shutdown_timeout_seconds = 10
```

离线人工测试保持 `auto_pull=false`，随后显式 `runtime import`。不要继续使用示例
registry，也不要关闭签名验证。

确认其余关键配置：

```toml
[storage]
minimum_free_gib = 10

[resources]
default_disk_gib = 20

[network]
default_policy = "restricted-default"
dns_servers = ["1.1.1.1"]
allow_private_cidrs = false

[features]
browser = true
schedules = true
custom_network_policy = false
attach_headers = false
```

没有 Browser bundle 时可临时设置 `browser=false`；不要把未实现项设为 true。配置的
20 GiB 必须与 bundle rootfs 的签名大小一致，并且创建第一个 Box 前至少要有约
`20 + minimum_free_gib` GiB 可用空间。

验证配置：

```sh
"$BOXD_BIN" config validate -c "$BOXD_CONFIG"
```

## 7. 导入 runtime 并执行 doctor

先导入签名 bundle：

```sh
"$BOXD_BIN" runtime import "$BOXD_RUNTIME_BUNDLE" -c "$BOXD_CONFIG"
```

成功输出类似：

```text
runtime=node version=22.x.y arch=aarch64 sha256=<rootfs-sha256> already_present=false
```

重复导入同一内容可以返回 `already_present=true`。任何 signature、descriptor、arch、
SemVer、libkrun version、容量或路径不匹配都必须失败。

然后运行真机检查：

```sh
"$BOXD_BIN" doctor --json -c "$BOXD_CONFIG" | tee "$BOXD_RUN_DIR/doctor.json"
jq -e '.overall == true' "$BOXD_RUN_DIR/doctor.json"
jq -r '.checks[] | [.name, .status, .required, .message] | @tsv' \
  "$BOXD_RUN_DIR/doctor.json"
```

必须看到 `overall=true`，macOS required checks 应覆盖：

- macOS 14+/arm64、HVF support、Hypervisor entitlement、code signature；
- embedded libkrun/firmware 存在、hash 和真实 BLK/NET/vsock capability；
- signed Node runtime bundle；
- data directory、free space、CoW、database migration。

SQLite single-active-instance 可以是 warning，但 required check 不能失败。

## 8. 启动 `boxd`

在保留正确 `BOXD_MASTER_KEY` 的终端启动：

```sh
"$BOXD_BIN" serve -c "$BOXD_CONFIG"
```

不要直接调用隐藏的 `__vmm-worker`；它只能由控制面以精确
`boxd __vmm-worker --spec-fd 0` 形式启动。

在第二个终端检查：

```sh
curl --fail --silent --show-error http://127.0.0.1:7331/health/live | jq
curl --fail --silent --show-error http://127.0.0.1:7331/health/ready | jq
curl --fail --silent --show-error http://127.0.0.1:7331/openapi.json \
  | jq '.info, (.paths | length)'
curl --fail --silent --show-error http://127.0.0.1:7331/metrics \
  | sed -n '1,30p'
```

只有 `/health/ready` 返回 HTTP 200 后才开始创建 Box。

Console 地址：

```sh
open http://127.0.0.1:7331/console/
```

使用用户名 `admin` 和初始化时输入的密码登录。Console 可以查看 Boxes、Runs、
Snapshots、Schedules、Audit、API Keys 和 capabilities；新 API key 的明文也只显示
一次。Console 使用 HttpOnly session + CSRF，不能用 `X-Box-Api-Key` 代替管理登录。

## 9. 使用 pinned SDK 验证真实沙盒

### 9.1 构建 hash-verified SDK entry

使用仓库固定 commit 的源码，而不是凭印象写 curl DTO：

```sh
cd /Users/payhon/work2026/cms/boxd/compat/upstash-box-0.6.3
npm ci --offline

export BOXD_SDK_BUILD_JSON=/tmp/boxd-manual-sdk-build.json
node scripts/build-pinned-sdk.mjs --json >"$BOXD_SDK_BUILD_JSON"
export BOXD_SDK_ENTRY="$(jq -r .entry "$BOXD_SDK_BUILD_JSON")"
```

### 9.2 最小 create/exec/files/pause/resume/delete

把下面内容保存为 `/tmp/boxd-manual-smoke.mjs`：

```js
#!/usr/bin/env node

const entry = process.argv[2];
if (!entry) throw new Error("usage: node boxd-manual-smoke.mjs <SDK_ENTRY>");
for (const name of ["UPSTASH_BOX_API_KEY", "UPSTASH_BOX_BASE_URL"]) {
  if (!process.env[name]) throw new Error(`${name} is required`);
}

const { Box } = await import(entry);
const browserEnabled = process.env.BOXD_MANUAL_BROWSER === "true";
let box;

try {
  const started = Date.now();
  box = await Box.create({
    runtime: "node",
    name: "manual-sandbox-check",
    timeout: 300_000,
    ...(browserEnabled ? { browser: true } : {}),
  });
  console.log("created", box.id, `${Date.now() - started}ms`);

  const command = await box.exec.command("printf manual-exec-ok");
  if (command.exitCode !== 0 || command.stdout !== "manual-exec-ok") {
    throw new Error(`exec failed: ${JSON.stringify(command)}`);
  }

  const code = await box.exec.code({
    lang: "ts",
    code: "const answer: number = 6 * 7; console.log(`ts-${answer}`);",
    timeout: 30_000,
  });
  if (code.exitCode !== 0 || code.stdout.trim() !== "ts-42") {
    throw new Error(`TypeScript failed: ${JSON.stringify(code)}`);
  }

  await box.files.write({ path: "manual.txt", content: "persistent-ok" });
  if ((await box.files.read("manual.txt")) !== "persistent-ok") {
    throw new Error("file read/write failed");
  }
  const files = await box.files.list();
  if (!files.some((file) => file.name === "manual.txt" && !file.is_dir)) {
    throw new Error("file list failed");
  }

  await box.pause();
  if ((await box.getStatus()).status !== "paused") throw new Error("pause failed");
  await box.resume();
  if ((await box.getStatus()).status !== "idle") throw new Error("resume failed");
  if ((await box.files.read("manual.txt")) !== "persistent-ok") {
    throw new Error("file did not persist across pause/resume");
  }

  if (browserEnabled) {
    const tab = await box.browser.tab.create("about:blank", {
      waitUntil: "load",
      timeout: 30_000,
    });
    const png = await tab.screenshot({ type: "png", fullPage: true });
    if (png[0] !== 0x89 || png[1] !== 0x50 || png[2] !== 0x4e || png[3] !== 0x47) {
      throw new Error("browser screenshot is not PNG");
    }
    console.log("browser", tab.id, `${png.length} PNG bytes`);
    await tab.close();
  }

  console.log("manual sandbox smoke: PASS");
} finally {
  if (box) await Box.delete({ boxIds: [box.id] }).catch(() => {});
}
```

在 repo 根目录或任意目录运行：

```sh
export UPSTASH_BOX_API_KEY
export UPSTASH_BOX_BASE_URL=http://127.0.0.1:7331

node /tmp/boxd-manual-smoke.mjs "$BOXD_SDK_ENTRY"
```

测试 Browser 时：

```sh
BOXD_MANUAL_BROWSER=true \
  node /tmp/boxd-manual-smoke.mjs "$BOXD_SDK_ENTRY"
```

期望最后输出 `manual sandbox smoke: PASS`。该脚本使用 `finally` 删除测试 Box。

### 9.3 Schedule 人工检查

在一个暂时保留的 Box 上执行：

```js
const schedule = await box.schedule.exec({
  cron: "* * * * *",
  command: [
    "/bin/sh",
    "-c",
    "date -u +%FT%TZ > /workspace/home/schedule-fired.txt",
  ],
});
console.log(schedule.id, schedule.status);
```

最多等待约 90 秒后读取：

```js
console.log(await box.files.read("schedule-fired.txt"));
console.log(await box.schedule.get(schedule.id));
await box.schedule.pause(schedule.id);
await box.schedule.resume(schedule.id);
await box.schedule.delete(schedule.id);
```

同时可在 Console 的 Schedules 和 Audit 页面确认 tenant-scoped 记录。

### 9.4 Browser 模型动作

基础 tab/content/screenshot/CDP 不要求外部 LLM。`extract/observe/act/run` 需要：

1. `[models.providers.*]` 配置真实 provider、base URL 和 `api_key_env` 名；
2. 创建 Box 时通过 encrypted Box env 提供对应 key；
3. 调用时传入 provider-prefixed model。

例如配置使用 `ANTHROPIC_API_KEY` 时，不要把 key 写入 TOML：

```js
const box = await Box.create({
  runtime: "node",
  browser: true,
  env: { ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY },
  timeout: 300_000,
});
```

完整 Browser/recording/OTLP 回归入口是 `scripts/phase3-browser-smoke.mjs`，它还要求
受控 model/OTLP fixture。普通人工测试不要在未准备 fixture 时直接把其失败解释为
Browser basic action 失败。

## 10. 人工验证 daemon restart

要验证真实持久化，不要让最小 smoke 的 `finally` 立即删除 Box。按以下顺序操作：

1. 创建一个 Box，写入 `/workspace/home/restart.txt`；
2. 记录 Box ID；
3. 在 `serve` 终端按一次 `Ctrl-C`，等待 boxd 完成 graceful shutdown；
4. 确认没有残留 worker：

   ```sh
   pgrep -fl '__vmm-worker' || true
   ```

5. 使用相同 `BOXD_MASTER_KEY`、`BOXD_CONFIG`、database 和 data dir 重新启动：

   ```sh
   "$BOXD_BIN" serve -c "$BOXD_CONFIG"
   ```

6. 等待 `/health/ready` 重新返回 200；
7. 用 `Box.get(<box-id>)` 或原 SDK recovery 流重新取得 Box，读取 `restart.txt`，再执行
   一条 command；
8. 最后调用 `Box.delete({ boxIds: [boxId] })`。

不要用 `kill -9` 代替正常 restart 验收；那属于 crash recovery 的另一项测试。正常
`Ctrl-C` 路径会先 quiesce guest、sync filesystem、停止 VMM 并等待 worker reap。

仓库已有完整自动化入口：

```sh
export BOXD_SMOKE_EXPECTED_DISK_BYTES="$((20 * 1024 * 1024 * 1024))"
node scripts/phase1-sdk-smoke.mjs lifecycle \
  "$BOXD_SDK_ENTRY" /tmp/boxd-lifecycle.json

# 完整停止并重启 boxd 后：
export BOXD_SMOKE_LIFECYCLE_EVIDENCE=/tmp/boxd-lifecycle.json
node scripts/phase1-sdk-smoke.mjs restart \
  "$BOXD_SDK_ENTRY" /tmp/boxd-restart.json
```

`lifecycle` 成功后会故意保留两个 Box 给 `restart` 做 reconciliation 与 bulk delete；
不要在两步之间手动清空 data dir。

## 11. 测试结束与清理

1. 先通过 SDK/Console 删除所有人工创建的 Box、schedule、snapshot 和 API key；
2. 在 `serve` 终端按 `Ctrl-C`，等待进程正常退出；
3. 检查无监听和 worker：

   ```sh
   lsof -nP -iTCP:7331 -sTCP:LISTEN || true
   pgrep -fl '__vmm-worker' || true
   ```

4. 校验并清理 pinned SDK 临时目录：

   ```sh
   SDK_DIR="$(jq -r .cleanup.dir "$BOXD_SDK_BUILD_JSON")"
   SDK_TOKEN="$(jq -r .cleanup.token "$BOXD_SDK_BUILD_JSON")"
   test "$SDK_DIR" = "$(jq -r .dir "$BOXD_SDK_BUILD_JSON")"
   test "$(printf %s "$SDK_DIR" | shasum -a 256 | awk '{print $1}')" = "$SDK_TOKEN"
   case "$SDK_DIR" in
     /tmp/boxd-pinned-sdk-*|/var/*/T/boxd-pinned-sdk-*) ;;
     *) echo "拒绝清理非预期 SDK 目录" >&2; exit 1 ;;
   esac
   find "$SDK_DIR" -depth -delete
   ```

5. 人工确认 `$BOXD_RUN_DIR` 正是本次独立测试目录后，将它移入废纸篓；其中包含
   SQLite、encrypted secrets、runtime image 和可能达到 20 GiB 的 Box 私盘；
6. 删除外部测试 signing private key。不要删除仍需发布或复验的 public key/bundle；
7. 不要清空仓库、`$HOME` 或共享 runtime 目录来代替精确清理。

## 12. 常见失败

| 现象 | 原因与处理 |
|---|---|
| `this boxd build has no embedded...` | 裸 build；按第 3 节设置完整六个 build-time 变量重新构建。 |
| `hvf_entitlement` fail | `boxd` 没有 Hypervisor entitlement；重新 ad-hoc 签名并检查 entitlements。 |
| `mapping process and mapped file have different Team IDs` | 本地 ad-hoc binary 错误启用了 hardened runtime/library validation；本地验收去掉 `--options runtime`，正式发行统一 Team ID。 |
| `no runtime.trusted_signing_keys are configured` | TOML 没有对应 raw Ed25519 public key。 |
| `runtime import failed` | 检查 key id/signature、arch、SemVer、descriptor hash、libkrun 1.19.4 和 rootfs 大小。 |
| `BundleNotFound` 或 readiness 503 | 没有安装当前架构的 signed Node bundle，或已安装内容完整性检查失败。 |
| 创建返回 422 `capacity_exceeded` | free space、vCPU、memory、Box count 或 tenant quota 不足；不要通过静默缩小 VM 绕过。 |
| `/health/live` 200、`/health/ready` 503 | 进程活着但 runtime/platform/reconciliation 未就绪；查看 doctor JSON 和 serve 日志。 |
| Browser create 失败 | 配置 `features.browser=false`，或 bundle 没有 Chromium/Browser manifest feature。 |
| Browser 模型动作失败 | provider base URL、model 名或 Box encrypted env 中的 API key 不匹配；basic tab/screenshot 与模型动作分开判断。 |
| nested download 返回 501 | 当前 pinned SDK 的已知诚实边界；flat/direct-folder download 才是已实现契约。 |
| `auth` 失败 | 使用 init 输出的 compatibility API key；Console admin session 与 `X-Box-Api-Key` 互不替代。 |
| 重启后 secret 解密失败 | `BOXD_MASTER_KEY` 与 init 时不同。 |
| SQLite 启动提示 single-active warning | 单进程本地模式的已知边界；不要同时启动第二个指向同一 SQLite/data dir 的 boxd。 |

## 13. 人工验收记录建议

人工测试至少记录以下信息，但不得记录 secret：

- `uname -a`、macOS version、`kern.hv_support`；
- `boxd` SHA-256、codesign 验证结果；
- libkrun/libkrunfw SHA-256；
- runtime bundle、rootfs SHA-256 和 runtime/arch/version；
- doctor JSON，确认所有 required checks pass；
- Box create elapsed、Box ID、exec/code/file/pause/resume/delete 结果；
- Browser/recording/schedule 是否实际执行；
- graceful shutdown、restart readiness、持久文件和 worker cleanup；
- 明确列出未执行的 Linux KVM、其他 runtime、production signing 等边界。

不要在记录中保存 `BOXD_MASTER_KEY`、admin password、compatibility API key、provider
credential、session cookie、CSRF token 或 runtime signing private key。
