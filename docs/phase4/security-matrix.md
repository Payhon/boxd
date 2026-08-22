# Phase 4 fuzz/security hermetic slice

本切片只验证不会依赖真实 VM 的边界。它不修改现有 crate、根 workspace 或
pinned SDK contract。真实 HVF/KVM execution gate 明确记录为 `blocked`，不能由
hosted CI 的 parser/fuzz smoke 冒充通过。

## Fuzz targets

`fuzz/Cargo.toml` 是独立 cargo-fuzz workspace，避免改变根 `Cargo.toml`。五个 target
均把输入截断到固定上限，并且不输出输入内容：

生产 workspace 继续固定 Rust 1.94.0；cargo-fuzz/ASan 单独使用
`nightly-2026-08-15`，不得把 fuzz nightly 用作发布编译器。

| Target | 覆盖 | 边界 |
|---|---|---|
| `network_policy` | `DomainPattern`、`IpCidr`、`CustomNetworkPolicy`、DNS/TCP policy evaluation | 64 rules、253-byte domain、8 KiB input |
| `dns` | public DNS query/NODATA parser | 1232-byte DNS message |
| `api_json` | public `RuntimeBundleManifest` serde DTO (`deny_unknown_fields`) | 64 KiB JSON |
| `http_sse` | bounded `data:` framing + JSON decode | 64 KiB input、8 KiB frame |
| `path_archive` | archive path grammar equivalent to importer safety boundary | 128 entries、512-byte entry |

生产 HTTP/SSE transport、auth、archive filesystem staging 和真实 guest network 不在
hermetic target 中；后者需要后续 protected HVF/KVM workflow。`path_archive` 因 public
importer 接受 filesystem source，采用独立 bounded parser target，并明确不声称替代
`RuntimeBundleManager::import` 的集成验收。

## Security matrix

`tests/security/cases.json` 是机器可读矩阵，必须同时覆盖 tenant、SSRF、path、redaction、
resource 和 runtime 六类，并且每类包含正/负场景。`scripts/phase4-security-matrix.py`
会 fail-closed 拒绝未知类别、重复/非法 case id、缺正负样本、未知 expected 状态和
secret-like fixture；输出只有计数、类别、输入文件 hash 和平台 blocked 边界，不回显
case payload。

本地命令：

```sh
python3 scripts/phase4-security-matrix.py --cases tests/security/cases.json
python3 -m unittest discover -s tests/security -p 'test_*.py'
cargo fuzz build
for target in network_policy dns api_json http_sse path_archive; do
  cargo fuzz run "$target" -- -runs=64 -max_len=65536
done
```

若本机没有 `cargo fuzz`，只报告工具缺失；不能把 `cargo test` 或普通 hosted CI 结果
写成 fuzz 通过。workflow `phase4-fuzz-security.yml` 运行 hermetic smoke，并上传无
secret 的矩阵与平台边界 artifact。Developer ID/notarization、Linux `/dev/kvm` 和
macOS HVF 仍需受保护的外部 runner。
