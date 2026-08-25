# 参与贡献

欢迎 issue、文档、测试、兼容 fixture、平台验证和实现贡献。boxd 的兼容与安全边界较强，提交代码前请先阅读：

- [开发蓝图](https://github.com/Payhon/boxd/blob/main/blueprint/boxd-development-blueprint.md)；
- [贡献指南](https://github.com/Payhon/boxd/blob/main/CONTRIBUTING.md)；
- [实现状态](https://github.com/Payhon/boxd/blob/main/docs/implementation-status.md)；
- [API 兼容基线](https://github.com/Payhon/boxd/blob/main/docs/api-compatibility.md)。

## 开始开发

```bash
git clone https://github.com/Payhon/boxd.git
cd boxd
git switch -c feat/your-change
cargo test --workspace
```

每个可验收切片至少运行：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
npm test --prefix compat/upstash-box-0.6.3
```

改动 Console 时再运行其 lint、typecheck、Vitest、build 和必要的 Playwright。改动文档站时：

```bash
npm ci --prefix docs
npm run check --prefix docs
```

## 兼容 API 贡献规则

1. 不凭印象设计 DTO；先更新固定 SDK fixture/manifest；
2. 新增路由时同步 OpenAPI、Node contract test 与 coverage；
3. 未实现语义必须 501，不能返回 mock success；
4. handler 只处理 DTO、auth、use case 与 response mapping；
5. secret、tenant/account 边界和失败路径必须有测试。
