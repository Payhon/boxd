# 配置参考

boxd 使用 TOML 配置。优先级为：内置默认值 `<` TOML `<` `BOXD__SECTION__KEY` 环境变量 `<` CLI override。

## 最小入口

```bash
cp config/boxd.example.toml boxd.toml
target/release/boxd config validate -c boxd.toml
target/release/boxd doctor --json -c boxd.toml
```

## 关键配置组

| 区域 | 用途 | 重要提示 |
| --- | --- | --- |
| `[server]` | listen、public URL、body limit | 本地默认只监听 `127.0.0.1:7331` |
| `[database]` | SQLite/PostgreSQL/MySQL URL | SQLite 仅允许单 control-plane 实例 |
| `[auth]` | 管理员、master key、API key header | 密码与 master key 只写环境变量名 |
| `[storage]` | runtime、Box、snapshot、recording 目录 | 保持在受控 data root 下 |
| `[runtime]` | libkrun、bundle registry、trust roots | 示例 registry 故意不可用，必须替换 |
| `[network]` | restricted default、DNS | 默认阻断私网、metadata 与控制面 |
| `[models.providers.*]` | Browser/Agent provider | credential 通过指定环境变量解析 |
| `[quotas]` | API key 与 tenant 资源限制 | 不要为本地便利关闭全部上限 |
| `[features]` | Browser、schedule、network policy | 未开启的 feature 不能假装可用 |

## Secret 处理

```bash
export BOXD_ADMIN_PASSWORD='...'
export BOXD_MASTER_KEY="$(openssl rand -hex 32)"
export OPENAI_API_KEY='...'
```

不要把 secret 放入：

- `boxd.toml`；
- shell history 或共享 `.env`；
- API 示例、issue、日志、SSE payload；
- snapshot metadata 或诊断包。

完整字段与注释见仓库的 [`config/boxd.example.toml`](https://github.com/Payhon/boxd/blob/main/config/boxd.example.toml)。
