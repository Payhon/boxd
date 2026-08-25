# 文件、Git 与快照

## Files

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/v2/box/{box_id}/files/read?path=&encoding=` | 读取 UTF-8 或 base64 |
| `POST` | `/v2/box/{box_id}/files/write` | 写入文件 |
| `GET` | `/v2/box/{box_id}/files/list?folder=` | 递归列出 |
| `POST` | `/v2/box/{box_id}/files/upload` | multipart upload |
| `GET` | `/v2/box/{box_id}/files/download?folder=` | 二进制下载 |

写文件：

```json
{
  "path": "notes/hello.txt",
  "content": "hello from boxd\n",
  "encoding": "utf8"
}
```

guest path 会经过 workspace 约束、规范化和 symlink 防护。当前支持 flat/direct-folder download；无法保持嵌套目录语义的 tree download 会明确返回 501。

## Git

| Method | Path | 说明 |
| --- | --- | --- |
| `POST` | `/git/clone`、`commit`、`push`、`create-pr` | 写操作 |
| `POST` | `/git/exec`、`checkout` | 受约束的 Git 操作 |
| `GET` | `/git/diff`、`status` | 读取状态 |
| `PUT` | `/git-config` | 设置 identity |

以上路径均位于 `/v2/box/{box_id}` 下。

`git/exec` 请求：

```json
{
  "args": ["status", "--short"],
  "folder": "/workspace/home/project"
}
```

GitHub token 使用 askpass 临时注入；remote URL 不保留 credential。clone/push/create-pr 对协议、redirect、URL 和输出做 fail-closed 校验。

## Snapshot

| Method | Path | 说明 |
| --- | --- | --- |
| `POST` | `/v2/box/{box_id}/snapshots` | 创建不可变 Snapshot |
| `GET` | `/v2/box/{box_id}/snapshots` | 列表 |
| `DELETE` | `/v2/box/{box_id}/snapshots/{snapshot_id}` | 删除一个 |
| `DELETE` | `/v2/box/snapshots` | selected/all 删除 |
| `POST` | `/v2/box/from-snapshot` | 克隆为新 Box |

```json
{ "name": "before-upgrade" }
```

创建时 boxd 会锁定 Box、quiesce/短暂停机、执行 CoW clone 或 sparse copy、计算 checksum，再恢复原 Box。恢复时绑定原 runtime bundle identity，不会静默切换基础镜像。
