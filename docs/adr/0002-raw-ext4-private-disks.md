# ADR-0002：raw ext4 私有盘与一致性快照

- Status: Accepted

## Context

不可信 guest 的主要边界是 microVM。默认共享宿主目录会削弱该边界，也无法提供可验证的快照一致性。

## Decision

- runtime bundle 中的 base `rootfs.raw` 永远只读；每个 Box 从其克隆出独立的 **raw ext4** 可写磁盘。
- 用户写入仅进入 guest disk；默认不以 virtiofs 或宿主目录作为 rootfs/workspace。
- 快照顺序固定为：锁定 → guest quiesce/sync → 阻止新写 → APFS `clonefile()` 或 Linux reflink → checksum → 恢复。
- 不支持 CoW/reflink 时使用停机 sparse copy，并记录性能警告；`fromSnapshot` 只克隆，不修改源盘。
- 删除前 canonicalize 路径并验证目标属于数据根。

## Consequences

该方案保留 VM 与文件隔离，并让 snapshot 可按固定流程验证；代价是需要存储空间预检、guest quiesce、CoW 能力探测和 sparse-copy 回退。首版可以短暂停机以换取一致性。

## Verification

实施后执行：

```sh
rg -n 'raw|ext4|clonefile|reflink|sparse|quiesce|canonicalize' crates docs
boxd doctor --json
cargo test -p box-image -p box-runtime
```

当前尚未实现镜像、磁盘或快照代码；本 ADR 不是实现完成声明。

## Related

- [Architecture](../architecture.md)
- [Implementation status](../implementation-status.md)
