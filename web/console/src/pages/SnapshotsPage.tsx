import { Button, Card, Space, Table, Tag, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { AdminApiClient, AdminApiError, AdminSnapshot, getCsrfToken } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { DestructiveBoxAction } from '../components/DestructiveBoxAction';

const client = new AdminApiClient(getCsrfToken);

export function SnapshotsPage() {
  const [snapshots, setSnapshots] = useState<AdminSnapshot[]>();
  const [error, setError] = useState<string>();
  const load = useCallback(async () => {
    setError(undefined);
    try { setSnapshots(await client.listSnapshots()); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '无法加载 Snapshots'); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const remove = async (id: string) => {
    setError(undefined);
    try { await client.deleteSnapshot(id); await load(); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '删除 Snapshot 失败'); }
  };
  return <main><Space align="center"><Typography.Title level={2}>Snapshots</Typography.Title><Button onClick={() => void load()}>刷新</Button></Space>
    {error ? <ErrorState message={error} /> : snapshots === undefined ? <LoadingState /> : snapshots.length === 0 ? <EmptyState description="当前租户暂无 Snapshot" /> : <Card><Table rowKey="id" dataSource={snapshots} pagination={{ pageSize: 20 }} columns={[
      { title: 'Snapshot ID', dataIndex: 'id', render: (value: string) => <Typography.Text code copyable>{value}</Typography.Text> },
      { title: '名称', dataIndex: 'name' },
      { title: 'Box ID', dataIndex: 'box_id', render: (value: string) => <Typography.Text code>{value}</Typography.Text> },
      { title: '状态', dataIndex: 'status', render: (value: string) => <Tag>{value}</Tag> },
      { title: '大小', dataIndex: 'size_bytes', render: formatBytes },
      { title: '创建时间', dataIndex: 'created_at', render: (value: number) => new Date(value * 1000).toLocaleString() },
      { title: '操作', render: (_: unknown, record: AdminSnapshot) => record.status !== 'deleted' ? <DestructiveBoxAction boxId={record.id} action="删除 Snapshot" onConfirm={() => remove(record.id)} /> : '—' },
    ]} /></Card>}
  </main>;
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MiB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}
