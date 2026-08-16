import { Button, Card, Space, Table, Tag, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { AdminApiClient, AdminApiError, AdminRun, getCsrfToken } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';

const client = new AdminApiClient(getCsrfToken);

export function RunsPage() {
  const [runs, setRuns] = useState<AdminRun[]>();
  const [error, setError] = useState<string>();
  const load = useCallback(async () => {
    setError(undefined);
    try { setRuns(await client.listRuns()); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '无法加载 Runs'); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const cancel = async (id: string) => {
    setError(undefined);
    try { await client.cancelRun(id); await load(); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '取消 Run 失败'); }
  };
  return <main><Space align="center"><Typography.Title level={2}>Runs</Typography.Title><Button onClick={() => void load()}>刷新</Button></Space>
    {error ? <ErrorState message={error} /> : runs === undefined ? <LoadingState /> : runs.length === 0 ? <EmptyState description="当前租户暂无 Run" /> : <Card><Table rowKey="id" dataSource={runs} pagination={{ pageSize: 20 }} columns={[
      { title: 'Run ID', dataIndex: 'id', render: (value: string) => <Typography.Text code copyable>{value}</Typography.Text> },
      { title: 'Box ID', dataIndex: 'box_id', render: (value: string) => <Typography.Text code>{value}</Typography.Text> },
      { title: '类型', dataIndex: 'type' },
      { title: '状态', dataIndex: 'status', render: (value: string) => <Tag>{value}</Tag> },
      { title: '创建时间', dataIndex: 'created_at', render: (value: number) => new Date(value).toLocaleString() },
      { title: '操作', render: (_: unknown, record: AdminRun) => record.status === 'running' ? <Button danger size="small" onClick={() => void cancel(record.id)}>Cancel</Button> : '—' },
    ]} /></Card>}
  </main>;
}
