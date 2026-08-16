import { Button, Card, Space, Table, Tag, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { AdminApiClient, AdminApiError, AdminAuditLog, getCsrfToken } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';

const client = new AdminApiClient(getCsrfToken);

export function SystemPage() {
  const [logs, setLogs] = useState<AdminAuditLog[]>();
  const [error, setError] = useState<string>();
  const load = useCallback(async () => {
    setError(undefined);
    try { setLogs(await client.listAuditLogs()); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '无法加载审计日志'); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  return <main><Space align="center"><Typography.Title level={2}>System / Audit</Typography.Title><Button onClick={() => void load()}>刷新</Button></Space>
    <Typography.Paragraph type="secondary">审计记录按当前 account 与 tenant 隔离；只记录结构化动作、目标和结果，不保存请求正文或 secret。</Typography.Paragraph>
    {error ? <ErrorState message={error} /> : logs === undefined ? <LoadingState /> : logs.length === 0 ? <EmptyState description="当前租户暂无审计记录" /> : <Card><Table rowKey="id" dataSource={logs} pagination={{ pageSize: 25 }} columns={[
      { title: '时间', dataIndex: 'created_at', render: (value: number) => new Date(value).toLocaleString() },
      { title: 'Actor', dataIndex: 'actor', render: (value: string) => <Tag>{value}</Tag> },
      { title: 'Action', dataIndex: 'action', render: (value: string) => <Typography.Text code>{value}</Typography.Text> },
      { title: 'Resource', dataIndex: 'resource', ellipsis: true },
      { title: '结果', render: (_: unknown, record: AdminAuditLog) => <Tag color={record.succeeded ? 'green' : 'red'}>{record.status_code}</Tag> },
      { title: 'Request ID', dataIndex: 'request_id', render: (value?: string) => value ? <Typography.Text code copyable>{value}</Typography.Text> : '—' },
      { title: 'IP', dataIndex: 'ip', render: (value?: string) => value ?? '—' },
    ]} /></Card>}
  </main>;
}
