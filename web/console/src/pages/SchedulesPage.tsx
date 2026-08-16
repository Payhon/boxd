import { Button, Card, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { AdminApiClient, AdminApiError, AdminSchedule, getCsrfToken } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';

const client = new AdminApiClient(getCsrfToken);

export function SchedulesPage() {
  const [schedules, setSchedules] = useState<AdminSchedule[]>();
  const [error, setError] = useState<string>();
  const load = useCallback(async () => {
    setError(undefined);
    try { setSchedules(await client.listSchedules()); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '无法加载 Schedules'); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const pause = async (schedule: AdminSchedule, paused: boolean) => {
    setError(undefined);
    try { await client.setSchedulePaused(schedule.box_id, schedule.id, paused); await load(); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '更新 Schedule 失败'); }
  };
  const remove = async (schedule: AdminSchedule) => {
    setError(undefined);
    try { await client.deleteSchedule(schedule.box_id, schedule.id); await load(); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '删除 Schedule 失败'); }
  };

  return <main><Space align="center"><Typography.Title level={2}>Schedules</Typography.Title><Button onClick={() => void load()}>刷新</Button></Space>
    {error ? <ErrorState message={error} /> : schedules === undefined ? <LoadingState /> : schedules.length === 0 ? <EmptyState description="当前租户暂无 Schedule" /> : <Card><Table rowKey="id" dataSource={schedules} pagination={{ pageSize: 20 }} columns={[
      { title: 'Schedule ID', dataIndex: 'id', render: (value: string) => <Typography.Text code copyable>{value}</Typography.Text> },
      { title: 'Box ID', dataIndex: 'box_id', render: (value: string) => <Typography.Text code>{value}</Typography.Text> },
      { title: '类型', dataIndex: 'type', render: (value: string) => <Tag>{value}</Tag> },
      { title: 'UTC cron', dataIndex: 'cron', render: (value: string) => <Typography.Text code>{value}</Typography.Text> },
      { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={value === 'active' ? 'green' : 'default'}>{value}</Tag> },
      { title: '最近结果', render: (_: unknown, record: AdminSchedule) => record.last_run_status ?? '—' },
      { title: '运行/失败', render: (_: unknown, record: AdminSchedule) => `${record.total_runs} / ${record.total_failures}` },
      { title: '操作', render: (_: unknown, record: AdminSchedule) => <Space><Button size="small" onClick={() => void pause(record, record.status === 'active')}>{record.status === 'active' ? 'Pause' : 'Resume'}</Button><Popconfirm title="删除这个 Schedule？" onConfirm={() => void remove(record)}><Button danger size="small">Delete</Button></Popconfirm></Space> },
    ]} /></Card>}
  </main>;
}
