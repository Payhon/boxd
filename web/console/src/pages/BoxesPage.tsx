import { Button, Card, Space, Table, Tag, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { AdminApiClient, AdminApiError, AdminBox, getCsrfToken } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { DestructiveBoxAction } from '../components/DestructiveBoxAction';
import { TerminalPlaceholder } from '../components/TerminalPlaceholder';
import { TerminalPanel } from '../components/TerminalPanel';

const client = new AdminApiClient(getCsrfToken);

export function BoxesPage() {
  const [boxes, setBoxes] = useState<AdminBox[]>();
  const [error, setError] = useState<string>();
  const [terminalBox, setTerminalBox] = useState<string>();
  const load = useCallback(async () => {
    setError(undefined);
    try {
      setBoxes(await client.listBoxes());
    } catch (reason) {
      setError(reason instanceof AdminApiError ? reason.message : '无法加载 Box');
    }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const mutate = async (operation: () => Promise<unknown>) => {
    setError(undefined);
    try { await operation(); await load(); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : 'Box 操作失败'); }
  };

  return <main><Space align="center"><Typography.Title level={2}>Boxes</Typography.Title><Button onClick={() => void load()}>刷新</Button></Space>
    {error ? <ErrorState message={error} /> : boxes === undefined ? <LoadingState /> : boxes.length === 0 ? <EmptyState description="当前租户暂无 Box" /> : <Card><Table rowKey="id" dataSource={boxes} pagination={{ pageSize: 20 }} columns={[
      { title: 'Box ID', dataIndex: 'id', render: (value: string) => <Typography.Text code copyable>{value}</Typography.Text> },
      { title: '名称', dataIndex: 'name', render: (value?: string) => value || '—' },
      { title: '状态', dataIndex: 'status', render: (value: string) => <Tag>{value}</Tag> },
      { title: 'Runtime', dataIndex: 'runtime' },
      { title: '规格', dataIndex: 'size' },
      { title: '标签', dataIndex: 'labels', render: (values: string[]) => values.map((value) => <Tag key={value}>{value}</Tag>) },
      { title: '创建时间', dataIndex: 'created_at', render: formatEpoch },
      { title: '操作', render: (_: unknown, record: AdminBox) => <Space wrap>
        {record.status === 'idle' && <Button size="small" onClick={() => void mutate(() => client.pauseBox(record.id))}>暂停</Button>}
        {record.status === 'paused' && <Button size="small" onClick={() => void mutate(() => client.resumeBox(record.id))}>恢复</Button>}
        {record.status === 'idle' && <Button size="small" onClick={() => setTerminalBox(record.id)}>Terminal</Button>}
        {record.status !== 'deleted' && <DestructiveBoxAction boxId={record.id} onConfirm={() => mutate(() => client.deleteBox(record.id))} />}
      </Space> },
    ]} /></Card>}
    <section className="terminal">{terminalBox ? <TerminalPanel boxId={terminalBox} onClose={() => setTerminalBox(undefined)} /> : <TerminalPlaceholder />}</section>
  </main>;
}

function formatEpoch(value: number): string {
  return new Date(value < 10_000_000_000 ? value * 1000 : value).toLocaleString();
}
