import { Alert, Button, Card, Checkbox, Form, InputNumber, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import { useCallback, useEffect, useState } from 'react';
import { AdminApiClient, AdminApiError, AdminApiKey, getCsrfToken } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { OnceOnlyCredential } from '../components/OnceOnlyCredential';

const client = new AdminApiClient(getCsrfToken);
const scopes = ['boxes_read', 'boxes_write', 'runs_write', 'secrets_read', 'admin'];
type CreateKeyValues = { scopes: string[]; expires_in_days?: number };

export function AccessPage() {
  const [keys, setKeys] = useState<AdminApiKey[]>();
  const [plaintext, setPlaintext] = useState<string>();
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(false);
  const load = useCallback(async () => {
    setError(undefined);
    try { setKeys(await client.listApiKeys()); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '无法加载 API Keys'); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const create = async (values: CreateKeyValues) => {
    setPending(true); setError(undefined); setPlaintext(undefined);
    try {
      const expiresAt = values.expires_in_days ? Date.now() + values.expires_in_days * 86_400_000 : undefined;
      const result = await client.createApiKey(values.scopes, expiresAt);
      setPlaintext(result.api_key);
      await load();
    } catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '创建 API Key 失败'); }
    finally { setPending(false); }
  };
  const revoke = async (id: string) => {
    setError(undefined);
    try { await client.revokeApiKey(id); await load(); }
    catch (reason) { setError(reason instanceof AdminApiError ? reason.message : '撤销 API Key 失败'); }
  };

  return <main><Typography.Title level={2}>API Keys</Typography.Title><Alert type="info" showIcon message="管理会话与兼容 API Key 隔离" description="Console 仅使用 HttpOnly 管理会话 Cookie。新兼容 API Key 的明文只在创建响应中显示一次，服务端仅保存 HMAC。" />
    <Card title="创建兼容 API Key" className="section-card"><Form<CreateKeyValues> layout="vertical" onFinish={create} initialValues={{ scopes: ['boxes_read'] }}>
      <Form.Item name="scopes" label="Scopes" rules={[{ required: true, message: '至少选择一个 scope' }]}><Checkbox.Group options={scopes} /></Form.Item>
      <Form.Item name="expires_in_days" label="有效天数（留空表示不过期）"><InputNumber min={1} max={3650} precision={0} /></Form.Item>
      <Button type="primary" htmlType="submit" loading={pending}>创建 API Key</Button>
    </Form>{plaintext && <div className="credential"><OnceOnlyCredential value={plaintext} /></div>}</Card>
    {error ? <ErrorState message={error} /> : keys === undefined ? <LoadingState /> : keys.length === 0 ? <EmptyState description="当前租户暂无 API Key" /> : <Card title="已签发 API Keys" className="section-card"><Table rowKey="id" dataSource={keys} pagination={false} columns={[
      { title: 'Prefix', dataIndex: 'prefix', render: (value: string) => <Typography.Text code>{value}</Typography.Text> },
      { title: 'Scopes', dataIndex: 'scopes', render: (values: string[]) => <Space wrap>{values.map((value) => <Tag key={value}>{value}</Tag>)}</Space> },
      { title: '创建时间', dataIndex: 'created_at', render: formatEpoch },
      { title: '到期时间', dataIndex: 'expires_at', render: (value?: number | null) => value ? formatEpoch(value) : '不过期' },
      { title: '最近使用', dataIndex: 'last_used_at', render: (value?: number | null) => value ? formatEpoch(value) : '从未' },
      { title: '操作', render: (_: unknown, record: AdminApiKey) => <Popconfirm title="撤销此 API Key？" description="撤销后无法恢复。" onConfirm={() => void revoke(record.id)} okButtonProps={{ danger: true }} okText="撤销"><Button danger size="small">撤销</Button></Popconfirm> },
    ]} /></Card>}
  </main>;
}

function formatEpoch(value: number): string {
  return new Date(value < 10_000_000_000 ? value * 1000 : value).toLocaleString();
}
