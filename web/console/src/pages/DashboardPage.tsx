import { Card, Col, Row, Statistic, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { AdminApiClient, AdminApiError, getCsrfToken } from '../api/client';
import { ErrorState, LoadingState } from '../components/AsyncState';

type Counts = { boxes: number; runs: number; snapshots: number; apiKeys: number };

export function DashboardPage() {
  const [counts, setCounts] = useState<Counts>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    const client = new AdminApiClient(getCsrfToken);
    void Promise.all([client.listBoxes(), client.listRuns(), client.listSnapshots(), client.listApiKeys()])
      .then(([boxes, runs, snapshots, apiKeys]) => setCounts({ boxes: boxes.length, runs: runs.length, snapshots: snapshots.length, apiKeys: apiKeys.length }))
      .catch((reason: unknown) => setError(reason instanceof AdminApiError ? reason.message : '无法加载 Dashboard'));
  }, []);
  return <main><Typography.Title level={2}>Dashboard</Typography.Title><Typography.Paragraph>以下数据来自当前管理会话所属 account/tenant，不使用 mock 指标。</Typography.Paragraph>
    {error ? <ErrorState message={error} /> : !counts ? <LoadingState /> : <Row gutter={[16, 16]}>{[
      ['Boxes', counts.boxes], ['Runs', counts.runs], ['Snapshots', counts.snapshots], ['API Keys', counts.apiKeys],
    ].map(([title, value]) => <Col xs={24} sm={12} xl={6} key={title}><Card><Statistic title={title} value={value} /></Card></Col>)}</Row>}
  </main>;
}
