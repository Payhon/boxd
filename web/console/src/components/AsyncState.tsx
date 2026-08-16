import { Alert, Empty, Spin } from 'antd';

export function LoadingState() { return <div className="loading-state"><Spin aria-label="正在加载" /><span>正在加载…</span></div>; }
export function ErrorState({ message }: { message: string }) { return <Alert type="error" showIcon message="请求失败" description={message} />; }
export function EmptyState({ description = '暂无数据' }: { description?: string }) { return <Empty description={description} />; }
export function UnsupportedCapability({ feature }: { feature: string }) {
  return <Alert type="warning" showIcon message="Unavailable" description={`${feature} 将在后续 Phase 实现；当前 capability 为 false。`} />;
}
