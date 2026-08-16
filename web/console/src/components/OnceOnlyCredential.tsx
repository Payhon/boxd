import { Alert, Button, Space, Typography } from 'antd';
import { useState } from 'react';

export function OnceOnlyCredential({ value }: { value: string }) {
  const [visible, setVisible] = useState(true);
  if (!visible) return <Alert type="info" showIcon message="凭据已隐藏" description="出于安全考虑，页面刷新或关闭后不会恢复明文。" />;
  return <Alert type="success" showIcon message="仅显示一次" description={<Space><Typography.Text code>{value}</Typography.Text><Button onClick={() => setVisible(false)}>我已保存，隐藏</Button></Space>} />;
}
