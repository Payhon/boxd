import { Button, Modal, Typography } from 'antd';
import { useState } from 'react';

export function DestructiveBoxAction({ boxId, action = '删除 Box', onConfirm }: { boxId: string; action?: string; onConfirm?: () => void | Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  return <><Button danger onClick={() => setOpen(true)}>{action}</Button><Modal title={`${action}确认`} open={open} okButtonProps={{ disabled: !confirmed, danger: true }} okText={action} onCancel={() => setOpen(false)} onOk={async () => { await onConfirm?.(); setOpen(false); setConfirmed(false); }}>
    <Typography.Paragraph>此操作不可撤销。请确认目标 Box ID：</Typography.Paragraph><Typography.Text code>{boxId}</Typography.Text>
    <label className="confirmation"><input aria-label={`确认 ${boxId}`} type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />我确认要对该 Box 执行此操作</label>
  </Modal></>;
}
