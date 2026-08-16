import { Alert } from 'antd';
export function TerminalPlaceholder() { return <Alert type="info" showIcon message="Terminal ready" description="在 Idle Box 的操作栏选择 Terminal 后，服务端会签发 60 秒单用途 WebSocket 票据；票据不会写入本地存储。" />; }
