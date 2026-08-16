import { Alert, Button, Card, Input, Space, Typography } from 'antd';
import { FormEvent, useEffect, useRef, useState } from 'react';
import { AdminApiClient, AdminApiError, getCsrfToken } from '../api/client';

const MAX_RENDERED_OUTPUT = 1024 * 1024;

export function TerminalPanel({ boxId, onClose }: { boxId: string; onClose: () => void }) {
  const [status, setStatus] = useState('正在签发单用途票据…');
  const [output, setOutput] = useState('');
  const [input, setInput] = useState('');
  const socket = useRef<WebSocket>();

  useEffect(() => {
    let cancelled = false;
    const connect = async () => {
      try {
        const ticket = await new AdminApiClient(getCsrfToken).issueTerminalTicket(boxId);
        if (cancelled) return;
        const url = new URL(ticket.websocket_url, window.location.origin);
        url.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const websocket = new WebSocket(url);
        websocket.binaryType = 'arraybuffer';
        socket.current = websocket;
        websocket.onopen = () => setStatus('已连接');
        websocket.onclose = () => setStatus('连接已关闭');
        websocket.onerror = () => setStatus('连接失败；票据不可重放，请关闭后重新打开');
        websocket.onmessage = (event) => {
          const append = (text: string) => setOutput((current) => `${current}${text}`.slice(-MAX_RENDERED_OUTPUT));
          if (typeof event.data === 'string') append(event.data);
          else if (event.data instanceof ArrayBuffer) append(new TextDecoder().decode(event.data));
          else if (event.data instanceof Blob) void event.data.arrayBuffer().then((bytes) => append(new TextDecoder().decode(bytes)));
        };
      } catch (reason) {
        setStatus(reason instanceof AdminApiError ? reason.message : '无法签发终端票据');
      }
    };
    void connect();
    return () => { cancelled = true; socket.current?.close(); };
  }, [boxId]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (socket.current?.readyState === WebSocket.OPEN && input) {
      socket.current.send(`${input}\n`);
      setInput('');
    }
  };
  return <Card title={<Space>Terminal <Typography.Text code>{boxId}</Typography.Text></Space>} extra={<Button onClick={onClose}>关闭</Button>}>
    <Alert type="info" showIcon message={status} description="票据有效期 60 秒且只能使用一次。当前未授予剪贴板或文件上传权限。" />
    <pre className="terminal-output" aria-label="终端输出">{output}</pre>
    <form onSubmit={submit}><Space.Compact block><Input aria-label="终端输入" value={input} onChange={(event) => setInput(event.target.value)} autoComplete="off" /><Button type="primary" htmlType="submit">发送</Button></Space.Compact></form>
  </Card>;
}
