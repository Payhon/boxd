import { Alert, Button, Card, Form, Input, Typography } from 'antd';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AdminApiClient, AdminApiError, getCsrfToken } from '../api/client';

type LoginValues = { username: string; password: string };

export function LoginPage() {
  const navigate = useNavigate();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async (values: LoginValues) => {
    setPending(true); setError(undefined);
    try {
      await new AdminApiClient(getCsrfToken).login(values.username, values.password);
      navigate('/', { replace: true });
    } catch (reason) {
      setError(reason instanceof AdminApiError ? reason.message : '网络请求失败，请确认 boxd 正在运行');
    } finally { setPending(false); }
  };
  return <main className="login"><Card title="boxd 管理登录"><Typography.Paragraph>会话凭据仅存于 HttpOnly Cookie；CSRF token 只保留在当前页面内存，刷新后需重新登录。</Typography.Paragraph>{error && <Alert type="error" showIcon message="登录失败" description={error} />}<Form<LoginValues> layout="vertical" aria-label="登录表单" onFinish={submit} initialValues={{ username: 'admin' }}><Form.Item name="username" label="用户名" rules={[{ required: true }]}><Input autoComplete="username" /></Form.Item><Form.Item name="password" label="密码" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item><Button type="primary" htmlType="submit" loading={pending}>登录</Button></Form></Card></main>;
}
