import { App as AntApp, ConfigProvider, Layout, Menu, Spin, Typography } from 'antd';
import { DashboardOutlined, DatabaseOutlined, KeyOutlined, ScheduleOutlined, SettingOutlined } from '@ant-design/icons';
import { lazy, Suspense } from 'react';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { getCsrfToken } from './api/client';

const LoginPage = lazy(() => import('./pages/LoginPage').then(({ LoginPage: page }) => ({ default: page })));
const DashboardPage = lazy(() => import('./pages/DashboardPage').then(({ DashboardPage: page }) => ({ default: page })));
const BoxesPage = lazy(() => import('./pages/BoxesPage').then(({ BoxesPage: page }) => ({ default: page })));
const RunsPage = lazy(() => import('./pages/RunsPage').then(({ RunsPage: page }) => ({ default: page })));
const SnapshotsPage = lazy(() => import('./pages/SnapshotsPage').then(({ SnapshotsPage: page }) => ({ default: page })));
const SchedulesPage = lazy(() => import('./pages/SchedulesPage').then(({ SchedulesPage: page }) => ({ default: page })));
const AccessPage = lazy(() => import('./pages/AccessPage').then(({ AccessPage: page }) => ({ default: page })));
const SystemPage = lazy(() => import('./pages/SystemPage').then(({ SystemPage: page }) => ({ default: page })));
const pageFallback = <div className="route-loading"><Spin aria-label="正在加载页面" /></div>;

const items = [
  { key: '/', icon: <DashboardOutlined />, label: <Link to="/">Dashboard</Link> },
  { key: '/boxes', icon: <DatabaseOutlined />, label: <Link to="/boxes">Boxes</Link> },
  { key: '/runs', label: <Link to="/runs">Runs</Link> },
  { key: '/snapshots', label: <Link to="/snapshots">Snapshots / Runtimes</Link> },
  { key: '/schedules', icon: <ScheduleOutlined />, label: <Link to="/schedules">Schedules</Link> },
  { key: '/access', icon: <KeyOutlined />, label: <Link to="/access">API keys / Users / Quotas</Link> },
  { key: '/system', icon: <SettingOutlined />, label: <Link to="/system">System</Link> },
];

function ConsoleShell() {
  const location = useLocation();
  if (!getCsrfToken()) return <Navigate to="/login" replace />;
  return <Layout className="shell"><Layout.Sider breakpoint="lg" collapsedWidth="0"><div className="brand">boxd Console</div><nav aria-label="控制台导航"><Menu theme="dark" mode="inline" selectedKeys={[location.pathname]} items={items} /></nav></Layout.Sider><Layout><Layout.Header><Typography.Text>Phase 3 Console</Typography.Text></Layout.Header><Layout.Content className="content"><Suspense fallback={pageFallback}><Routes>
    <Route path="/" element={<DashboardPage />} /><Route path="/boxes" element={<BoxesPage />} /><Route path="/runs" element={<RunsPage />} /><Route path="/snapshots" element={<SnapshotsPage />} /><Route path="/schedules" element={<SchedulesPage />} /><Route path="/access" element={<AccessPage />} /><Route path="/system" element={<SystemPage />} /><Route path="*" element={<Navigate to="/" replace />} />
  </Routes></Suspense></Layout.Content></Layout></Layout>;
}

export function App() { return <ConfigProvider><AntApp><BrowserRouter basename="/console" future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Suspense fallback={pageFallback}><Routes><Route path="/login" element={<LoginPage />} /><Route path="/*" element={<ConsoleShell />} /></Routes></Suspense></BrowserRouter></AntApp></ConfigProvider>; }
