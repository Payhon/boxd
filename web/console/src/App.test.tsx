import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { setCsrfToken } from './api/client';

describe('console routes', () => {
  beforeEach(() => {
    setCsrfToken('fixture');
    window.history.replaceState({}, '', '/console/');
    vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      const body = url.endsWith('/runs') ? { runs: [] }
        : url.endsWith('/snapshots') ? { snapshots: [] }
          : url.endsWith('/schedules') ? { schedules: [] }
          : url.endsWith('/api-keys') ? { api_keys: [] }
            : [];
      return new Response(JSON.stringify(body), { status: 200 });
    }));
  });

  afterEach(() => {
    cleanup();
    setCsrfToken(undefined);
    vi.unstubAllGlobals();
  });

  it('renders dashboard at console base', async () => {
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
  });

  it('renders the real run management surface', async () => {
    window.history.replaceState({}, '', '/console/runs');
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Runs' })).toBeInTheDocument();
    expect(await screen.findByText('当前租户暂无 Run')).toBeInTheDocument();
  });

  it('renders the phase 3 schedule management surface', async () => {
    window.history.replaceState({}, '', '/console/schedules');
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Schedules' })).toBeInTheDocument();
    expect(await screen.findByText('当前租户暂无 Schedule')).toBeInTheDocument();
  });

  it('requires a memory csrf token before rendering management routes', async () => {
    setCsrfToken(undefined);
    render(<App />);
    expect(await screen.findByText('boxd 管理登录')).toBeInTheDocument();
  });

});
