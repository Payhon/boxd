import { afterEach, describe, expect, it, vi } from 'vitest';
import { ADMIN_API_BASE, AdminApiClient, getCsrfToken, setCsrfToken } from './client';

describe('AdminApiClient', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setCsrfToken(undefined);
  });
  it('uses the admin base, cookies, and CSRF without compatibility key', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await new AdminApiClient(() => 'csrf-value').request('/capabilities');
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${ADMIN_API_BASE}/capabilities`); expect(init.credentials).toBe('include');
    const headers = new Headers(init.headers); expect(headers.get('X-CSRF-Token')).toBe('csrf-value'); expect(headers.has('X-Box-Api-Key')).toBe(false);
  });
  it('keeps the login csrf token in memory and never sends a compatibility key', async () => {
    setCsrfToken(undefined);
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ csrf_token: 'csrf-memory', expires_at: 42 }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await new AdminApiClient(getCsrfToken).login('admin', 'password');
    expect(getCsrfToken()).toBe('csrf-memory');
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(init.headers).has('X-Box-Api-Key')).toBe(false);
    expect(JSON.parse(String(init.body))).toEqual({ username: 'admin', password: 'password' });
  });

  it('creates a tenant API key with JSON and exposes plaintext only from that response', async () => {
    const created = { id: 'key-id', prefix: 'boxd_compat_prefix', scopes: ['boxes_read'], created_at: 1, api_key: 'boxd_compat_prefix_secret' };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(created), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const result = await new AdminApiClient(() => 'csrf').createApiKey(['boxes_read'], 1234);
    expect(result.api_key).toBe('boxd_compat_prefix_secret');
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${ADMIN_API_BASE}/api-keys`);
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({ scopes: ['boxes_read'], expires_at: 1234 });
    const headers = new Headers(init.headers);
    expect(headers.get('X-CSRF-Token')).toBe('csrf');
    expect(headers.has('X-Box-Api-Key')).toBe(false);
  });

  it('uses admin session routes for schedule actions', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response(JSON.stringify({}), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = new AdminApiClient(() => 'csrf');
    await client.setSchedulePaused('box/id', 'schedule/id', true);
    await client.deleteSchedule('box/id', 'schedule/id');
    expect(fetchMock.mock.calls.map(([url, init]) => [url, (init as RequestInit).method])).toEqual([
      [`${ADMIN_API_BASE}/schedules/box%2Fid/schedule%2Fid/pause`, 'POST'],
      [`${ADMIN_API_BASE}/schedules/box%2Fid/schedule%2Fid`, 'DELETE'],
    ]);
    for (const [, init] of fetchMock.mock.calls as [string, RequestInit][]) {
      const headers = new Headers(init.headers);
      expect(headers.get('X-CSRF-Token')).toBe('csrf');
      expect(headers.has('X-Box-Api-Key')).toBe(false);
    }
  });

  it('lists tenant audit logs with a bounded limit and no compatibility key', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ audit_logs: [] }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await new AdminApiClient(() => 'csrf').listAuditLogs(5000);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${ADMIN_API_BASE}/audit?limit=1000`);
    const headers = new Headers(init.headers);
    expect(headers.get('X-CSRF-Token')).toBe('csrf');
    expect(headers.has('X-Box-Api-Key')).toBe(false);
  });
});
