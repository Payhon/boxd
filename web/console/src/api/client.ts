export const ADMIN_API_BASE = '/api/admin/v1';

export class AdminApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = 'AdminApiError';
  }
}

type ErrorEnvelope = { error?: string; message?: string };

export type AdminBox = {
  id: string;
  name?: string | null;
  status: string;
  runtime: string;
  size: string;
  labels: string[];
  created_at: number;
  updated_at: number;
};

export type AdminRun = {
  id: string;
  box_id: string;
  type: string;
  status: string;
  created_at: number;
  completed_at?: number;
};

export type AdminSnapshot = {
  id: string;
  name: string;
  box_id: string;
  size_bytes: number;
  status: string;
  created_at: number;
};

export type AdminSchedule = {
  id: string;
  box_id: string;
  type: 'exec' | 'prompt';
  cron: string;
  status: 'active' | 'paused';
  last_run_at?: number;
  last_run_status?: 'completed' | 'failed' | 'skipped';
  total_runs: number;
  total_failures: number;
  created_at: number;
};

export type AdminApiKey = {
  id: string;
  prefix: string;
  scopes: string[];
  expires_at?: number | null;
  last_used_at?: number | null;
  created_at: number;
};

export type AdminAuditLog = {
  id: string;
  actor: string;
  action: string;
  resource: string;
  request_id?: string | null;
  ip?: string | null;
  status_code: number;
  succeeded: boolean;
  created_at: number;
};

export type CreatedAdminApiKey = AdminApiKey & { api_key: string };
export type TerminalTicket = { ticket: string; expires_at: number; websocket_url: string };

async function apiError(response: Response): Promise<AdminApiError> {
  const body = (await response.json().catch(() => ({}))) as ErrorEnvelope;
  return new AdminApiError(body.message ?? `Admin API request failed (${response.status})`, response.status, body.error);
}

export class AdminApiClient {
  constructor(private readonly csrfToken: () => string | undefined = () => undefined) {}

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    const token = this.csrfToken();
    if (token) headers.set('X-CSRF-Token', token);
    if (!headers.has('Accept')) headers.set('Accept', 'application/json');
    const response = await fetch(`${ADMIN_API_BASE}${path}`, {
      ...init,
      headers,
      credentials: 'include',
    });
    if (!response.ok) throw await apiError(response);
    return response.json() as Promise<T>;
  }

  async login(username: string, password: string): Promise<{ expires_at: number }> {
    const response = await fetch(`${ADMIN_API_BASE}/auth/login`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) throw await apiError(response);
    const result = (await response.json()) as { csrf_token: string; expires_at: number };
    if (!result.csrf_token || !Number.isFinite(result.expires_at)) throw new AdminApiError('登录响应无效', 0, 'invalid_response');
    setCsrfToken(result.csrf_token);
    return { expires_at: result.expires_at };
  }

  async logout(): Promise<void> {
    await this.request<Record<string, never>>('/auth/logout', { method: 'POST' });
    setCsrfToken(undefined);
  }

  listBoxes(): Promise<AdminBox[]> {
    return this.request<AdminBox[]>('/boxes');
  }

  async listRuns(): Promise<AdminRun[]> {
    return (await this.request<{ runs: AdminRun[] }>('/runs')).runs;
  }

  async listSnapshots(): Promise<AdminSnapshot[]> {
    return (await this.request<{ snapshots: AdminSnapshot[] }>('/snapshots')).snapshots;
  }

  async listSchedules(): Promise<AdminSchedule[]> {
    return (await this.request<{ schedules: AdminSchedule[] }>('/schedules')).schedules;
  }

  async setSchedulePaused(boxId: string, scheduleId: string, paused: boolean): Promise<void> {
    const action = paused ? 'pause' : 'resume';
    await this.request<Record<string, never>>(
      `/schedules/${encodeURIComponent(boxId)}/${encodeURIComponent(scheduleId)}/${action}`,
      { method: 'POST' },
    );
  }

  async deleteSchedule(boxId: string, scheduleId: string): Promise<void> {
    await this.request<Record<string, never>>(
      `/schedules/${encodeURIComponent(boxId)}/${encodeURIComponent(scheduleId)}`,
      { method: 'DELETE' },
    );
  }

  async listApiKeys(): Promise<AdminApiKey[]> {
    return (await this.request<{ api_keys: AdminApiKey[] }>('/api-keys')).api_keys;
  }

  async listAuditLogs(limit = 100): Promise<AdminAuditLog[]> {
    const bounded = Math.max(1, Math.min(1000, Math.trunc(limit)));
    return (await this.request<{ audit_logs: AdminAuditLog[] }>(`/audit?limit=${bounded}`)).audit_logs;
  }

  createApiKey(scopes: string[], expiresAt?: number): Promise<CreatedAdminApiKey> {
    return this.request<CreatedAdminApiKey>('/api-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scopes, expires_at: expiresAt }),
    });
  }

  async revokeApiKey(id: string): Promise<void> {
    await this.request<Record<string, never>>(`/api-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  pauseBox(id: string): Promise<AdminBox> {
    return this.request<AdminBox>(`/boxes/${encodeURIComponent(id)}/pause`, { method: 'POST' });
  }

  resumeBox(id: string): Promise<AdminBox> {
    return this.request<AdminBox>(`/boxes/${encodeURIComponent(id)}/resume`, { method: 'POST' });
  }

  async deleteBox(id: string): Promise<void> {
    await this.request<Record<string, never>>(`/boxes/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  async cancelRun(id: string): Promise<void> {
    await this.request<Record<string, never>>(`/runs/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
  }

  async deleteSnapshot(id: string): Promise<void> {
    await this.request<Record<string, never>>(`/snapshots/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  issueTerminalTicket(id: string): Promise<TerminalTicket> {
    return this.request<TerminalTicket>(`/boxes/${encodeURIComponent(id)}/terminal-ticket`, { method: 'POST' });
  }
}

let inMemoryCsrfToken: string | undefined;
export function getCsrfToken(): string | undefined { return inMemoryCsrfToken; }
export function setCsrfToken(value: string | undefined): void { inMemoryCsrfToken = value; }
