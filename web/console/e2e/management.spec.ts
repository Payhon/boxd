import { expect, test } from '@playwright/test';

const boxId = '01900000-0000-7000-8000-000000000001';
const keyId = '01900000-0000-7000-8000-000000000002';
const plaintext = 'boxd_e2e_once_only_secret';

test('admin login, tenant data, once-only key, and destructive confirmation', async ({ page }) => {
  let keyCreated = false;
  let boxDeleted = false;
  const observedHeaders: Headers[] = [];

  await page.route('**/api/admin/v1/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace('/api/admin/v1', '');
    if (path === '/auth/login' && request.method() === 'POST') {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'set-cookie': 'boxd_session=e2e; HttpOnly; SameSite=Strict; Path=/' },
        body: JSON.stringify({ csrf_token: 'csrf-e2e', expires_at: Date.now() + 60_000 }),
      });
    }
    observedHeaders.push(new Headers(request.headers()));
    if (path === '/boxes' && request.method() === 'GET') {
      return route.fulfill({ json: boxDeleted ? [] : [{ id: boxId, name: 'e2e', status: 'idle', runtime: 'node', size: 'small', labels: ['phase2'], created_at: 1_700_000_000, updated_at: 1_700_000_000 }] });
    }
    if (path === `/boxes/${boxId}` && request.method() === 'DELETE') {
      boxDeleted = true;
      return route.fulfill({ json: {} });
    }
    if (path === '/runs') return route.fulfill({ json: { runs: [] } });
    if (path === '/snapshots') return route.fulfill({ json: { snapshots: [] } });
    if (path === '/api-keys' && request.method() === 'GET') {
      return route.fulfill({ json: { api_keys: keyCreated ? [{ id: keyId, prefix: 'boxd_e2e', scopes: ['boxes_read'], expires_at: null, last_used_at: null, created_at: Date.now() }] : [] } });
    }
    if (path === '/api-keys' && request.method() === 'POST') {
      keyCreated = true;
      return route.fulfill({ json: { id: keyId, prefix: 'boxd_e2e', scopes: ['boxes_read'], expires_at: null, last_used_at: null, created_at: Date.now(), api_key: plaintext } });
    }
    return route.fulfill({ status: 404, json: { error: 'not_found', message: path } });
  });

  await page.goto('/console/login');
  await page.getByLabel('密码').fill('correct horse battery staple');
  await page.getByRole('button', { name: /登\s*录/ }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(page.getByText('1', { exact: true })).toBeVisible();

  await page.getByRole('link', { name: /API keys/ }).click();
  await expect(page.getByRole('heading', { name: 'API Keys' })).toBeVisible();
  await page.getByRole('button', { name: /创\s*建 API Key/ }).click();
  await expect(page.getByText(plaintext)).toBeVisible();
  await page.getByRole('button', { name: /我已保存/ }).click();
  await expect(page.getByText(plaintext)).toBeHidden();
  await expect(page.getByText('boxd_e2e')).toBeVisible();

  await page.getByRole('link', { name: 'Boxes' }).click();
  await expect(page.getByText(boxId)).toBeVisible();
  await page.getByRole('button', { name: /删\s*除 Box/ }).click();
  await expect(page.getByText(boxId).last()).toBeVisible();
  const confirm = page.getByLabel(`确认 ${boxId}`);
  await expect(page.getByRole('button', { name: /删\s*除 Box/, exact: true }).last()).toBeDisabled();
  await confirm.check();
  await page.getByRole('button', { name: /删\s*除 Box/, exact: true }).last().click();
  await expect(page.getByText('当前租户暂无 Box')).toBeVisible();

  expect(observedHeaders.length).toBeGreaterThan(0);
  for (const headers of observedHeaders) {
    expect(headers.get('x-csrf-token')).toBe('csrf-e2e');
    expect(headers.get('x-box-api-key')).toBeNull();
  }
});
