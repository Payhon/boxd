import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TerminalPanel } from './TerminalPanel';

class FakeWebSocket {
  static readonly OPEN = 1;
  readonly url: string;
  readyState = FakeWebSocket.OPEN;
  binaryType = '';
  onopen?: () => void;
  onclose?: () => void;
  onerror?: () => void;
  onmessage?: (event: MessageEvent) => void;
  sent: string[] = [];
  closed = false;
  constructor(url: string | URL) { this.url = String(url); instances.push(this); }
  send(value: string) { this.sent.push(value); }
  close() { this.closed = true; this.onclose?.(); }
}

const instances: FakeWebSocket[] = [];

describe('TerminalPanel', () => {
  afterEach(() => { instances.length = 0; vi.unstubAllGlobals(); });

  it('uses a one-use ticket in memory and bridges terminal bytes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      ticket: 'a'.repeat(64),
      expires_at: Date.now() + 60_000,
      websocket_url: `/api/admin/v1/terminal?ticket=${'a'.repeat(64)}`,
    }), { status: 200 })));
    vi.stubGlobal('WebSocket', FakeWebSocket);
    const view = render(<TerminalPanel boxId="box-fixture" onClose={() => undefined} />);
    await waitFor(() => expect(instances).toHaveLength(1));
    expect(instances[0].url).toContain(`/api/admin/v1/terminal?ticket=${'a'.repeat(64)}`);
    act(() => instances[0].onopen?.());
    expect(await screen.findByText('已连接')).toBeInTheDocument();
    act(() => instances[0].onmessage?.({ data: 'guest output' } as MessageEvent));
    expect(await screen.findByText('guest output')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('终端输入'), { target: { value: 'pwd' } });
    fireEvent.click(screen.getByRole('button', { name: /发\s*送/ }));
    expect(instances[0].sent).toEqual(['pwd\n']);
    view.unmount();
    expect(instances[0].closed).toBe(true);
  });
});
