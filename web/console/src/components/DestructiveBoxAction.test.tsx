import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DestructiveBoxAction } from './DestructiveBoxAction';

describe('DestructiveBoxAction', () => {
  it('requires confirmation with the target box id', () => { const confirmed = vi.fn(); render(<DestructiveBoxAction boxId="box-123" onConfirm={confirmed} />); fireEvent.click(screen.getByRole('button', { name: '删除 Box' })); expect(screen.getByText('box-123')).toBeInTheDocument(); const dialog = screen.getByRole('dialog'); const confirm = within(dialog).getByRole('button', { name: '删除 Box' }); expect(confirm).toBeDisabled(); fireEvent.click(screen.getByLabelText('确认 box-123')); expect(confirm).toBeEnabled(); fireEvent.click(confirm); expect(confirmed).toHaveBeenCalledOnce(); });
});
