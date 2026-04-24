import { useState, useCallback, useRef } from 'react';
import type { ConfirmDialogProps } from '../components/shared/ConfirmDialog';

interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'default' | 'danger' | 'warning';
}

type DialogProps = Omit<ConfirmDialogProps, 'onConfirm' | 'onCancel'> & {
  onConfirm: () => void;
  onCancel: () => void;
};

export function useConfirmDialog() {
  const [dialogState, setDialogState] = useState<ConfirmOptions & { open: boolean }>({
    open: false,
    title: '',
    message: '',
  });

  const resolveRef = useRef<((value: boolean) => void) | null>(null);

  const confirm = useCallback((options: ConfirmOptions): Promise<boolean> => {
    return new Promise((resolve) => {
      resolveRef.current = resolve;
      setDialogState({ ...options, open: true });
    });
  }, []);

  const handleConfirm = useCallback(() => {
    setDialogState((prev) => ({ ...prev, open: false }));
    resolveRef.current?.(true);
    resolveRef.current = null;
  }, []);

  const handleCancel = useCallback(() => {
    setDialogState((prev) => ({ ...prev, open: false }));
    resolveRef.current?.(false);
    resolveRef.current = null;
  }, []);

  const dialogProps: DialogProps = {
    open: dialogState.open,
    title: dialogState.title,
    message: dialogState.message,
    confirmLabel: dialogState.confirmLabel,
    cancelLabel: dialogState.cancelLabel,
    variant: dialogState.variant,
    onConfirm: handleConfirm,
    onCancel: handleCancel,
  };

  return { confirm, dialogProps };
}
