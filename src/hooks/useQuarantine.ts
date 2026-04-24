import { useState, useCallback } from 'react';
import { safeInvoke } from '../services/api';
import i18n from '../i18n';
import type { QuarantineEntry } from '../types/quarantine';

type ConfirmFn = (options: {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'default' | 'danger' | 'warning';
}) => Promise<boolean>;

export function useQuarantine(confirmFn?: ConfirmFn) {
  const [quarantinedFiles, setQuarantinedFiles] = useState<QuarantineEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const listQuarantined = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const files = await safeInvoke<QuarantineEntry[]>('list_quarantined');
      setQuarantinedFiles(files);
    } catch (err) {
      setError(err instanceof Error ? err.message : i18n.t('quarantine.failedList'));
    } finally {
      setLoading(false);
    }
  }, []);

  const restoreFile = useCallback(async (id: number, _fileHash?: string, _verdict?: string) => {
    const confirmed = confirmFn
      ? await confirmFn({
          title: i18n.t('quarantine.confirmRestoreTitle'),
          message: i18n.t('quarantine.confirmRestoreMessage'),
          confirmLabel: i18n.t('quarantine.restore'),
          cancelLabel: i18n.t('common.cancel'),
          variant: 'warning',
        })
      : confirm(i18n.t('quarantine.confirmRestoreMessage'));
    if (!confirmed) return;
    try {
      await safeInvoke('restore_file', { id });

      setQuarantinedFiles(prev => prev.filter(f => f.id !== id));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : i18n.t('quarantine.failedRestore'));
      // Re-fetch to get consistent state on error
      await listQuarantined();
    }
  }, [listQuarantined, confirmFn]);

  const deleteFile = useCallback(async (id: number) => {
    const confirmed = confirmFn
      ? await confirmFn({
          title: i18n.t('quarantine.confirmDeleteTitle'),
          message: i18n.t('quarantine.confirmDeleteMessage'),
          confirmLabel: i18n.t('quarantine.delete'),
          cancelLabel: i18n.t('common.cancel'),
          variant: 'danger',
        })
      : confirm(i18n.t('quarantine.confirmDeleteMessage'));
    if (!confirmed) return;
    try {
      await safeInvoke('delete_quarantined_file', { id });

      // Optimistically remove from local state
      setQuarantinedFiles(prev => prev.filter(f => f.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : i18n.t('quarantine.failedDelete'));
      // Re-fetch to get consistent state on error
      await listQuarantined();
    }
  }, [listQuarantined, confirmFn]);

  return {
    quarantinedFiles,
    loading,
    error,
    listQuarantined,
    restoreFile,
    deleteFile,
  };
}
