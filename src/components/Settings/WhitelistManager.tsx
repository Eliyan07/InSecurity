import React, { useState, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { getUserWhitelist, removeFromUserWhitelist, clearUserWhitelist } from '../../services/api';
import type { UserWhitelistEntry } from '../../services/api';
import { useConfirmDialog } from '../../hooks/useConfirmDialog';
import { ConfirmDialog } from '../shared/ConfirmDialog';

export const WhitelistManager: React.FC = () => {
  const { t, i18n } = useTranslation();
  const [entries, setEntries] = useState<UserWhitelistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [removing, setRemoving] = useState<string | null>(null);
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { confirm: confirmDialog, dialogProps } = useConfirmDialog();

  const fetchEntries = useCallback(async () => {
    try {
      const data = await getUserWhitelist();
      setEntries(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('whitelistMgr.loading'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEntries();
  }, [fetchEntries]);

  // Auto-dismiss success message
  useEffect(() => {
    if (!successMsg) return;
    const timer = setTimeout(() => setSuccessMsg(null), 5000);
    return () => clearTimeout(timer);
  }, [successMsg]);

  const handleRemove = useCallback(async (fileHash: string, fileName?: string) => {
    const displayName = fileName || fileHash.substring(0, 12) + '...';
    if (!await confirmDialog({
      title: t('whitelistMgr.confirmRemoveTitle'),
      message: t('whitelistMgr.confirmRemoveMessage', { name: displayName }),
      confirmLabel: t('whitelistMgr.confirmRemoveLabel'),
      variant: 'warning',
    })) {
      return;
    }

    setRemoving(fileHash);
    setError(null);
    setSuccessMsg(null);
    try {
      await removeFromUserWhitelist(fileHash);
      setEntries(prev => prev.filter(e => e.fileHash !== fileHash));
      setSuccessMsg(t('whitelistMgr.removedSuccess', { name: displayName }));
    } catch (err) {
      setError(err instanceof Error ? err.message : t('whitelistMgr.confirmRemoveTitle'));
    } finally {
      setRemoving(null);
    }
  }, [confirmDialog]);

  const handleClearAll = useCallback(async () => {
    if (!await confirmDialog({
      title: t('whitelistMgr.confirmClearTitle'),
      message: t('whitelistMgr.confirmClearMessage', { count: entries.length }),
      confirmLabel: t('whitelistMgr.confirmClearLabel'),
      variant: 'danger',
    })) {
      return;
    }

    setClearing(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const removed = await clearUserWhitelist();
      setEntries([]);
      setSuccessMsg(t('whitelistMgr.clearedSuccess', { count: removed }));
    } catch (err) {
      setError(err instanceof Error ? err.message : t('whitelistMgr.confirmClearTitle'));
    } finally {
      setClearing(false);
    }
  }, [entries.length, confirmDialog]);

  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleString(i18n.resolvedLanguage || i18n.language || undefined);
  };

  const truncateHash = (hash: string) => {
    if (hash.length <= 16) return hash;
    return `${hash.substring(0, 12)}...${hash.substring(hash.length - 4)}`;
  };

  if (loading) {
    return (
      <div className="whitelist-manager">
        <div className="settings-group">
          <h3>{t('whitelistMgr.title')}</h3>
          <p className="setting-description">{t('whitelistMgr.loading')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="whitelist-manager">
      <div className="settings-group">
        <h3>{t('whitelistMgr.title')}</h3>
        <p className="setting-description">
          {t('whitelistMgr.description')}
        </p>

        {error && (
          <div className="action-message error">{error}</div>
        )}

        {successMsg && (
          <div className="action-message success">{successMsg}</div>
        )}

        {entries.length > 0 && (
          <div className="actions-bar-end">
            <button
              className="btn-danger"
              onClick={handleClearAll}
              disabled={clearing || removing !== null}
            >
              {clearing ? t('whitelistMgr.clearingAll') : t('whitelistMgr.clearAll', { count: entries.length })}
            </button>
          </div>
        )}

        {entries.length === 0 ? (
          <div className="whitelist-empty">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
            <p>{t('whitelistMgr.emptyText')}</p>
          </div>
        ) : (
          <div className="whitelist-table-wrapper">
            <table className="whitelist-table">
              <thead>
                <tr>
                  <th>{t('whitelistMgr.hash')}</th>
                  <th>{t('whitelistMgr.filePath')}</th>
                  <th>{t('whitelistMgr.originalVerdict')}</th>
                  <th>{t('whitelistMgr.dateAdded')}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {entries.map(entry => (
                  <tr key={entry.id}>
                    <td className="whitelist-hash" title={entry.fileHash}>
                      <code>{truncateHash(entry.fileHash)}</code>
                    </td>
                    <td className="whitelist-path" title={entry.filePath ?? undefined}>
                      {entry.filePath
                        ? entry.filePath.split(/[/\\]/).pop() || entry.filePath
                        : <span className="text-muted">{t('whitelistMgr.unknown')}</span>
                      }
                    </td>
                    <td>
                      {entry.originalVerdict ? (
                        <span className={`verdict-tag ${entry.originalVerdict.toLowerCase()}`}>
                          {entry.originalVerdict}
                        </span>
                      ) : (
                        <span className="text-muted">-</span>
                      )}
                    </td>
                    <td className="whitelist-date">{formatDate(entry.createdAt)}</td>
                    <td>
                      <button
                        className="btn-remove-whitelist"
                        onClick={() => handleRemove(entry.fileHash)}
                        disabled={removing === entry.fileHash}
                        title={t('whitelistMgr.removeTitle')}
                      >
                        {removing === entry.fileHash ? (
                          <span className="spinner small" />
                        ) : (
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                          </svg>
                        )}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <ConfirmDialog {...dialogProps} />
    </div>
  );
};
