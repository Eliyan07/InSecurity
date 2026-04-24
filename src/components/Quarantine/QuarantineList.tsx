import React from 'react';
import { useTranslation } from 'react-i18next';
import type { QuarantineEntry } from '../../types/quarantine';
import { TrashIcon } from '../shared/Icons';
import { getThreatLevelKey, getVerdictKey, parseVerdict } from '../../utils/verdict';
import './QuarantineList.css';

const ShieldIcon = () => (
  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <polyline points="9,12 11,14 15,10" />
  </svg>
);

const RestoreIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
    <path d="M3 3v5h5" />
  </svg>
);

export interface QuarantineListProps {
  files: QuarantineEntry[];
  onRestore: (id: number, fileHash: string, verdict: string) => void;
  onDelete: (id: number) => void;
  loading?: boolean;
}

export const QuarantineList: React.FC<QuarantineListProps> = React.memo(({
  files,
  onRestore,
  onDelete,
  loading,
}) => {
  const { t, i18n } = useTranslation();

  if (loading) {
    return (
      <div className="quarantine-list">
        <div className="quarantine-header">
          <h2>{t('quarantine.title')}</h2>
        </div>
        <div className="loading-state">
          <div className="loading-spinner"></div>
          <p>{t('quarantine.loading')}</p>
        </div>
      </div>
    );
  }

  if (files.length === 0) {
    return (
      <div className="quarantine-list">
        <div className="quarantine-header">
          <h2>{t('quarantine.title')}</h2>
        </div>
        <div className="empty-state">
          <div className="empty-state-icon">
            <ShieldIcon />
          </div>
          <h3>{t('quarantine.allClear')}</h3>
          <p>{t('quarantine.noFiles')}</p>
          <span className="empty-state-hint">{t('quarantine.hintText')}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="quarantine-list">
      <div className="quarantine-header">
        <h2>{t('quarantine.title')}</h2>
        <span className="quarantine-count">{t('quarantine.fileCount', { count: files.length })}</span>
      </div>
      <table className="quarantine-table">
        <thead>
          <tr>
            <th>{t('quarantine.fileName')}</th>
            <th>{t('quarantine.verdict')}</th>
            <th>{t('quarantine.threatLevel')}</th>
            <th>{t('quarantine.date')}</th>
            <th>{t('quarantine.size')}</th>
            <th>{t('quarantine.actions')}</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => {
            const fileName = file.originalPath.split(/[\\/]/).pop() || file.originalPath;
            return (
            <tr key={file.id}>
              <td className="file-name" title={file.originalPath}>{fileName}</td>
              <td className="verdict">{t(getVerdictKey(parseVerdict(file.verdict)))}</td>
              <td className={`threat-level ${file.threatLevel.toLowerCase()}`}>
                {t(getThreatLevelKey(file.threatLevel))}
              </td>
              <td className="date">
                {new Date(file.quarantinedAt * 1000).toLocaleDateString(i18n.resolvedLanguage || i18n.language || undefined)}
              </td>
              <td className="size">{(file.fileSize / 1024).toFixed(2)} KB</td>
              <td className="actions">
                <button
                  className="btn-restore"
                  onClick={() => onRestore(file.id, file.fileHash, file.verdict)}
                  title={t('quarantine.restoreTitle')}
                >
                  <RestoreIcon /> {t('quarantine.restore')}
                </button>
                <button
                  className="btn-delete"
                  onClick={() => onDelete(file.id)}
                  title={t('quarantine.deleteTitle')}
                >
                  <TrashIcon /> {t('quarantine.delete')}
                </button>
              </td>
            </tr>
          );
          })}
        </tbody>
      </table>
    </div>
  );
});

QuarantineList.displayName = 'QuarantineList';
