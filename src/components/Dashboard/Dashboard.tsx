import React from 'react';
import { useTranslation } from 'react-i18next';
import type { DashboardStats } from '../../types/dashboard';
import type { ScanResult } from '../../types/scan';
import { RealtimeResults } from './RealtimeResults';
import './Dashboard.css';

export interface DashboardProps {
  stats: DashboardStats | null;
  loading: boolean;
  realtimeResults: ScanResult[];
  onThreatResolved?: (fileHash: string) => void;
  hasReputationKeys?: boolean;
}

export const Dashboard: React.FC<DashboardProps> = React.memo(({
  stats,
  loading,
  realtimeResults,
  onThreatResolved,
  hasReputationKeys,
}) => {
  const { t, i18n } = useTranslation();

  const formatLastScan = (timestamp: number | null) => {
    if (!timestamp) return t('dashboard.never');
    const date = new Date(timestamp * 1000);
    return date.toLocaleString(i18n.resolvedLanguage || i18n.language || undefined);
  };

  const isProtected = stats?.protectionStatus === 'active';
  const threatCount = (stats?.activeMalware ?? 0) + (stats?.activeSuspicious ?? 0);
  const hasThreats = threatCount > 0;
  const heroState = hasThreats ? 'threats' : !isProtected ? 'unprotected' : 'protected';

  if (loading && !stats) {
    return <div className="dashboard loading">{t('dashboard.loading')}</div>;
  }

  return (
    <div className="dashboard">
      {/* Protection Hero */}
      <div className={`protection-hero ${heroState}`}>
        <div className={`hero-shield ${heroState}`}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4z"
              fill={heroState === 'protected' ? 'var(--accent-primary)' : 'var(--danger)'} />
            {heroState === 'protected' ? (
              <path d="M9 12l2 2 4-4" stroke="#0b1120" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            ) : heroState === 'unprotected' ? (
              <path d="M12 9v4M12 17h.01" stroke="#fff" strokeWidth="2" strokeLinecap="round" />
            ) : (
              <path d="M10 10l4 4M14 10l-4 4" stroke="#fff" strokeWidth="2" strokeLinecap="round" />
            )}
          </svg>
        </div>

        <h2 className={`hero-title ${heroState}`}>
          {heroState === 'threats' ? t('dashboard.threatsDetected') : heroState === 'unprotected' ? t('dashboard.protectionDisabled') : t('dashboard.systemProtected')}
        </h2>
        <p className="hero-subtitle">
          {hasThreats
            ? t('dashboard.activeThreats', { count: threatCount })
            : isProtected
              ? t('dashboard.realtimeActive')
              : t('dashboard.notMonitored')}
        </p>

        <div className="hero-metrics">
          <div className={`hero-metric ${(stats?.activeMalware ?? 0) > 0 ? 'active danger' : ''}`}>
            <span className="hero-metric-dot danger" />
            <span className="hero-metric-value">{stats?.activeMalware ?? 0}</span>
            <span className="hero-metric-label">{t('dashboard.malware')}</span>
          </div>
          <div className={`hero-metric ${(stats?.activeSuspicious ?? 0) > 0 ? 'active warning' : ''}`}>
            <span className="hero-metric-dot warning" />
            <span className="hero-metric-value">{stats?.activeSuspicious ?? 0}</span>
            <span className="hero-metric-label">{t('dashboard.suspicious')}</span>
          </div>
          <div className={`hero-metric ${(stats?.quarantinedCount ?? 0) > 0 ? 'active info' : ''}`}>
            <span className="hero-metric-dot info" />
            <span className="hero-metric-value">{stats?.quarantinedCount ?? 0}</span>
            <span className="hero-metric-label">{t('dashboard.quarantined')}</span>
          </div>
        </div>

        <p className="hero-last-scan">
          {t('dashboard.lastScan', { time: formatLastScan(stats?.lastScanTime ?? null) })}
        </p>
      </div>

      {/* Real-time Scan Results */}
      <RealtimeResults results={realtimeResults} onThreatResolved={onThreatResolved} />

      {/* Cloud reputation notice — only shown when settings have loaded and no keys are set */}
      {hasReputationKeys === false && (
        <div className="reputation-notice">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <div className="reputation-notice-text">
            <span>{t('dashboard.noReputationKeys')}</span>
            <span className="reputation-notice-sub">{t('dashboard.noReputationKeysAction')}</span>
          </div>
        </div>
      )}
    </div>
  );
});

Dashboard.displayName = 'Dashboard';
