import React, { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { ErrorBanner } from '../shared/ErrorBanner';
import { safeInvoke } from '../../services/api';
import './AuditLog.css';

interface AuditEntry {
  timestamp: number;
  event_type: string;
  details: string;
  file_path: string | null;
}

interface AuditVerification {
  is_valid: boolean;
  total_entries: number;
  broken_links: number[];
  message: string;
}

const formatTimestamp = (timestamp: number, locale?: string): string => {
  const date = new Date(timestamp * 1000);
  return date.toLocaleString(locale);
};

const getEventIcon = (eventType: string): React.ReactNode => {
  const iconProps = {
    width: 18,
    height: 18,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };

  switch (eventType) {
    case 'THREAT_DETECTED':
    case 'THREAT_QUARANTINED':
    case 'THREAT_DELETED':
      return (
        <svg {...iconProps}>
          <path d="M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4z" />
          <path d="M12 9v4M12 17h.01" />
        </svg>
      );
    case 'EXCLUSION_ADDED':
    case 'EXCLUSION_REMOVED':
      return (
        <svg {...iconProps}>
          <path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2" />
          <rect x="8" y="2" width="8" height="4" rx="1" ry="1" />
        </svg>
      );
    case 'PROTECTION_ENABLED':
    case 'PROTECTION_DISABLED':
      return (
        <svg {...iconProps}>
          <path d="M18.36 6.64a9 9 0 11-12.73 0" />
          <line x1="12" y1="2" x2="12" y2="12" />
        </svg>
      );
    case 'INTEGRITY_CHECK_FAILED':
      return (
        <svg {...iconProps}>
          <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      );
    case 'APP_STARTED':
    case 'APP_STOPPED':
      return (
        <svg {...iconProps}>
          <polyline points="23 4 23 10 17 10" />
          <polyline points="1 20 1 14 7 14" />
          <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
        </svg>
      );
    case 'SCAN_STARTED':
    case 'SCAN_COMPLETED':
      return (
        <svg {...iconProps}>
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
      );
    case 'FILE_RESTORED':
      return (
        <svg {...iconProps}>
          <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
          <line x1="9" y1="14" x2="15" y2="14" />
        </svg>
      );
    case 'THREAT_IGNORED':
      return (
        <svg {...iconProps}>
          <circle cx="12" cy="12" r="10" />
          <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
        </svg>
      );
    case 'INTEGRITY_CHECK_PASSED':
      return (
        <svg {...iconProps}>
          <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
          <polyline points="22 4 12 14.01 9 11.01" />
        </svg>
      );
    case 'YARA_RULE_LOADED':
      return (
        <svg {...iconProps}>
          <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="12" y1="11" x2="12" y2="17" />
          <line x1="9" y1="14" x2="15" y2="14" />
        </svg>
      );
    case 'YARA_RULE_REJECTED':
      return (
        <svg {...iconProps}>
          <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="10" y1="12" x2="14" y2="16" />
          <line x1="14" y1="12" x2="10" y2="16" />
        </svg>
      );
    default:
      return (
        <svg {...iconProps}>
          <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="16" y1="13" x2="8" y2="13" />
          <line x1="16" y1="17" x2="8" y2="17" />
        </svg>
      );
  }
};

const getEventClass = (eventType: string): string => {
  if (eventType.includes('THREAT') || eventType.includes('FAILED')) {
    return 'event-warning';
  }
  if (eventType.includes('DISABLED')) {
    return 'event-danger';
  }
  if (eventType.includes('ENABLED') || eventType.includes('RESTORED')) {
    return 'event-success';
  }
  return 'event-info';
};

/** Map a backend detail string to a translated version using pattern matching. */
const translateDetail = (detail: string, t: (key: string, opts?: Record<string, string | number>) => string): string => {
  // Fixed strings (no variables)
  const fixed: Record<string, string> = {
    'Real-time protection enabled': 'audit.details.realtimeEnabled',
    'Real-time protection disabled': 'audit.details.realtimeDisabled',
    'Application started': 'audit.details.appStarted',
    'Ransomware protection enabled': 'audit.details.ransomwareEnabled',
    'Ransomware protection disabled': 'audit.details.ransomwareDisabled',
    'Ransomware auto-block enabled': 'audit.details.autoBlockEnabled',
    'Ransomware auto-block disabled': 'audit.details.autoBlockDisabled',
    'Autostart enabled': 'audit.details.autostartEnabled',
    'Autostart disabled': 'audit.details.autostartDisabled',
    'Network monitoring enabled': 'audit.details.networkMonitoringEnabled',
    'Network monitoring disabled': 'audit.details.networkMonitoringDisabled',
    'Auto-block malware network access enabled': 'audit.details.autoBlockNetworkEnabled',
    'Auto-block malware network access disabled': 'audit.details.autoBlockNetworkDisabled',
    'Protected folders updated': 'audit.details.protectedFoldersUpdated',
    'Missed-events scan started (protection was down)': 'audit.details.missedEventsScanStarted',
  };
  if (fixed[detail]) return t(fixed[detail]);

  // Parameterized patterns: [regex, translationKey, param-extractor]
  const patterns: [RegExp, string, (m: RegExpMatchArray) => Record<string, string>][] = [
    [/^File quarantined: (.+) \((\w+)\)$/, 'audit.details.fileQuarantined', m => ({ path: m[1], verdict: m[2] })],
    [/^Threat file permanently deleted: (.+)$/, 'audit.details.threatDeleted', m => ({ path: m[1] })],
    [/^Quarantined file restored: (.+)$/, 'audit.details.fileRestored', m => ({ path: m[1] })],
    [/^Threat ignored and whitelisted: (.+)$/, 'audit.details.threatIgnored', m => ({ hash: m[1] })],
    [/^User whitelist entry removed: (.+)$/, 'audit.details.whitelistRemoved', m => ({ hash: m[1] })],
    [/^All user whitelist entries cleared \((\d+) entries\)$/, 'audit.details.whitelistCleared', m => ({ count: m[1] })],
    [/^Scan worker count changed to (\d+)$/, 'audit.details.workerCountChanged', m => ({ count: m[1] })],
    [/^Added protected folder: (.+)$/, 'audit.details.addedProtectedFolder', m => ({ folder: m[1] })],
    [/^Removed protected folder: (.+)$/, 'audit.details.removedProtectedFolder', m => ({ folder: m[1] })],
    [/^Ransomware thresholds updated: (\d+) files in (\d+) seconds$/, 'audit.details.ransomwareThresholds', m => ({ threshold: m[1], window: m[2] })],
    [/^Ransomware alert dismissed for (.+) — adaptive threshold raised$/, 'audit.details.ransomwareAlertDismissed', m => ({ folder: m[1] })],
    [/^Manually killed suspected ransomware process: (.+) \(PID (\d+)\)$/, 'audit.details.manualKillProcess', m => ({ name: m[1], pid: m[2] })],
    [/^Auto-killed suspected ransomware process: (.+) \(PID (\d+)\)$/, 'audit.details.autoKillProcess', m => ({ name: m[1], pid: m[2] })],
    [/^CANARY TRIPWIRE: honeypot file tampered in (.+)$/, 'audit.details.canaryTripwire', m => ({ folder: m[1] })],
    [/^Ransomware behavior detected: (\d+) bulk modifications in (.+?)(?:\s*\(|$)/, 'audit.details.ransomwareBehavior', m => ({ count: m[1], folder: m[2] })],
    [/^Auto-blocked network access for '(.+)': (.+)$/, 'audit.details.autoBlockedNetwork', m => ({ path: m[1], name: m[2] })],
    [/^Network threat: (.+) \(PID (\d+)\) -> (.+):(\d+) \((.+)\)$/, 'audit.details.networkThreat', m => ({ proc: m[1], pid: m[2], addr: m[3], port: m[4], state: m[5] })],
    [/^YARA rule tampered: (.+)$/, 'audit.details.yaraRuleTampered', m => ({ path: m[1] })],
    [/^Loaded (\d+) rules? from (.+)$/, 'audit.details.yaraRulesLoaded', m => ({ count: m[1], path: m[2] })],
    [/^Unexpected shutdown detected\. Gap: (\d+)s$/, 'audit.details.unexpectedShutdown', m => ({ seconds: m[1] })],
    [/^Resource tampering detected: (.+)$/, 'audit.details.resourceTampering', m => ({ resources: m[1] })],
    [/^(\d+) resources verified in (\d+)ms$/, 'audit.details.resourcesVerified', m => ({ count: m[1], ms: m[2] })],
    [/^Exclusion tampered: (.+)$/, 'audit.details.exclusionTampered', m => ({ pattern: m[1] })],
    [/^Added (\w+) exclusion: (.+)$/, 'audit.details.addedExclusion', m => ({ type: m[1], pattern: m[2] })],
    [/^Removed (\w+) exclusion: (.+)$/, 'audit.details.removedExclusion', m => ({ type: m[1], pattern: m[2] })],
    [/^Firewall rule created: (.+)$/, 'audit.details.firewallRuleCreated', m => ({ name: m[1] })],
    [/^Firewall rule removed: (.+)$/, 'audit.details.firewallRuleRemoved', m => ({ name: m[1] })],
    [/^Missed-events scan completed\. Threats found: (\d+)$/, 'audit.details.missedEventsScanCompleted', m => ({ count: m[1] })],
    [/^Missed-events scan found threat: (.+) \((\w+)\)$/, 'audit.details.missedEventsThreat', m => ({ path: m[1], verdict: m[2] })],
  ];
  for (const [regex, key, extract] of patterns) {
    const match = detail.match(regex);
    if (match) return t(key, extract(match));
  }

  return detail; // fallback: show raw string
};

export const AuditLog: React.FC = () => {
  const { t, i18n } = useTranslation();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [verification, setVerification] = useState<AuditVerification | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [repairing, setRepairing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchEntries = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await safeInvoke<AuditEntry[]>('get_audit_entries', { limit: 100 });
      setEntries(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit log');
    } finally {
      setLoading(false);
    }
  }, []);

  const verifyLog = useCallback(async () => {
    try {
      setVerifying(true);
      const result = await safeInvoke<AuditVerification>('verify_audit_log');
      setVerification(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to verify audit log');
    } finally {
      setVerifying(false);
    }
  }, []);

  const repairLog = useCallback(async () => {
    try {
      setRepairing(true);
      const result = await safeInvoke<AuditVerification>('repair_audit_log');
      setVerification(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to repair audit log');
    } finally {
      setRepairing(false);
    }
  }, []);

  useEffect(() => {
    fetchEntries();
  }, [fetchEntries]);

  return (
    <div className="audit-log">
      <div className="audit-header">
        <h3>{t('audit.title')}</h3>
        <div className="audit-actions">
          <button
            className="btn-secondary"
            onClick={fetchEntries}
            disabled={loading}
          >
            {loading ? t('audit.loading') : t('audit.refresh')}
          </button>
          <button
            className="btn-secondary"
            onClick={verifyLog}
            disabled={verifying}
          >
            {verifying ? t('audit.verifying') : t('audit.verifyIntegrity')}
          </button>
          {verification && !verification.is_valid && (
            <button
              className="btn-secondary"
              onClick={repairLog}
              disabled={repairing}
            >
              {repairing ? t('audit.repairing') : t('audit.repairLog')}
            </button>
          )}
        </div>
      </div>

      <p className="audit-description">
        {t('audit.description')}
      </p>

      {verification && (
        <div className={`verification-result ${verification.is_valid ? 'valid' : 'invalid'}`}>
          <span className="verification-icon">
            {verification.is_valid ? (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
            ) : (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
            )}
          </span>
          <span className="verification-message">{verification.message}</span>
        </div>
      )}

      {error && (
        <ErrorBanner message={error} onDismiss={() => setError(null)} />
      )}

      {loading ? (
        <div className="audit-loading">{t('audit.loadingLog')}</div>
      ) : entries.length === 0 ? (
        <div className="audit-empty">
          <p>{t('audit.noEvents')}</p>
          <p className="help-text">{t('audit.eventsHint')}</p>
        </div>
      ) : (
        <div className="audit-entries">
          {entries.map((entry, index) => (
            <div key={index} className={`audit-entry ${getEventClass(entry.event_type)}`}>
              <div className="entry-icon">{getEventIcon(entry.event_type)}</div>
              <div className="entry-content">
                <div className="entry-header">
                  <span className="entry-type">{t(`audit.eventTypes.${entry.event_type}`, entry.event_type.replace(/_/g, ' '))}</span>
                  <span className="entry-time">{formatTimestamp(entry.timestamp, i18n.resolvedLanguage || i18n.language || undefined)}</span>
                </div>
                <div className="entry-details">{translateDetail(entry.details, t)}</div>
                {entry.file_path && (
                  <div className="entry-path" title={entry.file_path}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
                    </svg>
                    {' '}{entry.file_path}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
