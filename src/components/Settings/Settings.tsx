import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import i18n from '../../i18n';
import { ExclusionsManager } from '../Exclusions/ExclusionsManager';
import { AuditLog } from './AuditLog';
import { WhitelistManager } from './WhitelistManager';
import { FirewallRulesPanel, ActiveConnectionsViewer } from './NetworkSecurity';
import {
  safeInvoke,
  pickScanFolder,
  openExternalUrl,
  type AppUpdateCheckResult,
  type AppUpdateInfo,
} from '../../services/api';
import type { ApiKeySaveResult } from '../../hooks/useSettings';
import './Settings.css';

interface CacheStats {
  total_entries: number;
  expired_entries: number;
  capacity: number;
  hit_rate: number;
}

type SettingsTab = 'protection' | 'performance' | 'exclusions' | 'audit' | 'whitelist' | 'network';

export interface SettingsProps {
  autoQuarantine: boolean;
  realTimeProtection?: boolean;
  ransomwareProtection?: boolean;
  ransomwareAutoBlock?: boolean;
  ransomwareThreshold?: number;
  ransomwareWindowSeconds?: number;
  scanWorkerCount?: number;
  autostart?: boolean;
  onAutoQuarantineChange: (value: boolean) => void;
  onRealTimeChange?: (value: boolean) => void;
  onRansomwareProtectionChange?: (value: boolean) => void;
  onRansomwareAutoBlockChange?: (value: boolean) => void;
  onRansomwareThresholdsChange?: (threshold: number, windowSeconds: number) => void;
  onRedeployCanaryFiles?: () => void;
  onScanWorkerCountChange?: (value: number) => void;
  onAutostartChange?: (value: boolean) => void;
  networkMonitoringEnabled?: boolean;
  autoBlockMalwareNetwork?: boolean;
  onNetworkMonitoringChange?: (value: boolean) => void;
  onAutoBlockMalwareChange?: (value: boolean) => void;
  language?: string;
  onLanguageChange?: (lang: string) => void;
  virustotalKeySet?: boolean;
  malwarebazaarKeySet?: boolean;
  onVirusTotalApiKeyChange?: (key: string) => Promise<ApiKeySaveResult>;
  onMalwareBazaarApiKeyChange?: (key: string) => Promise<ApiKeySaveResult>;
  appVersion?: string;
  appUpdate?: AppUpdateInfo | null;
  appUpdateChecking?: boolean;
  onCheckAppUpdate?: (force?: boolean) => Promise<AppUpdateCheckResult | null>;
  onDismissAppUpdate?: () => Promise<void>;
  onDownloadAppUpdate?: () => Promise<void>;
}

export const Settings: React.FC<SettingsProps> = ({
  autoQuarantine,
  realTimeProtection,
  ransomwareProtection = true,
  ransomwareAutoBlock = true,
  ransomwareThreshold = 20,
  ransomwareWindowSeconds = 10,
  scanWorkerCount = 4,
  autostart = true,
  onAutoQuarantineChange,
  onRealTimeChange,
  onRansomwareProtectionChange,
  onRansomwareAutoBlockChange,
  onRansomwareThresholdsChange,
  onRedeployCanaryFiles,
  onScanWorkerCountChange,
  onAutostartChange,
  networkMonitoringEnabled = false,
  autoBlockMalwareNetwork = true,
  onNetworkMonitoringChange,
  onAutoBlockMalwareChange,
  language,
  onLanguageChange,
  virustotalKeySet = false,
  malwarebazaarKeySet = false,
  onVirusTotalApiKeyChange,
  onMalwareBazaarApiKeyChange,
  appVersion,
  appUpdate,
  appUpdateChecking = false,
  onCheckAppUpdate,
  onDismissAppUpdate,
  onDownloadAppUpdate,
}) => {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState<SettingsTab>('protection');
  const [cacheClearing, setCacheClearing] = useState(false);
  const [canaryRefreshing, setCanaryRefreshing] = useState(false);
  const [appUpdateMessage, setAppUpdateMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [appUpdateAction, setAppUpdateAction] = useState<'check' | 'download' | 'dismiss' | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [cacheStats, setCacheStats] = useState<CacheStats | null>(null);
  const [protectedFolders, setProtectedFolders] = useState<string[]>([]);
  const [newProtectedFolder, setNewProtectedFolder] = useState('');

  const messageTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const appUpdateMessageTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showMessage = useCallback((type: 'success' | 'error', text: string) => {
    setActionMessage({ type, text });
    if (messageTimerRef.current) clearTimeout(messageTimerRef.current);
    messageTimerRef.current = setTimeout(() => setActionMessage(null), 5000);
  }, []);

  const showAppUpdateMessage = useCallback((type: 'success' | 'error', text: string) => {
    setAppUpdateMessage({ type, text });
    if (appUpdateMessageTimerRef.current) clearTimeout(appUpdateMessageTimerRef.current);
    appUpdateMessageTimerRef.current = setTimeout(() => setAppUpdateMessage(null), 5000);
  }, []);

  // Clean up message timer on unmount
  useEffect(() => {
    return () => {
      if (messageTimerRef.current) clearTimeout(messageTimerRef.current);
      if (appUpdateMessageTimerRef.current) clearTimeout(appUpdateMessageTimerRef.current);
    };
  }, []);

  const fetchCacheStats = useCallback(async () => {
    try {
      const stats = await safeInvoke<CacheStats>('get_cache_stats');
      setCacheStats(stats);
    } catch (err) {
      console.error('Failed to fetch cache stats:', err);
      showMessage('error', t('settings.failedLoadCache'));
    }
  }, [showMessage, t]);

  const fetchProtectedFolders = useCallback(async () => {
    try {
      const folders = await safeInvoke<string[]>('get_protected_folders');
      setProtectedFolders(folders);
    } catch (err) {
      console.error('Failed to fetch protected folders:', err);
      showMessage('error', t('settings.failedLoadFolders'));
    }
  }, [showMessage, t]);

  useEffect(() => {
    fetchCacheStats();
    fetchProtectedFolders();
    const interval = setInterval(() => {
      if (activeTab === 'performance') {
        fetchCacheStats();
      }
    }, 10000);
    return () => clearInterval(interval);
  }, [activeTab, fetchCacheStats]);

  const handleClearCache = useCallback(async () => {
    setCacheClearing(true);
    try {
      const result = await safeInvoke<string>('clear_cache');
      showMessage('success', result);
      await fetchCacheStats();
    } catch (err) {
      showMessage('error', err instanceof Error ? err.message : 'Failed to clear cache');
    } finally {
      setCacheClearing(false);
    }
  }, [showMessage, fetchCacheStats]);



  const handleAddProtectedFolder = useCallback(async () => {
    if (!newProtectedFolder.trim()) return;
    try {
      await safeInvoke('add_protected_folder', { folder: newProtectedFolder.trim() });
      setNewProtectedFolder('');
      await fetchProtectedFolders();
      showMessage('success', t('settings.folderAdded'));
    } catch (err) {
      showMessage('error', err instanceof Error ? err.message : 'Failed to add folder');
    }
  }, [newProtectedFolder, fetchProtectedFolders, showMessage, t]);

  const handleBrowseProtectedFolder = useCallback(async () => {
    try {
      const path = await pickScanFolder();
      if (path) setNewProtectedFolder(path);
    } catch (e) {
      console.error('Failed to pick folder:', e);
    }
  }, []);

  const handleRemoveProtectedFolder = useCallback(async (folder: string) => {
    try {
      await safeInvoke('remove_protected_folder', { folder });
      await fetchProtectedFolders();
      showMessage('success', t('settings.folderRemoved'));
    } catch (err) {
      showMessage('error', err instanceof Error ? err.message : 'Failed to remove folder');
    }
  }, [fetchProtectedFolders, showMessage, t]);

  const handleCheckAppUpdate = useCallback(async () => {
    if (!onCheckAppUpdate) {
      return;
    }

    setAppUpdateAction('check');
    try {
      const result = await onCheckAppUpdate(true);
      if (!result) {
        showAppUpdateMessage('error', t('settings.updateCheckFailed'));
        return;
      }

      if (result.error) {
        showAppUpdateMessage('error', result.error);
        return;
      }

      if (!result.update) {
        showAppUpdateMessage(
          'success',
          t('settings.appUpToDate', { version: appVersion ?? 'unknown' }),
        );
      }
    } catch (err) {
      showAppUpdateMessage(
        'error',
        err instanceof Error ? err.message : t('settings.updateCheckFailed'),
      );
    } finally {
      setAppUpdateAction(null);
    }
  }, [appVersion, onCheckAppUpdate, showAppUpdateMessage, t]);

  const handleDownloadAppUpdate = useCallback(async () => {
    if (!onDownloadAppUpdate) {
      return;
    }

    setAppUpdateAction('download');
    try {
      await onDownloadAppUpdate();
    } catch (err) {
      showAppUpdateMessage(
        'error',
        err instanceof Error ? err.message : t('settings.updateCheckFailed'),
      );
    } finally {
      setAppUpdateAction(null);
    }
  }, [onDownloadAppUpdate, showAppUpdateMessage, t]);

  const handleDismissAppUpdate = useCallback(async () => {
    if (!onDismissAppUpdate) {
      return;
    }

    setAppUpdateAction('dismiss');
    try {
      await onDismissAppUpdate();
      showAppUpdateMessage('success', t('settings.updateDismissed'));
    } catch (err) {
      showAppUpdateMessage(
        'error',
        err instanceof Error ? err.message : t('settings.updateCheckFailed'),
      );
    } finally {
      setAppUpdateAction(null);
    }
  }, [onDismissAppUpdate, showAppUpdateMessage, t]);

  return (
    <div className="settings">
      <div className="settings-header">
        <h2>{t('settings.title')}</h2>
      </div>

      {/* Settings Sub-tabs */}
      <div className="settings-tabs">
        <button
          className={`settings-tab ${activeTab === 'protection' ? 'active' : ''}`}
          onClick={() => setActiveTab('protection')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          {t('settings.protection')}
        </button>
        <button
          className={`settings-tab ${activeTab === 'performance' ? 'active' : ''}`}
          onClick={() => setActiveTab('performance')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
          </svg>
          {t('settings.performance')}
        </button>
        <button
          className={`settings-tab ${activeTab === 'exclusions' ? 'active' : ''}`}
          onClick={() => setActiveTab('exclusions')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
            <line x1="9" y1="14" x2="15" y2="14" />
          </svg>
          {t('settings.exclusions')}
        </button>
        <button
          className={`settings-tab ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
            <polyline points="10 9 9 9 8 9" />
          </svg>
          {t('settings.auditLog')}
        </button>
        <button
          className={`settings-tab ${activeTab === 'whitelist' ? 'active' : ''}`}
          onClick={() => setActiveTab('whitelist')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          {t('settings.whitelist')}
        </button>
        <button
          className={`settings-tab ${activeTab === 'network' ? 'active' : ''}`}
          onClick={() => setActiveTab('network')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="2" />
            <path d="M16.24 7.76a6 6 0 010 8.49m-8.48-.01a6 6 0 010-8.49m11.31-2.82a10 10 0 010 14.14m-14.14 0a10 10 0 010-14.14" />
          </svg>
          {t('settings.network')}
        </button>
      </div>

      {activeTab === 'protection' && (
        <>
          <div className="settings-group">
            <h3>{t('settings.language')}</h3>
            <p className="setting-description">{t('settings.languageHelp')}</p>
            <select
              className="language-select"
              value={language || i18n.language}
              onChange={(e) => {
                const lang = e.target.value;
                i18n.changeLanguage(lang);
                onLanguageChange?.(lang);
              }}
            >
              <option value="en">{t('settings.languageEnglish')}</option>
              <option value="bg">{t('settings.languageBulgarian')}</option>
            </select>
            {false && (
            <select
              className="language-select"
              value={language || i18n.language}
              onChange={(e) => {
                const lang = e.target.value;
                i18n.changeLanguage(lang);
                onLanguageChange?.(lang);
              }}
            >
              <option value="en">{t('settings.languageEnglish')}</option>
              <option value="bg">Български</option>
            </select>
            )}
          </div>

          <div className="settings-group">
            <h3>{t('settings.appUpdates')}</h3>
            <p className="setting-description">{t('settings.appUpdatesHelp')}</p>

            {appUpdateMessage && (
              <div className={`action-message ${appUpdateMessage.type}`}>
                {appUpdateMessage.text}
              </div>
            )}

            <div className={`update-status-row ${appUpdate ? 'available' : ''}`}>
              <div className="update-info">
                {appUpdate ? (
                  <>
                    <p className="info-text">
                      {t('settings.updateAvailable', { version: appUpdate.latestVersion })}
                    </p>
                    <p className="help-text">
                      {t('settings.updateAvailableHelp', {
                        currentVersion: appVersion ?? appUpdate.currentVersion,
                      })}
                    </p>
                  </>
                ) : (
                  <>
                    <p className="info-text">
                      {t('settings.currentVersion', { version: appVersion ?? 'unknown' })}
                    </p>
                    <p className="help-text">
                      {appUpdateChecking
                        ? t('settings.checkingUpdates')
                        : t('settings.appUpToDate', { version: appVersion ?? 'unknown' })}
                    </p>
                  </>
                )}
              </div>

              <div className="update-actions">
                {appUpdate && (
                  <>
                    <button
                      className="btn-primary"
                      onClick={handleDownloadAppUpdate}
                      disabled={appUpdateAction === 'download'}
                    >
                      {appUpdateAction === 'download'
                        ? t('settings.openingDownload')
                        : t('settings.downloadInstaller')}
                    </button>
                    <button
                      className="btn-secondary"
                      onClick={handleDismissAppUpdate}
                      disabled={appUpdateAction === 'dismiss'}
                    >
                      {t('settings.hideUpdate')}
                    </button>
                  </>
                )}

                <button
                  className={`btn-secondary ${appUpdateChecking || appUpdateAction === 'check' ? 'updating' : ''}`}
                  onClick={handleCheckAppUpdate}
                  disabled={appUpdateChecking || appUpdateAction === 'check'}
                >
                  {appUpdateChecking || appUpdateAction === 'check'
                    ? t('settings.checkingNow')
                    : t('settings.checkNow')}
                </button>
              </div>
            </div>
          </div>

          <div className="settings-group">
            <h3>{t('settings.protectionGroup')}</h3>
            <label className={`checkbox-label protection-toggle ${!realTimeProtection ? 'protection-disabled' : ''}`}>
              <input
                type="checkbox"
                checked={realTimeProtection ?? true}
                onChange={(e) => onRealTimeChange && onRealTimeChange(e.target.checked)}
              />
              <span>{t('settings.realTimeProtection')}</span>
            </label>
            {!realTimeProtection && (
              <p className="warning-text">
                <svg className="warning-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                {t('settings.notProtected')}
              </p>
            )}
            <p className="help-text">{t('settings.monitorFolders')}</p>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={autoQuarantine}
                onChange={(e) => onAutoQuarantineChange(e.target.checked)}
              />
              <span>{t('settings.autoQuarantine')}</span>
            </label>
            <p className="help-text">{t('settings.autoQuarantineHelp')}</p>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={autostart}
                onChange={(e) => onAutostartChange && onAutostartChange(e.target.checked)}
              />
              <span>{t('settings.launchAtStartup')}</span>
            </label>
            <p className="help-text">{t('settings.launchAtStartupHelp')}</p>
          </div>

          <div className="settings-group">
            <h3>{t('settings.ransomwareShield')}</h3>
            <label className={`checkbox-label protection-toggle ${!ransomwareProtection ? 'protection-disabled' : ''}`}>
              <input
                type="checkbox"
                checked={ransomwareProtection}
                onChange={(e) => onRansomwareProtectionChange && onRansomwareProtectionChange(e.target.checked)}
              />
              <span>{t('settings.ransomwareProtection')}</span>
            </label>
            <p className="help-text">
              {t('settings.ransomwareHelp', { threshold: ransomwareThreshold, window: ransomwareWindowSeconds })}
            </p>

            {ransomwareProtection && (
              <>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={ransomwareAutoBlock}
                  onChange={(e) => onRansomwareAutoBlockChange && onRansomwareAutoBlockChange(e.target.checked)}
                />
                <span>{t('settings.autoBlockProcesses')}</span>
              </label>
              <p className="help-text">
                {t('settings.autoBlockHelp')}
              </p>

              <hr className="ransomware-divider" />

              <div className="threshold-controls">
                <div className="threshold-row">
                  <label className="threshold-label">
                    {t('settings.fileModThreshold')}
                    <input
                      type="number"
                      min={5}
                      max={100}
                      value={ransomwareThreshold}
                      onChange={(e) => {
                        const val = parseInt(e.target.value, 10);
                        if (!isNaN(val) && val >= 5) {
                          onRansomwareThresholdsChange && onRansomwareThresholdsChange(val, ransomwareWindowSeconds);
                        }
                      }}
                      className="threshold-input"
                    />
                    <span className="threshold-unit">{t('settings.files')}</span>
                  </label>
                </div>
                <div className="threshold-row">
                  <label className="threshold-label">
                    {t('settings.timeWindow')}
                    <input
                      type="number"
                      min={5}
                      max={60}
                      value={ransomwareWindowSeconds}
                      onChange={(e) => {
                        const val = parseInt(e.target.value, 10);
                        if (!isNaN(val) && val >= 5 && val <= 60) {
                          onRansomwareThresholdsChange && onRansomwareThresholdsChange(ransomwareThreshold, val);
                        }
                      }}
                      className="threshold-input"
                    />
                    <span className="threshold-unit">{t('settings.seconds')}</span>
                  </label>
                </div>
                <p className="help-text">
                  {t('settings.thresholdHelp')}
                </p>
                {(ransomwareThreshold !== 20 || ransomwareWindowSeconds !== 10) && (
                  <button
                    className="btn-secondary btn-sm threshold-reset"
                    onClick={() => onRansomwareThresholdsChange && onRansomwareThresholdsChange(20, 10)}
                  >
                    {t('settings.resetDefaults')}
                  </button>
                )}
              </div>

              <div className="canary-section">
                <h4>{t('settings.canaryFiles')}</h4>
                <p className="help-text">
                  {t('settings.canaryHelp')}
                </p>
                <button
                  className={`btn-secondary btn-canary ${canaryRefreshing ? 'refreshing' : ''}`}
                  disabled={canaryRefreshing}
                  onClick={async () => {
                    if (!onRedeployCanaryFiles) return;
                    setCanaryRefreshing(true);
                    try {
                      await onRedeployCanaryFiles();
                      showMessage('success', t('settings.canaryRefreshed'));
                    } catch {
                      showMessage('error', t('settings.canaryFailed'));
                    } finally {
                      setCanaryRefreshing(false);
                    }
                  }}
                >
                  <svg className={canaryRefreshing ? 'spin' : ''} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="23 4 23 10 17 10" />
                    <path d="M20.49 15a9 9 0 11-2.12-9.36L23 10" />
                  </svg>
                  {canaryRefreshing ? t('settings.refreshingCanary') : t('settings.refreshCanary')}
                </button>
                {actionMessage && (
                  <div className={`action-message canary-message ${actionMessage.type}`}>
                    {actionMessage.text}
                  </div>
                )}
              </div>

              <div className="protected-folders-section">
                <h4>{t('settings.protectedFolders')}</h4>
                <div className="protected-folders-list">
                  {protectedFolders.map((folder, index) => (
                    <div key={index} className="protected-folder-item">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                      </svg>
                      <span className="folder-path" title={folder}>{folder}</span>
                      <button
                        className="btn-remove-folder"
                        onClick={() => handleRemoveProtectedFolder(folder)}
                        title={t('settings.removeFromProtection')}
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M18 6L6 18M6 6l12 12"/>
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
                <div className="add-folder-row">
                  <input
                    type="text"
                    placeholder={t('settings.addFolderPlaceholder')}
                    value={newProtectedFolder}
                    onChange={(e) => setNewProtectedFolder(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddProtectedFolder()}
                  />
                  <button
                    className="btn-browse-folder"
                    onClick={handleBrowseProtectedFolder}
                    title={t('exclusions.browseFolder')}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                    </svg>
                  </button>
                  <button
                    className="btn-add-folder"
                    onClick={handleAddProtectedFolder}
                    disabled={!newProtectedFolder.trim()}
                  >
                    {t('settings.add')}
                  </button>
                </div>
              </div>
              </>
            )}
          </div>

          <div className="settings-group">
            <h3>{t('settings.apiKeys')}</h3>
            <p className="setting-description">{t('settings.apiKeysHelp')}</p>
            <div className="api-key-fields">
              <div className="api-key-field">
                <div className="api-key-label-row">
                  <label>VirusTotal</label>
                  <span className={`api-key-status ${virustotalKeySet ? 'configured' : 'not-configured'}`}>
                    {virustotalKeySet ? t('settings.apiKeyConfigured') : t('settings.apiKeyNotSet')}
                  </span>
                </div>
                <div className="api-key-input-row">
                  <input
                    type="password"
                    placeholder={t('settings.apiKeyPlaceholder')}
                    defaultValue=""
                    onBlur={(e) => {
                      const val = e.target.value.trim();
                      if (val && onVirusTotalApiKeyChange) {
                        onVirusTotalApiKeyChange(val).then((result) => {
                          showMessage('success', result.warning ?? t('settings.apiKeySaved'));
                          e.target.value = '';
                        }).catch((err) => {
                          showMessage('error', err instanceof Error ? err.message : t('settings.apiKeyFailed'));
                        });
                      }
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') (e.target as HTMLInputElement).blur();
                    }}
                  />
                </div>
                <p className="help-text">{t('settings.vtHelp')}</p>
                <p className="help-text">{t('settings.apiKeysStoredSecurely')}</p>
                <button
                  className="btn-get-api-key"
                  onClick={() => openExternalUrl('https://www.virustotal.com/gui/my-apikey').catch(() => {})}
                >
                  {t('settings.getVtKey')}{' ->'}
                </button>
              </div>
              <div className="api-key-field">
                <div className="api-key-label-row">
                  <label>MalwareBazaar</label>
                  <span className={`api-key-status ${malwarebazaarKeySet ? 'configured' : 'not-configured'}`}>
                    {malwarebazaarKeySet ? t('settings.apiKeyConfigured') : t('settings.apiKeyNotSet')}
                  </span>
                </div>
                <div className="api-key-input-row">
                  <input
                    type="password"
                    placeholder={t('settings.apiKeyPlaceholder')}
                    defaultValue=""
                    onBlur={(e) => {
                      const val = e.target.value.trim();
                      if (val && onMalwareBazaarApiKeyChange) {
                        onMalwareBazaarApiKeyChange(val).then((result) => {
                          showMessage('success', result.warning ?? t('settings.apiKeySaved'));
                          e.target.value = '';
                        }).catch((err) => {
                          showMessage('error', err instanceof Error ? err.message : t('settings.apiKeyFailed'));
                        });
                      }
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') (e.target as HTMLInputElement).blur();
                    }}
                  />
                </div>
                <p className="help-text">{t('settings.mbHelp')}</p>
                <p className="help-text">{t('settings.apiKeysStoredSecurely')}</p>
                <button
                  className="btn-get-api-key"
                  onClick={() => openExternalUrl('https://bazaar.abuse.ch/api/').catch(() => {})}
                >
                  {t('settings.getMbKey')}{' ->'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {activeTab === 'performance' && (
        <>
          <div className="settings-group">
            <h3>{t('settings.scanWorkers')}</h3>
            <label>{t('settings.scanWorkersLabel', { count: scanWorkerCount })}</label>
            <input
              type="range"
              min={1}
              max={16}
              value={scanWorkerCount}
              onChange={(e) => onScanWorkerCountChange && onScanWorkerCountChange(Number(e.target.value))}
              style={{
                width: '100%',
                background: `linear-gradient(to right, var(--accent-primary) 0%, var(--accent-secondary) ${((scanWorkerCount - 1) / 15) * 100}%, var(--bg-tertiary) ${((scanWorkerCount - 1) / 15) * 100}%)`,
              }}
            />
            <p className="help-text">
              {t('settings.scanWorkersHelp')}
            </p>
          </div>

          <div className="settings-group">
            <h3>{t('settings.cacheHistory')}</h3>

            {actionMessage && (
              <div className={`action-message ${actionMessage.type}`}>
                {actionMessage.text}
              </div>
            )}

            <div className="cache-info">
              <div className="cache-stat">
                <span className="cache-label">{t('settings.cachedScans')}</span>
                <span className="cache-value">{t('settings.cachedFiles', { count: cacheStats?.total_entries ?? 0 })}</span>
              </div>
              <p className="help-text">
                {t('settings.cacheHelp')}
              </p>
            </div>

            <div className="cache-actions">
              <button
                className="btn-secondary"
                onClick={handleClearCache}
                disabled={cacheClearing}
              >
                {cacheClearing ? t('settings.clearing') : t('settings.clearCache')}
              </button>
            </div>
            <p className="help-text">
              <strong>{t('settings.clearCacheLabel')}</strong> {t('settings.clearCacheHelp')}
            </p>
          </div>
        </>
      )}

      {activeTab === 'exclusions' && (
        <ExclusionsManager />
      )}

      {activeTab === 'audit' && (
        <AuditLog />
      )}

      {activeTab === 'whitelist' && (
        <WhitelistManager />
      )}

      {activeTab === 'network' && (
        <>
          <div className="settings-group">
            <h3>{t('settings.networkSecurity')}</h3>
            <p className="setting-description">{t('settings.networkDescription')}</p>



            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={networkMonitoringEnabled}
                onChange={e => onNetworkMonitoringChange && onNetworkMonitoringChange(e.target.checked)}
              />
              <span>{t('settings.networkMonitoring')}</span>
            </label>
            <p className="help-text">{t('settings.networkMonitoringHelp')}</p>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={autoBlockMalwareNetwork}
                onChange={e => onAutoBlockMalwareChange && onAutoBlockMalwareChange(e.target.checked)}
              />
              <span>{t('settings.autoBlockMalware')}</span>
            </label>
            <p className="help-text">{t('settings.autoBlockMalwareHelp')}</p>
          </div>


          <FirewallRulesPanel />

          {networkMonitoringEnabled && <ActiveConnectionsViewer />}
        </>
      )}

    </div>
  );
};
