import { useState, useEffect, useCallback, useMemo, lazy, Suspense } from 'react';
import { useTranslation } from 'react-i18next';
import { useRealtimeScan } from './hooks/useRealtimeScan';
import { useSettings } from './hooks/useSettings';
import { useQuarantine } from './hooks/useQuarantine';
import { useConfirmDialog } from './hooks/useConfirmDialog';
import { useDashboard } from './hooks/useDashboard';
import { Sidebar, NavItem } from './components/Sidebar/Sidebar';
import { ErrorBoundary, withErrorBoundary } from './components/ErrorBoundary/ErrorBoundary';
import { ConfirmDialog } from './components/shared/ConfirmDialog';
import {
  checkAppUpdate,
  dismissAppUpdate,
  isTauriAvailable,
  openExternalUrl,
  safeInvoke,
  safeListen,
  type AppUpdateCheckResult,
  type AppUpdateInfo,
} from './services/api';
import packageJson from '../package.json';
import './App.css';

// Lazy-load page-level components - only parsed/compiled when navigated to
const DashboardBase = lazy(() => import('./components/Dashboard/Dashboard').then(m => ({ default: m.Dashboard })));
const ScannerBase = lazy(() => import('./components/Scanner/Scanner').then(m => ({ default: m.Scanner })));
const QuarantineListBase = lazy(() => import('./components/Quarantine/QuarantineList').then(m => ({ default: m.QuarantineList })));
const SettingsBase = lazy(() => import('./components/Settings/Settings').then(m => ({ default: m.Settings })));

const Dashboard = withErrorBoundary(DashboardBase);
const Scanner = withErrorBoundary(ScannerBase);
const QuarantineList = withErrorBoundary(QuarantineListBase);
const Settings = withErrorBoundary(SettingsBase);
interface ProcessInfo {
  pid: number;
  name: string;
  exe_path: string;
}

interface RansomwareAlert {
  folder: string;
  modification_count: number;
  time_window_seconds: number;
  sample_files: string[];
  alert_level: string;
  suspected_processes: ProcessInfo[];
  processes_killed: string[];
  average_entropy: number;
}

function App() {
  const { t, i18n } = useTranslation();
  // Navigation state - now uses sidebar nav items
  const [activeNav, setActiveNav] = useState<NavItem>('dashboard');

  // Hooks now receive activeNav so they can pause polling when their page is inactive
  const { realtimeResults, removeResult, refreshActiveThreats } = useRealtimeScan(activeNav);
  const { confirm: confirmDialog, dialogProps: appDialogProps } = useConfirmDialog();
  const { quarantinedFiles: quarantineItems, loading: quarantineLoading, listQuarantined, restoreFile: restoreItem, deleteFile: deleteItem } = useQuarantine(confirmDialog);
  const { settings, getSettings, setRealTimeProtection, setAutoQuarantine, setRansomwareProtection, setScanWorkerCount, setAutostart, setRansomwareAutoBlock, setRansomwareThresholds, redeployCanaryFiles, setNetworkMonitoring, setAutoBlockMalware, setLanguage, setVirusTotalApiKey, setMalwareBazaarApiKey } = useSettings();
  const { stats: dashboardStats, loading: dashboardLoading, refresh: refreshDashboard } = useDashboard(activeNav);
  

  // Ransomware alert state
  const [ransomwareAlert, setRansomwareAlert] = useState<RansomwareAlert | null>(null);
  const [appUpdate, setAppUpdate] = useState<AppUpdateInfo | null>(null);
  const [appUpdateChecking, setAppUpdateChecking] = useState(false);

  // Separate effects to avoid quarantine re-fetching when dashboard deps change
  useEffect(() => {
    if (activeNav === 'quarantine') {
      listQuarantined();
    }
  }, [activeNav, listQuarantined]);

  useEffect(() => {
    if (activeNav === 'dashboard') {
      refreshDashboard();
      refreshActiveThreats();
    }
  }, [activeNav, refreshDashboard, refreshActiveThreats]);

  // Load app settings on mount
  useEffect(() => {
    getSettings().catch(() => {});
  }, [getSettings]);

  // Sync language from backend settings to i18n
  useEffect(() => {
    if (!settings) return;
    if (settings.language && settings.language !== i18n.language) {
      i18n.changeLanguage(settings.language);
    } else if (!settings.language) {
      // First launch: save detected language to backend
      const detected = i18n.language?.startsWith('bg') ? 'bg' : 'en';
      setLanguage(detected).catch(() => {});
    }
  }, [settings?.language, i18n, setLanguage]);

  // Request notification permission on mount so background threat alerts work
  useEffect(() => {
    let isMounted = true;
    const requestNotificationPermission = async () => {
      try {
        const { isPermissionGranted, requestPermission } = await import('@tauri-apps/plugin-notification');
        const granted = await isPermissionGranted();
        if (!granted && isMounted) {
          const result = await requestPermission();
          if (result !== 'granted') {
            console.warn('Notification permission not granted - threat alerts will be silent');
          }
        }
      } catch (err) {
        // Not in Tauri context or plugin not available - ignore
        if (import.meta.env.DEV) {
          console.debug('Notification permission check skipped:', err);
        }
      }
    };
    requestNotificationPermission();
    return () => { isMounted = false; };
  }, []);

  const runAppUpdateCheck = useCallback(async (force = false): Promise<AppUpdateCheckResult | null> => {
    setAppUpdateChecking(true);
    try {
      const result = await checkAppUpdate(force);
      if (result.update) {
        setAppUpdate(result.update);
      } else if (!result.error) {
        setAppUpdate(null);
      }

      if (!force && result.shouldNotify && result.update && isTauriAvailable()) {
        try {
          const { sendNotification } = await import('@tauri-apps/plugin-notification');
          sendNotification({
            title: t('settings.updateAvailableNotificationTitle'),
            body: t('settings.updateAvailableNotificationBody', { version: result.update.latestVersion }),
          });
        } catch (err) {
          if (import.meta.env.DEV) {
            console.debug('Update notification skipped:', err);
          }
        }
      }

      return result;
    } catch (err) {
      if (import.meta.env.DEV) {
        console.debug('App update check skipped:', err);
      }
      return null;
    } finally {
      setAppUpdateChecking(false);
    }
  }, [t]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void runAppUpdateCheck(false);
    }, 6000);

    return () => window.clearTimeout(timer);
  }, [runAppUpdateCheck]);

  const handleDismissAppUpdate = useCallback(async () => {
    if (!appUpdate) {
      return;
    }

    await dismissAppUpdate(appUpdate.latestVersion);
    setAppUpdate(null);
  }, [appUpdate]);

  const handleDownloadAppUpdate = useCallback(async () => {
    if (!appUpdate) {
      return;
    }

    await openExternalUrl(appUpdate.downloadUrl || appUpdate.releasePageUrl);
  }, [appUpdate]);
  
  // Listen for ransomware alerts from backend
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let isMounted = true;
    
    const setupListener = async () => {
      try {
        const unlistenFn = await safeListen<RansomwareAlert>('ransomware_alert', (event) => {
          if (!isMounted) return;
          setRansomwareAlert(event.payload);
        });
        
        if (isMounted) {
          unlisten = unlistenFn;
        } else {
          unlistenFn();
        }
      } catch (err) {
        console.error('Failed to listen for ransomware alerts:', err);
      }
    };
    
    setupListener();
    
    return () => {
      isMounted = false;
      unlisten?.();
    };
  }, []);
  
  const handleLanguageChange = useCallback(async (lang: string) => {
    await i18n.changeLanguage(lang);
    await setLanguage(lang);
  }, [i18n, setLanguage]);

  const dismissRansomwareAlert = useCallback(() => {
    setRansomwareAlert(null);
  }, []);

  const markRansomwareFalsePositive = useCallback(async () => {
    if (!ransomwareAlert) {
      return;
    }

    try {
      await safeInvoke('dismiss_ransomware_alert', { folder: ransomwareAlert.folder });
    } catch (_) {
      // Closing the alert is still better than trapping the user in the modal.
    }

    setRansomwareAlert(null);
  }, [ransomwareAlert]);

  const handleKillProcess = useCallback(async (pid: number) => {
    try {
      await safeInvoke('kill_ransomware_process', { pid });
      // Update the alert to reflect the kill
      setRansomwareAlert(prev => {
        if (!prev) return null;
        return {
          ...prev,
          suspected_processes: prev.suspected_processes.filter(p => p.pid !== pid),
          processes_killed: [...prev.processes_killed, prev.suspected_processes.find(p => p.pid === pid)?.name ?? `PID ${pid}`],
        };
      });
    } catch (err) {
      console.error('Failed to kill process:', err);
    }
  }, []);

  // Memoize quarantine malware count to avoid filtering on every render
  const quarantineMalwareCount = useMemo(
    () => quarantineItems.filter(f => f.verdict === 'Malware').length,
    [quarantineItems]
  );


  // Handle threat resolution - remove from results and refresh dashboard
  const handleThreatResolved = useCallback(async (threatId: string) => {
    removeResult(threatId);
    await refreshDashboard();
    // No need to refresh active threats here - removeResult already did it locally
  }, [removeResult, refreshDashboard]);

  return (
    <ErrorBoundary>
      <div className="app-layout">
        {/* Ransomware Alert Overlay */}
        {ransomwareAlert && (
          <div className="ransomware-alert-overlay">
            <div className={`ransomware-alert-modal ${ransomwareAlert.alert_level === 'CRITICAL_CANARY' ? 'canary-alert' : ''}`}>
              <div className="ransomware-alert-header">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <path d="M12 2L2 20h20L12 2z" />
                  <path d="M12 9v4M12 17h.01" />
                </svg>
                <h2>
                  {ransomwareAlert.alert_level === 'CRITICAL_CANARY'
                    ? ` ${t('ransomware.canaryTripwire')}`
                    : ` ${t('ransomware.activityDetected')}`}
                </h2>
              </div>
              <div className="ransomware-alert-body">
                <p className="alert-description">
                  {ransomwareAlert.alert_level === 'CRITICAL_CANARY'
                    ? t('ransomware.honeypotTampered')
                    : t('ransomware.bulkModifications')}
                </p>
                {ransomwareAlert.alert_level !== 'CRITICAL_CANARY' && (
                  <p className="alert-hint">
                    {t('ransomware.falsePositiveHint')}
                  </p>
                )}
                <div className="alert-details">
                  <div className="alert-stat">
                    <span className="stat-label">{t('ransomware.protectedFolder')}</span>
                    <span className="stat-value">{ransomwareAlert.folder}</span>
                  </div>
                  <div className="alert-stat">
                    <span className="stat-label">{t('ransomware.filesModified')}</span>
                    <span className="stat-value critical">{ransomwareAlert.modification_count}</span>
                  </div>
                  <div className="alert-stat">
                    <span className="stat-label">{t('ransomware.timeWindow')}</span>
                    <span className="stat-value">{t('ransomware.secondsValue', { value: ransomwareAlert.time_window_seconds })}</span>
                  </div>
                  {ransomwareAlert.average_entropy > 0 && (
                    <div className="alert-stat">
                      <span className="stat-label">{t('ransomware.avgEntropy')}</span>
                      <span className={`stat-value ${ransomwareAlert.average_entropy > 7.5 ? 'critical' : ''}`}>
                        {ransomwareAlert.average_entropy.toFixed(2)} / 8.0
                      </span>
                    </div>
                  )}
                </div>

                {/* Process attribution */}
                {ransomwareAlert.suspected_processes.length > 0 && (
                  <div className="suspected-processes">
                    <h4>{t('ransomware.suspectedProcesses')}</h4>
                    <ul>
                      {ransomwareAlert.suspected_processes.map((proc) => (
                        <li key={proc.pid} className="process-item">
                          <span className="process-info">
                            <strong>{proc.name}</strong> (PID: {proc.pid})
                            <span className="process-path" title={proc.exe_path}>{proc.exe_path}</span>
                          </span>
                          <button
                            className="btn-kill-process"
                            onClick={() => handleKillProcess(proc.pid)}
                            title={t('ransomware.terminateProcess')}
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M18 6L6 18M6 6l12 12"/>
                            </svg>
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Auto-killed processes */}
                {ransomwareAlert.processes_killed.length > 0 && (
                  <div className="killed-processes">
                    <h4>{t('ransomware.processesTerminated')}</h4>
                    <ul>
                      {ransomwareAlert.processes_killed.map((name, idx) => (
                        <li key={idx} className="killed-item">&#10003; {name}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {ransomwareAlert.sample_files.length > 0 && (
                  <div className="affected-files">
                    <h4>{t('ransomware.recentlyModified')}</h4>
                    <ul>
                      {ransomwareAlert.sample_files.slice(0, 5).map((file, idx) => (
                        <li key={idx} title={file}>{file.split('\\').pop()}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="alert-recommendations">
                  <h4>{t('ransomware.recommendedActions')}</h4>
                  <ol>
                    {ransomwareAlert.alert_level === 'CRITICAL_CANARY' ? (
                      <>
                        <li>{t('ransomware.disconnectNetwork')}</li>
                        <li>{t('ransomware.killProcesses')}</li>
                        <li>{t('ransomware.runFullScan')}</li>
                        <li>{t('ransomware.checkBackups')}</li>
                      </>
                    ) : (
                      <>
                        <li>{t('ransomware.reviewProcesses')}</li>
                        <li>{t('ransomware.runFullScan')}</li>
                        <li>{t('ransomware.verifyRecentActivity')}</li>
                        <li>{t('ransomware.markFalsePositiveAction')}</li>
                      </>
                    )}
                  </ol>
                </div>
              </div>
              <div className="ransomware-alert-actions">
                {ransomwareAlert.alert_level !== 'CRITICAL_CANARY' && (
                  <button className="btn-alert-secondary" onClick={markRansomwareFalsePositive}>
                    {t('ransomware.markFalsePositive')}
                  </button>
                )}
                <button className="btn-dismiss" onClick={dismissRansomwareAlert}>
                  {t('ransomware.acknowledge')}
                </button>
              </div>
            </div>
          </div>
        )}
        
        <Sidebar
          activeItem={activeNav}
          onNavigate={setActiveNav}
          quarantineCount={quarantineMalwareCount}
          protectionEnabled={settings?.realTimeProtection ?? true}
        />

        <main className="main-content">
        <Suspense fallback={<div className="page-loading"><div className="loading-spinner" /><span>{t('common.loading')}</span></div>}>
        {activeNav === 'dashboard' && (
          <Dashboard
            stats={dashboardStats}
            loading={dashboardLoading}
            realtimeResults={realtimeResults}
            onThreatResolved={handleThreatResolved}
            hasReputationKeys={settings ? !!(settings.virustotalApiKey || settings.malwarebazaarApiKey) : undefined}
          />
        )}

        {activeNav === 'scanner' && (
          <Scanner autoQuarantine={settings?.autoQuarantine ?? true} />
        )}

        {activeNav === 'quarantine' && (
          <QuarantineList
            files={quarantineItems}
            onRestore={restoreItem}
            onDelete={deleteItem}
            loading={quarantineLoading}
          />
        )}

        {activeNav === 'settings' && (
          <Settings
            autoQuarantine={settings?.autoQuarantine ?? false}
            realTimeProtection={settings?.realTimeProtection ?? true}
            ransomwareProtection={settings?.ransomwareProtection ?? true}
            ransomwareAutoBlock={settings?.ransomwareAutoBlock ?? true}
            ransomwareThreshold={settings?.ransomwareThreshold ?? 20}
            ransomwareWindowSeconds={settings?.ransomwareWindowSeconds ?? 10}
            scanWorkerCount={settings?.scanWorkerCount ?? 4}
            autostart={settings?.autostart ?? true}
            onAutoQuarantineChange={setAutoQuarantine}
            onRealTimeChange={setRealTimeProtection}
            onRansomwareProtectionChange={setRansomwareProtection}
            onRansomwareAutoBlockChange={setRansomwareAutoBlock}
            onRansomwareThresholdsChange={setRansomwareThresholds}
            onRedeployCanaryFiles={redeployCanaryFiles}
            onScanWorkerCountChange={setScanWorkerCount}
            onAutostartChange={setAutostart}
            networkMonitoringEnabled={settings?.networkMonitoringEnabled ?? false}
            autoBlockMalwareNetwork={settings?.autoBlockMalwareNetwork ?? true}
            
            onNetworkMonitoringChange={setNetworkMonitoring}
            onAutoBlockMalwareChange={setAutoBlockMalware}
            language={settings?.language}
            onLanguageChange={handleLanguageChange}
            virustotalKeySet={!!settings?.virustotalApiKey}
            malwarebazaarKeySet={!!settings?.malwarebazaarApiKey}
            onVirusTotalApiKeyChange={setVirusTotalApiKey}
            onMalwareBazaarApiKeyChange={setMalwareBazaarApiKey}
            appVersion={packageJson.version}
            appUpdate={appUpdate}
            appUpdateChecking={appUpdateChecking}
            onCheckAppUpdate={runAppUpdateCheck}
            onDismissAppUpdate={handleDismissAppUpdate}
            onDownloadAppUpdate={handleDownloadAppUpdate}
          />
        )}
        </Suspense>
      </main>

        <ConfirmDialog {...appDialogProps} />
      </div>
    </ErrorBoundary>
  );
}

export default App;
