import { useState, useCallback } from 'react';
import { safeInvoke } from '../services/api';

const MASKED_API_KEY_VALUE = '[configured]';

export interface AppSettings {
  realTimeProtection?: boolean;
  autoQuarantine: boolean;
  cacheSizeMb: number;
  cacheTtlHours: number;
  ransomwareProtection?: boolean;
  ransomwareAutoBlock?: boolean;
  ransomwareThreshold?: number;
  ransomwareWindowSeconds?: number;
  scanWorkerCount?: number;
  autostart?: boolean;
  networkMonitoringEnabled?: boolean;
  autoBlockMalwareNetwork?: boolean;
  networkMonitorIntervalSecs?: number;
  language?: string;
  virustotalApiKey?: string | null;
  malwarebazaarApiKey?: string | null;
}

export interface ApiKeySaveResult {
  configured: boolean;
  verified: boolean;
  warning?: string | null;
}

export function useSettings() {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const getSettings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await safeInvoke<AppSettings>('get_settings');
      setSettings(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load settings');
    } finally {
      setLoading(false);
    }
  }, []);

  const setAutoQuarantine = useCallback(async (enabled: boolean) => {
    try {
      await safeInvoke('set_auto_quarantine', { enabled });
      setSettings(prev => prev ? { ...prev, autoQuarantine: enabled } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update quarantine setting');
    }
  }, []);

  const setRealTimeProtection = useCallback(async (enabled: boolean) => {
    try {
      await safeInvoke('set_real_time_protection', { enabled });
      setSettings(prev => prev ? { ...prev, realTimeProtection: enabled } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update real-time protection');
    }
  }, []);

  const setRansomwareProtection = useCallback(async (enabled: boolean) => {
    try {
      await safeInvoke('set_ransomware_protection', { enabled });
      setSettings(prev => prev ? { ...prev, ransomwareProtection: enabled } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update ransomware protection');
    }
  }, []);

  const setScanWorkerCount = useCallback(async (count: number) => {
    if (count < 1 || count > 16) {
      setError('Worker count must be between 1 and 16');
      return;
    }
    try {
      await safeInvoke('set_scan_worker_count', { count });
      setSettings(prev => prev ? { ...prev, scanWorkerCount: count } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update scan worker count');
    }
  }, []);

  const setAutostart = useCallback(async (enabled: boolean) => {
    try {
      await safeInvoke('set_autostart', { enabled });
      setSettings(prev => prev ? { ...prev, autostart: enabled } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update autostart setting');
    }
  }, []);

  const setRansomwareAutoBlock = useCallback(async (enabled: boolean) => {
    try {
      await safeInvoke('set_ransomware_auto_block', { enabled });
      setSettings(prev => prev ? { ...prev, ransomwareAutoBlock: enabled } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update auto-block setting');
    }
  }, []);

  const setRansomwareThresholds = useCallback(async (threshold: number, windowSeconds: number) => {
    if (threshold < 5) {
      setError('Threshold must be at least 5');
      return;
    }
    if (windowSeconds < 5 || windowSeconds > 60) {
      setError('Window must be between 5 and 60 seconds');
      return;
    }
    try {
      await safeInvoke('set_ransomware_thresholds', { threshold, windowSeconds });
      setSettings(prev => prev ? { ...prev, ransomwareThreshold: threshold, ransomwareWindowSeconds: windowSeconds } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update ransomware thresholds');
    }
  }, []);

  const dismissRansomwareAlert = useCallback(async (folder: string) => {
    try {
      await safeInvoke('dismiss_ransomware_alert', { folder });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to dismiss alert');
    }
  }, []);

  const killRansomwareProcess = useCallback(async (pid: number) => {
    try {
      await safeInvoke('kill_ransomware_process', { pid });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to kill process');
    }
  }, []);

  const redeployCanaryFiles = useCallback(async () => {
    try {
      await safeInvoke('redeploy_canary_files');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to redeploy canary files');
    }
  }, []);

  
  const setNetworkMonitoring = useCallback(async (enabled: boolean) => {
    try {
      await safeInvoke('set_network_monitoring', { enabled });
      setSettings(prev => prev ? { ...prev, networkMonitoringEnabled: enabled } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update network monitoring');
    }
  }, []);

  const setAutoBlockMalware = useCallback(async (enabled: boolean) => {
    try {
      await safeInvoke('set_auto_block_malware', { enabled });
      setSettings(prev => prev ? { ...prev, autoBlockMalwareNetwork: enabled } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update auto-block setting');
    }
  }, []);

  const setVirusTotalApiKey = useCallback(async (key: string) => {
    try {
      const result = await safeInvoke<ApiKeySaveResult>('set_virustotal_api_key', { key });
      setSettings(prev => prev ? { ...prev, virustotalApiKey: result.configured ? MASKED_API_KEY_VALUE : null } : prev);
      return result;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update VirusTotal API key');
      throw err;
    }
  }, []);

  const setMalwareBazaarApiKey = useCallback(async (key: string) => {
    try {
      const result = await safeInvoke<ApiKeySaveResult>('set_malwarebazaar_api_key', { key });
      setSettings(prev => prev ? { ...prev, malwarebazaarApiKey: result.configured ? MASKED_API_KEY_VALUE : null } : prev);
      return result;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update MalwareBazaar API key');
      throw err;
    }
  }, []);

  const setLanguage = useCallback(async (language: string) => {
    try {
      await safeInvoke('set_language', { language });
      setSettings(prev => prev ? { ...prev, language } : prev);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update language');
    }
  }, []);

  return {
    settings,
    loading,
    error,
    getSettings,
    setAutoQuarantine,
    setRealTimeProtection,
    setRansomwareProtection,
    setScanWorkerCount,
    setAutostart,
    setRansomwareAutoBlock,
    setRansomwareThresholds,
    dismissRansomwareAlert,
    killRansomwareProcess,
    redeployCanaryFiles,
    
    setNetworkMonitoring,
    setAutoBlockMalware,
    setLanguage,
    setVirusTotalApiKey,
    setMalwareBazaarApiKey,
  };
}
