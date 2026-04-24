import { useState, useCallback, useEffect, useRef } from 'react';
import { safeInvoke } from '../services/api';
import type { DashboardStats } from '../types/dashboard';

// Convert snake_case from Rust to camelCase
interface RustDashboardStats {
  total_scans: number;
  malware_detected: number;
  suspicious_detected: number;
  quarantined_count: number;
  threat_intel_count: number;
  last_scan_time: number | null;
  protection_status: string;
  active_malware: number;
  active_suspicious: number;
}

const mapStats = (data: RustDashboardStats): DashboardStats => ({
  totalScans: data.total_scans,
  malwareDetected: data.malware_detected,
  suspiciousDetected: data.suspicious_detected,
  quarantinedCount: data.quarantined_count,
  threatIntelCount: data.threat_intel_count,
  lastScanTime: data.last_scan_time,
  protectionStatus: data.protection_status,
  activeMalware: data.active_malware,
  activeSuspicious: data.active_suspicious,
});

export function useDashboard(activeNav?: string) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await safeInvoke<RustDashboardStats>('get_dashboard_stats');
      setStats(mapStats(data));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard stats');
    } finally {
      setLoading(false);
    }
  }, []);

  // Only poll when dashboard page is active (or on first mount)
  const activeNavRef = useRef(activeNav);
  activeNavRef.current = activeNav;

  useEffect(() => {
    let isMounted = true;

    const safeRefresh = async () => {
      if (!isMounted) return;
      // Skip polling if not on dashboard (still do initial load)
      setLoading(true);
      setError(null);
      try {
        const data = await safeInvoke<RustDashboardStats>('get_dashboard_stats');
        if (isMounted) setStats(mapStats(data));
      } catch (err) {
        if (isMounted) setError(err instanceof Error ? err.message : 'Failed to load dashboard stats');
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    // Initial load
    safeRefresh();

    const intervalId = setInterval(() => {
      // Only poll when dashboard is active
      if (activeNavRef.current === 'dashboard' || activeNavRef.current === undefined) {
        safeRefresh();
      }
    }, 10000);

    return () => {
      isMounted = false;
      clearInterval(intervalId);
    };
  }, []);

  return {
    stats,
    loading,
    error,
    refresh,
  };
}
