import { useState, useCallback, useEffect, useRef } from 'react';
import { safeInvoke, safeListen } from '../services/api';
import type { ScanResult, ScanStatus, DetailedResults } from '../types/scan';
import { parseVerdict } from '../utils/verdict';

export function useRealtimeScan(activeNav?: string) {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [realtimeResults, setRealtimeResults] = useState<ScanResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Helper to parse detailed_results from the event payload
  const parseDetailedResults = (payload: Record<string, unknown>): DetailedResults | undefined => {
    const detailed = payload['detailed_results'] ?? payload['detailedResults'];
    if (!detailed || typeof detailed !== 'object') {
      return undefined;
    }
    // The Rust struct uses snake_case, so we pass it through as-is
    return detailed as DetailedResults;
  };

  // Helper to map event payload to ScanResult
  const mapPayloadToResult = (payload: Record<string, unknown>): ScanResult => ({
    fileHash: (payload['file_hash'] as string) ?? (payload['fileHash'] as string) ?? '',
    verdict: parseVerdict(payload['verdict']),
    confidence: (payload['confidence'] as number) ?? 0,
    threatLevel: (payload['threat_level'] as 'HIGH' | 'MEDIUM' | 'LOW') ?? (payload['threatLevel'] as 'HIGH' | 'MEDIUM' | 'LOW') ?? 'LOW',
    threatName: (payload['threat_name'] as string) ?? (payload['threatName'] as string) ?? undefined,
    scanTimeMs: (payload['scan_time_ms'] as number) ?? (payload['scanTimeMs'] as number) ?? 0,
    filePath: (payload['file_path'] as string) ?? (payload['filePath'] as string) ?? '',
    detailedResults: parseDetailedResults(payload),
  });

  // Listen for REALTIME scan results (from real-time protection)
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let isMounted = true; // Track mount state to prevent updates after unmount
    const MAX_RESULTS = 500; // Keep last 500 results in memory

    const setupListener = async () => {
      try {
        const unlistenFn = await safeListen<Record<string, unknown>>('realtime_scan_result', async (event) => {
          // Don't update state if component unmounted
          if (!isMounted) return;
          
          const mapped = mapPayloadToResult(event.payload);
          
          // Skip if missing required fields
          if (!mapped.filePath || !mapped.fileHash) {
            console.warn('[useRealtimeScan] Skipping result with missing filePath or fileHash');
            return;
          }
          
          setRealtimeResults(prev => {
            // Deduplicate by file path - same file scanned multiple times should update, not duplicate
            // Also check hash to handle case where file content changed
            const existingByPath = prev.findIndex(r => r.filePath === mapped.filePath);
            if (existingByPath !== -1) {
              // Replace existing entry with newer scan result
              const next = [...prev];
              next.splice(existingByPath, 1);
              return [mapped, ...next].slice(0, MAX_RESULTS);
            }
            // Also skip if same hash already exists (different path, same content)
            if (prev.some(r => r.fileHash === mapped.fileHash)) {
              return prev;
            }
            const next = [mapped, ...prev];
            if (next.length > MAX_RESULTS) next.length = MAX_RESULTS;
            return next;
          });
        });
        
        // Only store unlisten if still mounted
        if (isMounted) {
          unlisten = unlistenFn;
        } else {
          // Component unmounted while we were setting up - clean up immediately
          unlistenFn();
        }
      } catch (e) {
        if (isMounted) {
          setError(String(e));
        }
      }
    };
    
    setupListener();

    return () => {
      isMounted = false;
      if (unlisten) unlisten();
    };
  }, []);

  // Get initial status on mount
  useEffect(() => {
    let isMounted = true;
    
    (async () => {
      try {
        const initial = await safeInvoke<ScanStatus>('get_scan_status');
        if (isMounted) {
          setStatus(initial);
        }
      } catch (err) {
        if (isMounted) {
          setError(String(err));
        }
      }
    })();
    
    return () => {
      isMounted = false;
    };
  }, []);

  // Load historical threats from database on mount
  const loadActiveThreats = useCallback(async () => {
    interface VerdictRecord {
      file_hash: string;
      file_path: string;
      verdict: string;
      confidence: number;
      threat_level: string;
      scanned_at: number;
    }

    try {
        // Use dedicated endpoint that returns ONLY active threats (malware, suspicious)
      // that are not in quarantine or resolved
      const records = await safeInvoke<VerdictRecord[]>('get_active_threats');

      // Convert to ScanResult format - all records are already threats
      const historicalResults: ScanResult[] = records
        .map(r => {
          const parsedVerdict = parseVerdict(r.verdict);
          return {
            fileHash: r.file_hash,
            verdict: parsedVerdict,
            confidence: r.confidence,
            threatLevel: (r.threat_level as 'HIGH' | 'MEDIUM' | 'LOW') || 'LOW',
            threatName: undefined,
            scanTimeMs: 0,
            filePath: r.file_path,
          };
        });
      
      // Replace all results with the fresh data from DB
      setRealtimeResults(historicalResults);
    } catch (err) {
      console.warn('[useRealtimeScan] Could not load historical verdicts:', err);
    }
  }, []);

  // Track active nav to pause polling when not on dashboard
  const activeNavRef = useRef(activeNav);
  activeNavRef.current = activeNav;

  useEffect(() => {
    loadActiveThreats();
    
    // Only poll active threats when dashboard is visible
    const intervalId = setInterval(() => {
      if (activeNavRef.current === 'dashboard' || activeNavRef.current === undefined) {
        loadActiveThreats();
      }
    }, 30000); 
    
    return () => clearInterval(intervalId);
  }, [loadActiveThreats]);

  const getScanStatus = useCallback(async (): Promise<ScanStatus> => {
    const s = await safeInvoke<ScanStatus>('get_scan_status');
    setStatus(s);
    return s;
  }, []);

  const clearResults = useCallback(() => setRealtimeResults([]), []);

  // Remove a specific result by file hash (used when threat is resolved)
  const removeResult = useCallback((fileHash: string) => {
    setRealtimeResults(prev => prev.filter(r => r.fileHash !== fileHash));
  }, []);

  // Refresh active threats from database (used after dashboard refresh)
  const refreshActiveThreats = useCallback(async () => {
    await loadActiveThreats();
  }, [loadActiveThreats]);

  return {
    status,
    realtimeResults,
    error,
    getScanStatus,
    clearResults,
    removeResult,
    refreshActiveThreats,
  };
}
