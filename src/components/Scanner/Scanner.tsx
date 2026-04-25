import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  startScan,
  cancelScan,
  getScanStatus,
  forceResetScan,
  safeListen,
  safeInvoke,
  ignoreThreat,
  pickScanFolder,
  pickScanFile,
  getScheduledScans,
  createScheduledScan,
  toggleScheduledScan,
  deleteScheduledScan,
  runScheduledScanNow,
  type ScheduledScan,
  type CreateScheduledScan,
} from '../../services/api';
import type { ScanStatus, ScanSummary } from '../../services/api';
import type { ScanResult } from '../../types/scan';
import { Verdict } from '../../types/scan';
import { getVerdictClass, getVerdictKey, isThreat, parseVerdict } from '../../utils/verdict';
import { getFileName } from '../../utils/file';
import { useConfirmDialog } from '../../hooks/useConfirmDialog';
import { useTranslation } from 'react-i18next';
import './Scanner.css';

import { ErrorBanner } from '../shared/ErrorBanner';
import { ConfirmDialog } from '../shared/ConfirmDialog';

export interface ScannerProps {
  autoQuarantine: boolean;
}

type ThreatResolution = 'quarantined' | 'deleted' | 'whitelisted';

// Helper to map scan-result event payload to ScanResult
const mapPayloadToResult = (payload: Record<string, unknown>): ScanResult => {
  const filePath = (payload['file_path'] as string) ?? (payload['filePath'] as string) ?? '';
  const rawThreatId = payload['threat_id'] ?? payload['threatId'];

  return {
    threatId: rawThreatId != null ? String(rawThreatId) : filePath,
    fileHash: (payload['file_hash'] as string) ?? (payload['fileHash'] as string) ?? '',
    verdict: parseVerdict(payload['verdict']),
    confidence: (payload['confidence'] as number) ?? 0,
    threatLevel: (payload['threat_level'] as 'HIGH' | 'MEDIUM' | 'LOW') ?? (payload['threatLevel'] as 'HIGH' | 'MEDIUM' | 'LOW') ?? 'LOW',
    threatName: (payload['threat_name'] as string) ?? (payload['threatName'] as string) ?? undefined,
    scanTimeMs: (payload['scan_time_ms'] as number) ?? (payload['scanTimeMs'] as number) ?? 0,
    filePath,
  };
};

const getErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

// Auto-quarantine a threat and return an error message on failure.
const autoQuarantineThreat = async (result: ScanResult): Promise<string | null> => {
  try {
    await safeInvoke('quarantine_file_by_path', {
      filePath: result.filePath,
      fileHash: result.fileHash,
      verdict: result.verdict === Verdict.MALWARE ? 'malware' : 'suspicious',
      threatLevel: result.threatLevel.toLowerCase(),
    });
    return null;
  } catch (e) {
    console.error('[Scanner] Failed to auto-quarantine threat:', e);
    return getErrorMessage(e);
  }
};

export const Scanner: React.FC<ScannerProps> = ({ autoQuarantine }) => {
  const { t, i18n } = useTranslation();
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [customPath, setCustomPath] = useState<string>('');

  // Flag to prevent polling after force-completion
  const [forceCompleted, setForceCompleted] = useState(false);

  // Scan results (threats found during manual scan - only used when autoQuarantine is OFF)
  const MAX_SCAN_THREATS = 500;
  const [scanThreats, setScanThreats] = useState<ScanResult[]>([]);
  const [threatActionLoading, setThreatActionLoading] = useState<string | null>(null);
  const [threatResolutions, setThreatResolutions] = useState<Record<string, ThreatResolution>>({});

  // Track auto-quarantined count for display
  const [autoQuarantinedCount, setAutoQuarantinedCount] = useState(0);

  // Scheduled scans state
  const [scheduledScans, setScheduledScans] = useState<ScheduledScan[]>([]);
  const { confirm: confirmDialog, dialogProps } = useConfirmDialog();
  const [showScheduleForm, setShowScheduleForm] = useState(false);
  const [scheduleForm, setScheduleForm] = useState<CreateScheduledScan>({
    name: '',
    scanType: 'quick',
    frequency: 'daily',
    timeOfDay: '09:00',
  });
  const [scheduleError, setScheduleError] = useState<string | null>(null);
  const [exportMessage, setExportMessage] = useState<string | null>(null);

  // Batching refs for scan results (prevents UI overwhelm with fast multi-threaded scans)
  const threatBufferRef = useRef<ScanResult[]>([]);
  const flushIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const markThreatResolved = useCallback((fileHash: string, resolution: ThreatResolution) => {
    setThreatResolutions(prev => {
      if (prev[fileHash] === resolution) {
        return prev;
      }
      return {
        ...prev,
        [fileHash]: resolution,
      };
    });
  }, []);

  // Flush buffered scan results into state (batched to reduce re-renders)
  const flushBuffer = useCallback(() => {
    if (threatBufferRef.current.length > 0) {
      const buffered = threatBufferRef.current;
      threatBufferRef.current = [];
      setScanThreats(prev => {
        const existingHashes = new Set(prev.map(r => r.fileHash));
        const seenInBatch = new Set<string>();
        const newThreats = buffered.filter(r => {
          if (existingHashes.has(r.fileHash) || seenInBatch.has(r.fileHash)) return false;
          seenInBatch.add(r.fileHash);
          return true;
        });
        if (newThreats.length === 0) return prev;
        const next = [...prev, ...newThreats];
        if (next.length > MAX_SCAN_THREATS) next.length = MAX_SCAN_THREATS;
        return next;
      });
    }
  }, []);

  // Listen for scan results during manual scans
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let isMounted = true;

    const setupListener = async () => {
      try {
        const unlistenFn = await safeListen<Record<string, unknown>>('scan-result', (event) => {
          if (!isMounted) return;

          const result = mapPayloadToResult(event.payload);
          if (result.fileHash && result.filePath && isThreat(result.verdict)) {
            // Buffer threat for batched state update (prevents UI overwhelm)
            threatBufferRef.current.push(result);

            if (autoQuarantine) {
              void autoQuarantineThreat(result).then((errorMessage) => {
                if (!isMounted) return;
                if (errorMessage) {
                  setScanError(t('scanner.failedQuarantine', { error: errorMessage }));
                  return;
                }
                setAutoQuarantinedCount(prev => prev + 1);
                markThreatResolved(result.fileHash, 'quarantined');
              });
            }
          }
        });

        if (isMounted) {
          unlisten = unlistenFn;
        } else {
          unlistenFn();
        }
      } catch (e) {
        console.error('[Scanner] Failed to setup scan-result listener:', e);
      }
    };

    setupListener();

    return () => {
      isMounted = false;
      unlisten?.();
    };
  }, [autoQuarantine, markThreatResolved, t]);

  // Periodic flush of buffered scan results while scanning
  useEffect(() => {
    if (scanStatus?.isScanning) {
      flushIntervalRef.current = setInterval(flushBuffer, 250);
    } else {
      if (flushIntervalRef.current) {
        clearInterval(flushIntervalRef.current);
        flushIntervalRef.current = null;
      }
      flushBuffer(); // Final flush for any remaining buffered results
    }

    return () => {
      if (flushIntervalRef.current) {
        clearInterval(flushIntervalRef.current);
        flushIntervalRef.current = null;
      }
    };
  }, [scanStatus?.isScanning, flushBuffer]);

  // Poll scan status while scanning
  useEffect(() => {
    // Don't poll if we force-completed the scan
    if (forceCompleted) {
      return;
    }

    let interval: ReturnType<typeof setInterval> | null = null;
    let stuckAt100Counter = 0;  // Track how long we've been stuck at 100%
    let isMounted = true;

    const pollStatus = async () => {
      if (!isMounted) return;
      try {
        const status = await getScanStatus();
        if (!isMounted) return;

        // Check if scan is stuck at 100% - force complete after 10 polls (5 seconds)
        // Don't trigger during file collection phase (totalFiles === 0)
        if (status.isScanning && status.totalFiles > 0 && status.progressPercent >= 100) {
          stuckAt100Counter++;
          if (stuckAt100Counter >= 10) {
            console.warn('[Scanner] Scan stuck at 100% - forcing completion');

            // Force reset on backend
            try {
              await forceResetScan();
            } catch (e) {
              console.error('[Scanner] Failed to force reset:', e);
            }

            if (!isMounted) return;

            // Create a synthetic summary from current status
            const syntheticSummary: ScanSummary = {
              totalFiles: status.totalFiles || status.filesScanned,
              cleanCount: status.cleanCount,
              suspiciousCount: status.suspiciousCount,
              malwareCount: status.malwareCount,
              elapsedSeconds: status.elapsedSeconds,
              scanType: status.scanType || 'unknown',
            };
            setScanSummary(syntheticSummary);
            setScanStatus({ ...status, isScanning: false });
            setForceCompleted(true);  // Prevent further polling
            if (interval) {
              clearInterval(interval);
              interval = null;
            }
            return;
          }
        } else {
          stuckAt100Counter = 0;  // Reset if not at 100%
        }

        setScanStatus(status);

        if (!status.isScanning && interval) {
          clearInterval(interval);
          interval = null;
        }
      } catch (e) {
        console.error('Failed to get scan status:', e);
      }
    };

    // Initial poll
    pollStatus();

    if (scanStatus?.isScanning) {
      interval = setInterval(pollStatus, 1000);
    }

    return () => {
      isMounted = false;
      if (interval) clearInterval(interval);
    };
  }, [scanStatus?.isScanning, forceCompleted]);

  // Listen for scan completion
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let isMounted = true;

    const setupListener = async () => {
      try {
        const unlistenFn = await safeListen<ScanSummary>('scan-complete', (event) => {
          if (!isMounted) return;

          // Don't process if we already force-completed
          if (forceCompleted) {
            return;
          }
          setScanSummary(event.payload);
          // Force refresh status to update isScanning state
          getScanStatus()
            .then(status => {
              if (isMounted) {
                setScanStatus(status);
              }
            })
            .catch(error => {
              console.error('[Scanner] Failed to refresh status after completion:', error);
            });
        });

        if (isMounted) {
          unlisten = unlistenFn;
        } else {
          unlistenFn();
        }
      } catch (e) {
        console.error('[Scanner] Failed to setup scan-complete listener:', e);
      }
    };

    setupListener();

    return () => {
      isMounted = false;
      unlisten?.();
    };
  }, [forceCompleted]);

  // Load scheduled scans
  useEffect(() => {
    loadScheduledScans();
  }, []);

  const loadScheduledScans = async () => {
    try {
      const scans = await getScheduledScans();
      setScheduledScans(scans);
    } catch (e) {
      console.error('Failed to load scheduled scans:', e);
    }
  };

  const handleStartScan = useCallback(async (type: 'quick' | 'full' | 'custom') => {
    setScanError(null);
    setScanSummary(null);
    setScanThreats([]);  // Clear previous threats
    setThreatResolutions({});  // Clear resolved threat actions
    setAutoQuarantinedCount(0);  // Reset auto-quarantine counter
    setForceCompleted(false);  // Reset force-completed flag
    threatBufferRef.current = [];

    try {
      const path = type === 'custom' ? (customPath || undefined) : undefined;

      if (type === 'custom' && !customPath) {
        setScanError(t('scanner.enterPathError'));
        return;
      }

      await startScan(type, path);
      // Immediately get status to show scanning state
      const status = await getScanStatus();
      setScanStatus(status);
    } catch (e) {
      console.error('Scan start failed:', e);
      // Tauri errors come as strings or objects with message property
      const errorMessage = typeof e === 'string' ? e : (e instanceof Error ? e.message : JSON.stringify(e));
      setScanError(errorMessage || t('scanner.failedToStart'));
    }
  }, [customPath, t]);

  const handleCancelScan = useCallback(async () => {
    try {
      await cancelScan();
      const status = await getScanStatus();
      setScanStatus(status);
    } catch (e) {
      console.error('Failed to cancel scan:', e);
    }
  }, []);

  const formatDuration = (seconds: number): string => {
    if (seconds < 60) return `${seconds}s`;
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  const handleCreateSchedule = async () => {
    setScheduleError(null);

    if (!scheduleForm.name.trim()) {
      setScheduleError(t('scanner.enterScheduleName'));
      return;
    }

    if (scheduleForm.scanType === 'custom' && !scheduleForm.customPath?.trim()) {
      setScheduleError(t('scanner.enterSchedulePath'));
      return;
    }

    try {
      await createScheduledScan(scheduleForm);
      await loadScheduledScans();
      setShowScheduleForm(false);
      setScheduleForm({
        name: '',
        scanType: 'quick',
        frequency: 'daily',
        timeOfDay: '09:00',
      });
    } catch (e) {
      const msg = typeof e === 'string' ? e : (e instanceof Error ? e.message : 'Failed to create scheduled scan');
      setScheduleError(msg);
    }
  };

  const handleToggleSchedule = async (id: number) => {
    try {
      await toggleScheduledScan(id);
      await loadScheduledScans();
    } catch (e) {
      console.error('Failed to toggle scheduled scan:', e);
    }
  };

  const handleDeleteSchedule = async (id: number) => {
    if (!await confirmDialog({
      title: t('scanner.deleteScheduleTitle'),
      message: t('scanner.deleteScheduleMessage'),
      confirmLabel: t('common.delete'),
      variant: 'danger',
    })) return;

    try {
      await deleteScheduledScan(id);
      await loadScheduledScans();
    } catch (e) {
      console.error('Failed to delete scheduled scan:', e);
    }
  };

  const handleRunScheduleNow = async (id: number) => {
      try {
        setScanSummary(null);
        setScanThreats([]);  // Clear previous threats
        setThreatResolutions({});
        setAutoQuarantinedCount(0);  // Reset auto-quarantine counter
        setForceCompleted(false);  // Reset force-completed flag
        threatBufferRef.current = [];
        await runScheduledScanNow(id);
      // Immediately refresh scan status to trigger UI polling
      const status = await getScanStatus();
      setScanStatus(status);
      await loadScheduledScans();
    } catch (e) {
      console.error('Failed to run scheduled scan:', e);
      setScanError(typeof e === 'string' ? e : t('scanner.failedRunSchedule'));
    }
  };

  const formatNextRun = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    const now = new Date();
    const diff = timestamp * 1000 - now.getTime();

    if (diff < 0) return t('scanner.overdue');
    if (diff < 60 * 60 * 1000) return t('scanner.inMinutes', { count: Math.round(diff / 60000) });
    if (diff < 24 * 60 * 60 * 1000) return t('scanner.inHours', { count: Math.round(diff / 3600000) });

    return date.toLocaleString(i18n.resolvedLanguage || i18n.language || undefined, {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getDayName = (day: number): string => {
    const days = [
      t('scanner.days.sunday'),
      t('scanner.days.monday'),
      t('scanner.days.tuesday'),
      t('scanner.days.wednesday'),
      t('scanner.days.thursday'),
      t('scanner.days.friday'),
      t('scanner.days.saturday'),
    ];
    return days[day] || '';
  };

  // Threat action handlers
  const handleQuarantineThreat = async (threat: ScanResult) => {
    setThreatActionLoading(threat.fileHash);
    try {
      await safeInvoke('quarantine_file_by_path', {
        filePath: threat.filePath,
        fileHash: threat.fileHash,
        verdict: threat.verdict === Verdict.MALWARE ? 'malware' : 'suspicious',
        threatLevel: threat.threatLevel.toLowerCase(),
      });
      markThreatResolved(threat.fileHash, 'quarantined');
    } catch (e) {
      setScanError(t('scanner.failedQuarantine', { error: getErrorMessage(e) }));
    } finally {
      setThreatActionLoading(null);
    }
  };

  const handleDeleteThreat = async (threat: ScanResult) => {
    setThreatActionLoading(threat.fileHash);
    try {
      await safeInvoke('delete_threat_file', {
        filePath: threat.filePath,
        fileHash: threat.fileHash,
      });
      markThreatResolved(threat.fileHash, 'deleted');
    } catch (e) {
      setScanError(t('scanner.failedDelete', { error: getErrorMessage(e) }));
    } finally {
      setThreatActionLoading(null);
    }
  };

  const handleIgnoreThreat = async (threat: ScanResult) => {
    setThreatActionLoading(threat.fileHash);
    try {
      await ignoreThreat(threat.fileHash, threat.filePath);
      markThreatResolved(threat.fileHash, 'whitelisted');
    } catch (e) {
      setScanError(t('scanner.failedIgnore', { error: getErrorMessage(e) }));
    } finally {
      setThreatActionLoading(null);
    }
  };

  const handleQuarantineAll = async () => {
    const unresolvedThreats = scanThreats.filter(t => !threatResolutions[t.fileHash]);
    for (const threat of unresolvedThreats) {
      await handleQuarantineThreat(threat);
    }
  };

  const handleBrowseFolder = useCallback(async () => {
    try {
      const path = await pickScanFolder();
      if (path) setCustomPath(path);
    } catch (e) {
      console.error('Failed to pick folder:', e);
    }
  }, []);

  const handleBrowseFile = useCallback(async () => {
    try {
      const path = await pickScanFile();
      if (path) setCustomPath(path);
    } catch (e) {
      console.error('Failed to pick file:', e);
    }
  }, []);

  const handleExportReport = async () => {
    try {
      // Get downloads path for default save location
      const downloadsPath = await safeInvoke<string>('get_downloads_path');
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
      const filename = `scan-report-${timestamp}.json`;
      const outputPath = `${downloadsPath}\\${filename}`;

      await safeInvoke<string>('export_scan_report', { outputPath });

      setExportMessage(t('scanner.reportSaved', { path: outputPath }));
      setTimeout(() => setExportMessage(null), 5000);
    } catch (e) {
      console.error('[Scanner] Failed to export report:', e);
      setScanError(t('scanner.failedExport', { error: getErrorMessage(e) }));
    }
  };

  // Get unresolved threats
  const unresolvedThreats = scanThreats.filter(t => !threatResolutions[t.fileHash]);

  const getThreatResolutionMeta = (resolution: ThreatResolution) => {
    switch (resolution) {
      case 'quarantined':
        return {
          className: 'quarantined',
          label: t('scanner.quarantinedStatus'),
          icon: (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          ),
        };
      case 'deleted':
        return {
          className: 'deleted',
          label: t('scanner.deletedStatus'),
          icon: (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3 6 5 6 21 6" />
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
            </svg>
          ),
        };
      case 'whitelisted':
        return {
          className: 'whitelisted',
          label: t('scanner.whitelistedStatus'),
          icon: (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          ),
        };
    }
  };

  return (
    <div className="scanner">
      <div className="scanner-header">
        <h2>{t('scanner.title')}</h2>
        <p className="scanner-description">
          {t('scanner.description')}
        </p>
      </div>

      {/* Scan Progress */}
      {scanStatus?.isScanning && (
        <div className="scan-progress-card">
          <div className="scan-progress-header">
            <div className="scan-progress-title">
              <div className="scanning-indicator"></div>
              <span>
                {scanStatus.totalFiles === 0 ? (
                  // File collection phase - totalFiles not set yet
                  <>
                    {scanStatus.scanType === 'quick' && t('scanner.preparingQuick')}
                    {scanStatus.scanType === 'full' && t('scanner.preparingFull')}
                    {scanStatus.scanType === 'custom' && t('scanner.preparingCustom')}
                    {!scanStatus.scanType && t('scanner.preparingScan')}
                  </>
                ) : (
                  <>
                    {scanStatus.scanType === 'quick' && t('scanner.quickInProgress')}
                    {scanStatus.scanType === 'full' && t('scanner.fullInProgress')}
                    {scanStatus.scanType === 'custom' && t('scanner.customInProgress')}
                    {!scanStatus.scanType && t('scanner.scanning')}
                  </>
                )}
              </span>
            </div>
            <button className="btn-cancel" onClick={handleCancelScan}>
              {t('scanner.cancelScan')}
            </button>
          </div>

          {scanStatus.totalFiles === 0 ? (
            /* Indeterminate progress bar during file collection */
            <div className="scan-progress-bar">
              <div className="scan-progress-fill indeterminate" />
            </div>
          ) : (
            <div className="scan-progress-bar">
              <div
                className="scan-progress-fill"
                style={{ width: `${Math.min(100, Math.max(0, scanStatus.progressPercent))}%` }}
              />
            </div>
          )}

          <div className="scan-progress-stats">
            {scanStatus.totalFiles === 0 ? (
              <span className="progress-files collecting">{t('scanner.collectingFiles')}</span>
            ) : (
              <>
                <span className="progress-files">
                  {(() => {
                    const total = scanStatus.totalFiles || (scanStatus.filesScanned + scanStatus.filesRemaining);
                    const scanned = Math.min(scanStatus.filesScanned, total);
                    return t('scanner.filesProgress', { scanned, total });
                  })()}
                </span>
                <span className="progress-speed">
                  {scanStatus.filesPerSecond > 0 ? t('scanner.filesPerSecond', { speed: scanStatus.filesPerSecond.toFixed(1) }) : ''}
                </span>
                <span className="progress-percent">
                  {Math.min(100, Math.round(scanStatus.progressPercent))}%
                </span>
              </>
            )}
            <span className="progress-time">
              {formatDuration(scanStatus.elapsedSeconds)}
            </span>
          </div>

          {scanStatus.currentFile && (
            <div className="scan-current-file" title={scanStatus.currentFile}>
              <span className="current-file-label">{t('scanner.currentFile')}</span>
              <span className="current-file-path">
                {scanStatus.currentFile.length > 70
                  ? '...' + scanStatus.currentFile.slice(-67)
                  : scanStatus.currentFile}
              </span>
            </div>
          )}

          {scanStatus.totalFiles > 0 && (
            <div className="scan-live-counts">
              <div className="count-item clean">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>{scanStatus.cleanCount} {t('scanner.clean')}</span>
              </div>
              <div className="count-item suspicious">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M12 8v4M12 16h.01" />
                </svg>
                <span>{scanStatus.suspiciousCount} {t('scanner.suspicious')}</span>
              </div>
              <div className="count-item malware">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 6L6 18M6 6l12 12" />
                </svg>
                <span>{scanStatus.malwareCount} {t('scanner.malware')}</span>
              </div>
              {(() => {
                const effectiveScanned = scanStatus.totalFiles > 0
                  ? Math.min(scanStatus.filesScanned, scanStatus.totalFiles)
                  : scanStatus.filesScanned;
                const skipped = effectiveScanned - (scanStatus.cleanCount + scanStatus.suspiciousCount + scanStatus.malwareCount);
                return skipped > 0 ? (
                  <div className="count-item skipped">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                    </svg>
                    <span>{skipped} {t('scanner.skipped')}</span>
                  </div>
                ) : null;
              })()}
            </div>
          )}
        </div>
      )}

      {/* Scan Complete - unified summary + threats view */}
      {scanSummary && !scanStatus?.isScanning && (
        <div className="scan-complete-view">
          {/* Summary Header */}
          <div className="scan-summary-card">
            <div className="summary-header">
              <div className="summary-title-row">
                {(scanSummary.suspiciousCount > 0 || scanSummary.malwareCount > 0) ? (
                  <svg className="summary-icon warning" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <path d="M12 2L2 20h20L12 2z" />
                    <path d="M12 9v4M12 17h.01" />
                  </svg>
                ) : (
                  <svg className="summary-icon clean" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <path d="M8 12l3 3 5-6" />
                  </svg>
                )}
                <div>
                  <h3>{t('scanner.scanComplete')}</h3>
                  <span className="summary-type">{t('scanner.scanType', { type: scanSummary.scanType })}</span>
                </div>
              </div>
            </div>
            <div className="summary-stats">
              <div className="summary-stat">
                <span className="stat-value">{scanSummary.totalFiles}</span>
                <span className="stat-label">{t('scanner.filesScanned')}</span>
              </div>
              <div className="summary-stat">
                <span className="stat-value">{formatDuration(scanSummary.elapsedSeconds)}</span>
                <span className="stat-label">{t('scanner.duration')}</span>
              </div>
              <div className="summary-stat clean">
                <span className="stat-value">{scanSummary.cleanCount}</span>
                <span className="stat-label">{t('scanner.clean')}</span>
              </div>
              <div className="summary-stat suspicious">
                <span className="stat-value">{scanSummary.suspiciousCount}</span>
                <span className="stat-label">{t('scanner.suspicious')}</span>
              </div>
              <div className="summary-stat malware">
                <span className="stat-value">{scanSummary.malwareCount}</span>
                <span className="stat-label">{t('scanner.malware')}</span>
              </div>
              {(() => {
                const skipped = scanSummary.totalFiles - (scanSummary.cleanCount + scanSummary.suspiciousCount + scanSummary.malwareCount);
                return skipped > 0 ? (
                  <div className="summary-stat skipped">
                    <span className="stat-value">{skipped}</span>
                    <span className="stat-label">{t('scanner.skipped')}</span>
                  </div>
                ) : null;
              })()}
            </div>

            {/* Status messages */}
            {scanSummary.suspiciousCount === 0 && scanSummary.malwareCount === 0 && (
              <div className="summary-status clean">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M8 12l3 3 5-6" />
                </svg>
                <span>{t('scanner.noThreats')}</span>
              </div>
            )}
            {autoQuarantine && autoQuarantinedCount > 0 && (
              <div className="summary-status quarantined">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4z" />
                  <path d="M9 12l2 2 4-4" />
                </svg>
                <span>{t('scanner.autoQuarantined', { count: autoQuarantinedCount })}</span>
              </div>
            )}
            {!autoQuarantine && scanThreats.length > 0 && unresolvedThreats.length === 0 && (
              <div className="summary-status clean">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M8 12l3 3 5-6" />
                </svg>
                <span>{t('scanner.allResolved')}</span>
              </div>
            )}

            {/* Action buttons */}
            <div className="summary-actions">
              <button
                className="btn-new-scan"
                onClick={() => {
                  setScanSummary(null);
                  setScanThreats([]);
                  setThreatResolutions({});
                  setAutoQuarantinedCount(0);
                  setForceCompleted(false);
                  threatBufferRef.current = [];
                }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M23 4v6h-6M1 20v-6h6" />
                  <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
                </svg>
                {t('scanner.startNewScan')}
              </button>
              {!autoQuarantine && unresolvedThreats.length > 0 && (
                <button
                  className="btn-quarantine-all"
                  onClick={handleQuarantineAll}
                  disabled={!!threatActionLoading}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4z" />
                  </svg>
                  {t('scanner.quarantineAll')}
                </button>
              )}
              <button
                className="btn-export-report"
                onClick={handleExportReport}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                {t('scanner.exportReport')}
              </button>
            </div>
            {exportMessage && (
              <div className="export-success-message">
                {exportMessage}
              </div>
            )}
          </div>

          {/* Threat details - always shown if any threats were found */}
          {scanThreats.length > 0 && (
            <div className="scan-threats-card">
              <div className="threats-header">
                <h3>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <path d="M12 2L2 20h20L12 2z" />
                    <path d="M12 9v4M12 17h.01" />
                  </svg>
                  {unresolvedThreats.length > 0
                    ? `${t('scanner.threatsFound')} (${unresolvedThreats.length})`
                    : `${t('scanner.threatsFound')} (${scanThreats.length})`
                  }
                </h3>
              </div>

              <div className="threats-list">
                {scanThreats.map(threat => {
                  const resolution = threatResolutions[threat.fileHash];
                  const isResolved = !!resolution;
                  const resolutionMeta = resolution ? getThreatResolutionMeta(resolution) : null;
                  return (
                    <div key={threat.fileHash} className={`threat-item ${getVerdictClass(threat.verdict)} ${isResolved ? 'resolved' : ''}`}>
                      <div className="threat-info">
                        <div className="threat-name">
                          <span className={`threat-badge ${getVerdictClass(threat.verdict)}`}>
                            {t(getVerdictKey(threat.verdict))}
                          </span>
                          <span className="threat-filename" title={threat.filePath}>
                            {getFileName(threat.filePath)}
                          </span>
                        </div>
                        <div className="threat-path" title={threat.filePath}>
                          {threat.filePath.length > 60 ? '...' + threat.filePath.slice(-57) : threat.filePath}
                        </div>
                        {threat.threatName && (
                          <div className="threat-type">{threat.threatName}</div>
                        )}
                      </div>
                      {isResolved && resolutionMeta ? (
                        <div className={`threat-status-badge ${resolutionMeta.className}`}>
                          {resolutionMeta.icon}
                          {resolutionMeta.label}
                        </div>
                      ) : (
                        <div className="threat-actions">
                          <button
                            className="btn-threat-action quarantine"
                            onClick={() => handleQuarantineThreat(threat)}
                            disabled={threatActionLoading === threat.fileHash}
                          >
                            {threatActionLoading === threat.fileHash ? (
                              <span className="loading-spinner"></span>
                            ) : (
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4z" />
                              </svg>
                            )}
                            {t('realtime.quarantine')}
                          </button>
                          <button
                            className="btn-threat-action delete"
                            onClick={() => handleDeleteThreat(threat)}
                            disabled={threatActionLoading === threat.fileHash}
                          >
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <polyline points="3 6 5 6 21 6" />
                              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                            </svg>
                            {t('realtime.delete')}
                          </button>
                          <button
                            className="btn-threat-action ignore"
                            onClick={() => handleIgnoreThreat(threat)}
                            disabled={threatActionLoading === threat.fileHash}
                          >
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M9 12l2 2 4-4" />
                              <circle cx="12" cy="12" r="10" />
                            </svg>
                            {t('scanner.ignore')}
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Error Message */}
      {scanError && (
        <ErrorBanner message={scanError} onDismiss={() => setScanError(null)}>
          <button
            className="btn-reset-scan"
            onClick={async () => {
              try {
                await forceResetScan();
                setScanError(null);
                const status = await getScanStatus();
                setScanStatus(status);
              } catch (e) {
                console.error('Failed to reset scan:', e);
              }
            }}
          >
            {t('scanner.reset')}
          </button>
        </ErrorBanner>
      )}

      {/* Scan Options */}
      {!scanStatus?.isScanning && (
        <div className="scan-options">
          <div className="scan-card quick" onClick={() => handleStartScan('quick')}>
            <div className="scan-card-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 6v6l4 2" />
              </svg>
            </div>
            <div className="scan-card-content">
              <h3>{t('scanner.quickScan')}</h3>
              <p>{t('scanner.quickDescription')}</p>
              <ul className="scan-targets">
                <li>{t('scanner.quickTarget1')}</li>
                <li>{t('scanner.quickTarget2')}</li>
                <li>{t('scanner.quickTarget3')}</li>
                <li>{t('scanner.quickTarget4')}</li>
              </ul>
            </div>
            <div className="scan-card-time">{t('scanner.quickTime')}</div>
          </div>

          <div className="scan-card full" onClick={() => handleStartScan('full')}>
            <div className="scan-card-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
            </div>
            <div className="scan-card-content">
              <h3>{t('scanner.fullScan')}</h3>
              <p>{t('scanner.fullDescription')}</p>
              <ul className="scan-targets">
                <li>{t('scanner.fullTarget1')}</li>
                <li>{t('scanner.fullTarget2')}</li>
                <li>{t('scanner.fullTarget3')}</li>
              </ul>
            </div>
            <div className="scan-card-time">{t('scanner.fullTime')}</div>
          </div>

          <div className="scan-card custom">
            <div className="scan-card-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
              </svg>
            </div>
            <div className="scan-card-content">
              <h3>{t('scanner.customScan')}</h3>
              <p>{t('scanner.customDescription')}</p>
              <div className="custom-path-input">
                <input
                  type="text"
                  placeholder="C:\path\to\folder\or\file"
                  value={customPath}
                  onChange={(e) => setCustomPath(e.target.value)}
                  onClick={(e) => e.stopPropagation()}
                />
                <button
                  className="btn-browse"
                  onClick={(e) => { e.stopPropagation(); handleBrowseFolder(); }}
                  title={t('scanner.browseFolder')}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                  </svg>
                </button>
                <button
                  className="btn-browse"
                  onClick={(e) => { e.stopPropagation(); handleBrowseFile(); }}
                  title={t('scanner.browseFile')}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                  </svg>
                </button>
                <button
                  className="btn-scan-custom"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleStartScan('custom');
                  }}
                >
                  {t('scanner.scan')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scheduled Scans Section */}
      <div className="scheduled-scans-section">
        <div className="scheduled-header">
          <h3>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            {t('scanner.scheduledScans')}
          </h3>
        </div>

        {/* Scheduled Scans Cards Grid */}
        <div className="scan-options scheduled-scan-cards">
          {/* Add New Schedule Card */}
          <div
            className={`scan-card schedule-card add-schedule ${showScheduleForm ? 'active' : ''}`}
            onClick={() => !showScheduleForm && setShowScheduleForm(true)}
          >
            {!showScheduleForm ? (
              <>
                <div className="scan-card-icon">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <path d="M12 8v8M8 12h8" />
                  </svg>
                </div>
                <div className="scan-card-content">
                  <h3>{t('scanner.addSchedule')}</h3>
                  <p>{t('scanner.addScheduleDesc')}</p>
                  <ul className="scan-targets">
                    <li>{t('scanner.scheduleHint1')}</li>
                    <li>{t('scanner.scheduleHint2')}</li>
                    <li>{t('scanner.scheduleHint3')}</li>
                  </ul>
                </div>
              </>
            ) : (
              <div className="schedule-form-inline" onClick={(e) => e.stopPropagation()}>
                {scheduleError && (
                  <ErrorBanner message={scheduleError} onDismiss={() => setScheduleError(null)} />
                )}

                <div className="form-row">
                  <label>{t('scanner.scanName')}</label>
                  <input
                    type="text"
                    placeholder={t('scanner.namePlaceholder')}
                    value={scheduleForm.name}
                    onChange={(e) => setScheduleForm(prev => ({ ...prev, name: e.target.value }))}
                  />
                </div>

                <div className="form-row-group">
                  <div className="form-row">
                    <label>{t('scanner.scanTypeLabel')}</label>
                    <select
                      value={scheduleForm.scanType}
                      onChange={(e) => setScheduleForm(prev => ({ ...prev, scanType: e.target.value }))}
                    >
                      <option value="quick">{t('scanner.quickScan')}</option>
                      <option value="full">{t('scanner.fullScan')}</option>
                      <option value="custom">{t('scanner.customScan')}</option>
                    </select>
                  </div>

                  <div className="form-row">
                    <label>{t('scanner.frequency')}</label>
                    <select
                      value={scheduleForm.frequency}
                      onChange={(e) => setScheduleForm(prev => ({ ...prev, frequency: e.target.value }))}
                    >
                      <option value="daily">{t('scanner.daily')}</option>
                      <option value="weekly">{t('scanner.weekly')}</option>
                      <option value="monthly">{t('scanner.monthly')}</option>
                    </select>
                  </div>
                </div>

                {scheduleForm.scanType === 'custom' && (
                  <div className="form-row">
                    <label>{t('scanner.customPath')}</label>
                    <input
                      type="text"
                      placeholder="C:\path\to\scan"
                      value={scheduleForm.customPath || ''}
                      onChange={(e) => setScheduleForm(prev => ({ ...prev, customPath: e.target.value }))}
                    />
                  </div>
                )}

                <div className="form-row-group">
                  <div className="form-row">
                    <label>{t('scanner.time')}</label>
                    <input
                      type="time"
                      value={scheduleForm.timeOfDay}
                      onChange={(e) => setScheduleForm(prev => ({ ...prev, timeOfDay: e.target.value }))}
                    />
                  </div>

                  {scheduleForm.frequency === 'weekly' && (
                    <div className="form-row">
                      <label>{t('scanner.dayOfWeek')}</label>
                      <select
                        value={scheduleForm.dayOfWeek ?? 0}
                        onChange={(e) => setScheduleForm(prev => ({ ...prev, dayOfWeek: parseInt(e.target.value) }))}
                      >
                        <option value={0}>{t('scanner.days.sunday')}</option>
                        <option value={1}>{t('scanner.days.monday')}</option>
                        <option value={2}>{t('scanner.days.tuesday')}</option>
                        <option value={3}>{t('scanner.days.wednesday')}</option>
                        <option value={4}>{t('scanner.days.thursday')}</option>
                        <option value={5}>{t('scanner.days.friday')}</option>
                        <option value={6}>{t('scanner.days.saturday')}</option>
                      </select>
                    </div>
                  )}

                  {scheduleForm.frequency === 'monthly' && (
                    <div className="form-row">
                      <label>{t('scanner.dayOfMonth')}</label>
                      <input
                        type="number"
                        min={1}
                        max={28}
                        value={scheduleForm.dayOfMonth ?? 1}
                        onChange={(e) => setScheduleForm(prev => ({ ...prev, dayOfMonth: parseInt(e.target.value) }))}
                      />
                    </div>
                  )}
                </div>

                <div className="form-actions">
                  <button className="btn-cancel-schedule" onClick={() => setShowScheduleForm(false)}>
                    {t('scanner.cancel')}
                  </button>
                  <button className="btn-create-schedule" onClick={handleCreateSchedule}>
                    {t('scanner.create')}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Existing Scheduled Scans as Cards */}
          {scheduledScans.map(scan => (
            <div
              key={scan.id}
              className={`scan-card schedule-card existing-schedule ${scan.scanType} ${scan.enabled ? '' : 'disabled'}`}
            >
              <div className="scan-card-icon">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  {scan.scanType === 'quick' && (
                    <>
                      <circle cx="12" cy="12" r="10" />
                      <path d="M12 6v6l4 2" />
                    </>
                  )}
                  {scan.scanType === 'full' && (
                    <>
                      <path d="M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4z" />
                      <path d="M9 12l2 2 4-4" />
                    </>
                  )}
                  {scan.scanType === 'custom' && (
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                  )}
                </svg>
                <span className={`schedule-status-indicator ${scan.enabled ? 'enabled' : 'disabled'}`} />
              </div>
              <div className="scan-card-content">
                <h3>{scan.name}</h3>
                <p className="schedule-frequency-text">
                  {scan.frequency === 'daily' && t('scanner.scheduleDailyAt', { time: scan.timeOfDay })}
                  {scan.frequency === 'weekly' && t('scanner.scheduleWeeklyAt', { day: getDayName(scan.dayOfWeek ?? 0), time: scan.timeOfDay })}
                  {scan.frequency === 'monthly' && t('scanner.scheduleMonthlyAt', { day: scan.dayOfMonth, time: scan.timeOfDay })}
                </p>
                {scan.customPath && (
                  <p className="schedule-path-text" title={scan.customPath}>
                    📁 {scan.customPath.length > 25 ? '...' + scan.customPath.slice(-22) : scan.customPath}
                  </p>
                )}
                <div className="schedule-timing">
                  <span className="next-run-badge">
                    {t('scanner.nextRun')}: {formatNextRun(scan.nextRun)}
                  </span>
                </div>
              </div>
              <div className="schedule-card-actions">
                <button
                  className="btn-schedule-action run"
                  onClick={() => handleRunScheduleNow(scan.id)}
                  title={t('scanner.runNow')}
                  disabled={scanStatus?.isScanning}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                    <polygon points="5 3 19 12 5 21 5 3" />
                  </svg>
                </button>
                <button
                  className={`btn-schedule-action toggle ${scan.enabled ? 'enabled' : ''}`}
                  onClick={() => handleToggleSchedule(scan.id)}
                  title={scan.enabled ? t('scanner.disable') : t('scanner.enable')}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    {scan.enabled ? (
                      <>
                        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                        <path d="M13.73 21a2 2 0 0 1-3.46 0" />
                      </>
                    ) : (
                      <>
                        <path d="M13.73 21a2 2 0 0 1-3.46 0M18.63 13A17.89 17.89 0 0 1 18 8M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14" />
                        <line x1="1" y1="1" x2="23" y2="23" />
                      </>
                    )}
                  </svg>
                </button>
                <button
                  className="btn-schedule-action delete"
                  onClick={() => handleDeleteSchedule(scan.id)}
                  title={t('common.delete')}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M18 6L6 18M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
      <ConfirmDialog {...dialogProps} />
    </div>
  );
};
