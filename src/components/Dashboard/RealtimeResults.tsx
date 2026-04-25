import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import type { ScanResult, DetailedResults } from '../../types/scan';
import type { DetailedScanResult, DetailedResults as ThreatIntelDetailedResults } from '../../types/threatIntel';
import { Verdict } from '../../types/scan';
import { safeInvoke, ignoreThreat } from '../../services/api';
import { useConfirmDialog } from '../../hooks/useConfirmDialog';
import { ThreatIntelligencePanel } from '../ThreatIntel/ThreatIntelligencePanel';
import { getThreatLevelKey, getVerdictClass, getVerdictKey, isThreat } from '../../utils/verdict';
import { getFileName } from '../../utils/file';
import './RealtimeResults.css';

import { ErrorBanner } from '../shared/ErrorBanner';
import { ConfirmDialog } from '../shared/ConfirmDialog';

export interface RealtimeResultsProps {
  results: ScanResult[];
  onThreatResolved?: (threatId: string) => void;
}

type ActionType = 'quarantine' | 'delete' | 'ignore';

interface ActionState {
  threatId: string;
  action: ActionType;
  loading: boolean;
}

const getErrorMessage = (err: unknown) =>
  err instanceof Error ? err.message : String(err);

const normalizePathKey = (filePath: string) =>
  filePath.replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();

const getFolderHint = (filePath: string) => {
  const parts = filePath.replace(/\//g, '\\').split('\\').filter(Boolean);
  const directories = parts.slice(0, -1);
  if (directories.length === 0) return filePath;
  return directories.slice(-2).join('\\');
};

// Convert scan.DetailedResults to threatIntel.DetailedResults format
const convertDetailedResults = (details?: DetailedResults): ThreatIntelDetailedResults => {
  if (!details) return {};

  return {
    static_analysis: details.static_analysis ? {
      yara_matches: details.static_analysis.yara_matches?.map(m => ({
        rule_name: m.rule_name,
        severity: m.severity,
        description: m.description || '',
        category: m.category || 'unknown',
        offset: m.offset,
        matched_strings: [],
      })),
      entropy_score: details.static_analysis.entropy_score,
      is_whitelisted: details.static_analysis.is_whitelisted,
      is_blacklisted: details.static_analysis.is_blacklisted,
      suspicious_characteristics: details.static_analysis.suspicious_characteristics,
    } : undefined,
    ml_prediction: details.ml_prediction ? {
      is_malware: details.ml_prediction.is_malware,
      confidence: details.ml_prediction.confidence,
      malware_family: details.ml_prediction.malware_family,
      model_version: details.ml_prediction.model_version,
      model_available: details.ml_prediction.model_available,
      verdict: details.ml_prediction.verdict as any,
      raw_score: details.ml_prediction.raw_score,
    } : undefined,
    reputation_score: details.reputation_score ? {
      overall_score: details.reputation_score.overall_score,
      threat_count: details.reputation_score.threat_count,
      last_analysis_date: details.reputation_score.last_analysis_date,
      sources: details.reputation_score.sources,
      detections: details.reputation_score.detections?.map(d => ({
        engine_name: d.engine_name,
        category: d.category,
        result: d.result,
        detected: d.detected,
      })) || [],
      suggested_names: details.reputation_score.suggested_names,
    } : undefined,
    novelty_score: details.novelty_score ? {
      is_novel: details.novelty_score.is_novel,
      anomaly_score: details.novelty_score.anomaly_score,
      confidence: details.novelty_score.confidence,
    } : undefined,
    behavior_analysis: details.behavior_analysis ? {
      behavior_score: details.behavior_analysis.behavior_score,
      suspicious_behaviors: details.behavior_analysis.suspicious_behaviors,
      api_indicators: details.behavior_analysis.api_indicators,
      string_indicators: details.behavior_analysis.string_indicators,
    } : undefined,
    emulation_result: details.emulation_result ? {
      instructions_executed: details.emulation_result.instructions_executed,
      detected_oep: details.emulation_result.detected_oep,
      api_call_count: details.emulation_result.api_call_count,
      suspicious_behaviors: details.emulation_result.suspicious_behaviors,
      unpacking_detected: details.emulation_result.unpacking_detected,
    } : undefined,
    signature_info: details.signature_info ? {
      is_signed: details.signature_info.is_signed,
      is_valid: details.signature_info.is_valid,
      signer_name: details.signature_info.signer_name,
      is_trusted_publisher: details.signature_info.is_trusted_publisher,
    } : undefined,
  };
};

// Merge detailed results from event payload with fetched database info
const toDetailedResult = (result: ScanResult, fetchedData?: any): DetailedScanResult => {
  const eventDetails = convertDetailedResults(result.detailedResults);
  const mergedDetails = { ...eventDetails };

  if (fetchedData) {
    if (fetchedData.intel_threat_name || fetchedData.malware_family) {
      if (!mergedDetails.reputation_score) {
        mergedDetails.reputation_score = {
          overall_score: 0,
          threat_count: 0,
          last_analysis_date: 0,
          sources: [],
          detections: [],
          suggested_names: [],
        };
      }
      if (fetchedData.intel_threat_name && !mergedDetails.reputation_score.suggested_names?.length) {
        mergedDetails.reputation_score.suggested_names = [fetchedData.intel_threat_name];
      }
    }

    if (fetchedData.external_reports?.length > 0 && mergedDetails.reputation_score) {
      mergedDetails.reputation_score.sources = [
        ...(mergedDetails.reputation_score.sources || []),
        ...fetchedData.external_reports.map((r: any) => r.provider),
      ];
    }
  }

  const pinnedGenericSuspiciousHeadline =
    result.verdict === Verdict.SUSPICIOUS
    && (result.threatName === 'Suspicious.Activity' || fetchedData?.threat_name === 'Suspicious.Activity');

  const threatName = pinnedGenericSuspiciousHeadline
    ? 'Suspicious.Activity'
    : result.threatName
      || fetchedData?.threat_name
      || fetchedData?.intel_threat_name
      || mergedDetails.reputation_score?.suggested_names?.[0]
      || mergedDetails.ml_prediction?.malware_family;

  return {
    file_hash: result.fileHash,
    file_path: result.filePath,
    verdict: result.verdict === Verdict.MALWARE ? 'Malware' :
             result.verdict === Verdict.SUSPICIOUS ? 'Suspicious' :
             result.verdict === Verdict.CLEAN ? 'Clean' : 'Unknown',
    confidence: result.confidence,
    threat_level: result.threatLevel,
    threat_name: threatName,
    scan_time_ms: result.scanTimeMs,
    detailed_results: mergedDetails,
  };
};

export const RealtimeResults: React.FC<RealtimeResultsProps> = React.memo(({ results, onThreatResolved }) => {
  const { t } = useTranslation();
  const [expandedItem, setExpandedItem] = useState<string | null>(null);
  const [detailPanelItem, setDetailPanelItem] = useState<ScanResult | null>(null);
  const [detailedData, setDetailedData] = useState<any>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [actionState, setActionState] = useState<ActionState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [resolvedThreatIds, setResolvedThreatIds] = useState<Set<string>>(new Set());
  const { confirm: confirmDialog, dialogProps } = useConfirmDialog();

  const fetchDetailedInfo = async (result: ScanResult) => {
    if (!result.detailedResults) {
      setLoadingDetails(true);
    }
    try {
      const data = await safeInvoke<any>('get_full_threat_info', { threatId: result.threatId });
      setDetailedData(data);
    } catch {
      setDetailedData(null);
    } finally {
      setLoadingDetails(false);
    }
  };

  const openDetailPanel = async (result: ScanResult) => {
    setDetailPanelItem(result);
    if (result.detailedResults) {
      setLoadingDetails(false);
      fetchDetailedInfo(result).catch(() => {});
    } else {
      await fetchDetailedInfo(result);
    }
  };

  const closeDetailPanel = () => {
    setDetailPanelItem(null);
    setDetailedData(null);
  };

  const handleQuarantine = async (result: ScanResult) => {
    if (!await confirmDialog({
      title: t('realtime.confirmQuarantineTitle'),
      message: t('realtime.confirmQuarantineMessage'),
      confirmLabel: t('realtime.quarantine'),
      variant: 'warning',
    })) return;
    setActionState({ threatId: result.threatId, action: 'quarantine', loading: true });
    setError(null);
    try {
      await safeInvoke('quarantine_file_by_path', {
        filePath: result.filePath, fileHash: result.fileHash,
        verdict: result.verdict, threatLevel: result.threatLevel,
      });
      setResolvedThreatIds(prev => new Set(prev).add(result.threatId));
      onThreatResolved?.(result.threatId);
      setExpandedItem(null);
      closeDetailPanel();
    } catch (err) {
      setError(t('scanner.failedQuarantine', { error: getErrorMessage(err) }));
    } finally {
      setActionState(null);
    }
  };

  const handleDelete = async (result: ScanResult) => {
    if (!await confirmDialog({
      title: t('realtime.confirmDeleteTitle'),
      message: t('realtime.confirmDeleteMessage'),
      confirmLabel: t('realtime.delete'),
      variant: 'danger',
    })) return;
    setActionState({ threatId: result.threatId, action: 'delete', loading: true });
    setError(null);
    try {
      await safeInvoke('delete_threat_file', { filePath: result.filePath, fileHash: result.fileHash });
      setResolvedThreatIds(prev => new Set(prev).add(result.threatId));
      onThreatResolved?.(result.threatId);
      setExpandedItem(null);
      closeDetailPanel();
    } catch (err) {
      setError(t('scanner.failedDelete', { error: getErrorMessage(err) }));
    } finally {
      setActionState(null);
    }
  };

  const handleIgnore = async (result: ScanResult) => {
    setActionState({ threatId: result.threatId, action: 'ignore', loading: true });
    setError(null);
    try {
      await ignoreThreat(result.fileHash, result.filePath);
      setResolvedThreatIds(prev => new Set(prev).add(result.threatId));
      onThreatResolved?.(result.threatId);
      setExpandedItem(null);
      closeDetailPanel();
    } catch (err) {
      setError(t('scanner.failedIgnore', { error: getErrorMessage(err) }));
    } finally {
      setActionState(null);
    }
  };

  const isLoading = (threatId: string, action: ActionType) =>
    actionState?.threatId === threatId && actionState?.action === action && actionState?.loading;

  const displayResults = useMemo(() => {
    const filtered = results.filter(
      r => isThreat(r.verdict) && !resolvedThreatIds.has(r.threatId) && r.threatId && r.fileHash && r.filePath
    );
    const seenPaths = new Set<string>();
    return filtered.filter(r => {
      const pathKey = normalizePathKey(r.filePath);
      if (seenPaths.has(pathKey)) return false;
      seenPaths.add(pathKey);
      return true;
    });
  }, [results, resolvedThreatIds]);

  const basenameCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const result of displayResults) {
      const basename = getFileName(result.filePath);
      counts.set(basename, (counts.get(basename) ?? 0) + 1);
    }
    return counts;
  }, [displayResults]);

  const itemRefs = useRef<Map<string, HTMLDivElement | null>>(new Map());

  useEffect(() => {
    if (!expandedItem) return;
    const el = itemRefs.current.get(expandedItem) || null;
    if (el) {
      try {
        el.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
      } catch {
        el.scrollIntoView();
      }
      try {
        el.focus?.({ preventScroll: true } as any);
      } catch {
        el.focus?.();
      }
    }
  }, [expandedItem]);

  if (results.length === 0) {
    return (
      <div className="realtime-results-minimal">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
        <p>{t('realtime.monitoringActive')}</p>
      </div>
    );
  }

  if (displayResults.length === 0) {
    return (
      <div className="realtime-results-minimal">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M9 12l2 2 4-4" />
          <circle cx="12" cy="12" r="10" />
        </svg>
        <p>{t('realtime.allClean')}</p>
      </div>
    );
  }

  return (
    <>
      <div className="realtime-results">
        <h3 className="realtime-results-title">
          {t('realtime.activeThreats')}
          <span className="results-count">{displayResults.length}</span>
        </h3>

        {displayResults.length > 20 && (
          <div className="results-warning">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M12 2L2 20h20L12 2z" /><path d="M12 9v4M12 17h.01" />
            </svg>
            <span>{t('realtime.unresolvedWarning', { count: displayResults.length })}</span>
          </div>
        )}

        {error && (
          <ErrorBanner message={error} onDismiss={() => setError(null)} />
        )}

        {expandedItem && (
          <div className="results-backdrop" onClick={() => setExpandedItem(null)} />
        )}

        <div className={`results-list ${expandedItem ? 'has-expanded' : ''}`}>
          {displayResults.map((result) => {
            const isExpanded = expandedItem === result.threatId;
            const isCurrentLoading = actionState?.threatId === result.threatId;
            const basename = getFileName(result.filePath);
            const showFolderHint = (basenameCounts.get(basename) ?? 0) > 1;

            return (
              <div
                key={result.threatId}
                className={`result-item ${getVerdictClass(result.verdict)} ${isExpanded ? 'expanded' : ''}`}
                ref={(el) => {
                  if (el) itemRefs.current.set(result.threatId, el);
                  else itemRefs.current.delete(result.threatId);
                }}
                tabIndex={isExpanded ? -1 : undefined}
              >
                <div
                  className="result-main"
                  onClick={() => setExpandedItem(isExpanded ? null : result.threatId)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setExpandedItem(isExpanded ? null : result.threatId);
                    }
                  }}
                >
                  <div className="result-verdict">
                    <span className={`verdict-badge ${getVerdictClass(result.verdict)}`}>
                      {t(getVerdictKey(result.verdict))}
                    </span>
                  </div>
                  <div className="result-details">
                    <span className="result-filename" title={result.filePath}>{basename}</span>
                    {showFolderHint && (
                      <span className="result-folder-hint" title={result.filePath}>
                        {getFolderHint(result.filePath)}
                      </span>
                    )}
                    {result.threatName && <span className="result-threat">{result.threatName}</span>}
                  </div>
                  <div className="result-confidence">{Math.round(result.confidence * 100)}%</div>
                  <div className="result-expand-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d={isExpanded ? "M18 15l-6-6-6 6" : "M6 9l6 6 6-6"} />
                    </svg>
                  </div>
                </div>

                {isExpanded && (
                  <div className="result-expanded">
                    <div className="result-path">
                      <span className="path-label">{t('realtime.fullPath')}</span>
                      <span className="path-value">{result.filePath}</span>
                    </div>

                    <div className="result-actions">
                      <button className="action-btn quarantine" onClick={() => handleQuarantine(result)} disabled={isCurrentLoading}>
                        {isLoading(result.threatId, 'quarantine') ? <span className="spinner" /> : (
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" />
                          </svg>
                        )}
                        {t('realtime.quarantine')}
                      </button>

                      <button className="action-btn delete" onClick={() => handleDelete(result)} disabled={isCurrentLoading}>
                        {isLoading(result.threatId, 'delete') ? <span className="spinner" /> : (
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="3 6 5 6 21 6" />
                            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                          </svg>
                        )}
                        {t('realtime.delete')}
                      </button>

                      <button className="action-btn ignore" onClick={() => handleIgnore(result)} disabled={isCurrentLoading}>
                        {isLoading(result.threatId, 'ignore') ? <span className="spinner" /> : (
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" />
                          </svg>
                        )}
                        {t('realtime.trustWhitelist')}
                      </button>

                      <button className="action-btn details" onClick={() => openDetailPanel(result)}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
                        </svg>
                        {t('realtime.viewFullAnalysis')}
                      </button>
                    </div>

                    <div className="result-info">
                      <span className="info-item"><strong>{t('realtime.confidence')}</strong><span>{Math.round(result.confidence * 100)}%</span></span>
                      <span className="info-item"><strong>{t('realtime.threatLevel')}</strong><span className={`level-badge level-${result.threatLevel.toLowerCase()}`}>{t(getThreatLevelKey(result.threatLevel))}</span></span>
                      {result.threatName && <span className="info-item"><strong>{t('realtime.detection')}</strong><span className="threat-name-tag">{result.threatName}</span></span>}
                      <span className="info-item"><strong>{t('realtime.hash')}</strong><span className="mono-text">{result.fileHash.substring(0, 16)}...</span></span>
                    </div>

                    {/* Quick Analysis Summary */}
                    {result.detailedResults && (
                      <div className="quick-analysis-summary">
                        {result.detailedResults.static_analysis?.yara_matches && result.detailedResults.static_analysis.yara_matches.length > 0 && (
                          <div className="analysis-badge yara">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/>
                            </svg>
                            {t('realtime.yaraMatch', { count: result.detailedResults.static_analysis.yara_matches.length })}
                          </div>
                        )}
                        {result.detailedResults.reputation_score?.threat_count !== undefined && result.detailedResults.reputation_score.threat_count > 0 && (
                          <div className="analysis-badge reputation">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                              <circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>
                            </svg>
                            {t('realtime.avDetection', { count: result.detailedResults.reputation_score.threat_count })}
                          </div>
                        )}
                        {result.detailedResults.ml_prediction?.is_malware && (
                          <div className="analysis-badge ml">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>
                            </svg>
                            {t('realtime.mlConfidence', { percent: Math.round((result.detailedResults.ml_prediction.confidence || 0) * 100) })}
                          </div>
                        )}
                        {result.detailedResults.behavior_analysis?.behavior_score !== undefined && result.detailedResults.behavior_analysis.behavior_score > 0.5 && (
                          <div className="analysis-badge behavior">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                            {t('realtime.suspiciousBehavior')}
                          </div>
                        )}
                        {result.detailedResults.signature_info?.is_signed === false && (
                          <div className="analysis-badge unsigned">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
                            </svg>
                            {t('realtime.unsigned')}
                          </div>
                        )}
                      </div>
                    )}

                    {result.confidence < 0.7 && (
                      <div className="fp-hint">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                          <circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" />
                        </svg>
                        <span>{t('realtime.fpHint')}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail Panel Modal */}
      {detailPanelItem && (
        <div className="detail-panel-overlay" onClick={closeDetailPanel}>
          <div className="detail-panel-container" onClick={e => e.stopPropagation()}>
            {loadingDetails ? (
              <div className="detail-panel-loading">
                <div className="spinner large" />
                <p>{t('realtime.loadingThreatIntel')}</p>
              </div>
            ) : (
              <ThreatIntelligencePanel
                result={toDetailedResult(detailPanelItem, detailedData)}
                onClose={closeDetailPanel}
                onQuarantine={() => handleQuarantine(detailPanelItem)}
                onWhitelist={() => handleIgnore(detailPanelItem)}
              />
            )}
          </div>
        </div>
      )}
      <ConfirmDialog {...dialogProps} />
    </>
  );
});

RealtimeResults.displayName = 'RealtimeResults';
