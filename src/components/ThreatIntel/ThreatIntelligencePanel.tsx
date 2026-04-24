import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { ErrorBanner } from '../shared/ErrorBanner';
import type { DetailedScanResult, YaraMatch, VtDetection, SignatureInfo, EmulationSummary } from '../../types/threatIntel';
import { Verdict } from '../../types/scan';
import { getPersistenceForFile } from '../../services/api';
import type { FilePersistenceContext } from '../../types/insights';
import { getThreatLevelKey, parseVerdict } from '../../utils/verdict';
import './ThreatIntelligencePanel.css';

// ============================================================================
// SVG ICONS
// ============================================================================

const ShieldIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);

const AlertTriangleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);

const InfoIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><circle cx="12" cy="8" r="0.5" fill="currentColor"/>
  </svg>
);

const CheckCircleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
  </svg>
);

const FolderIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
  </svg>
);

const CopyIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
  </svg>
);

const ChevronIcon = ({ open }: { open: boolean }) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>
    <polyline points="6 9 12 15 18 9"/>
  </svg>
);

const TargetIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>
  </svg>
);

const LockIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
  </svg>
);

const NetworkIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="2" y="2" width="6" height="6" rx="1"/><rect x="16" y="2" width="6" height="6" rx="1"/><rect x="9" y="16" width="6" height="6" rx="1"/><path d="M5 8v3a1 1 0 001 1h12a1 1 0 001-1V8M12 12v4"/>
  </svg>
);

const CpuIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>
  </svg>
);

const ZapIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
  </svg>
);

const ActivityIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
  </svg>
);

const FileTextIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>
  </svg>
);

// ============================================================================
// SUB-COMPONENTS
// ============================================================================

const CollapsibleSection: React.FC<{
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
  badge?: string | number;
  badgeType?: 'danger' | 'warning' | 'success' | 'info';
}> = ({ title, icon, children, defaultOpen = false, badge, badgeType = 'info' }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="tip-section">
      <button onClick={() => setIsOpen(!isOpen)} className="tip-section-header">
        <span className="tip-section-icon">{icon}</span>
        <span className="tip-section-title">{title}</span>
        {badge !== undefined && (
          <span className={`tip-badge-small tip-badge-${badgeType}`}>{badge}</span>
        )}
        <span className="tip-section-chevron"><ChevronIcon open={isOpen} /></span>
      </button>
      {isOpen && <div className="tip-section-content">{children}</div>}
    </div>
  );
};

const CopyableHash: React.FC<{ hash: string }> = ({ hash }) => {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  const copyHash = async () => {
    await navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="tip-hash-box">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="tip-hash-icon">
        <line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>
      </svg>
      <code className="tip-hash-value">{hash}</code>
      <button onClick={copyHash} className="tip-copy-btn" title={t('threatIntel.copyHash')}>
        {copied ? <CheckCircleIcon /> : <CopyIcon />}
      </button>
    </div>
  );
};

const ConfidenceMeter: React.FC<{ value: number; label: string }> = ({ value, label }) => {
  const percentage = Math.round(value * 100);
  const getColor = () => {
    if (percentage >= 70) return 'high';
    if (percentage >= 40) return 'medium';
    return 'low';
  };

  return (
    <div className="tip-meter">
      <div className="tip-meter-header">
        <span>{label}</span>
        <span className="tip-meter-value">{percentage}%</span>
      </div>
      <div className="tip-meter-track">
        <div className={`tip-meter-fill tip-meter-${getColor()}`} style={{ width: `${percentage}%` }} />
      </div>
    </div>
  );
};

const DetectionEngineList: React.FC<{ detections: VtDetection[] }> = ({ detections }) => {
  const { t } = useTranslation();
  const detected = detections.filter(d => d.detected);
  const clean = detections.filter(d => !d.detected);

  return (
    <div className="tip-detection-list">
      {detected.length > 0 && (
        <div className="tip-detection-group">
          <h5 className="tip-detection-group-title danger">{t('threatIntel.detected', { count: detected.length })}</h5>
          <div className="tip-detection-grid">
            {detected.slice(0, 12).map((d, i) => (
              <div key={i} className="tip-detection-item detected">
                <span className="tip-detection-engine">{d.engine_name}</span>
                <span className="tip-detection-result">{d.result || t('threatIntel.malicious')}</span>
              </div>
            ))}
            {detected.length > 12 && (
              <div className="tip-detection-more">{t('threatIntel.more', { count: detected.length - 12 })}</div>
            )}
          </div>
        </div>
      )}
      {clean.length > 0 && (
        <div className="tip-detection-group">
          <h5 className="tip-detection-group-title success">{t('threatIntel.cleanEngines', { count: clean.length })}</h5>
          <p className="tip-detection-summary">{t('threatIntel.enginesNoThreats', { count: clean.length })}</p>
        </div>
      )}
    </div>
  );
};

const YaraMatchCard: React.FC<{ match: YaraMatch }> = ({ match }) => (
  <div className={`tip-yara-card severity-${match.severity.toLowerCase()}`}>
    <div className="tip-yara-header">
      <span className="tip-yara-name">{match.rule_name}</span>
      <span className={`tip-yara-severity severity-${match.severity.toLowerCase()}`}>{match.severity}</span>
    </div>
    {match.matched_strings && match.matched_strings.length > 0 && (
      <div className="tip-yara-strings">
        {match.matched_strings.slice(0, 3).map((s: string, i: number) => (
          <code key={i} className="tip-yara-string">{s}</code>
        ))}
        {match.matched_strings.length > 3 && <span className="tip-yara-more">+{match.matched_strings.length - 3}</span>}
      </div>
    )}
  </div>
);

const SignatureStatus: React.FC<{ info: SignatureInfo }> = ({ info }) => {
  const { t } = useTranslation();
  return (
    <div className={`tip-signature ${info.is_valid ? (info.is_trusted_publisher ? 'trusted' : 'valid') : 'invalid'}`}>
      <div className="tip-sig-status">
        {info.is_valid ? (
          info.is_trusted_publisher ? (
            <><CheckCircleIcon /> <span>{t('threatIntel.validTrusted')}</span></>
          ) : (
            <><CheckCircleIcon /> <span>{t('threatIntel.validSignature')}</span></>
          )
        ) : (
          <><AlertTriangleIcon /> <span>{t('threatIntel.invalidMissing')}</span></>
        )}
      </div>
      {info.signer_name && (
        <div className="tip-sig-row"><span className="label">{t('threatIntel.signer')}</span><span className="value">{info.signer_name}</span></div>
      )}
      {info.issuer && (
        <div className="tip-sig-row"><span className="label">{t('threatIntel.issuer')}</span><span className="value">{info.issuer}</span></div>
      )}
    </div>
  );
};

const BehaviorIndicatorList: React.FC<{ analysis: any }> = ({ analysis }) => {
  const { t } = useTranslation();
  const items: { label: string; items: string[]; severity: string }[] = [];

  if (analysis.suspicious_apis?.length > 0) {
    items.push({ label: t('threatIntel.suspiciousApis'), items: analysis.suspicious_apis, severity: 'high' });
  }
  if (analysis.dangerous_behaviors?.length > 0) {
    items.push({ label: t('threatIntel.dangerousBehaviors'), items: analysis.dangerous_behaviors, severity: 'critical' });
  }
  if (analysis.suspicious_strings?.length > 0) {
    items.push({ label: t('threatIntel.suspiciousStrings'), items: analysis.suspicious_strings, severity: 'medium' });
  }

  if (items.length === 0) return null;

  return (
    <div className="tip-behavior-list">
      {items.map((group, i) => (
        <div key={i} className="tip-behavior-group">
          <h5 className={`tip-behavior-title severity-${group.severity}`}>{group.label}</h5>
          <div className="tip-behavior-tags">
            {group.items.slice(0, 8).map((item, j) => (
              <span key={j} className={`tip-tag severity-${group.severity}`}>{item}</span>
            ))}
            {group.items.length > 8 && <span className="tip-tag-more">+{group.items.length - 8}</span>}
          </div>
        </div>
      ))}
    </div>
  );
};

const EmulationResults: React.FC<{ data: EmulationSummary }> = ({ data }) => {
  const { t } = useTranslation();
  return (
    <div className="tip-emulation">
      <div className="tip-emu-stats">
        <div className="tip-emu-stat">
          <span className="label">{t('threatIntel.instructions')}</span>
          <span className="value">{data.instructions_executed.toLocaleString()}</span>
        </div>
        <div className="tip-emu-stat">
          <span className="label">{t('threatIntel.memoryWrites')}</span>
          <span className="value">{data.memory_writes}</span>
        </div>
        <div className="tip-emu-stat">
          <span className="label">{t('threatIntel.apiCalls')}</span>
          <span className="value">{data.api_calls_made}</span>
        </div>
      </div>
      {(data.unpacking_detected || data.self_modifying_code) && (
        <div className="tip-emu-alerts">
          {data.unpacking_detected && <span className="tip-alert warning">{t('threatIntel.unpackingDetected')}</span>}
          {data.self_modifying_code && <span className="tip-alert danger">{t('threatIntel.selfModifyingCode')}</span>}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export interface ThreatIntelligencePanelProps {
  result: DetailedScanResult;
  onClose?: () => void;
  onQuarantine?: () => void;
  onWhitelist?: () => void;
  onRescan?: () => void;
}

export const ThreatIntelligencePanel: React.FC<ThreatIntelligencePanelProps> = ({
  result,
  onClose,
  onQuarantine,
  onWhitelist,
}) => {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const [persistenceContext, setPersistenceContext] = useState<FilePersistenceContext | null>(null);
  const [persistenceLoading, setPersistenceLoading] = useState(false);
  const detailed_results = result?.detailed_results || {};
  const verdictValue = parseVerdict(result?.verdict);

  useEffect(() => {
    if (result?.file_path && (verdictValue === Verdict.MALWARE || verdictValue === Verdict.SUSPICIOUS)) {
      setPersistenceLoading(true);
      getPersistenceForFile(result.file_path)
        .then(ctx => setPersistenceContext(ctx))
        .catch(() => setPersistenceContext(null))
        .finally(() => setPersistenceLoading(false));
    }
  }, [result?.file_path, verdictValue]);

  // Derive display values
  const fileName = result?.file_path?.split(/[/\\]/).pop() || t('threatIntel.unknownFile');
  const confidencePercent = Math.round((result?.confidence || 0) * 100);

  const getVerdictConfig = (verdict: Verdict) => {
    switch (verdict) {
      case Verdict.MALWARE: return { className: 'verdict-malware', label: t('threatIntel.malwareDetected') };
      case Verdict.SUSPICIOUS: return { className: 'verdict-suspicious', label: t('threatIntel.suspiciousLabel') };
      case Verdict.CLEAN: return { className: 'verdict-clean', label: t('threatIntel.cleanLabel') };
      default: return { className: 'verdict-unknown', label: t('threatIntel.unknownLabel') };
    }
  };

  const verdictConfig = getVerdictConfig(verdictValue);
  const translatePersistenceItemType = (itemType: string) => {
    switch (itemType) {
      case 'Service':
        return t('threatIntel.persistenceTypes.service');
      case 'Scheduled Task':
      case 'Task':
        return t('threatIntel.persistenceTypes.scheduledTask');
      default:
        return itemType;
    }
  };
  const translateObservation = (observation: string) => {
    const scriptFileMatch = observation.match(/^Script file \((.+)\)$/i);
    if (scriptFileMatch) {
      return t('threatIntel.observations.scriptFile', { ext: scriptFileMatch[1] });
    }

    switch (observation) {
      case 'Binary not found on disk':
        return t('threatIntel.observations.binaryMissing');
      case 'Script in user-writable location':
        return t('threatIntel.observations.scriptInUserWritableLocation');
      case 'Unsigned binary':
        return t('threatIntel.observations.unsignedBinary');
      case 'Invalid signature':
        return t('threatIntel.observations.invalidSignature');
      case 'Runs from user-writable location':
        return t('threatIntel.observations.runsFromUserWritableLocation');
      case 'Dead reference - target binary missing':
        return t('threatIntel.observations.deadReference');
      case 'Shortcut target not resolved':
        return t('threatIntel.observations.shortcutUnresolved');
      case 'Auto-start service from user-writable path':
        return t('threatIntel.observations.autostartServiceUserWritable');
      case 'SYSTEM-level service from user-writable path (unsigned)':
        return t('threatIntel.observations.systemServiceUserWritableUnsigned');
      default:
        return observation;
    }
  };

  // Derive threat name
  const derivedThreatName = result?.threat_name ||
    detailed_results.reputation_score?.suggested_names?.[0] ||
    detailed_results.ml_prediction?.malware_family ||
    null;

  // Example error handling: show error if result is missing or invalid
  if (!result) {
    return (
      <div className="threat-intel-panel">
        <ErrorBanner message={t('threatIntel.noResult')} />
      </div>
    );
  }

  return (
    <div className="threat-intel-panel">
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {/* Header - Compact with key info */}
      <div className={`tip-header ${verdictConfig.className}`}>
        <div className="tip-header-content">
          <div className="tip-verdict-icon">
            <ShieldIcon />
          </div>
          <div className="tip-verdict-info">
            <span className="tip-verdict-label">{verdictConfig.label}</span>
            <h2 className="tip-file-name">{derivedThreatName || fileName}</h2>
            {derivedThreatName && <span className="tip-file-subname">{fileName}</span>}
          </div>
          <div className="tip-confidence">
            <span className="tip-confidence-value">{confidencePercent}%</span>
            <span className="tip-confidence-label">{t('threatIntel.confidence')}</span>
          </div>
        </div>

        {onClose && (
          <button className="tip-close-btn" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        )}
      </div>

      {/* Scrollable Content */}
      <div className="tip-body">
        {/* Quick Stats Bar */}
        <div className="tip-quick-stats">
          <div className="tip-stat">
            <span className="tip-stat-label">{t('threatIntel.threatLevel')}</span>
            <span className={`tip-stat-value level-${(result.threat_level || 'unknown').toLowerCase()}`}>
              {t(getThreatLevelKey(result.threat_level))}
            </span>
          </div>
          <div className="tip-stat">
            <span className="tip-stat-label">{t('threatIntel.scanTime')}</span>
            <span className="tip-stat-value">{t('common.durationMs', { ms: result.scan_time_ms || 0 })}</span>
          </div>
          {detailed_results.reputation_score?.threat_count !== undefined && (
            <div className="tip-stat">
              <span className="tip-stat-label">{t('threatIntel.avDetections')}</span>
              <span className="tip-stat-value danger">
                {detailed_results.reputation_score.threat_count}/{detailed_results.reputation_score.detections?.length || 0}
              </span>
            </div>
          )}
          {detailed_results.static_analysis?.yara_matches && (
            <div className="tip-stat">
              <span className="tip-stat-label">{t('threatIntel.yaraMatches')}</span>
              <span className="tip-stat-value">{detailed_results.static_analysis.yara_matches.length}</span>
            </div>
          )}
        </div>

        {/* Hash Section - Single location */}
        <div className="tip-hash-section">
          <CopyableHash hash={result.file_hash} />
        </div>

        {/* Sections */}
        <div className="tip-sections">
          {/* Why Flagged - Always show */}
          <CollapsibleSection title={t('threatIntel.whyFlagged')} icon={<TargetIcon />} defaultOpen={true}>
            <div className="tip-why-flagged">
              <ul className="tip-reason-list">
                {confidencePercent > 50 && (
                  <li>
                    <span className="tip-reason-icon"><ActivityIcon /></span>
                    <span>{t('threatIntel.flaggedConfidence', { percent: confidencePercent })}</span>
                  </li>
                )}
                {derivedThreatName && derivedThreatName !== fileName && (
                  <li>
                    <span className="tip-reason-icon"><AlertTriangleIcon /></span>
                    <span>{t('threatIntel.matchedSignature', { name: derivedThreatName })} <strong>{derivedThreatName}</strong></span>
                  </li>
                )}
                {verdictValue === Verdict.MALWARE && (
                  <li>
                    <span className="tip-reason-icon"><AlertTriangleIcon /></span>
                    <span>{t('threatIntel.malwareCharacteristics')}</span>
                  </li>
                )}
                {verdictValue === Verdict.SUSPICIOUS && (
                  <li>
                    <span className="tip-reason-icon"><InfoIcon /></span>
                    <span>{t('threatIntel.riskyBehavior')}</span>
                  </li>
                )}
                {detailed_results.static_analysis?.entropy_score && detailed_results.static_analysis.entropy_score > 7.5 && (
                  <li>
                    <span className="tip-reason-icon"><LockIcon /></span>
                    <span>{t('threatIntel.highEntropy')}</span>
                  </li>
                )}
                {detailed_results.emulation_result?.unpacking_detected && (
                  <li>
                    <span className="tip-reason-icon"><CpuIcon /></span>
                    <span>{t('threatIntel.runtimeUnpacking')}</span>
                  </li>
                )}
              </ul>
            </div>
          </CollapsibleSection>

          {/* Recommended Action - Always show */}
          <CollapsibleSection title={t('threatIntel.recommendedAction')} icon={<ZapIcon />} defaultOpen={true}>
            <div className="tip-recommendation-box">
              {verdictValue === Verdict.MALWARE ? (
                <div className="tip-rec danger">
                  <div className="tip-rec-header">
                    <AlertTriangleIcon />
                    <strong>{t('threatIntel.quarantineImmediately')}</strong>
                  </div>
                  <p>{t('threatIntel.quarantineImmediatelyDesc')}</p>
                </div>
              ) : verdictValue === Verdict.SUSPICIOUS && confidencePercent > 60 ? (
                <div className="tip-rec warning">
                  <div className="tip-rec-header">
                    <AlertTriangleIcon />
                    <strong>{t('threatIntel.reviewQuarantine')}</strong>
                  </div>
                  <p>{t('threatIntel.reviewQuarantineDesc')}</p>
                </div>
              ) : (
                <div className="tip-rec info">
                  <div className="tip-rec-header">
                    <InfoIcon />
                    <strong>{t('threatIntel.possibleFP')}</strong>
                  </div>
                  <p>{t('threatIntel.possibleFPDesc')}</p>
                </div>
              )}
            </div>
          </CollapsibleSection>

          {/* File Location - Collapsed by default, no duplicate name/hash */}
          <CollapsibleSection title={t('threatIntel.fileLocation')} icon={<FolderIcon />} defaultOpen={false}>
            <div className="tip-file-location">
              <code>{result.file_path}</code>
            </div>
          </CollapsibleSection>

          {/* Digital Signature */}
          {detailed_results.signature_info && (
            <CollapsibleSection title={t('threatIntel.digitalSignature')} icon={<LockIcon />} defaultOpen={false}>
              <SignatureStatus info={detailed_results.signature_info} />
            </CollapsibleSection>
          )}

          {/* System Footprint / Persistence */}
          {(persistenceLoading || persistenceContext) && (
            <CollapsibleSection
              title={t('threatIntel.systemFootprint')}
              icon={<NetworkIcon />}
              defaultOpen={true}
              badge={persistenceContext
                ? (persistenceContext.startupEntries.length + persistenceContext.persistenceItems.length) || undefined
                : undefined}
              badgeType="warning"
            >
              {persistenceLoading ? (
                <div className="tip-persistence-loading">{t('threatIntel.checkingPersistence')}</div>
              ) : persistenceContext && (
                <div className="tip-persistence-section">
                  {persistenceContext.startupEntries.length === 0 && persistenceContext.persistenceItems.length === 0 ? (
                    <div className="tip-persistence-empty">{t('threatIntel.noPersistence')}</div>
                  ) : (
                    <>
                      {persistenceContext.startupEntries.map((entry, i) => (
                        <div key={`startup-${i}`} className="tip-persistence-item">
                          <span className="tip-persistence-type startup">{t('threatIntel.startup')}</span>
                          <div className="tip-persistence-info">
                            <span className="tip-persistence-name">{entry.name}</span>
                            <span className="tip-persistence-location">{entry.location}</span>
                          </div>
                        </div>
                      ))}
                      {persistenceContext.persistenceItems.map((item, i) => (
                        <div key={`persist-${i}`} className="tip-persistence-item">
                          <span className={`tip-persistence-type ${item.itemType === 'Service' ? 'service' : 'task'}`}>
                            {translatePersistenceItemType(item.itemType)}
                          </span>
                          <div className="tip-persistence-info">
                            <span className="tip-persistence-name">{item.name}</span>
                            {item.details && <span className="tip-persistence-detail">{item.details}</span>}
                          </div>
                        </div>
                      ))}
                    </>
                  )}
                  {persistenceContext.observations.length > 0 && (
                    <div className="tip-persistence-observations">
                      {persistenceContext.observations.map((obs, i) => (
                        <span key={i} className="tip-observation-tag">{translateObservation(obs)}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </CollapsibleSection>
          )}

          {/* AV Detections */}
          {detailed_results.reputation_score && detailed_results.reputation_score.detections && detailed_results.reputation_score.detections.length > 0 && (
            <CollapsibleSection
              title={t('threatIntel.avDetectionsTitle')}
              icon={<NetworkIcon />}
              badge={detailed_results.reputation_score.threat_count}
              badgeType={detailed_results.reputation_score.threat_count > 10 ? 'danger' : 'warning'}
              defaultOpen={detailed_results.reputation_score.threat_count > 0}
            >
              <DetectionEngineList detections={detailed_results.reputation_score.detections} />
            </CollapsibleSection>
          )}

          {/* YARA Matches */}
          {detailed_results.static_analysis && detailed_results.static_analysis.yara_matches && detailed_results.static_analysis.yara_matches.length > 0 && (
            <CollapsibleSection
              title={t('threatIntel.yaraSignatures')}
              icon={<FileTextIcon />}
              badge={detailed_results.static_analysis.yara_matches.length}
              badgeType="warning"
              defaultOpen={true}
            >
              <div className="tip-yara-list">
                {detailed_results.static_analysis.yara_matches.map((match: YaraMatch, i: number) => (
                  <YaraMatchCard key={i} match={match} />
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* ML Analysis - Only shows when backend provides it */}
          {detailed_results.ml_prediction && (
            <CollapsibleSection title={t('threatIntel.mlAnalysis')} icon={<CpuIcon />} defaultOpen={false}>
              <div className="tip-ml-section">
                <ConfidenceMeter value={detailed_results.ml_prediction.confidence} label={t('threatIntel.mlModelConfidence')} />
                {detailed_results.ml_prediction.malware_family && (
                  <div className="tip-ml-family">
                    <span className="label">{t('threatIntel.predictedFamily')}</span>
                    <span className="value">{detailed_results.ml_prediction.malware_family}</span>
                  </div>
                )}
              </div>
            </CollapsibleSection>
          )}

          {/* Behavior Analysis */}
          {detailed_results.behavior_analysis && (
            <CollapsibleSection title={t('threatIntel.behaviorIndicators')} icon={<ActivityIcon />} defaultOpen={false}>
              <BehaviorIndicatorList analysis={detailed_results.behavior_analysis} />
            </CollapsibleSection>
          )}

          {/* Emulation Results */}
          {detailed_results.emulation_result && (
            <CollapsibleSection title={t('threatIntel.emulationResults')} icon={<CpuIcon />} defaultOpen={false}>
              <EmulationResults data={detailed_results.emulation_result} />
            </CollapsibleSection>
          )}
        </div>
      </div>

      {/* Footer Actions */}
      <div className="tip-footer">
        <span className="tip-scan-time">{t('threatIntel.scannedIn', { ms: result.scan_time_ms || 0 })}</span>
        <div className="tip-actions">
          {onWhitelist && (
            <button className="tip-btn tip-btn-secondary" onClick={onWhitelist}>
              <CheckCircleIcon /> {t('threatIntel.whitelist')}
            </button>
          )}
          {onQuarantine && (
            <button className="tip-btn tip-btn-danger" onClick={onQuarantine}>
              <LockIcon /> {t('threatIntel.quarantine')}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
