/**
 * Shared verdict utilities used across the application
 */

import { Verdict } from '../types/scan';

/**
 * Parse a verdict string from the backend into the Verdict enum
 */
export function parseVerdict(v: unknown): Verdict {
  if (typeof v === 'string') {
    const lower = v.toLowerCase().trim();
    if (lower === 'clean' || lower === 'safe') return Verdict.CLEAN;
    if (lower === 'malware' || lower === 'malicious' || lower === 'virus') return Verdict.MALWARE;
    // PUP is treated as Suspicious
    if (lower === 'suspicious' || lower === 'pup' || lower === 'potentially unwanted' || lower === 'adware') return Verdict.SUSPICIOUS;
  }
  // Unknown = couldn't determine verdict (scan error, unsupported file, etc.)
  return Verdict.UNKNOWN;
}

/**
 * Get the CSS class name for a verdict
 */
export function getVerdictClass(verdict: Verdict): string {
  switch (verdict) {
    case Verdict.MALWARE: return 'verdict-malware';
    case Verdict.SUSPICIOUS: return 'verdict-suspicious';
    default: return 'verdict-clean';
  }
}

/**
 * Get the human-readable label for a verdict
 */
export function getVerdictLabel(verdict: Verdict): string {
  switch (verdict) {
    case Verdict.MALWARE: return 'Malware';
    case Verdict.SUSPICIOUS: return 'Suspicious';
    case Verdict.CLEAN: return 'Clean';
    default: return 'Unknown';
  }
}

/**
 * Get the translation key for a verdict
 */
export function getVerdictKey(verdict: Verdict): string {
  switch (verdict) {
    case Verdict.MALWARE: return 'verdict.malware';
    case Verdict.SUSPICIOUS: return 'verdict.suspicious';
    case Verdict.CLEAN: return 'verdict.clean';
    default: return 'verdict.unknown';
  }
}

/**
 * Get the translation key for a threat level label
 */
export function getThreatLevelKey(level: string | null | undefined): string {
  const normalized = (level ?? '').toLowerCase().trim();

  switch (normalized) {
    case 'critical': return 'common.threatLevels.critical';
    case 'high': return 'common.threatLevels.high';
    case 'medium': return 'common.threatLevels.medium';
    case 'low': return 'common.threatLevels.low';
    default: return 'common.threatLevels.unknown';
  }
}

/**
 * Check if a verdict represents a threat
 */
export function isThreat(verdict: Verdict): boolean {
  return verdict === Verdict.MALWARE || verdict === Verdict.SUSPICIOUS;
}
