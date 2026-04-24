/**
 * Integration test: verifies that hooks, utils, and types work together correctly
 * when composing the full app data flow (mock API → hook → display utils).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useDashboard } from '../hooks/useDashboard';
import { useSettings } from '../hooks/useSettings';
import { useQuarantine } from '../hooks/useQuarantine';
import { parseVerdict, getVerdictClass, getVerdictLabel, isThreat } from '../utils/verdict';
import { getFileName, formatFileSize, truncateHash } from '../utils/file';
import { formatError } from '../utils/error';
import { Verdict } from '../types/scan';

// Mock API
const mockSafeInvoke = vi.fn();
vi.mock('../services/api', () => ({
  safeInvoke: (...args: unknown[]) => mockSafeInvoke(...args),
  safeListen: vi.fn().mockResolvedValue(() => {}),
}));

describe('Integration: data flow from hooks to display', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockSafeInvoke.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('dashboard stats flow through to display-ready format', async () => {
    const rustStats = {
      total_scans: 250,
      malware_detected: 12,
      suspicious_detected: 8,
      quarantined_count: 5,
      threat_intel_count: 1000,
      last_scan_time: 1700000000,
      protection_status: 'active',
      active_malware: 3,
      active_suspicious: 2,
    };
    mockSafeInvoke.mockResolvedValue(rustStats);

    const { result } = renderHook(() => useDashboard('dashboard'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    const stats = result.current.stats!;
    expect(stats).not.toBeNull();

    // Verify the full pipeline: Rust snake_case → camelCase
    expect(stats.totalScans).toBe(250);
    expect(stats.malwareDetected).toBe(12);
    expect(stats.activeMalware + stats.activeSuspicious).toBe(5);
    expect(stats.protectionStatus).toBe('active');
  });

  it('settings + quarantine hooks work together for sidebar badge', async () => {
    const globalConfirm = globalThis.confirm;
    globalThis.confirm = vi.fn(() => true);

    // Setup settings
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_settings') {
        return Promise.resolve({
          realTimeProtection: true,
          autoQuarantine: true,
          cacheSizeMb: 100,
          cacheTtlHours: 24,
        });
      }
      if (cmd === 'list_quarantined') {
        return Promise.resolve([
          { id: 1, verdict: 'Malware', fileHash: 'abc', originalPath: 'C:\\file1.exe', fileSize: 1024 },
          { id: 2, verdict: 'Suspicious', fileHash: 'def', originalPath: 'C:\\file2.dll', fileSize: 2048 },
          { id: 3, verdict: 'Malware', fileHash: 'ghi', originalPath: 'C:\\file3.exe', fileSize: 512 },
        ]);
      }
      return Promise.resolve(null);
    });

    const { result: settingsResult } = renderHook(() => useSettings());
    const { result: quarantineResult } = renderHook(() => useQuarantine());

    await act(async () => {
      await settingsResult.current.getSettings();
    });
    await act(async () => {
      await quarantineResult.current.listQuarantined();
    });

    // Same logic App.tsx uses for sidebar badge
    const malwareCount = quarantineResult.current.quarantinedFiles
      .filter(f => f.verdict === 'Malware').length;
    expect(malwareCount).toBe(2);
    expect(settingsResult.current.settings?.realTimeProtection).toBe(true);

    globalThis.confirm = globalConfirm;
  });

  it('verdict parsing handles all backend string variants', () => {
    // All malware variants
    expect(parseVerdict('Malware')).toBe(Verdict.MALWARE);
    expect(parseVerdict('malicious')).toBe(Verdict.MALWARE);
    expect(parseVerdict('virus')).toBe(Verdict.MALWARE);

    // All suspicious variants
    expect(parseVerdict('Suspicious')).toBe(Verdict.SUSPICIOUS);
    expect(parseVerdict('pup')).toBe(Verdict.SUSPICIOUS);
    expect(parseVerdict('adware')).toBe(Verdict.SUSPICIOUS);
    expect(parseVerdict('potentially unwanted')).toBe(Verdict.SUSPICIOUS);

    // Clean
    expect(parseVerdict('Clean')).toBe(Verdict.CLEAN);
    expect(parseVerdict('safe')).toBe(Verdict.CLEAN);

    // Unknown / fallback
    expect(parseVerdict('Unknown')).toBe(Verdict.UNKNOWN);
    expect(parseVerdict(null)).toBe(Verdict.UNKNOWN);
    expect(parseVerdict(42)).toBe(Verdict.UNKNOWN);
  });

  it('verdict utilities compose for display rendering', () => {
    const verdict = parseVerdict('Malware');
    expect(getVerdictClass(verdict)).toBe('verdict-malware');
    expect(getVerdictLabel(verdict)).toBe('Malware');
    expect(isThreat(verdict)).toBe(true);

    const clean = parseVerdict('Clean');
    expect(getVerdictClass(clean)).toBe('verdict-clean');
    expect(isThreat(clean)).toBe(false);
  });

  it('file utilities handle edge cases', () => {
    expect(getFileName('C:\\Users\\admin\\Downloads\\malware.exe')).toBe('malware.exe');
    expect(getFileName('/usr/bin/suspicious')).toBe('suspicious');
    expect(getFileName('')).toBe('Unknown file');

    expect(formatFileSize(0)).toBe('0 B');
    expect(formatFileSize(1024)).toBe('1 KB');
    expect(formatFileSize(1536)).toBe('1.5 KB');
    expect(formatFileSize(1048576)).toBe('1 MB');

    expect(truncateHash('abcdef1234567890abcdef1234567890')).toBe('abcdef1234567890...');
    expect(truncateHash('short')).toBe('short');
    expect(truncateHash('')).toBe('');
  });

  it('error formatting handles all types consistently', () => {
    expect(formatError(new Error('Test error'))).toBe('Test error');
    expect(formatError('string error')).toBe('string error');
    expect(formatError({ message: 'object error' })).toBe('object error');
    expect(formatError(42)).toBe('42');
    expect(formatError(null)).toBe('null');
  });
});
