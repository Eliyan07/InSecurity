import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useDashboard } from '../useDashboard';

const mockSafeInvoke = vi.fn();
vi.mock('../../services/api', () => ({
  safeInvoke: (...args: unknown[]) => mockSafeInvoke(...args),
}));

const mockRustStats = {
  total_scans: 100,
  malware_detected: 5,
  suspicious_detected: 10,
  quarantined_count: 3,
  threat_intel_count: 500,
  last_scan_time: 1700000000,
  protection_status: 'active',
  active_malware: 2,
  active_suspicious: 4,
};

describe('useDashboard', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockSafeInvoke.mockReset();
    // Default: initial auto-load succeeds
    mockSafeInvoke.mockResolvedValue(mockRustStats);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('starts with null stats', () => {
    mockSafeInvoke.mockImplementation(() => new Promise(() => {})); // never resolve
    const { result } = renderHook(() => useDashboard());
    // Before effect runs, stats is null
    expect(result.current.stats).toBeNull();
  });

  it('auto-loads stats on mount', async () => {
    const { result } = renderHook(() => useDashboard());

    // Flush the initial useEffect async call
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.stats).not.toBeNull();
    expect(result.current.stats?.totalScans).toBe(100);
    expect(result.current.stats?.malwareDetected).toBe(5);
    expect(result.current.stats?.protectionStatus).toBe('active');
  });

  it('maps snake_case fields to camelCase', async () => {
    const { result } = renderHook(() => useDashboard());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    const stats = result.current.stats!;
    expect(stats.totalScans).toBe(100);
    expect(stats.suspiciousDetected).toBe(10);
    expect(stats.quarantinedCount).toBe(3);
    expect(stats.threatIntelCount).toBe(500);
    expect(stats.lastScanTime).toBe(1700000000);
    expect(stats.activeMalware).toBe(2);
    expect(stats.activeSuspicious).toBe(4);
  });

  it('refresh manually loads stats', async () => {
    const { result } = renderHook(() => useDashboard());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    mockSafeInvoke.mockResolvedValueOnce({
      ...mockRustStats,
      total_scans: 200,
    });

    await act(async () => {
      await result.current.refresh();
    });

    expect(result.current.stats?.totalScans).toBe(200);
    expect(result.current.error).toBeNull();
  });

  it('handles errors on refresh', async () => {
    const { result } = renderHook(() => useDashboard());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    mockSafeInvoke.mockRejectedValueOnce(new Error('Network error'));

    await act(async () => {
      await result.current.refresh();
    });

    expect(result.current.error).toBe('Network error');
  });

  it('handles non-Error exceptions', async () => {
    const { result } = renderHook(() => useDashboard());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    mockSafeInvoke.mockRejectedValueOnce('string error');

    await act(async () => {
      await result.current.refresh();
    });

    expect(result.current.error).toBe('Failed to load dashboard stats');
  });

  it('sets loading during fetch', async () => {
    let resolvePromise: (v: unknown) => void;
    mockSafeInvoke.mockImplementation(
      () => new Promise((r) => { resolvePromise = r; })
    );

    const { result } = renderHook(() => useDashboard());

    // Loading should eventually be true during the fetch
    await act(async () => {
      resolvePromise!(mockRustStats);
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.loading).toBe(false);
  });

  it('calls get_dashboard_stats', async () => {
    const { result: _ } = renderHook(() => useDashboard());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(mockSafeInvoke).toHaveBeenCalledWith('get_dashboard_stats');
  });

  it('polls every 10 seconds when activeNav is dashboard', async () => {
    const { result: _ } = renderHook(() => useDashboard('dashboard'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const callsAfterMount = mockSafeInvoke.mock.calls.length;

    // Advance 10s - should poll again
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(mockSafeInvoke.mock.calls.length).toBeGreaterThan(callsAfterMount);
  });

  it('does not poll when activeNav is not dashboard', async () => {
    const { result: _ } = renderHook(() => useDashboard('scanner'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const callsAfterMount = mockSafeInvoke.mock.calls.length;

    // Advance 10s - should NOT poll because activeNav is 'scanner'
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(mockSafeInvoke.mock.calls.length).toBe(callsAfterMount);
  });

  it('handles error on initial mount fetch', async () => {
    mockSafeInvoke.mockRejectedValue(new Error('Init failure'));
    const { result } = renderHook(() => useDashboard());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.error).toBe('Init failure');
    expect(result.current.stats).toBeNull();
  });
});
