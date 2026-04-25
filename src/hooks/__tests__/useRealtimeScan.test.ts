import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useRealtimeScan } from '../useRealtimeScan';

const mockSafeInvoke = vi.fn();
const mockSafeListen = vi.fn();

vi.mock('../../services/api', () => ({
  safeInvoke: (...args: unknown[]) => mockSafeInvoke(...args),
  safeListen: (...args: unknown[]) => mockSafeListen(...args),
}));

vi.mock('../../utils/verdict', () => ({
  parseVerdict: (v: unknown) => {
    if (typeof v === 'string') return v;
    return 'Unknown';
  },
}));

const mockScanStatus = {
  isScanning: false,
  currentFile: null,
  filesScanned: 0,
  filesRemaining: 0,
  totalFiles: 0,
  progressPercent: 0,
  cleanCount: 0,
  suspiciousCount: 0,
  malwareCount: 0,
  elapsedSeconds: 0,
  lastThreat: null,
  scanType: null,
  filesPerSecond: 0,
};

describe('useRealtimeScan', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockSafeInvoke.mockReset();
    mockSafeListen.mockReset();
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    // Mock safeListen to store the callback and return an unlisten function
    mockSafeListen.mockResolvedValue(() => {});

    // Default: get_scan_status returns idle, get_active_threats returns empty
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') return Promise.resolve([]);
      return Promise.resolve(null);
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    warnSpy.mockRestore();
  });

  it('starts with null status', () => {
    mockSafeInvoke.mockImplementation(() => new Promise(() => {}));
    const { result } = renderHook(() => useRealtimeScan());
    expect(result.current.status).toBeNull();
    expect(result.current.realtimeResults).toEqual([]);
    expect(result.current.error).toBeNull();
  });

  it('loads initial scan status on mount', async () => {
    const { result } = renderHook(() => useRealtimeScan());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(mockSafeInvoke).toHaveBeenCalledWith('get_scan_status');
    expect(result.current.status).toEqual(mockScanStatus);
  });

  it('loads active threats on mount', async () => {
    const mockThreats = [
      {
        id: 1,
        file_hash: 'abc123',
        file_path: 'C:\\test\\malware.exe',
        verdict: 'Malware',
        confidence: 0.95,
        threat_level: 'HIGH',
        threat_name: 'Trojan.Test',
        scanned_at: 1700000000,
      },
    ];

    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') return Promise.resolve(mockThreats);
      return Promise.resolve(null);
    });

    const { result } = renderHook(() => useRealtimeScan());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.realtimeResults).toHaveLength(1);
    expect(result.current.realtimeResults[0].threatId).toBe('1');
    expect(result.current.realtimeResults[0].fileHash).toBe('abc123');
    expect(result.current.realtimeResults[0].verdict).toBe('Malware');
  });

  it('getScanStatus fetches and updates status', async () => {
    const { result } = renderHook(() => useRealtimeScan());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    const newStatus = { ...mockScanStatus, isScanning: true, filesScanned: 10 };
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(newStatus);
      if (cmd === 'get_active_threats') return Promise.resolve([]);
      return Promise.resolve(null);
    });

    await act(async () => {
      const s = await result.current.getScanStatus();
      expect(s.isScanning).toBe(true);
    });

    expect(result.current.status?.isScanning).toBe(true);
  });

  it('clearResults empties the results array', async () => {
    const mockThreats = [
      {
        id: 1,
        file_hash: 'abc123',
        file_path: 'C:\\test\\malware.exe',
        verdict: 'Malware',
        confidence: 0.95,
        threat_level: 'HIGH',
        threat_name: 'Trojan.Test',
        scanned_at: 1700000000,
      },
    ];

    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') return Promise.resolve(mockThreats);
      return Promise.resolve(null);
    });

    const { result } = renderHook(() => useRealtimeScan());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.realtimeResults).toHaveLength(1);

    act(() => {
      result.current.clearResults();
    });

    expect(result.current.realtimeResults).toEqual([]);
  });

  it('removeResult removes a specific result by threat id', async () => {
    const mockThreats = [
      {
        id: 1,
        file_hash: 'abc123',
        file_path: 'C:\\test\\a.exe',
        verdict: 'Malware',
        confidence: 0.9,
        threat_level: 'HIGH',
        threat_name: 'Trojan.Test',
        scanned_at: 1700000000,
      },
      {
        id: 2,
        file_hash: 'def456',
        file_path: 'C:\\test\\b.exe',
        verdict: 'Suspicious',
        confidence: 0.7,
        threat_level: 'MEDIUM',
        threat_name: 'Suspicious.Activity',
        scanned_at: 1700000001,
      },
    ];

    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') return Promise.resolve(mockThreats);
      return Promise.resolve(null);
    });

    const { result } = renderHook(() => useRealtimeScan());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.realtimeResults).toHaveLength(2);

    act(() => {
      result.current.removeResult('1');
    });

    expect(result.current.realtimeResults).toHaveLength(1);
    expect(result.current.realtimeResults[0].fileHash).toBe('def456');
  });

  it('sets up realtime_scan_result listener', async () => {
    renderHook(() => useRealtimeScan());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(mockSafeListen).toHaveBeenCalledWith(
      'realtime_scan_result',
      expect.any(Function)
    );
  });

  it('handles errors when loading scan status', async () => {
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.reject(new Error('timeout'));
      if (cmd === 'get_active_threats') return Promise.resolve([]);
      return Promise.resolve(null);
    });

    const { result } = renderHook(() => useRealtimeScan());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.error).toBeTruthy();
  });

  it('deduplicates results by file path (replaces existing)', async () => {
    // Start with a loaded threat
    const initialThreat = {
      id: 1,
      file_hash: 'hash1',
      file_path: 'C:\\test\\malware.exe',
      verdict: 'Suspicious',
      confidence: 0.6,
      threat_level: 'MEDIUM',
      threat_name: 'Suspicious.Activity',
      scanned_at: 1700000000,
    };
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') return Promise.resolve([initialThreat]);
      return Promise.resolve(null);
    });

    let listenerCallback: ((event: { payload: Record<string, unknown> }) => void) | null = null;
    mockSafeListen.mockImplementation((_event: string, cb: any) => {
      listenerCallback = cb;
      return Promise.resolve(() => {});
    });

    const { result } = renderHook(() => useRealtimeScan());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.realtimeResults).toHaveLength(1);
    expect(result.current.realtimeResults[0].verdict).toBe('Suspicious');

    // Receive a new scan result for the same file path (different hash / updated)
    await act(async () => {
      listenerCallback!({
        payload: {
          file_hash: 'hash2',
          file_path: 'C:\\test\\malware.exe',
          verdict: 'Malware',
          confidence: 0.95,
          threat_level: 'HIGH',
          scan_time_ms: 100,
        },
      });
    });

    // Should still be 1 result, but updated
    expect(result.current.realtimeResults).toHaveLength(1);
    expect(result.current.realtimeResults[0].verdict).toBe('Malware');
    expect(result.current.realtimeResults[0].confidence).toBe(0.95);
  });

  it('keeps results with duplicate hash but different path', async () => {
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') return Promise.resolve([]);
      return Promise.resolve(null);
    });

    let listenerCallback: ((event: { payload: Record<string, unknown> }) => void) | null = null;
    mockSafeListen.mockImplementation((_event: string, cb: any) => {
      listenerCallback = cb;
      return Promise.resolve(() => {});
    });

    const { result } = renderHook(() => useRealtimeScan());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // First result
    await act(async () => {
      listenerCallback!({
        payload: {
          file_hash: 'samehash',
          file_path: 'C:\\path1\\file.exe',
          verdict: 'Malware',
          confidence: 0.9,
          threat_level: 'HIGH',
          scan_time_ms: 100,
        },
      });
    });
    expect(result.current.realtimeResults).toHaveLength(1);

    // Second result with same hash but different path should remain visible
    await act(async () => {
      listenerCallback!({
        payload: {
          file_hash: 'samehash',
          file_path: 'C:\\path2\\file_copy.exe',
          verdict: 'Malware',
          confidence: 0.9,
          threat_level: 'HIGH',
          scan_time_ms: 50,
        },
      });
    });
    expect(result.current.realtimeResults).toHaveLength(2);
  });

  it('skips results with missing filePath or fileHash', async () => {
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') return Promise.resolve([]);
      return Promise.resolve(null);
    });

    let listenerCallback: ((event: { payload: Record<string, unknown> }) => void) | null = null;
    mockSafeListen.mockImplementation((_event: string, cb: any) => {
      listenerCallback = cb;
      return Promise.resolve(() => {});
    });

    const { result } = renderHook(() => useRealtimeScan());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // Missing file_hash
    await act(async () => {
      listenerCallback!({
        payload: {
          file_path: 'C:\\test\\file.exe',
          verdict: 'Malware',
          confidence: 0.9,
          threat_level: 'HIGH',
          scan_time_ms: 100,
        },
      });
    });
    expect(result.current.realtimeResults).toHaveLength(0);

    // Missing file_path
    await act(async () => {
      listenerCallback!({
        payload: {
          file_hash: 'abc123',
          verdict: 'Malware',
          confidence: 0.9,
          threat_level: 'HIGH',
          scan_time_ms: 100,
        },
      });
    });
    expect(result.current.realtimeResults).toHaveLength(0);
  });

  it('refreshActiveThreats reloads from database', async () => {
    let callCount = 0;
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') {
        callCount++;
        if (callCount <= 1) return Promise.resolve([]);
        return Promise.resolve([{
          id: 1,
          file_hash: 'new1',
          file_path: 'C:\\test\\new.exe',
          verdict: 'Malware',
          confidence: 0.8,
          threat_level: 'HIGH',
          threat_name: 'Trojan.Test',
          scanned_at: 1700000000,
        }]);
      }
      return Promise.resolve(null);
    });

    const { result } = renderHook(() => useRealtimeScan());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.realtimeResults).toHaveLength(0);

    await act(async () => {
      await result.current.refreshActiveThreats();
    });
    expect(result.current.realtimeResults).toHaveLength(1);
  });

  it('does not poll active threats when nav is not dashboard', async () => {
    let activeThreatsCallCount = 0;
    mockSafeInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'get_scan_status') return Promise.resolve(mockScanStatus);
      if (cmd === 'get_active_threats') {
        activeThreatsCallCount++;
        return Promise.resolve([]);
      }
      return Promise.resolve(null);
    });

    // Render with activeNav = 'scanner' (not dashboard)
    renderHook(() => useRealtimeScan('scanner'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const initialCalls = activeThreatsCallCount;

    // Advance past the 30s polling interval
    await act(async () => {
      await vi.advanceTimersByTimeAsync(31000);
    });

    // Should not have polled again because activeNav is 'scanner'
    expect(activeThreatsCallCount).toBe(initialCalls);
  });
});
