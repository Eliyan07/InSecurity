import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useSettings } from '../useSettings';

// Mock safeInvoke from the api module
const mockSafeInvoke = vi.fn();
vi.mock('../../services/api', () => ({
  safeInvoke: (...args: unknown[]) => mockSafeInvoke(...args),
}));

describe('useSettings', () => {
  beforeEach(() => {
    mockSafeInvoke.mockReset();
  });

  it('starts with null settings and no loading', () => {
    const { result } = renderHook(() => useSettings());
    expect(result.current.settings).toBeNull();
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('getSettings loads settings successfully', async () => {
    const mockSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      scanWorkerCount: 4,
    };

    mockSafeInvoke.mockResolvedValueOnce(mockSettings);

    const { result } = renderHook(() => useSettings());

    await act(async () => {
      await result.current.getSettings();
    });

    expect(result.current.settings).toEqual(mockSettings);
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(mockSafeInvoke).toHaveBeenCalledWith('get_settings');
  });

  it('getSettings handles errors', async () => {
    mockSafeInvoke.mockRejectedValueOnce(new Error('Network error'));

    const { result } = renderHook(() => useSettings());

    await act(async () => {
      await result.current.getSettings();
    });

    expect(result.current.settings).toBeNull();
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBe('Network error');
  });

  it('getSettings handles non-Error exceptions', async () => {
    mockSafeInvoke.mockRejectedValueOnce('string error');

    const { result } = renderHook(() => useSettings());

    await act(async () => {
      await result.current.getSettings();
    });

    expect(result.current.error).toBe('Failed to load settings');
  });

  it('setAutoQuarantine updates settings optimistically', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
    };

    mockSafeInvoke.mockResolvedValueOnce(initialSettings);

    const { result } = renderHook(() => useSettings());

    await act(async () => {
      await result.current.getSettings();
    });

    mockSafeInvoke.mockResolvedValueOnce(undefined);

    await act(async () => {
      await result.current.setAutoQuarantine(false);
    });

    expect(result.current.settings?.autoQuarantine).toBe(false);
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_auto_quarantine', { enabled: false });
  });

  it('setRealTimeProtection updates settings optimistically', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
    };

    mockSafeInvoke.mockResolvedValueOnce(initialSettings);

    const { result } = renderHook(() => useSettings());

    await act(async () => {
      await result.current.getSettings();
    });

    mockSafeInvoke.mockResolvedValueOnce(undefined);

    await act(async () => {
      await result.current.setRealTimeProtection(false);
    });

    expect(result.current.settings?.realTimeProtection).toBe(false);
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_real_time_protection', { enabled: false });
  });

  it('setScanWorkerCount rejects invalid values', async () => {
    const { result } = renderHook(() => useSettings());

    await act(async () => {
      await result.current.setScanWorkerCount(0);
    });
    expect(result.current.error).toBe('Worker count must be between 1 and 16');
    expect(mockSafeInvoke).not.toHaveBeenCalled();

    await act(async () => {
      await result.current.setScanWorkerCount(17);
    });
    expect(result.current.error).toBe('Worker count must be between 1 and 16');
  });

  it('setScanWorkerCount updates settings optimistically', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      scanWorkerCount: 4,
    };

    mockSafeInvoke.mockResolvedValueOnce(initialSettings);

    const { result } = renderHook(() => useSettings());

    await act(async () => {
      await result.current.getSettings();
    });

    mockSafeInvoke.mockResolvedValueOnce(undefined);

    await act(async () => {
      await result.current.setScanWorkerCount(8);
    });

    expect(result.current.settings?.scanWorkerCount).toBe(8);
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_scan_worker_count', { count: 8 });
  });

  it('setRansomwareProtection updates settings optimistically', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      ransomwareProtection: true,
    };

    mockSafeInvoke.mockResolvedValueOnce(initialSettings);

    const { result } = renderHook(() => useSettings());

    await act(async () => {
      await result.current.getSettings();
    });

    mockSafeInvoke.mockResolvedValueOnce(undefined);

    await act(async () => {
      await result.current.setRansomwareProtection(false);
    });

    expect(result.current.settings?.ransomwareProtection).toBe(false);
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_ransomware_protection', { enabled: false });
  });

  it('setAutostart updates settings optimistically', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      autostart: true,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });
    mockSafeInvoke.mockResolvedValueOnce(undefined);
    await act(async () => {
      await result.current.setAutostart(false);
    });
    expect(result.current.settings?.autostart).toBe(false);
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_autostart', { enabled: false });
  });

  it('setAutostart handles API errors', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      autostart: true,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });
    mockSafeInvoke.mockRejectedValueOnce(new Error('Permission denied'));
    await act(async () => {
      await result.current.setAutostart(false);
    });
    expect(result.current.error).toBe('Permission denied');
  });

  it('setAutoQuarantine handles API errors', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });
    mockSafeInvoke.mockRejectedValueOnce(new Error('Server error'));
    await act(async () => {
      await result.current.setAutoQuarantine(false);
    });
    expect(result.current.error).toBe('Server error');
  });

  it('setRealTimeProtection handles API errors', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });
    mockSafeInvoke.mockRejectedValueOnce(new Error('timeout'));
    await act(async () => {
      await result.current.setRealTimeProtection(false);
    });
    expect(result.current.error).toBe('timeout');
  });

  it('setScanWorkerCount handles API errors', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      scanWorkerCount: 4,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });
    mockSafeInvoke.mockRejectedValueOnce(new Error('Failed'));
    await act(async () => {
      await result.current.setScanWorkerCount(8);
    });
    expect(result.current.error).toBe('Failed');
  });

  it('setRansomwareAutoBlock updates settings optimistically', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      ransomwareAutoBlock: true,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });
    mockSafeInvoke.mockResolvedValueOnce(undefined);
    await act(async () => {
      await result.current.setRansomwareAutoBlock(false);
    });
    expect(result.current.settings?.ransomwareAutoBlock).toBe(false);
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_ransomware_auto_block', { enabled: false });
  });

  it('setRansomwareThresholds validates and updates settings', async () => {
    const initialSettings = {

      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      ransomwareThreshold: 20,
      ransomwareWindowSeconds: 10,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });
    mockSafeInvoke.mockResolvedValueOnce(undefined);
    await act(async () => {
      await result.current.setRansomwareThresholds(30, 15);
    });
    expect(result.current.settings?.ransomwareThreshold).toBe(30);
    expect(result.current.settings?.ransomwareWindowSeconds).toBe(15);
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_ransomware_thresholds', { threshold: 30, windowSeconds: 15 });
  });

  it('setRansomwareThresholds rejects invalid threshold', async () => {
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.setRansomwareThresholds(2, 10);
    });
    expect(result.current.error).toBe('Threshold must be at least 5');
    expect(mockSafeInvoke).not.toHaveBeenCalled();
  });

  it('setRansomwareThresholds rejects invalid window', async () => {
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.setRansomwareThresholds(20, 3);
    });
    expect(result.current.error).toBe('Window must be between 5 and 60 seconds');
    expect(mockSafeInvoke).not.toHaveBeenCalled();
  });

  it('dismissRansomwareAlert calls backend', async () => {
    mockSafeInvoke.mockResolvedValueOnce(undefined);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.dismissRansomwareAlert('/some/folder');
    });
    expect(mockSafeInvoke).toHaveBeenCalledWith('dismiss_ransomware_alert', { folder: '/some/folder' });
  });

  it('killRansomwareProcess calls backend', async () => {
    mockSafeInvoke.mockResolvedValueOnce(undefined);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.killRansomwareProcess(1234);
    });
    expect(mockSafeInvoke).toHaveBeenCalledWith('kill_ransomware_process', { pid: 1234 });
  });

  it('redeployCanaryFiles calls backend', async () => {
    mockSafeInvoke.mockResolvedValueOnce(undefined);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.redeployCanaryFiles();
    });
    expect(mockSafeInvoke).toHaveBeenCalledWith('redeploy_canary_files');
  });

  it('setVirusTotalApiKey stores masked state after save', async () => {
    const initialSettings = {
      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      virustotalApiKey: null,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });

    mockSafeInvoke.mockResolvedValueOnce({
      configured: true,
      verified: true,
      warning: null,
    });

    await act(async () => {
      await result.current.setVirusTotalApiKey('test-key');
    });

    expect(result.current.settings?.virustotalApiKey).toBe('[configured]');
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_virustotal_api_key', { key: 'test-key' });
  });

  it('setMalwareBazaarApiKey stores masked state after save', async () => {
    const initialSettings = {
      realTimeProtection: true,
      autoQuarantine: true,
      cacheSizeMb: 256,
      cacheTtlHours: 24,
      malwarebazaarApiKey: null,
    };
    mockSafeInvoke.mockResolvedValueOnce(initialSettings);
    const { result } = renderHook(() => useSettings());
    await act(async () => {
      await result.current.getSettings();
    });

    mockSafeInvoke.mockResolvedValueOnce({
      configured: true,
      verified: false,
      warning: 'Saved without verification',
    });

    await act(async () => {
      await result.current.setMalwareBazaarApiKey('mb-key');
    });

    expect(result.current.settings?.malwarebazaarApiKey).toBe('[configured]');
    expect(mockSafeInvoke).toHaveBeenCalledWith('set_malwarebazaar_api_key', { key: 'mb-key' });
  });
});
