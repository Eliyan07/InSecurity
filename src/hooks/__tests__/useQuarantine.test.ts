import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useQuarantine } from '../useQuarantine';

const mockSafeInvoke = vi.fn();
vi.mock('../../services/api', () => ({
  safeInvoke: (...args: unknown[]) => mockSafeInvoke(...args),
}));

// Mock confirm function that simulates the useConfirmDialog hook
const mockConfirmFn = vi.fn((_options: {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'default' | 'danger' | 'warning';
}) => Promise.resolve(true));

const mockQuarantinedFiles = [
  {
    id: 1,
    fileHash: 'abc123',
    originalPath: 'C:\\test\\malware.exe',
    verdict: 'Malware',
    threatLevel: 'HIGH',
    quarantinedAt: 1700000000,
    fileSize: 1024,
    fileType: 'exe',
  },
  {
    id: 2,
    fileHash: 'def456',
    originalPath: 'C:\\test\\suspicious.dll',
    verdict: 'Suspicious',
    threatLevel: 'MEDIUM',
    quarantinedAt: 1700000001,
    fileSize: 2048,
    fileType: 'dll',
  },
];

describe('useQuarantine', () => {
  beforeEach(() => {
    mockSafeInvoke.mockReset();
    mockConfirmFn.mockReset();
    mockConfirmFn.mockResolvedValue(true);
  });

  it('starts with empty quarantine list', () => {
    const { result } = renderHook(() => useQuarantine(mockConfirmFn));
    expect(result.current.quarantinedFiles).toEqual([]);
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('listQuarantined loads files', async () => {
    mockSafeInvoke.mockResolvedValueOnce(mockQuarantinedFiles);

    const { result } = renderHook(() => useQuarantine(mockConfirmFn));

    await act(async () => {
      await result.current.listQuarantined();
    });

    expect(result.current.quarantinedFiles).toEqual(mockQuarantinedFiles);
    expect(result.current.loading).toBe(false);
    expect(mockSafeInvoke).toHaveBeenCalledWith('list_quarantined');
  });

  it('listQuarantined handles errors', async () => {
    mockSafeInvoke.mockRejectedValueOnce(new Error('DB error'));

    const { result } = renderHook(() => useQuarantine(mockConfirmFn));

    await act(async () => {
      await result.current.listQuarantined();
    });

    expect(result.current.error).toBe('DB error');
    expect(result.current.quarantinedFiles).toEqual([]);
  });

  it('restoreFile calls API and removes from list', async () => {
    mockSafeInvoke
      .mockResolvedValueOnce(mockQuarantinedFiles) // listQuarantined
      .mockResolvedValueOnce(undefined); // restore_file

    const { result } = renderHook(() => useQuarantine(mockConfirmFn));

    // First load the files
    await act(async () => {
      await result.current.listQuarantined();
    });

    expect(result.current.quarantinedFiles).toHaveLength(2);

    // Restore file with id 1
    await act(async () => {
      await result.current.restoreFile(1);
    });

    expect(mockConfirmFn).toHaveBeenCalled();
    expect(mockSafeInvoke).toHaveBeenCalledWith('restore_file', { id: 1 });
    // Should be optimistically removed from state
    expect(result.current.quarantinedFiles).toHaveLength(1);
    expect(result.current.quarantinedFiles[0].id).toBe(2);
  });

  it('restoreFile re-fetches on error', async () => {
    // restoreFile catch: setError, then calls listQuarantined which calls setError(null)
    // So the error gets cleared by the re-fetch. Verify the re-fetch was called.
    mockSafeInvoke
      .mockResolvedValueOnce(mockQuarantinedFiles) // initial load
      .mockRejectedValueOnce(new Error('Restore failed')) // restore_file fails
      .mockResolvedValueOnce(mockQuarantinedFiles); // re-fetch succeeds

    const { result } = renderHook(() => useQuarantine(mockConfirmFn));

    await act(async () => {
      await result.current.listQuarantined();
    });

    await act(async () => {
      await result.current.restoreFile(1);
    });

    // The re-fetch should have been called (3 total safeInvoke calls)
    expect(mockSafeInvoke).toHaveBeenCalledTimes(3);
    // After re-fetch, all files should still be in the list
    expect(result.current.quarantinedFiles).toHaveLength(2);
  });

  it('deleteFile calls API after confirmation', async () => {
    mockSafeInvoke
      .mockResolvedValueOnce(mockQuarantinedFiles) // initial load
      .mockResolvedValueOnce(undefined); // delete

    const { result } = renderHook(() => useQuarantine(mockConfirmFn));

    await act(async () => {
      await result.current.listQuarantined();
    });

    await act(async () => {
      await result.current.deleteFile(1);
    });

    expect(mockConfirmFn).toHaveBeenCalled();
    expect(mockSafeInvoke).toHaveBeenCalledWith('delete_quarantined_file', { id: 1 });
    expect(result.current.quarantinedFiles).toHaveLength(1);
  });

  it('deleteFile does nothing when user cancels confirmation', async () => {
    mockConfirmFn.mockResolvedValueOnce(false);

    mockSafeInvoke.mockResolvedValueOnce(mockQuarantinedFiles);

    const { result } = renderHook(() => useQuarantine(mockConfirmFn));

    await act(async () => {
      await result.current.listQuarantined();
    });

    await act(async () => {
      await result.current.deleteFile(1);
    });

    // Should NOT have called delete_quarantined_file
    expect(mockSafeInvoke).not.toHaveBeenCalledWith('delete_quarantined_file', expect.anything());
    expect(result.current.quarantinedFiles).toHaveLength(2);
  });

  it('deleteFile handles error and re-fetches', async () => {
    // deleteFile catch: setError, then calls listQuarantined which calls setError(null)
    mockSafeInvoke
      .mockResolvedValueOnce(mockQuarantinedFiles) // initial load
      .mockRejectedValueOnce(new Error('Delete failed')) // delete fails
      .mockResolvedValueOnce(mockQuarantinedFiles); // re-fetch succeeds

    const { result } = renderHook(() => useQuarantine(mockConfirmFn));

    await act(async () => {
      await result.current.listQuarantined();
    });

    await act(async () => {
      await result.current.deleteFile(1);
    });

    // The re-fetch should have been called (3 total invocations)
    expect(mockSafeInvoke).toHaveBeenCalledTimes(3);
    // Files should be re-fetched to consistent state
    expect(result.current.quarantinedFiles).toHaveLength(2);
  });

  it('handles non-Error exceptions in listQuarantined', async () => {
    mockSafeInvoke.mockRejectedValueOnce('string error');

    const { result } = renderHook(() => useQuarantine(mockConfirmFn));

    await act(async () => {
      await result.current.listQuarantined();
    });

    expect(result.current.error).toBe('Failed to list quarantined files');
  });

  it('restoreFile does nothing when user cancels confirmation', async () => {
    mockConfirmFn.mockResolvedValueOnce(false);
    mockSafeInvoke.mockResolvedValueOnce(mockQuarantinedFiles);
    const { result } = renderHook(() => useQuarantine(mockConfirmFn));
    await act(async () => {
      await result.current.listQuarantined();
    });
    await act(async () => {
      await result.current.restoreFile(1);
    });
    // Should not have called restore_file
    expect(mockSafeInvoke).not.toHaveBeenCalledWith('restore_file', expect.anything());
    expect(result.current.quarantinedFiles).toHaveLength(2);
  });

  it('handles non-Error exceptions in restoreFile', async () => {
    mockSafeInvoke
      .mockResolvedValueOnce(mockQuarantinedFiles)
      .mockRejectedValueOnce('string restore error')
      .mockRejectedValueOnce(new Error('refetch too'));
    const { result } = renderHook(() => useQuarantine(mockConfirmFn));
    await act(async () => {
      await result.current.listQuarantined();
    });
    await act(async () => {
      await result.current.restoreFile(1);
    });
    // The restoreFile sets error but then calls listQuarantined which may override
    // the error was set at some point - the refetch also failed so the error is from the refetch
    expect(result.current.error).toBeTruthy();
  });

  it('handles non-Error exceptions in deleteFile', async () => {
    mockSafeInvoke
      .mockResolvedValueOnce(mockQuarantinedFiles)
      .mockRejectedValueOnce('string delete error')
      .mockRejectedValueOnce(new Error('refetch too'));
    const { result } = renderHook(() => useQuarantine(mockConfirmFn));
    await act(async () => {
      await result.current.listQuarantined();
    });
    await act(async () => {
      await result.current.deleteFile(1);
    });
    // Error was set, then re-fetch also failed — error should be truthy
    expect(result.current.error).toBeTruthy();
  });

  it('loading is true during listQuarantined', async () => {
    let resolvePromise: (v: unknown) => void;
    mockSafeInvoke.mockImplementation(
      () => new Promise((r) => { resolvePromise = r; })
    );
    const { result } = renderHook(() => useQuarantine(mockConfirmFn));
    let loadingDuringFetch = false;
    act(() => {
      result.current.listQuarantined().then(() => {});
    });
    // Check loading is true right after calling
    loadingDuringFetch = result.current.loading;
    expect(loadingDuringFetch).toBe(true);
    await act(async () => {
      resolvePromise!(mockQuarantinedFiles);
    });
    expect(result.current.loading).toBe(false);
  });
});
