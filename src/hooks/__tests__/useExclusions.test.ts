import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useExclusions } from '../useExclusions';

const mockSafeInvoke = vi.fn();
vi.mock('../../services/api', () => ({
  safeInvoke: (...args: unknown[]) => mockSafeInvoke(...args),
}));

const mockExclusions = [
  { id: 1, exclusion_type: 'path', pattern: 'C:\\safe\\file.txt', reason: 'Trusted', enabled: true, created_at: 1700000000, signature: 'abc' },
  { id: 2, exclusion_type: 'extension', pattern: '.log', reason: null, enabled: true, created_at: 1700000001, signature: 'def' },
];

describe('useExclusions', () => {
  beforeEach(() => {
    mockSafeInvoke.mockReset();
  });

  it('starts with empty exclusions', () => {
    const { result } = renderHook(() => useExclusions());
    expect(result.current.exclusions).toEqual([]);
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('fetchExclusions loads exclusions', async () => {
    mockSafeInvoke.mockResolvedValueOnce(mockExclusions);

    const { result } = renderHook(() => useExclusions());

    await act(async () => {
      await result.current.fetchExclusions();
    });

    expect(result.current.exclusions).toEqual(mockExclusions);
    expect(result.current.loading).toBe(false);
    expect(mockSafeInvoke).toHaveBeenCalledWith('get_exclusions');
  });

  it('fetchExclusions handles errors', async () => {
    mockSafeInvoke.mockRejectedValueOnce(new Error('DB locked'));

    const { result } = renderHook(() => useExclusions());

    await act(async () => {
      await result.current.fetchExclusions();
    });

    expect(result.current.error).toBe('DB locked');
    expect(result.current.exclusions).toEqual([]);
  });

  it('addExclusion calls API and refreshes', async () => {
    mockSafeInvoke
      .mockResolvedValueOnce(3) // add_exclusion returns ID
      .mockResolvedValueOnce(mockExclusions); // fetchExclusions after add

    const { result } = renderHook(() => useExclusions());

    let success: boolean = false;
    await act(async () => {
      success = await result.current.addExclusion({
        exclusion_type: 'path',
        pattern: 'C:\\new\\path',
        reason: 'Test',
      });
    });

    expect(success).toBe(true);
    expect(mockSafeInvoke).toHaveBeenCalledWith('add_exclusion', {
      exclusionType: 'path',
      pattern: 'C:\\new\\path',
      reason: 'Test',
    });
  });

  it('addExclusion returns false on error', async () => {
    mockSafeInvoke.mockRejectedValueOnce(new Error('Blocked pattern'));

    const { result } = renderHook(() => useExclusions());

    let success: boolean = true;
    await act(async () => {
      success = await result.current.addExclusion({
        exclusion_type: 'extension',
        pattern: '*',
      });
    });

    expect(success).toBe(false);
    expect(result.current.error).toBe('Blocked pattern');
  });

  it('updateExclusion calls API and refreshes', async () => {
    mockSafeInvoke
      .mockResolvedValueOnce(undefined) // update_exclusion
      .mockResolvedValueOnce(mockExclusions); // refresh

    const { result } = renderHook(() => useExclusions());

    let success: boolean = false;
    await act(async () => {
      success = await result.current.updateExclusion({
        id: 1,
        exclusion_type: 'folder',
        pattern: 'C:\\new',
      });
    });

    expect(success).toBe(true);
    expect(mockSafeInvoke).toHaveBeenCalledWith('update_exclusion', {
      id: 1,
      exclusionType: 'folder',
      pattern: 'C:\\new',
      reason: undefined,
      enabled: undefined,
    });
  });

  it('toggleExclusion calls API', async () => {
    mockSafeInvoke
      .mockResolvedValueOnce(undefined) // toggle
      .mockResolvedValueOnce(mockExclusions); // refresh

    const { result } = renderHook(() => useExclusions());

    await act(async () => {
      await result.current.toggleExclusion(1, false);
    });

    expect(mockSafeInvoke).toHaveBeenCalledWith('toggle_exclusion', { id: 1, enabled: false });
  });

  it('deleteExclusion calls API and refreshes', async () => {
    mockSafeInvoke
      .mockResolvedValueOnce(undefined) // delete
      .mockResolvedValueOnce([]); // refresh

    const { result } = renderHook(() => useExclusions());

    await act(async () => {
      await result.current.deleteExclusion(1);
    });

    expect(mockSafeInvoke).toHaveBeenCalledWith('delete_exclusion', { id: 1 });
  });

  it('checkPathExcluded returns boolean', async () => {
    mockSafeInvoke.mockResolvedValueOnce(true);

    const { result } = renderHook(() => useExclusions());

    let excluded: boolean = false;
    await act(async () => {
      excluded = await result.current.checkPathExcluded('C:\\safe\\file.txt');
    });

    expect(excluded).toBe(true);
    expect(mockSafeInvoke).toHaveBeenCalledWith('is_path_excluded', { path: 'C:\\safe\\file.txt' });
  });

  it('checkPathExcluded returns false on error', async () => {
    mockSafeInvoke.mockRejectedValueOnce(new Error('fail'));

    const { result } = renderHook(() => useExclusions());

    let excluded: boolean = true;
    await act(async () => {
      excluded = await result.current.checkPathExcluded('C:\\test');
    });

    expect(excluded).toBe(false);
  });

  it('clearError resets error state', async () => {
    mockSafeInvoke.mockRejectedValueOnce(new Error('oops'));

    const { result } = renderHook(() => useExclusions());

    await act(async () => {
      await result.current.fetchExclusions();
    });

    expect(result.current.error).toBe('oops');

    act(() => {
      result.current.clearError();
    });

    expect(result.current.error).toBeNull();
  });
});
