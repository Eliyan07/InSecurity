import { useState, useCallback } from 'react';
import { safeInvoke } from '../services/api';
import { Exclusion, ExclusionInput, ExclusionUpdate } from '../types/exclusion';

export function useExclusions() {
  const [exclusions, setExclusions] = useState<Exclusion[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchExclusions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await safeInvoke<Exclusion[]>('get_exclusions');
      setExclusions(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const addExclusion = useCallback(async (input: ExclusionInput) => {
    setError(null);
    try {
      await safeInvoke('add_exclusion', {
        exclusionType: input.exclusion_type,
        pattern: input.pattern,
        reason: input.reason || null,
      });
      await fetchExclusions();
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    }
  }, [fetchExclusions]);

  const updateExclusion = useCallback(async (update: ExclusionUpdate) => {
    setError(null);
    try {
      await safeInvoke('update_exclusion', {
        id: update.id,
        exclusionType: update.exclusion_type,
        pattern: update.pattern,
        reason: update.reason,
        enabled: update.enabled,
      });
      await fetchExclusions();
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    }
  }, [fetchExclusions]);

  const toggleExclusion = useCallback(async (id: number, enabled: boolean) => {
    setError(null);
    try {
      await safeInvoke('toggle_exclusion', { id, enabled });
      await fetchExclusions();
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    }
  }, [fetchExclusions]);

  const deleteExclusion = useCallback(async (id: number) => {
    setError(null);
    try {
      await safeInvoke('delete_exclusion', { id });
      await fetchExclusions();
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    }
  }, [fetchExclusions]);

  const checkPathExcluded = useCallback(async (path: string): Promise<boolean> => {
    try {
      return await safeInvoke<boolean>('is_path_excluded', { path });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    }
  }, []);

  return {
    exclusions,
    loading,
    error,
    fetchExclusions,
    addExclusion,
    updateExclusion,
    toggleExclusion,
    deleteExclusion,
    checkPathExcluded,
    clearError: () => setError(null),
  };
}
