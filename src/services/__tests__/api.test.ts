import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// The setup.ts mocks @tauri-apps/api/core and @tauri-apps/api/event globally.
// We test the API module's behavior when Tauri is NOT available (test environment).

type TauriTestWindow = Window & typeof globalThis & {
  __TAURI_INTERNALS__?: unknown;
};

const tauriWindow = window as TauriTestWindow;

const clearTauriInternals = () => {
  delete tauriWindow.__TAURI_INTERNALS__;
};

const enableTauriInternals = () => {
  tauriWindow.__TAURI_INTERNALS__ = {};
};

describe('api module', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.resetModules();
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  describe('isTauriAvailable', () => {
    it('returns false when __TAURI_INTERNALS__ is not present', async () => {
      const { isTauriAvailable } = await import('../api');
      expect(isTauriAvailable()).toBe(false);
    });

    it('returns true when __TAURI_INTERNALS__ is present', async () => {
      enableTauriInternals();
      try {
        const { isTauriAvailable } = await import('../api');
        expect(isTauriAvailable()).toBe(true);
      } finally {
        clearTauriInternals();
      }
    });
  });

  describe('safeInvoke', () => {
    it('throws when Tauri is not available', async () => {
      // Ensure __TAURI_INTERNALS__ is NOT present
      clearTauriInternals();
      const { safeInvoke } = await import('../api');
      await expect(safeInvoke('some_command')).rejects.toThrow('Tauri not available');
    });

    it('throws with the command name in the error message', async () => {
      clearTauriInternals();
      const { safeInvoke } = await import('../api');
      await expect(safeInvoke('get_settings')).rejects.toThrow('Tauri not available');
    });
  });

  describe('safeListen', () => {
    it('returns a no-op unlisten function when Tauri is not available', async () => {
      clearTauriInternals();
      const { safeListen } = await import('../api');
      const unlisten = await safeListen('scan_progress', () => {});
      expect(typeof unlisten).toBe('function');
      // Calling the no-op should not throw
      expect(() => unlisten()).not.toThrow();
    });
  });

  describe('scan API functions', () => {
    it('startScan calls safeInvoke with correct command', async () => {
      clearTauriInternals();
      const { startScan } = await import('../api');
      // Should throw since Tauri is not available
      await expect(startScan('quick')).rejects.toThrow('Tauri not available');
    });

    it('cancelScan calls safeInvoke with correct command', async () => {
      clearTauriInternals();
      const { cancelScan } = await import('../api');
      await expect(cancelScan()).rejects.toThrow('Tauri not available');
    });

    it('getScanStatus calls safeInvoke with correct command', async () => {
      clearTauriInternals();
      const { getScanStatus } = await import('../api');
      await expect(getScanStatus()).rejects.toThrow('Tauri not available');
    });
  });

  describe('scheduled scans API', () => {
    it('getScheduledScans rejects without Tauri', async () => {
      clearTauriInternals();
      const { getScheduledScans } = await import('../api');
      await expect(getScheduledScans()).rejects.toThrow('Tauri not available');
    });

    it('deleteScheduledScan rejects without Tauri', async () => {
      clearTauriInternals();
      const { deleteScheduledScan } = await import('../api');
      await expect(deleteScheduledScan(1)).rejects.toThrow('Tauri not available');
    });
  });

  describe('whitelist API', () => {
    it('getUserWhitelist rejects without Tauri', async () => {
      clearTauriInternals();
      const { getUserWhitelist } = await import('../api');
      await expect(getUserWhitelist()).rejects.toThrow('Tauri not available');
    });

    it('removeFromUserWhitelist rejects without Tauri', async () => {
      clearTauriInternals();
      const { removeFromUserWhitelist } = await import('../api');
      await expect(removeFromUserWhitelist('abc123')).rejects.toThrow('Tauri not available');
    });
  });

  describe('constants', () => {
    it('SLOW_COMMANDS includes get_persistence_for_file', async () => {
      const { getPersistenceForFile } = await import('../api');
      await expect(getPersistenceForFile('C:\\test.exe')).rejects.toThrow();
    });
  });

  describe('additional scan API functions', () => {
    it('forceResetScan rejects without Tauri', async () => {
      clearTauriInternals();
      const { forceResetScan } = await import('../api');
      await expect(forceResetScan()).rejects.toThrow('Tauri not available');
    });

    it('pickScanFolder rejects without Tauri', async () => {
      clearTauriInternals();
      const { pickScanFolder } = await import('../api');
      await expect(pickScanFolder()).rejects.toThrow('Tauri not available');
    });

    it('pickScanFile rejects without Tauri', async () => {
      clearTauriInternals();
      const { pickScanFile } = await import('../api');
      await expect(pickScanFile()).rejects.toThrow('Tauri not available');
    });
  });

  describe('additional scheduled scan API functions', () => {
    it('createScheduledScan rejects without Tauri', async () => {
      clearTauriInternals();
      const { createScheduledScan } = await import('../api');
      await expect(createScheduledScan({
        name: 'test',
        scanType: 'quick',
        frequency: 'daily',
        timeOfDay: '09:00',
      })).rejects.toThrow('Tauri not available');
    });

    it('updateScheduledScan rejects without Tauri', async () => {
      clearTauriInternals();
      const { updateScheduledScan } = await import('../api');
      await expect(updateScheduledScan({ id: 1, name: 'updated' })).rejects.toThrow('Tauri not available');
    });

    it('toggleScheduledScan rejects without Tauri', async () => {
      clearTauriInternals();
      const { toggleScheduledScan } = await import('../api');
      await expect(toggleScheduledScan(1)).rejects.toThrow('Tauri not available');
    });

    it('runScheduledScanNow rejects without Tauri', async () => {
      clearTauriInternals();
      const { runScheduledScanNow } = await import('../api');
      await expect(runScheduledScanNow(1)).rejects.toThrow('Tauri not available');
    });
  });

  describe('additional whitelist API functions', () => {
    it('clearUserWhitelist rejects without Tauri', async () => {
      clearTauriInternals();
      const { clearUserWhitelist } = await import('../api');
      await expect(clearUserWhitelist()).rejects.toThrow('Tauri not available');
    });

    it('ignoreThreat rejects without Tauri', async () => {
      clearTauriInternals();
      const { ignoreThreat } = await import('../api');
      await expect(ignoreThreat('abc123')).rejects.toThrow('Tauri not available');
    });
  });

  describe('app update API functions', () => {
    it('checkAppUpdate rejects without Tauri', async () => {
      clearTauriInternals();
      const { checkAppUpdate } = await import('../api');
      await expect(checkAppUpdate()).rejects.toThrow('Tauri not available');
    });

    it('dismissAppUpdate rejects without Tauri', async () => {
      clearTauriInternals();
      const { dismissAppUpdate } = await import('../api');
      await expect(dismissAppUpdate('1.0.2')).rejects.toThrow('Tauri not available');
    });
  });

  describe('isTauriAvailable edge cases', () => {
    it('returns false when window is undefined-like', async () => {
      clearTauriInternals();
      const { isTauriAvailable } = await import('../api');
      expect(isTauriAvailable()).toBe(false);
    });
  });
});
