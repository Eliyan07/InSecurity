import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Scanner } from './Scanner';
import * as api from '../../services/api';
import type { ScanStatus } from '../../services/api';

// Mock API services
vi.mock('../../services/api', () => ({
  startScan: vi.fn().mockResolvedValue(undefined),
  cancelScan: vi.fn().mockResolvedValue(undefined),
  getScanStatus: vi.fn().mockResolvedValue({
    isScanning: false,
    filesScanned: 0,
    filesRemaining: 0,
    progressPercent: 0,
    cleanCount: 0,
    suspiciousCount: 0,
    malwareCount: 0,
    elapsedSeconds: 0,
  }),
  forceResetScan: vi.fn().mockResolvedValue(undefined),
  safeInvoke: vi.fn().mockResolvedValue({}),
  safeListen: vi.fn().mockResolvedValue(() => {}),
  ignoreThreat: vi.fn().mockResolvedValue(undefined),
  pickScanFolder: vi.fn().mockResolvedValue(null),
  pickScanFile: vi.fn().mockResolvedValue(null),
  getScheduledScans: vi.fn().mockResolvedValue([]),
  createScheduledScan: vi.fn().mockResolvedValue(undefined),
  toggleScheduledScan: vi.fn().mockResolvedValue(undefined),
  deleteScheduledScan: vi.fn().mockResolvedValue(undefined),
  runScheduledScanNow: vi.fn().mockResolvedValue(undefined),
}));

const baseStatus: ScanStatus = {
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

describe('Scanner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getScanStatus).mockResolvedValue(baseStatus);
    vi.mocked(api.safeListen).mockResolvedValue(() => {});
  });

  it('renders scan controls', async () => {
    await act(async () => {
      render(<Scanner autoQuarantine={true} />);
    });
    // Should show scan buttons/controls
    expect(screen.getAllByText(/scan/i).length).toBeGreaterThan(0);
  });

  it('renders without crashing with autoQuarantine=false', async () => {
    await act(async () => {
      render(<Scanner autoQuarantine={false} />);
    });
    expect(screen.getAllByText(/scan/i).length).toBeGreaterThan(0);
  });

  it('has a quick scan button', async () => {
    await act(async () => {
      render(<Scanner autoQuarantine={true} />);
    });
    const quickScanBtn = screen.getByText(/quick scan/i);
    expect(quickScanBtn).toBeInTheDocument();
  });

  it('has a full scan button', async () => {
    await act(async () => {
      render(<Scanner autoQuarantine={true} />);
    });
    const fullScanBtn = screen.getByText(/full scan/i);
    expect(fullScanBtn).toBeInTheDocument();
  });

  it('has a custom scan option', async () => {
    await act(async () => {
      render(<Scanner autoQuarantine={true} />);
    });
    expect(screen.getByText(/Custom Scan/)).toBeInTheDocument();
  });

  it('shows a whitelisted status after trusting a detected file', async () => {
    const listeners: Record<string, (event: { payload: Record<string, unknown> }) => void> = {};
    const hash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const scanningStatus = {
      ...baseStatus,
      isScanning: true,
      filesScanned: 1,
      progressPercent: 100,
      suspiciousCount: 1,
      elapsedSeconds: 1,
      totalFiles: 1,
      scanType: 'quick',
    };
    let currentStatus: ScanStatus = baseStatus;

    vi.mocked(api.getScanStatus).mockImplementation(async () => currentStatus);
    vi.mocked(api.startScan).mockImplementation(async () => {
      currentStatus = scanningStatus;
    });
    vi.mocked(api.safeListen).mockImplementation(async (eventName: string, callback: any) => {
      listeners[eventName] = callback;
      return () => {
        delete listeners[eventName];
      };
    });

    render(<Scanner autoQuarantine={false} />);

    await waitFor(() => expect(api.safeListen).toHaveBeenCalledTimes(2));

    fireEvent.click(screen.getAllByText(/quick scan/i)[0]);

    await waitFor(() => expect(api.startScan).toHaveBeenCalled());

    await act(async () => {
      listeners['scan-result']({
        payload: {
          file_hash: hash,
          verdict: 'suspicious',
          confidence: 0.65,
          threat_level: 'MEDIUM',
          scan_time_ms: 120,
          file_path: 'C:\\test\\sus.exe',
        },
      });
    });

    currentStatus = {
      ...scanningStatus,
      isScanning: false,
    };

    await act(async () => {
      listeners['scan-complete']({
        payload: {
          totalFiles: 1,
          cleanCount: 0,
          suspiciousCount: 1,
          malwareCount: 0,
          elapsedSeconds: 1,
          scanType: 'quick',
        },
      });
    });

    await waitFor(() => expect(screen.getByText('Trust & Whitelist')).toBeInTheDocument());

    fireEvent.click(screen.getByText('Trust & Whitelist'));

    await waitFor(() => expect(api.ignoreThreat).toHaveBeenCalledWith(hash));
    expect(screen.getByText('Whitelisted')).toBeInTheDocument();
    expect(screen.queryByText('Quarantined')).not.toBeInTheDocument();
  });
});
