import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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
  getLastManualScanThreats: vi.fn().mockResolvedValue([]),
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
    vi.mocked(api.getLastManualScanThreats).mockResolvedValue([]);
  });

  afterEach(() => {
    cleanup();
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

  it('renders external media scan labels during progress and completion', async () => {
    const listeners: Record<string, (event: { payload: any }) => void> = {};
    let currentStatus: ScanStatus = {
      ...baseStatus,
      isScanning: true,
      totalFiles: 0,
      scanType: 'external',
    };
    vi.mocked(api.getScanStatus).mockImplementation(async () => currentStatus);
    vi.mocked(api.safeListen).mockImplementation(async (eventName: string, callback: any) => {
      listeners[eventName] = callback;
      return () => {
        delete listeners[eventName];
      };
    });

    render(<Scanner autoQuarantine={true} />);

    await waitFor(() => {
      expect(screen.getByText('Preparing External Media Scan...')).toBeInTheDocument();
    });

    currentStatus = {
      ...baseStatus,
      scanType: 'external',
    };

    await act(async () => {
      listeners['scan-complete']({
        payload: {
          totalFiles: 5,
          cleanCount: 5,
          suspiciousCount: 0,
          malwareCount: 0,
          elapsedSeconds: 2,
          scanType: 'external',
        },
      });
    });

    await waitFor(() => {
      expect(screen.getByText('External Media Scan')).toBeInTheDocument();
    });
  });

  it('restores the last completed external media scan when the scanner tab opens later', async () => {
    vi.mocked(api.getScanStatus).mockResolvedValue({
      ...baseStatus,
      totalFiles: 2,
      cleanCount: 1,
      suspiciousCount: 0,
      malwareCount: 1,
      elapsedSeconds: 0,
      scanType: 'external',
    });
    vi.mocked(api.getLastManualScanThreats).mockResolvedValue([
      {
        filePath: 'E:\\USB\\usb-dropper.exe',
        fileHash: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        verdict: 'Malware',
        threatLevel: 'HIGH',
        threatName: 'USB.Dropper',
        confidence: 0.97,
        detectedAt: '2026-05-29 10:00:00 UTC',
        detectionReasons: [],
      },
    ]);

    render(<Scanner autoQuarantine={false} />);

    await waitFor(() => expect(screen.getByText('External Media Scan')).toBeInTheDocument());
    await waitFor(() => expect(api.getLastManualScanThreats).toHaveBeenCalled());
    expect(screen.getByText('usb-dropper.exe')).toBeInTheDocument();
    expect(screen.getByText('USB.Dropper')).toBeInTheDocument();
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

    await waitFor(() => expect(screen.getAllByText('Trust & Whitelist').length).toBeGreaterThan(0));

    fireEvent.click(screen.getAllByText('Trust & Whitelist')[0]);

    await waitFor(() => expect(api.ignoreThreat).toHaveBeenCalledWith(hash, 'C:\\test\\sus.exe'));
    expect(screen.getByText('Whitelisted')).toBeInTheDocument();
    expect(screen.queryByText('Quarantined')).not.toBeInTheDocument();
  });

  it('keeps same-hash files in different folders separate in the manual scanner', async () => {
    const listeners: Record<string, (event: { payload: Record<string, unknown> }) => void> = {};
    const hash = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const scanningStatus = {
      ...baseStatus,
      isScanning: true,
      filesScanned: 2,
      progressPercent: 100,
      suspiciousCount: 2,
      elapsedSeconds: 1,
      totalFiles: 2,
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
          threat_name: 'Suspicious.Activity',
          file_path: 'C:\\test\\dup.exe',
        },
      });
      listeners['scan-result']({
        payload: {
          file_hash: hash,
          verdict: 'suspicious',
          confidence: 0.66,
          threat_level: 'MEDIUM',
          scan_time_ms: 121,
          threat_name: 'Suspicious.Activity',
          file_path: 'D:\\other\\dup.exe',
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
          totalFiles: 2,
          cleanCount: 0,
          suspiciousCount: 2,
          malwareCount: 0,
          elapsedSeconds: 1,
          scanType: 'quick',
        },
      });
    });

    await waitFor(() => expect(screen.getByText('C:\\test\\dup.exe')).toBeInTheDocument());
    expect(screen.getByText('D:\\other\\dup.exe')).toBeInTheDocument();

    const rows = screen.getAllByText('dup.exe');
    expect(rows).toHaveLength(2);
    expect(screen.getByText('C:\\test')).toBeInTheDocument();
    expect(screen.getByText('D:\\other')).toBeInTheDocument();

    const secondRow = screen.getByText('D:\\other\\dup.exe').closest('.threat-item');
    expect(secondRow).not.toBeNull();
    fireEvent.click(within(secondRow as HTMLElement).getByText('Trust & Whitelist'));

    await waitFor(() => expect(api.ignoreThreat).toHaveBeenCalledWith(hash, 'D:\\other\\dup.exe'));

    expect(screen.getByText('C:\\test\\dup.exe')).toBeInTheDocument();
    expect(screen.getByText('D:\\other\\dup.exe')).toBeInTheDocument();
    expect(screen.getByText('Whitelisted')).toBeInTheDocument();
    expect(screen.getAllByText('Trust & Whitelist').length).toBeGreaterThanOrEqual(1);
  });

  it.each(['custom', 'full'] as const)('hydrates malware details after %s scan completion', async (scanType) => {
    const listeners: Record<string, (event: { payload: any }) => void> = {};
    const scanningStatus: ScanStatus = {
      ...baseStatus,
      isScanning: true,
      filesScanned: 1,
      progressPercent: 100,
      malwareCount: 1,
      elapsedSeconds: 1,
      totalFiles: 1,
      scanType,
    };
    let currentStatus: ScanStatus = baseStatus;

    vi.mocked(api.getScanStatus).mockImplementation(async () => currentStatus);
    vi.mocked(api.startScan).mockImplementation(async () => {
      currentStatus = scanningStatus;
    });
    vi.mocked(api.getLastManualScanThreats).mockResolvedValue([
      {
        filePath: scanType === 'custom' ? 'C:\\samples\\eicar.com.txt' : 'C:\\Users\\test\\Downloads\\payload.exe',
        fileHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        verdict: 'Malware',
        threatLevel: 'HIGH',
        threatName: 'EICAR Test File',
        confidence: 0.99,
        detectedAt: '2026-05-27 12:00:00 UTC',
        detectionReasons: [],
      },
    ]);
    vi.mocked(api.safeListen).mockImplementation(async (eventName: string, callback: any) => {
      listeners[eventName] = callback;
      return () => {
        delete listeners[eventName];
      };
    });

    render(<Scanner autoQuarantine={false} />);

    await waitFor(() => expect(api.safeListen).toHaveBeenCalledTimes(2));

    if (scanType === 'custom') {
      const customInput = screen.getByPlaceholderText('C:\\path\\to\\folder\\or\\file');
      fireEvent.change(customInput, { target: { value: 'C:\\samples\\eicar.com.txt' } });
      fireEvent.click(within(customInput.closest('.custom-path-input') as HTMLElement).getByText(/^scan$/i));
    } else {
      fireEvent.click(screen.getAllByText(/full scan/i)[0]);
    }

    await waitFor(() => expect(api.startScan).toHaveBeenCalled());

    currentStatus = {
      ...scanningStatus,
      isScanning: false,
    };

    await act(async () => {
      listeners['scan-complete']({
        payload: {
          totalFiles: 1,
          cleanCount: 0,
          suspiciousCount: 0,
          malwareCount: 1,
          elapsedSeconds: 1,
          scanType,
        },
      });
    });

    await waitFor(() => expect(api.getLastManualScanThreats).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText('EICAR Test File')).toBeInTheDocument());
    expect(screen.getByText(scanType === 'custom' ? 'eicar.com.txt' : 'payload.exe')).toBeInTheDocument();
    expect(screen.getByText(/threats found \(1\)/i)).toBeInTheDocument();
  });
});
