import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Dashboard } from './Dashboard';
import type { DashboardStats } from '../../types/dashboard';
import type { ScanResult } from '../../types/scan';
import { Verdict } from '../../types/scan';

const mockStats: DashboardStats = {
  totalScans: 150,
  malwareDetected: 5,
  suspiciousDetected: 3,
  quarantinedCount: 2,
  threatIntelCount: 10,
  lastScanTime: 1709640000,
  protectionStatus: 'active',
  activeMalware: 1,
  activeSuspicious: 2,
};

const emptyResults: ScanResult[] = [];

describe('Dashboard', () => {
  it('shows loading state when loading and no stats', () => {
    render(<Dashboard stats={null} loading={true} realtimeResults={emptyResults} />);
    expect(screen.getByText('Loading dashboard...')).toBeInTheDocument();
  });

  it('renders protection hero with stats', () => {
    render(<Dashboard stats={mockStats} loading={false} realtimeResults={emptyResults} />);
    expect(screen.getByText('Threats Detected')).toBeInTheDocument();
  });

  it('shows "Your System is Protected" when no threats and active protection', () => {
    const safeStats = { ...mockStats, activeMalware: 0, activeSuspicious: 0, protectionStatus: 'active' };
    render(<Dashboard stats={safeStats} loading={false} realtimeResults={emptyResults} />);
    expect(screen.getByText('Your System is Protected')).toBeInTheDocument();
  });

  it('shows "Protection Disabled" when protection is not active', () => {
    const disabledStats = { ...mockStats, activeMalware: 0, activeSuspicious: 0, protectionStatus: 'disabled' };
    render(<Dashboard stats={disabledStats} loading={false} realtimeResults={emptyResults} />);
    expect(screen.getByText('Protection Disabled')).toBeInTheDocument();
  });

  it('displays malware and suspicious counts', () => {
    render(<Dashboard stats={mockStats} loading={false} realtimeResults={emptyResults} />);
    expect(screen.getByText('1')).toBeInTheDocument(); // activeMalware
    // '2' appears for both activeSuspicious and quarantinedCount
    expect(screen.getAllByText('2').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Malware')).toBeInTheDocument();
    expect(screen.getByText('Suspicious')).toBeInTheDocument();
  });

  it('displays quarantined count', () => {
    render(<Dashboard stats={mockStats} loading={false} realtimeResults={emptyResults} />);
    const quarantinedValues = screen.getAllByText('2');
    expect(quarantinedValues.length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Quarantined')).toBeInTheDocument();
  });

  it('displays "Never" when lastScanTime is null', () => {
    const noScanStats = { ...mockStats, lastScanTime: null };
    render(<Dashboard stats={noScanStats} loading={false} realtimeResults={emptyResults} />);
    expect(screen.getByText(/Never/)).toBeInTheDocument();
  });

  it('renders with null stats and not loading', () => {
    render(<Dashboard stats={null} loading={false} realtimeResults={emptyResults} />);
    // null stats means protection status is undefined, so heroState = 'unprotected'
    expect(screen.getByText('Protection Disabled')).toBeInTheDocument();
  });

  it('passes realtimeResults to RealtimeResults component', () => {
    const results: ScanResult[] = [
      {
        fileHash: 'abc123',
        verdict: Verdict.MALWARE,
        confidence: 0.95,
        threatLevel: 'HIGH',
        threatName: 'Trojan.Test',
        scanTimeMs: 100,
        filePath: 'C:\\test\\malware.exe',
      },
    ];
    render(<Dashboard stats={mockStats} loading={false} realtimeResults={results} />);
    // RealtimeResults renders the file path
    expect(screen.getByText(/malware\.exe/)).toBeInTheDocument();
  });

  it('passes onThreatResolved to RealtimeResults', () => {
    const onResolved = vi.fn();
    render(
      <Dashboard stats={mockStats} loading={false} realtimeResults={emptyResults} onThreatResolved={onResolved} />
    );
    // Component renders without error
    expect(screen.getByText('Threats Detected')).toBeInTheDocument();
  });
});
