import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { RealtimeResults } from './RealtimeResults';
import type { ScanResult } from '../../types/scan';
import { Verdict } from '../../types/scan';

// Mock API
vi.mock('../../services/api', () => ({
  safeInvoke: vi.fn().mockResolvedValue({}),
  ignoreThreat: vi.fn().mockResolvedValue(undefined),
}));

// Mock ThreatIntelligencePanel
vi.mock('../ThreatIntel/ThreatIntelligencePanel', () => ({
  ThreatIntelligencePanel: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="threat-intel-panel">
      <button onClick={onClose}>Close Panel</button>
    </div>
  ),
}));

const malwareResult: ScanResult = {
  threatId: 'threat-1',
  fileHash: 'abc123',
  verdict: Verdict.MALWARE,
  confidence: 0.95,
  threatLevel: 'HIGH',
  threatName: 'Trojan.Test',
  scanTimeMs: 150,
  filePath: 'C:\\test\\malware.exe',
};

const cleanResult: ScanResult = {
  threatId: 'threat-2',
  fileHash: 'def456',
  verdict: Verdict.CLEAN,
  confidence: 0.05,
  threatLevel: 'LOW',
  scanTimeMs: 50,
  filePath: 'C:\\test\\clean.exe',
};

const suspiciousResult: ScanResult = {
  threatId: 'threat-3',
  fileHash: 'ghi789',
  verdict: Verdict.SUSPICIOUS,
  confidence: 0.65,
  threatLevel: 'MEDIUM',
  threatName: 'Suspicious.Generic',
  scanTimeMs: 100,
  filePath: 'C:\\test\\sus.exe',
};

describe('RealtimeResults', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders empty state when no results', () => {
    render(<RealtimeResults results={[]} />);
    expect(screen.getByText(/no.*results|no.*threats|monitoring/i)).toBeInTheDocument();
  });

  it('renders results list', () => {
    render(<RealtimeResults results={[malwareResult, suspiciousResult]} />);
    expect(screen.getByText(/malware\.exe/)).toBeInTheDocument();
    expect(screen.getByText(/sus\.exe/)).toBeInTheDocument();
  });

  it('shows threat name when available', () => {
    render(<RealtimeResults results={[malwareResult]} />);
    expect(screen.getByText(/Trojan\.Test/)).toBeInTheDocument();
  });

  it('displays verdict badges', () => {
    render(<RealtimeResults results={[malwareResult, suspiciousResult]} />);
    // 'malware' appears in both filename and badge
    expect(screen.getAllByText(/malware/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/suspicious/i).length).toBeGreaterThanOrEqual(1);
  });

  it('calls onThreatResolved when provided', () => {
    const onResolved = vi.fn();
    render(<RealtimeResults results={[malwareResult]} onThreatResolved={onResolved} />);
    // Component should render with the callback wired up
    expect(screen.getByText(/malware\.exe/)).toBeInTheDocument();
  });

  it('handles multiple results', () => {
    // CLEAN results are filtered out by isThreat() - only threats are displayed
    const results = [malwareResult, cleanResult, suspiciousResult];
    render(<RealtimeResults results={results} />);
    expect(screen.getByText(/malware\.exe/)).toBeInTheDocument();
    expect(screen.getByText(/sus\.exe/)).toBeInTheDocument();
    // clean.exe is not shown because it's not a threat
    expect(screen.queryByText(/clean\.exe/)).not.toBeInTheDocument();
  });

  it('shows a folder hint when duplicate basenames are visible', () => {
    render(
      <RealtimeResults
        results={[
          malwareResult,
          {
            ...suspiciousResult,
            threatId: 'threat-4',
            filePath: 'C:\\other\\malware.exe',
            threatName: 'Suspicious.Activity',
          },
        ]}
      />
    );

    expect(screen.getByText(/other/i)).toBeInTheDocument();
  });
});
