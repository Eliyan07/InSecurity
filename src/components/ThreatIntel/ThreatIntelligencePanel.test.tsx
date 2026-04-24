import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThreatIntelligencePanel } from './ThreatIntelligencePanel';
import type { DetailedScanResult } from '../../types/threatIntel';

// Mock API services
const { mockGetPersistenceForFile } = vi.hoisted(() => ({
  mockGetPersistenceForFile: vi.fn(),
}));

vi.mock('../../services/api', () => ({
  safeInvoke: vi.fn().mockResolvedValue(null),
  getPersistenceForFile: (...args: unknown[]) => mockGetPersistenceForFile(...args),
}));

const makeMockResult = (overrides: Partial<DetailedScanResult> = {}): DetailedScanResult => ({
  file_hash: 'abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789a',
  file_path: 'C:\\Users\\test\\suspicious_file.exe',
  verdict: 'Malware',
  confidence: 0.92,
  threat_level: 'HIGH',
  scan_time_ms: 200,
  detailed_results: {
    ml_prediction: {
      is_malware: true,
      confidence: 0.92,
      model_available: true,
      model_version: '1.0',
      verdict: 'malware',
      raw_score: 0.92,
    },
    signature_info: {
      is_signed: false,
      is_valid: false,
      is_trusted_publisher: false,
    },
  },
  ...overrides,
});

describe('ThreatIntelligencePanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetPersistenceForFile.mockImplementation(() => new Promise(() => {}));
  });

  it('renders the panel with file name', () => {
    render(<ThreatIntelligencePanel result={makeMockResult()} />);
    expect(screen.getByText(/suspicious_file\.exe/)).toBeInTheDocument();
  });

  it('displays MALWARE DETECTED verdict label', () => {
    render(<ThreatIntelligencePanel result={makeMockResult()} />);
    expect(screen.getByText('MALWARE DETECTED')).toBeInTheDocument();
  });

  it('displays confidence percentage', () => {
    render(<ThreatIntelligencePanel result={makeMockResult()} />);
    expect(screen.getByText('92%')).toBeInTheDocument();
  });

  it('displays file hash in copyable area', () => {
    render(<ThreatIntelligencePanel result={makeMockResult()} />);
    expect(screen.getByText(/abc123def456789/)).toBeInTheDocument();
  });

  it('shows close button and calls onClose when clicked', () => {
    const onClose = vi.fn();
    render(<ThreatIntelligencePanel result={makeMockResult()} onClose={onClose} />);
    const closeBtn = document.querySelector('.tip-close-btn');
    expect(closeBtn).toBeTruthy();
    fireEvent.click(closeBtn!);
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('does not render close button when onClose is not provided', () => {
    render(<ThreatIntelligencePanel result={makeMockResult()} />);
    expect(document.querySelector('.tip-close-btn')).toBeNull();
  });

  it('renders with CLEAN verdict', () => {
    render(<ThreatIntelligencePanel result={makeMockResult({ verdict: 'Clean', confidence: 0.05, threat_level: 'LOW' })} />);
    expect(screen.getByText('CLEAN')).toBeInTheDocument();
    expect(screen.getByText('5%')).toBeInTheDocument();
  });

  it('renders with SUSPICIOUS verdict', () => {
    render(<ThreatIntelligencePanel result={makeMockResult({ verdict: 'Suspicious', confidence: 0.6 })} />);
    expect(screen.getByText('SUSPICIOUS')).toBeInTheDocument();
  });

  it('renders with UNKNOWN verdict', () => {
    render(<ThreatIntelligencePanel result={makeMockResult({ verdict: 'Unknown' })} />);
    expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
  });

  it('shows scan time in quick stats', () => {
    render(<ThreatIntelligencePanel result={makeMockResult({ scan_time_ms: 1234 })} />);
    expect(screen.getByText('1234 ms')).toBeInTheDocument();
  });

  it('shows threat level in quick stats', () => {
    render(<ThreatIntelligencePanel result={makeMockResult({ threat_level: 'CRITICAL' })} />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });

  it('displays threat name when provided', () => {
    render(<ThreatIntelligencePanel result={makeMockResult({ threat_name: 'Trojan.GenericKD' })} />);
    // threat_name may appear in multiple places (header and detail)
    expect(screen.getAllByText('Trojan.GenericKD').length).toBeGreaterThanOrEqual(1);
  });

  it('shows "Why This Was Flagged" section by default', () => {
    render(<ThreatIntelligencePanel result={makeMockResult()} />);
    expect(screen.getByText('Why This Was Flagged')).toBeInTheDocument();
  });

  it('renders ErrorBanner when result is null', () => {
    // @ts-expect-error - testing null input
    render(<ThreatIntelligencePanel result={null} />);
    expect(screen.getByText('No scan result available.')).toBeInTheDocument();
  });

  it('renders ML prediction section', () => {
    render(<ThreatIntelligencePanel result={makeMockResult()} />);
    expect(screen.getByText(/ML|Machine Learning|prediction/i)).toBeInTheDocument();
  });
});
