import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { AuditLog } from './AuditLog';

// Mock safeInvoke
const mockSafeInvoke = vi.fn();
vi.mock('../../services/api', () => ({
  safeInvoke: (...args: any[]) => mockSafeInvoke(...args),
}));

const sampleEntries = [
  {
    timestamp: 1709640000,
    event_type: 'SCAN_COMPLETED',
    details: 'Quick scan completed: 100 files',
    file_path: null,
  },
  {
    timestamp: 1709726400,
    event_type: 'THREAT_QUARANTINED',
    details: 'File quarantined: malware.exe',
    file_path: 'C:\\test\\malware.exe',
  },
];

describe('AuditLog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSafeInvoke.mockImplementation(() => new Promise(() => {}));
  });

  it('renders header', async () => {
    render(<AuditLog />);
    expect(screen.getByText('Security Audit Log')).toBeInTheDocument();
  });

  it('shows loading state initially', () => {
    // Never resolve so it stays in loading
    mockSafeInvoke.mockReturnValue(new Promise(() => {}));
    render(<AuditLog />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('displays audit entries when loaded', async () => {
    mockSafeInvoke.mockResolvedValueOnce(sampleEntries);
    render(<AuditLog />);
    await waitFor(() => {
      expect(screen.getByText(/Quick scan completed/)).toBeInTheDocument();
    });
  });

  it('shows empty state when no entries', async () => {
    mockSafeInvoke.mockResolvedValueOnce([]);
    render(<AuditLog />);
    await waitFor(() => {
      expect(screen.getByText('No audit events recorded yet.')).toBeInTheDocument();
    });
  });

  it('handles API error gracefully', async () => {
    mockSafeInvoke.mockRejectedValueOnce(new Error('API failure'));
    render(<AuditLog />);
    await waitFor(() => {
      // The component displays err.message via ErrorBanner
      expect(screen.getByText('API failure')).toBeInTheDocument();
    });
  });

  it('has verify integrity button', async () => {
    mockSafeInvoke.mockResolvedValueOnce(sampleEntries);
    render(<AuditLog />);
    await waitFor(() => {
      expect(screen.getByText('Verify Integrity')).toBeInTheDocument();
    });
  });
});
