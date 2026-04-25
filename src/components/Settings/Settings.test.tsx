import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Settings } from './Settings';
import type { SettingsProps } from './Settings';

const { mockSafeInvoke, mockPickScanFolder } = vi.hoisted(() => ({
  mockSafeInvoke: vi.fn(),
  mockPickScanFolder: vi.fn(),
}));

// Mock sub-components with heavy dependencies
vi.mock('../Exclusions/ExclusionsManager', () => ({
  ExclusionsManager: () => <div data-testid="exclusions-manager">ExclusionsManager</div>,
}));
vi.mock('./AuditLog', () => ({
  AuditLog: () => <div data-testid="audit-log">AuditLog</div>,
}));
vi.mock('./WhitelistManager', () => ({
  WhitelistManager: () => <div data-testid="whitelist-manager">WhitelistManager</div>,
}));

// Mock safeInvoke and pickScanFolder
vi.mock('../../services/api', () => ({
  safeInvoke: (...args: unknown[]) => mockSafeInvoke(...args),
  pickScanFolder: (...args: unknown[]) => mockPickScanFolder(...args),
  openExternalUrl: vi.fn().mockResolvedValue(undefined),
}));

const defaultProps: SettingsProps = {
  autoQuarantine: true,
  realTimeProtection: true,
  ransomwareProtection: true,
  ransomwareAutoBlock: true,
  ransomwareThreshold: 20,
  ransomwareWindowSeconds: 10,
  scanWorkerCount: 4,
  autostart: true,
  onAutoQuarantineChange: vi.fn(),
  onRealTimeChange: vi.fn(),
  onRansomwareProtectionChange: vi.fn(),
  onRansomwareAutoBlockChange: vi.fn(),
  onRansomwareThresholdsChange: vi.fn(),
  onRedeployCanaryFiles: vi.fn(),
  onScanWorkerCountChange: vi.fn(),
  onAutostartChange: vi.fn(),
};

describe('Settings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSafeInvoke.mockImplementation(() => new Promise(() => {}));
    mockPickScanFolder.mockResolvedValue(null);
  });

  it('renders Settings heading', () => {
    render(<Settings {...defaultProps} />);
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('renders navigation tabs', () => {
    render(<Settings {...defaultProps} />);
    // 'Protection' appears both as tab and section heading
    expect(screen.getAllByText('Protection').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Performance')).toBeInTheDocument();
    expect(screen.getByText('Exclusions')).toBeInTheDocument();
    expect(screen.getByText('Audit Log')).toBeInTheDocument();
  });

  it('shows Protection tab by default', () => {
    render(<Settings {...defaultProps} />);
    // Protection tab content should be visible
    expect(screen.getByText(/Real-time Protection/i)).toBeInTheDocument();
  });

  it('switches to Exclusions tab', () => {
    render(<Settings {...defaultProps} />);
    fireEvent.click(screen.getByText('Exclusions'));
    expect(screen.getByTestId('exclusions-manager')).toBeInTheDocument();
  });

  it('switches to Audit Log tab', () => {
    render(<Settings {...defaultProps} />);
    fireEvent.click(screen.getByText('Audit Log'));
    expect(screen.getByTestId('audit-log')).toBeInTheDocument();
  });

  it('renders auto-quarantine toggle', () => {
    render(<Settings {...defaultProps} />);
    // Find the auto quarantine switch
    const switches = screen.getAllByRole('checkbox');
    expect(switches.length).toBeGreaterThan(0);
  });

  it('renders app update section', () => {
    render(<Settings {...defaultProps} appVersion="1.0.1" />);
    expect(screen.getByText('App Updates')).toBeInTheDocument();
    expect(screen.getByText('Current version: v1.0.1')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Check Now' })).toBeInTheDocument();
  });

  it('shows download action when an update is available', () => {
    render(
      <Settings
        {...defaultProps}
        appVersion="1.0.1"
        appUpdate={{
          currentVersion: '1.0.1',
          latestVersion: '1.0.2',
          downloadUrl: 'https://example.com/InSecurity_1.0.2.exe',
          releasePageUrl: 'https://github.com/example/releases/latest',
          publishedAt: null,
        }}
      />
    );

    expect(screen.getByText('Installer v1.0.2 is available.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download Installer' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Hide This Update' })).toBeInTheDocument();
  });

  it('renders with minimal required props only', () => {
    const minProps: SettingsProps = {
      autoQuarantine: false,
      onAutoQuarantineChange: vi.fn(),
    };
    // Should not crash with missing optional props
    render(<Settings {...minProps} />);
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });
});
