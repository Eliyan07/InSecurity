import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import App from './App';

const { mockSafeListen, mockSafeInvoke } = vi.hoisted(() => ({
  mockSafeListen: vi.fn().mockResolvedValue(() => {}),
  mockSafeInvoke: vi.fn().mockResolvedValue(undefined),
}));

// Mock all lazy-loaded components
vi.mock('./components/Dashboard/Dashboard', () => ({
  Dashboard: (props: any) => <div data-testid="dashboard">Dashboard {props.loading ? 'loading' : 'ready'}</div>,
}));
vi.mock('./components/Scanner/Scanner', () => ({
  Scanner: (props: any) => <div data-testid="scanner">Scanner autoQ={String(props.autoQuarantine)}</div>,
}));
vi.mock('./components/Quarantine/QuarantineList', () => ({
  QuarantineList: (props: any) => <div data-testid="quarantine">Quarantine {props.loading ? 'loading' : 'ready'}</div>,
}));
vi.mock('./components/Settings/Settings', () => ({
  Settings: () => <div data-testid="settings">Settings</div>,
}));

// Mock ErrorBoundary as a transparent wrapper
vi.mock('./components/ErrorBoundary/ErrorBoundary', () => ({
  ErrorBoundary: ({ children }: any) => <div>{children}</div>,
  withErrorBoundary: (Component: any) => Component,
}));

// Mock Sidebar
vi.mock('./components/Sidebar/Sidebar', () => ({
  Sidebar: ({ activeItem, onNavigate, quarantineCount, protectionEnabled }: any) => (
    <nav data-testid="sidebar">
      <span data-testid="active-nav">{activeItem}</span>
      <span data-testid="protection">{String(protectionEnabled)}</span>
      <span data-testid="quarantine-count">{quarantineCount}</span>
      <button onClick={() => onNavigate('dashboard')}>Dashboard</button>
      <button onClick={() => onNavigate('scanner')}>Scanner</button>
      <button onClick={() => onNavigate('quarantine')}>Quarantine</button>
      <button onClick={() => onNavigate('settings')}>Settings</button>
    </nav>
  ),
}));

// Mock hooks
const mockRealtimeScan = {
  realtimeResults: [],
  removeResult: vi.fn(),
  clearResults: vi.fn(),
  refreshActiveThreats: vi.fn(),
};

const mockQuarantine = {
  quarantinedFiles: [] as any[],
  loading: false,
  listQuarantined: vi.fn(),
  restoreFile: vi.fn(),
  deleteFile: vi.fn(),
};

const mockSettings = {
  settings: {
    realTimeProtection: true,
    autoQuarantine: false,
    ransomwareProtection: true,
    ransomwareAutoBlock: true,
    ransomwareThreshold: 20,
    ransomwareWindowSeconds: 10,
    cacheSizeMb: 50,
    scanWorkerCount: 4,
    autostart: true,
    language: 'en',
  },
  getSettings: vi.fn().mockResolvedValue(undefined),
  setRealTimeProtection: vi.fn(),
  setAutoQuarantine: vi.fn(),
  setRansomwareProtection: vi.fn(),
  setRansomwareAutoBlock: vi.fn(),
  setRansomwareThresholds: vi.fn(),
  dismissRansomwareAlert: vi.fn(),
  killRansomwareProcess: vi.fn(),
  redeployCanaryFiles: vi.fn(),
  setScanWorkerCount: vi.fn(),
  setAutostart: vi.fn(),
  setLanguage: vi.fn().mockResolvedValue(undefined),
};

const mockDashboard = {
  stats: null,
  loading: false,
  refresh: vi.fn(),
};

vi.mock('./hooks/useRealtimeScan', () => ({
  useRealtimeScan: () => mockRealtimeScan,
}));
vi.mock('./hooks/useQuarantine', () => ({
  useQuarantine: () => mockQuarantine,
}));
vi.mock('./hooks/useSettings', () => ({
  useSettings: () => mockSettings,
}));
vi.mock('./hooks/useDashboard', () => ({
  useDashboard: () => mockDashboard,
}));
vi.mock('./services/api', () => ({
  safeListen: mockSafeListen,
  safeInvoke: mockSafeInvoke,
}));

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSafeListen.mockResolvedValue(() => {});
    mockSafeInvoke.mockResolvedValue(undefined);
  });

  it('renders sidebar and dashboard by default', async () => {
    render(<App />);
    expect(screen.getByTestId('sidebar')).toBeInTheDocument();
    // Dashboard is default active nav
    expect(screen.getByTestId('active-nav')).toHaveTextContent('dashboard');
    await waitFor(() => {
      expect(screen.getByTestId('dashboard')).toBeInTheDocument();
    });
  });

  it('navigates to scanner when sidebar button clicked', async () => {
    render(<App />);
    fireEvent.click(screen.getByText('Scanner'));
    await waitFor(() => {
      expect(screen.getByTestId('scanner')).toBeInTheDocument();
    });
    expect(screen.getByTestId('active-nav')).toHaveTextContent('scanner');
  });

  it('navigates to quarantine page', async () => {
    render(<App />);
    fireEvent.click(screen.getByText('Quarantine'));
    await waitFor(() => {
      expect(screen.getByTestId('quarantine')).toBeInTheDocument();
    });
    expect(mockQuarantine.listQuarantined).toHaveBeenCalled();
  });

  it('navigates to settings page', async () => {
    render(<App />);
    fireEvent.click(screen.getByText('Settings'));
    await waitFor(() => {
      expect(screen.getByTestId('settings')).toBeInTheDocument();
    });
  });

  it('passes protection status to sidebar', () => {
    render(<App />);
    expect(screen.getByTestId('protection')).toHaveTextContent('true');
  });

  it('passes quarantine malware count to sidebar', () => {
    mockQuarantine.quarantinedFiles = [
      { verdict: 'Malware', file_hash: 'a' } as any,
      { verdict: 'Suspicious', file_hash: 'b' } as any,
      { verdict: 'Malware', file_hash: 'c' } as any,
    ];
    render(<App />);
    // Only Malware items counted: 2
    expect(screen.getByTestId('quarantine-count')).toHaveTextContent('2');
    mockQuarantine.quarantinedFiles = []; // reset
  });

  it('loads settings on mount', () => {
    render(<App />);
    expect(mockSettings.getSettings).toHaveBeenCalled();
  });

  it('refreshes dashboard when navigating back to dashboard', async () => {
    render(<App />);
    // First navigate away
    fireEvent.click(screen.getByText('Scanner'));
    await waitFor(() => {
      expect(screen.getByTestId('scanner')).toBeInTheDocument();
    });
    // Navigate back to dashboard
    fireEvent.click(screen.getByText('Dashboard'));
    await waitFor(() => {
      expect(screen.getByTestId('dashboard')).toBeInTheDocument();
    });
    expect(mockDashboard.refresh).toHaveBeenCalled();
  });

  it('passes autoQuarantine setting to Scanner', async () => {
    render(<App />);
    fireEvent.click(screen.getByText('Scanner'));
    await waitFor(() => {
      expect(screen.getByTestId('scanner')).toHaveTextContent('autoQ=false');
    });
  });

  it('lets the user mark a ransomware alert as false positive', async () => {
    let ransomwareCallback: ((event: any) => void) | undefined;
    mockSafeListen.mockImplementation(async (_eventName: string, callback: (event: any) => void) => {
      ransomwareCallback = callback;
      return () => {};
    });

    render(<App />);

    await waitFor(() => {
      expect(mockSafeListen).toHaveBeenCalledWith('ransomware_alert', expect.any(Function));
    });

    await act(async () => {
      ransomwareCallback?.({
        payload: {
          folder: 'C:\\Users\\123\\Documents',
          modification_count: 6,
          time_window_seconds: 10,
          sample_files: ['C:\\Users\\123\\Documents\\photo.jpg'],
          alert_level: 'CRITICAL',
          suspected_processes: [],
          processes_killed: [],
          average_entropy: 4.72,
        },
      });
    });

    fireEvent.click(screen.getByText('Mark False Positive'));

    await waitFor(() => {
      expect(mockSafeInvoke).toHaveBeenCalledWith('dismiss_ransomware_alert', {
        folder: 'C:\\Users\\123\\Documents',
      });
    });
  });
});
