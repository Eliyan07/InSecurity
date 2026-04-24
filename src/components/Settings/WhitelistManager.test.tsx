import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { WhitelistManager } from './WhitelistManager';

// Mock API
const mockGetUserWhitelist = vi.fn().mockResolvedValue([]);
const mockRemoveFromUserWhitelist = vi.fn().mockResolvedValue(undefined);
const mockClearUserWhitelist = vi.fn().mockResolvedValue(2);

vi.mock('../../services/api', () => ({
  getUserWhitelist: (...args: any[]) => mockGetUserWhitelist(...args),
  removeFromUserWhitelist: (...args: any[]) => mockRemoveFromUserWhitelist(...args),
  clearUserWhitelist: (...args: any[]) => mockClearUserWhitelist(...args),
}));

const sampleEntries = [
  {
    id: 1,
    fileHash: 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
    filePath: 'C:\\Users\\test\\trusted.exe',
    originalVerdict: 'suspicious',
    createdAt: 1709640000,
  },
  {
    id: 2,
    fileHash: 'ghi789jkl012ghi789jkl012ghi789jkl012ghi789jkl012ghi789jkl012ghij',
    filePath: 'C:\\Users\\test\\utility.exe',
    originalVerdict: 'malware',
    createdAt: 1709726400,
  },
];

describe('WhitelistManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUserWhitelist.mockImplementation(() => new Promise(() => {}));
  });

  it('renders heading', () => {
    render(<WhitelistManager />);
    expect(screen.getByText(/whitelist/i)).toBeInTheDocument();
  });

  it('shows empty state when no entries', async () => {
    mockGetUserWhitelist.mockResolvedValueOnce([]);
    render(<WhitelistManager />);
    await waitFor(() => {
      expect(screen.getByText(/no.*whitelist/i)).toBeInTheDocument();
    });
  });

  it('displays whitelist entries when loaded', async () => {
    mockGetUserWhitelist.mockResolvedValueOnce(sampleEntries);
    render(<WhitelistManager />);
    await waitFor(() => {
      expect(screen.getByText(/trusted\.exe/)).toBeInTheDocument();
      expect(screen.getByText(/utility\.exe/)).toBeInTheDocument();
    });
  });

  it('shows hash in the table', async () => {
    mockGetUserWhitelist.mockResolvedValueOnce(sampleEntries);
    render(<WhitelistManager />);
    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeInTheDocument();
    });
  });

  it('shows original verdict', async () => {
    mockGetUserWhitelist.mockResolvedValueOnce(sampleEntries);
    render(<WhitelistManager />);
    await waitFor(() => {
      expect(screen.getByText(/suspicious/i)).toBeInTheDocument();
    });
  });

  it('remove button calls API with confirmation', async () => {
    mockGetUserWhitelist.mockResolvedValueOnce(sampleEntries);
    render(<WhitelistManager />);

    await waitFor(() => {
      expect(screen.getByText(/trusted\.exe/)).toBeInTheDocument();
    });

    const removeButtons = screen.getAllByTitle(/remove/i);
    fireEvent.click(removeButtons[0]);

    // Confirm dialog should appear - click the confirm button
    await waitFor(() => {
      expect(screen.getByText('Remove from Whitelist')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('Remove'));

    await waitFor(() => {
      expect(mockRemoveFromUserWhitelist).toHaveBeenCalled();
    });
  });

  it('remove cancelled by confirmation does not call API', async () => {
    mockGetUserWhitelist.mockResolvedValueOnce(sampleEntries);
    render(<WhitelistManager />);

    await waitFor(() => {
      expect(screen.getByText(/trusted\.exe/)).toBeInTheDocument();
    });

    const removeButtons = screen.getAllByTitle(/remove/i);
    fireEvent.click(removeButtons[0]);

    // Confirm dialog should appear - click cancel
    await waitFor(() => {
      expect(screen.getByText('Remove from Whitelist')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('Cancel'));

    await waitFor(() => {
      expect(screen.queryByText('Remove from Whitelist')).not.toBeInTheDocument();
    });
    expect(mockRemoveFromUserWhitelist).not.toHaveBeenCalled();
  });

  it('clear all button calls API with confirmation', async () => {
    mockGetUserWhitelist.mockResolvedValueOnce(sampleEntries);
    render(<WhitelistManager />);

    await waitFor(() => {
      expect(screen.getByText(/clear all/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/clear all/i));

    // Confirm dialog should appear - click the confirm button
    await waitFor(() => {
      expect(screen.getByText('Clear Whitelist')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('Clear All'));

    await waitFor(() => {
      expect(mockClearUserWhitelist).toHaveBeenCalled();
    });
  });
});
