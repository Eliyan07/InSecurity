import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ExclusionsManager } from './ExclusionsManager';

// Mock the useExclusions hook
const mockUseExclusions = {
  exclusions: [] as any[],
  loading: false,
  error: null as string | null,
  fetchExclusions: vi.fn(),
  addExclusion: vi.fn().mockResolvedValue(true),
  updateExclusion: vi.fn().mockResolvedValue(undefined),
  toggleExclusion: vi.fn().mockResolvedValue(undefined),
  deleteExclusion: vi.fn().mockResolvedValue(undefined),
  checkPathExcluded: vi.fn().mockResolvedValue(false),
  clearError: vi.fn(),
};

vi.mock('../../hooks/useExclusions', () => ({
  useExclusions: () => mockUseExclusions,
}));

const sampleExclusions = [
  {
    id: 1,
    exclusion_type: 'folder' as const,
    pattern: 'C:\\TrustedFolder',
    reason: 'Dev tools',
    enabled: true,
    created_at: 1709640000,
    updated_at: 1709640000,
  },
  {
    id: 2,
    exclusion_type: 'extension' as const,
    pattern: '.log',
    reason: null,
    enabled: false,
    created_at: 1709726400,
    updated_at: 1709726400,
  },
];

describe('ExclusionsManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseExclusions.exclusions = [];
    mockUseExclusions.loading = false;
    mockUseExclusions.error = null;
  });

  it('renders header', () => {
    render(<ExclusionsManager />);
    expect(screen.getByText('Exclusions Manager')).toBeInTheDocument();
  });

  it('calls fetchExclusions on mount', () => {
    render(<ExclusionsManager />);
    expect(mockUseExclusions.fetchExclusions).toHaveBeenCalled();
  });

  it('shows loading state', () => {
    mockUseExclusions.loading = true;
    render(<ExclusionsManager />);
    expect(screen.getByText('Loading exclusions...')).toBeInTheDocument();
  });

  it('shows empty state when no exclusions', () => {
    render(<ExclusionsManager />);
    expect(screen.getByText('No exclusions yet')).toBeInTheDocument();
  });

  it('renders exclusion list', () => {
    mockUseExclusions.exclusions = sampleExclusions;
    render(<ExclusionsManager />);
    expect(screen.getByText('C:\\TrustedFolder')).toBeInTheDocument();
    expect(screen.getByText('.log')).toBeInTheDocument();
    expect(screen.getByText('Dev tools')).toBeInTheDocument();
  });

  it('shows error banner when error exists', () => {
    mockUseExclusions.error = 'Failed to load exclusions';
    render(<ExclusionsManager />);
    expect(screen.getByText('Failed to load exclusions')).toBeInTheDocument();
  });

  it('shows filter tabs', () => {
    mockUseExclusions.exclusions = sampleExclusions;
    render(<ExclusionsManager />);
    expect(screen.getByText(/All/)).toBeInTheDocument();
    expect(screen.getByText('Paths')).toBeInTheDocument();
    expect(screen.getByText('Folders')).toBeInTheDocument();
    expect(screen.getByText('Extensions')).toBeInTheDocument();
    expect(screen.getByText('Patterns')).toBeInTheDocument();
  });

  it('filters exclusions by type', () => {
    mockUseExclusions.exclusions = sampleExclusions;
    render(<ExclusionsManager />);

    fireEvent.click(screen.getByText('Extensions'));
    expect(screen.getByText('.log')).toBeInTheDocument();
    expect(screen.queryByText('C:\\TrustedFolder')).not.toBeInTheDocument();
  });

  it('can toggle exclusion enabled state', () => {
    mockUseExclusions.exclusions = sampleExclusions;
    render(<ExclusionsManager />);

    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[0]); // Toggle first exclusion
    expect(mockUseExclusions.toggleExclusion).toHaveBeenCalledWith(1, false);
  });

  it('can delete exclusion with confirmation', async () => {
    mockUseExclusions.exclusions = sampleExclusions;
    render(<ExclusionsManager />);

    const deleteButtons = screen.getAllByTitle('Delete');
    fireEvent.click(deleteButtons[0]);

    // The confirm dialog should appear - click the confirm button
    await waitFor(() => {
      expect(screen.getByText('Delete Exclusion')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('Delete'));

    await waitFor(() => {
      expect(mockUseExclusions.deleteExclusion).toHaveBeenCalledWith(1);
    });
  });

  it('does not delete when confirmation is cancelled', async () => {
    mockUseExclusions.exclusions = sampleExclusions;
    render(<ExclusionsManager />);

    const deleteButtons = screen.getAllByTitle('Delete');
    fireEvent.click(deleteButtons[0]);

    // The confirm dialog should appear - click cancel
    await waitFor(() => {
      expect(screen.getByText('Delete Exclusion')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('Cancel'));

    // Dialog should close and delete should not be called
    await waitFor(() => {
      expect(screen.queryByText('Delete Exclusion')).not.toBeInTheDocument();
    });
    expect(mockUseExclusions.deleteExclusion).not.toHaveBeenCalled();
  });

  it('add form submits new exclusion', async () => {
    render(<ExclusionsManager />);

    const input = screen.getByPlaceholderText('C:\\Users\\Documents\\TrustedFolder');
    fireEvent.change(input, { target: { value: 'C:\\NewFolder' } });

    const addBtn = screen.getByText('Add');
    fireEvent.click(addBtn);

    await waitFor(() => {
      expect(mockUseExclusions.addExclusion).toHaveBeenCalledWith(
        expect.objectContaining({
          exclusion_type: 'folder',
          pattern: 'C:\\NewFolder',
        })
      );
    });
  });

  it('add button is disabled when pattern is empty', () => {
    render(<ExclusionsManager />);
    const addBtn = screen.getByText('Add');
    expect(addBtn).toBeDisabled();
  });
});
