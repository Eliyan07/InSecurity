import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QuarantineList } from './QuarantineList';
import type { QuarantineEntry } from '../../types/quarantine';

const mockFiles: QuarantineEntry[] = [
  {
    id: 1,
    fileHash: 'abc123',
    originalPath: 'C:\\Users\\test\\malware.exe',
    quarantinePath: 'C:\\quarantine\\abc123',
    verdict: 'Malware',
    threatLevel: 'HIGH',
    reason: 'YARA match',
    quarantinedAt: 1709640000,
    permanentlyDeleted: false,
    fileSize: 102400,
    fileType: 'exe',
  },
  {
    id: 2,
    fileHash: 'def456',
    originalPath: 'C:\\Users\\test\\suspicious.dll',
    quarantinePath: 'C:\\quarantine\\def456',
    verdict: 'Suspicious',
    threatLevel: 'MEDIUM',
    reason: 'Behavioral analysis',
    quarantinedAt: 1709726400,
    permanentlyDeleted: false,
    fileSize: 51200,
    fileType: 'dll',
  },
];

describe('QuarantineList', () => {
  it('renders loading state', () => {
    render(<QuarantineList files={[]} onRestore={vi.fn()} onDelete={vi.fn()} loading={true} />);
    expect(screen.getByText('Loading quarantined files...')).toBeInTheDocument();
  });

  it('renders empty state when no files', () => {
    render(<QuarantineList files={[]} onRestore={vi.fn()} onDelete={vi.fn()} loading={false} />);
    expect(screen.getByText('All Clear!')).toBeInTheDocument();
    expect(screen.getByText('No files are currently quarantined.')).toBeInTheDocument();
  });

  it('renders file list with correct data', () => {
    render(<QuarantineList files={mockFiles} onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('malware.exe')).toBeInTheDocument();
    expect(screen.getByText('suspicious.dll')).toBeInTheDocument();
    expect(screen.getByText('Malware')).toBeInTheDocument();
    expect(screen.getByText('Suspicious')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();
  });

  it('shows file count', () => {
    render(<QuarantineList files={mockFiles} onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('2 files')).toBeInTheDocument();
  });

  it('shows singular "file" for one item', () => {
    render(<QuarantineList files={[mockFiles[0]]} onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('1 file')).toBeInTheDocument();
  });

  it('calls onRestore with correct arguments when Restore clicked', () => {
    const onRestore = vi.fn();
    render(<QuarantineList files={mockFiles} onRestore={onRestore} onDelete={vi.fn()} />);
    const restoreButtons = screen.getAllByText('Restore');
    fireEvent.click(restoreButtons[0]);
    expect(onRestore).toHaveBeenCalledWith(1, 'abc123', 'Malware');
  });

  it('calls onDelete with correct id when Delete clicked', () => {
    const onDelete = vi.fn();
    render(<QuarantineList files={mockFiles} onRestore={vi.fn()} onDelete={onDelete} />);
    const deleteButtons = screen.getAllByText('Delete');
    fireEvent.click(deleteButtons[1]);
    expect(onDelete).toHaveBeenCalledWith(2);
  });

  it('displays file size in KB', () => {
    render(<QuarantineList files={mockFiles} onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('100.00 KB')).toBeInTheDocument();
    expect(screen.getByText('50.00 KB')).toBeInTheDocument();
  });

  it('renders table headers', () => {
    render(<QuarantineList files={mockFiles} onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('File Name')).toBeInTheDocument();
    expect(screen.getByText('Verdict')).toBeInTheDocument();
    expect(screen.getByText('Threat Level')).toBeInTheDocument();
    expect(screen.getByText('Date')).toBeInTheDocument();
    expect(screen.getByText('Size')).toBeInTheDocument();
    expect(screen.getByText('Actions')).toBeInTheDocument();
  });

  it('extracts filename from full path', () => {
    render(<QuarantineList files={mockFiles} onRestore={vi.fn()} onDelete={vi.fn()} />);
    // Should show just the filename, not full path
    expect(screen.getByText('malware.exe')).toBeInTheDocument();
    expect(screen.queryByText('C:\\Users\\test\\malware.exe')).not.toBeInTheDocument();
  });
});
