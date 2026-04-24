import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Sidebar } from './Sidebar';
import type { NavItem } from './Sidebar';
import packageJson from '../../../package.json';

// Mock the image import
vi.mock('../../assets/insecurity-icon.png', () => ({ default: 'test-icon.png' }));

describe('Sidebar', () => {
  const defaultProps = {
    activeItem: 'dashboard' as NavItem,
    onNavigate: vi.fn(),
  };

  it('renders all navigation items', () => {
    render(<Sidebar {...defaultProps} />);
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Scanner')).toBeInTheDocument();
    expect(screen.getByText('Quarantine')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('renders brand name', () => {
    render(<Sidebar {...defaultProps} />);
    expect(screen.getByText('InSecurity')).toBeInTheDocument();
  });

  it('highlights active nav item', () => {
    render(<Sidebar {...defaultProps} activeItem="scanner" />);
    const scannerBtn = screen.getByText('Scanner').closest('button');
    expect(scannerBtn).toHaveClass('active');

    const dashboardBtn = screen.getByText('Dashboard').closest('button');
    expect(dashboardBtn).not.toHaveClass('active');
  });

  it('calls onNavigate when nav item clicked', () => {
    const onNavigate = vi.fn();
    render(<Sidebar {...defaultProps} onNavigate={onNavigate} />);
    
    fireEvent.click(screen.getByText('Scanner'));
    expect(onNavigate).toHaveBeenCalledWith('scanner');
    
    fireEvent.click(screen.getByText('Quarantine'));
    expect(onNavigate).toHaveBeenCalledWith('quarantine');
    
    fireEvent.click(screen.getByText('Settings'));
    expect(onNavigate).toHaveBeenCalledWith('settings');
  });

  it('shows quarantine badge when count > 0', () => {
    render(<Sidebar {...defaultProps} quarantineCount={5} />);
    expect(screen.getByText('5')).toBeInTheDocument();
  });

  it('hides quarantine badge when count is 0', () => {
    render(<Sidebar {...defaultProps} quarantineCount={0} />);
    // Just verify no number badge is shown
    expect(screen.queryByText('0')).not.toBeInTheDocument();
  });

  it('shows "Protected" status when protectionEnabled is true', () => {
    render(<Sidebar {...defaultProps} protectionEnabled={true} />);
    expect(screen.getByText('Protected')).toBeInTheDocument();
  });

  it('shows "At Risk" status when protectionEnabled is false', () => {
    render(<Sidebar {...defaultProps} protectionEnabled={false} />);
    expect(screen.getByText('At Risk')).toBeInTheDocument();
  });

  it('shows version number', () => {
    render(<Sidebar {...defaultProps} />);
    expect(screen.getByText(`v${packageJson.version}`)).toBeInTheDocument();
  });

  it('defaults protectionEnabled to true', () => {
    render(<Sidebar activeItem="dashboard" onNavigate={vi.fn()} />);
    expect(screen.getByText('Protected')).toBeInTheDocument();
  });
});
