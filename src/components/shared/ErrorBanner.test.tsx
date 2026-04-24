import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ErrorBanner } from './ErrorBanner';

describe('ErrorBanner', () => {
  it('renders the error message', () => {
    render(<ErrorBanner message="Something went wrong" />);
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });

  it('has role="alert" for accessibility', () => {
    render(<ErrorBanner message="Error!" />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('shows dismiss button when onDismiss is provided', () => {
    const onDismiss = vi.fn();
    render(<ErrorBanner message="Error" onDismiss={onDismiss} />);
    const dismissBtn = screen.getByLabelText('Dismiss error');
    expect(dismissBtn).toBeInTheDocument();
  });

  it('calls onDismiss when dismiss button is clicked', () => {
    const onDismiss = vi.fn();
    render(<ErrorBanner message="Error" onDismiss={onDismiss} />);
    fireEvent.click(screen.getByLabelText('Dismiss error'));
    expect(onDismiss).toHaveBeenCalledOnce();
  });

  it('does not show dismiss button when onDismiss is not provided', () => {
    render(<ErrorBanner message="Error" />);
    expect(screen.queryByLabelText('Dismiss error')).not.toBeInTheDocument();
  });

  it('applies custom className', () => {
    render(<ErrorBanner message="Error" className="custom-class" />);
    const banner = screen.getByRole('alert');
    expect(banner.className).toContain('custom-class');
  });

  it('renders children content', () => {
    render(
      <ErrorBanner message="Error">
        <button>Retry</button>
      </ErrorBanner>
    );
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('renders without onDismiss or className', () => {
    render(<ErrorBanner message="Simple error" />);
    const banner = screen.getByRole('alert');
    expect(banner.className).toContain('error-banner');
  });
});
