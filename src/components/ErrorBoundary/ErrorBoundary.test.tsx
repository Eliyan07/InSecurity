import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ErrorBoundary, withErrorBoundary } from './ErrorBoundary';

// Component that throws on render
const ThrowingComponent = ({ shouldThrow = true }: { shouldThrow?: boolean }) => {
  if (shouldThrow) throw new Error('Test render error');
  return <div>Child content</div>;
};

// Suppress React error boundary console noise in tests
beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

describe('ErrorBoundary', () => {
  it('renders children when no error', () => {
    render(
      <ErrorBoundary>
        <div>Hello World</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('Hello World')).toBeInTheDocument();
  });

  it('renders fallback UI when child throws', () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent />
      </ErrorBoundary>
    );
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    expect(screen.getByText('Try Again')).toBeInTheDocument();
    expect(screen.getByText('Reload App')).toBeInTheDocument();
  });

  it('renders custom fallback when provided', () => {
    render(
      <ErrorBoundary fallback={<div>Custom error UI</div>}>
        <ThrowingComponent />
      </ErrorBoundary>
    );
    expect(screen.getByText('Custom error UI')).toBeInTheDocument();
    expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
  });

  it('shows error details in expandable section', () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent />
      </ErrorBoundary>
    );
    const details = screen.getByText('Error Details');
    expect(details).toBeInTheDocument();
    // The error message should be visible in the details section
    expect(screen.getByText(/Test render error/)).toBeInTheDocument();
  });

  it('"Try Again" resets the error state and re-renders children', () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={true} />
      </ErrorBoundary>
    );
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();

    // Click Try Again — ErrorBoundary resets state, will re-render children
    // Since ThrowingComponent still throws, it will go back to error state
    fireEvent.click(screen.getByText('Try Again'));
    // After reset, it tries to render the child again which throws again
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });

  it('"Reload App" calls window.location.reload', () => {
    const reloadMock = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { reload: reloadMock },
      writable: true,
    });

    render(
      <ErrorBoundary>
        <ThrowingComponent />
      </ErrorBoundary>
    );
    fireEvent.click(screen.getByText('Reload App'));
    expect(reloadMock).toHaveBeenCalled();
  });
});

describe('withErrorBoundary', () => {
  it('wraps a component with ErrorBoundary', () => {
    const Inner = () => <div>Wrapped content</div>;
    const Wrapped = withErrorBoundary(Inner);
    render(<Wrapped />);
    expect(screen.getByText('Wrapped content')).toBeInTheDocument();
  });

  it('catches errors from wrapped component', () => {
    const Wrapped = withErrorBoundary(ThrowingComponent);
    render(<Wrapped shouldThrow={true} />);
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });

  it('sets displayName on the wrapper', () => {
    const MyComponent = () => <div />;
    MyComponent.displayName = 'MyComponent';
    const Wrapped = withErrorBoundary(MyComponent);
    expect(Wrapped.displayName).toBe('withErrorBoundary(MyComponent)');
  });
});
