import React from 'react';
import './ErrorBanner.css';

export interface ErrorBannerProps {
  message: string;
  onDismiss?: () => void;
  className?: string;
  children?: React.ReactNode;
}

export const ErrorBanner: React.FC<ErrorBannerProps> = ({ message, onDismiss, className = '', children }) => (
  <div className={`error-banner ${className}`.trim()} role="alert">
    <span className="error-banner-icon" aria-hidden>
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <circle cx="12" cy="16" r="1" />
      </svg>
    </span>
    <span className="error-banner-message">{message}</span>
    {children}
    {onDismiss && (
      <button className="error-banner-dismiss" onClick={onDismiss} aria-label="Dismiss error">×</button>
    )}
  </div>
);
