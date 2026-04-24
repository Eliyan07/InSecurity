import React from 'react';
import { useTranslation } from 'react-i18next';
import './Sidebar.css';
import insecurityIcon from '../../assets/insecurity-icon.png';
import packageJson from '../../../package.json';

export type NavItem =
  | 'dashboard'
  | 'scanner'
  | 'quarantine'
  | 'settings';

interface SidebarProps {
  activeItem: NavItem;
  onNavigate: (item: NavItem) => void;
  quarantineCount?: number;
  protectionEnabled?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = React.memo(({
  activeItem,
  onNavigate,
  quarantineCount = 0,
  protectionEnabled = true,
}) => {
  const { t } = useTranslation();

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <img className="sidebar-logo" src={insecurityIcon} alt="InSecurity" width="32" height="32" />
        <div className="sidebar-brand-divider" />
        <span className="sidebar-title">InSecurity</span>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section">
          {/* Dashboard */}
          <button
            className={`nav-item ${activeItem === 'dashboard' ? 'active' : ''}`}
            onClick={() => onNavigate('dashboard')}
            data-nav="dashboard"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" rx="1" />
              <rect x="14" y="3" width="7" height="7" rx="1" />
              <rect x="3" y="14" width="7" height="7" rx="1" />
              <rect x="14" y="14" width="7" height="7" rx="1" />
            </svg>
            <span>{t('sidebar.dashboard')}</span>
          </button>

          {/* Scanner */}
          <button
            className={`nav-item ${activeItem === 'scanner' ? 'active' : ''}`}
            onClick={() => onNavigate('scanner')}
            data-nav="scanner"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <span>{t('sidebar.scanner')}</span>
          </button>

          {/* Quarantine */}
          <button
            className={`nav-item ${activeItem === 'quarantine' ? 'active' : ''}`}
            onClick={() => onNavigate('quarantine')}
            data-nav="quarantine"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <path d="M9 9l6 6" />
              <path d="M15 9l-6 6" />
            </svg>
            <span>{t('sidebar.quarantine')}</span>
            {quarantineCount > 0 && <span className="badge">{quarantineCount}</span>}
          </button>
        </div>

        <div className="nav-section nav-section-bottom">
          {/* Settings */}
          <button
            className={`nav-item ${activeItem === 'settings' ? 'active' : ''}`}
            onClick={() => onNavigate('settings')}
            data-nav="settings"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3" />
              <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
            </svg>
            <span>{t('sidebar.settings')}</span>
          </button>
        </div>
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-footer-row">
          <span className={`status-indicator ${protectionEnabled ? 'active' : 'inactive'}`} />
          <span className={`status-text ${protectionEnabled ? '' : 'at-risk'}`}>
            {protectionEnabled ? t('sidebar.protected') : t('sidebar.atRisk')}
          </span>
          <span className="sidebar-version">v{packageJson.version}</span>
        </div>
      </div>
    </aside>
  );
});

Sidebar.displayName = 'Sidebar';
