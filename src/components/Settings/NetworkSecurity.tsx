import React, { useState, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useNetworkSecurity } from '../../hooks/useNetworkSecurity';
import { pickScanFile } from '../../services/api';

// ─── Firewall Rules Panel ───────────────────────────────────────────────────

export const FirewallRulesPanel: React.FC = () => {
  const { t, i18n } = useTranslation();
  const {
    firewallRules,
    fetchFirewallRules,
    addFirewallRule,
    removeFirewallRule,
    toggleFirewallRule,
    error,
  } = useNetworkSecurity();
  const [newPath, setNewPath] = useState('');
  const [direction, setDirection] = useState<'out' | 'in' | 'both'>('out');
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => { fetchFirewallRules(); }, [fetchFirewallRules]);
  useEffect(() => {
    if (error) setMessage({ type: 'error', text: error });
  }, [error]);

  const handleBrowseExecutable = useCallback(async () => {
    const path = await pickScanFile();
    if (path) setNewPath(path);
  }, []);

  const handleAdd = useCallback(async () => {
    const p = newPath.trim();
    if (!p) return;
    await addFirewallRule(p, direction);
    setNewPath('');
    setMessage({ type: 'success', text: t('firewall.ruleCreated') });
  }, [newPath, direction, addFirewallRule, t]);

  const formatDate = (ts: number) =>
    new Date(ts * 1000).toLocaleDateString(i18n.resolvedLanguage || i18n.language || undefined);

  return (
    <div className="network-subsection">
      <h4>{t('firewall.title', { count: firewallRules.length })}</h4>
      <p className="help-text">{t('firewall.description')}</p>

      {message && (
        <div className={`action-message ${message.type}`}>{message.text}</div>
      )}

      <div className="firewall-input-row">
        <input
          type="text"
          placeholder={t('firewall.pathPlaceholder')}
          value={newPath}
          onChange={e => setNewPath(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
        />
        <button
          className="btn-browse-folder"
          onClick={handleBrowseExecutable}
          title={t('firewall.browseExecutable')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
          </svg>
        </button>
        <select value={direction} onChange={e => setDirection(e.target.value as 'out' | 'in' | 'both')}>
          <option value="out">{t('firewall.outbound')}</option>
          <option value="in">{t('firewall.inbound')}</option>
          <option value="both">{t('firewall.both')}</option>
        </select>
        <button className="btn-primary btn-sm" onClick={handleAdd} disabled={!newPath.trim()}>
          {t('firewall.block')}
        </button>
      </div>

      {firewallRules.length > 0 && (
        <div className="network-table-wrapper">
          <table className="network-table">
            <thead>
              <tr>
                <th>{t('firewall.executable')}</th>
                <th>{t('firewall.direction')}</th>
                <th>{t('firewall.created')}</th>
                <th style={{ width: 60 }}>{t('firewall.on')}</th>
                <th style={{ width: 60 }}>{t('firewall.del')}</th>
              </tr>
            </thead>
            <tbody>
              {firewallRules.map(rule => (
                <tr key={rule.id} className={rule.autoCreated ? 'auto-created-row' : ''}>
                  <td className="monospace truncate" title={rule.executablePath}>
                    {rule.executablePath.split('\\').pop() || rule.executablePath}
                    {rule.autoCreated && <span className="badge-auto">{t('firewall.auto')}</span>}
                  </td>
                  <td>{rule.direction}</td>
                  <td>{formatDate(rule.createdAt)}</td>
                  <td>
                    <label className="mini-toggle">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => toggleFirewallRule(rule.id)}
                      />
                    </label>
                  </td>
                  <td>
                    <button
                      className="btn-remove-sm"
                      onClick={() => removeFirewallRule(rule.id)}
                      title={t('firewall.removeRule')}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M18 6L6 18M6 6l12 12" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// ─── Active Connections Viewer ──────────────────────────────────────────────

export const ActiveConnectionsViewer: React.FC = () => {
  const { t } = useTranslation();
  const { connections, startPolling, stopPolling } = useNetworkSecurity();
  const [filter, setFilter] = useState('');

  useEffect(() => {
    startPolling(3000);
    return () => stopPolling();
  }, [startPolling, stopPolling]);

  const filtered = filter
    ? connections.filter(
        c =>
          c.processName.toLowerCase().includes(filter.toLowerCase()) ||
          c.remoteAddr.includes(filter) ||
          String(c.remotePort).includes(filter)
      )
    : connections;

  const suspiciousCount = connections.filter(c => c.suspicious).length;

  return (
    <div className="network-subsection">
      <h4>
        {t('connections.title', { count: connections.length })}
        {suspiciousCount > 0 && (
          <span className="badge-danger">{suspiciousCount} {t('connections.suspicious')}</span>
        )}
      </h4>
      <p className="help-text">{t('connections.description')}</p>

      <div className="connections-filter-row">
        <input
          type="text"
          placeholder={t('connections.filterPlaceholder')}
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>

      {filtered.length > 0 ? (
        <div className="network-table-wrapper connections-table-wrapper">
          <table className="network-table connections-table">
            <thead>
              <tr>
                <th>{t('connections.process')}</th>
                <th>{t('connections.remote')}</th>
                <th>{t('connections.port')}</th>
                <th>{t('connections.state')}</th>
                <th>{t('connections.threat')}</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((conn, i) => (
                <tr
                  key={`${conn.pid}-${conn.remoteAddr}-${conn.remotePort}-${i}`}
                  className={conn.suspicious ? 'suspicious-row' : ''}
                >
                  <td title={`PID: ${conn.pid}`}>{conn.processName}</td>
                  <td className="monospace">{conn.remoteAddr}</td>
                  <td>{conn.remotePort}</td>
                  <td>{conn.state}</td>
                  <td>
                    {conn.suspicious ? (
                      <span className="threat-badge">{conn.threatName || t('connections.suspiciousBadge')}</span>
                    ) : (
                      <span className="ok-badge">{t('connections.okBadge')}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-state-text">
          {connections.length === 0
            ? t('connections.noConnections')
            : t('connections.noFilterMatch')}
        </p>
      )}
    </div>
  );
};
