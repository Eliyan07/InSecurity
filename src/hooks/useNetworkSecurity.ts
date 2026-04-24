import { useState, useCallback, useEffect, useRef } from 'react';
import type {
  NetworkEvent,
  FirewallRule,
  ActiveConnection,
} from '../types/network';
import {
  getActiveConnections,
  getNetworkEvents,
  getFirewallRules,
  addFirewallRule,
  removeFirewallRule,
  toggleFirewallRule,
  onNetworkThreat,
  onFirewallRuleCreated,
} from '../services/api';

export function useNetworkSecurity() {
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>([]);
  const [connections, setConnections] = useState<ActiveConnection[]>([]);
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);



  // ── Firewall rules ────────────────────────────────────────────────

  const fetchFirewallRules = useCallback(async () => {
    try {
      const data = await getFirewallRules();
      setFirewallRules(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load firewall rules');
    }
  }, []);

  const handleAddFirewallRule = useCallback(async (path: string, direction: string) => {
    try {
      await addFirewallRule(path, direction);
      await fetchFirewallRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add firewall rule');
    }
  }, [fetchFirewallRules]);

  const handleRemoveFirewallRule = useCallback(async (id: number) => {
    try {
      await removeFirewallRule(id);
      setFirewallRules(prev => prev.filter(r => r.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove firewall rule');
    }
  }, []);

  const handleToggleFirewallRule = useCallback(async (id: number) => {
    try {
      const newEnabled = await toggleFirewallRule(id);
      setFirewallRules(prev =>
        prev.map(r => (r.id === id ? { ...r, enabled: newEnabled } : r))
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle firewall rule');
    }
  }, []);

  // ── Active connections ────────────────────────────────────────────

  const refreshConnections = useCallback(async () => {
    try {
      const data = await getActiveConnections();
      setConnections(data);
    } catch {
      // Silently fail on polling errors
    }
  }, []);

  const startPolling = useCallback((intervalMs = 3000) => {
    if (pollRef.current) clearInterval(pollRef.current);
    refreshConnections();
    pollRef.current = setInterval(refreshConnections, intervalMs);
  }, [refreshConnections]);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  // ── Network events ────────────────────────────────────────────────

  const fetchEvents = useCallback(async (limit = 200) => {
    try {
      const data = await getNetworkEvents(limit);
      setNetworkEvents(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load network events');
    }
  }, []);

  // ── Initial load + event listeners ────────────────────────────────

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    await Promise.all([fetchFirewallRules(), fetchEvents()]);
    setLoading(false);
  }, [fetchFirewallRules, fetchEvents]);

  useEffect(() => {
    const unlisteners: (() => void)[] = [];
    onNetworkThreat(() => {
      fetchEvents();
      refreshConnections();
    }).then(u => unlisteners.push(u));
    onFirewallRuleCreated(() => {
      fetchFirewallRules();
    }).then(u => unlisteners.push(u));

    return () => {
      unlisteners.forEach(u => u());
      stopPolling();
    };
  }, [fetchEvents, refreshConnections, fetchFirewallRules, stopPolling]);

  return {
    firewallRules,
    connections,
    networkEvents,
    loading,
    error,
    // Firewall
    // Firewall
    fetchFirewallRules,
    addFirewallRule: handleAddFirewallRule,
    removeFirewallRule: handleRemoveFirewallRule,
    toggleFirewallRule: handleToggleFirewallRule,
    // Connections
    refreshConnections,
    startPolling,
    stopPolling,
    // Events
    fetchEvents,
    // Bulk load
    loadAll,
  };
}
