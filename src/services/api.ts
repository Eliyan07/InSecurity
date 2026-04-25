/// Safe Tauri API wrapper
/// Provides fallback behavior when running outside Tauri context (e.g., browser-only dev)

// Check if we're running in Tauri context
const isTauri = (): boolean => {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
};

// Lazy-loaded invoke function to avoid import errors
let invokeFunction: typeof import('@tauri-apps/api/core').invoke | null = null;
let listenFunction: typeof import('@tauri-apps/api/event').listen | null = null;

const loadInvoke = async () => {
  if (invokeFunction) return invokeFunction;
  
  if (isTauri()) {
    try {
      const module = await import('@tauri-apps/api/core');
      invokeFunction = module.invoke;
      return invokeFunction;
    } catch (e) {
      console.warn('Failed to load Tauri API:', e);
    }
  }
  return null;
};

const loadListen = async () => {
  if (listenFunction) return listenFunction;
  
  if (isTauri()) {
    try {
      const module = await import('@tauri-apps/api/event');
      listenFunction = module.listen;
      return listenFunction;
    } catch (e) {
      console.warn('Failed to load Tauri event API:', e);
    }
  }
  return null;
};

/**
 * Safe invoke wrapper that handles non-Tauri environments gracefully
 */
// Default timeout for Tauri commands (ms). Most commands should complete quickly.
const DEFAULT_COMMAND_TIMEOUT = 30_000;
// Commands that do heavy work (registry enumeration, PowerShell signature checks)
const SLOW_COMMANDS = new Set([
  'get_persistence_for_file',
]);
const SLOW_COMMAND_TIMEOUT = 90_000;

export async function safeInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const invoke = await loadInvoke();
  
  if (!invoke) {
    console.warn(`[Dev Mode] Tauri command "${command}" called outside Tauri context`);
    throw new Error(`Tauri not available. Run with "npm run tauri dev" to use this feature.`);
  }
  
  const timeout = SLOW_COMMANDS.has(command) ? SLOW_COMMAND_TIMEOUT : DEFAULT_COMMAND_TIMEOUT;
  
  // Use AbortController pattern so the timer is always cleaned up
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      invoke<T>(command, args),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Command "${command}" timed out after ${timeout / 1000}s`)), timeout);
      }),
    ]);
    clearTimeout(timer);
    return result;
  } catch (e) {
    clearTimeout(timer);
    console.error(`[Tauri] Command "${command}" failed:`, e);
    throw e;
  }
}

/**
 * Safe listen wrapper that handles non-Tauri environments gracefully
 */
export async function safeListen<T>(
  event: string, 
  handler: (event: { payload: T }) => void
): Promise<() => void> {
  const listen = await loadListen();
  
  if (!listen) {
    console.warn(`[Dev Mode] Tauri event listener "${event}" called outside Tauri context`);
    // Return a no-op unlisten function
    return () => {};
  }
  
  return listen<T>(event, handler);
}

/**
 * Check if Tauri runtime is available
 */
export function isTauriAvailable(): boolean {
  return isTauri();
}

export interface ScanStatus {
  isScanning: boolean;
  currentFile: string | null;
  filesScanned: number;
  filesRemaining: number;
  totalFiles: number;
  progressPercent: number;
  cleanCount: number;
  suspiciousCount: number;
  malwareCount: number;
  elapsedSeconds: number;
  lastThreat: {
    filePath: string;
    threatName: string | null;
    verdict: string;
  } | null;
  scanType: string | null;
  filesPerSecond: number;
}

export interface ScanSummary {
  totalFiles: number;
  cleanCount: number;
  suspiciousCount: number;
  malwareCount: number;
  elapsedSeconds: number;
  scanType: string;
}

/**
 * Start a scan (quick, full, or custom)
 */
export async function startScan(scanType: 'quick' | 'full' | 'custom', customPath?: string): Promise<void> {
  return safeInvoke<void>('start_scan', {
    scanType: scanType,
    customPath: customPath ?? null,
  });
}

/**
 * Cancel an ongoing scan
 */
export async function cancelScan(): Promise<void> {
  return safeInvoke<void>('cancel_scan');
}

/**
 * Get current scan status
 */
export async function getScanStatus(): Promise<ScanStatus> {
  return safeInvoke<ScanStatus>('get_scan_status');
}

/**
 * Force reset scan state when stuck
 */
export async function forceResetScan(): Promise<void> {
  return safeInvoke<void>('force_reset_scan');
}

/**
 * Open native folder picker for custom scan
 */
export async function pickScanFolder(): Promise<string | null> {
  return safeInvoke<string | null>('pick_scan_folder');
}

/**
 * Open native file picker for custom scan
 */
export async function pickScanFile(): Promise<string | null> {
  return safeInvoke<string | null>('pick_scan_file');
}

export interface ScheduledScan {
  id: number;
  name: string;
  scanType: string;
  customPath: string | null;
  frequency: string;
  timeOfDay: string;
  dayOfWeek: number | null;
  dayOfMonth: number | null;
  enabled: boolean;
  lastRun: number | null;
  nextRun: number;
  createdAt: number;
  updatedAt: number;
}

export interface CreateScheduledScan {
  name: string;
  scanType: string;
  customPath?: string;
  frequency: string;
  timeOfDay: string;
  dayOfWeek?: number;
  dayOfMonth?: number;
}

export interface UpdateScheduledScan {
  id: number;
  name?: string;
  scanType?: string;
  customPath?: string;
  frequency?: string;
  timeOfDay?: string;
  dayOfWeek?: number;
  dayOfMonth?: number;
  enabled?: boolean;
}

/**
 * Get all scheduled scans
 */
export async function getScheduledScans(): Promise<ScheduledScan[]> {
  return safeInvoke<ScheduledScan[]>('get_scheduled_scans');
}

/**
 * Create a new scheduled scan
 */
export async function createScheduledScan(scan: CreateScheduledScan): Promise<ScheduledScan> {
  return safeInvoke<ScheduledScan>('create_scheduled_scan', { scan });
}

/**
 * Update an existing scheduled scan
 */
export async function updateScheduledScan(update: UpdateScheduledScan): Promise<ScheduledScan> {
  return safeInvoke<ScheduledScan>('update_scheduled_scan', { update });
}

/**
 * Toggle a scheduled scan's enabled state
 */
export async function toggleScheduledScan(id: number): Promise<boolean> {
  return safeInvoke<boolean>('toggle_scheduled_scan', { id });
}

/**
 * Delete a scheduled scan
 */
export async function deleteScheduledScan(id: number): Promise<void> {
  return safeInvoke<void>('delete_scheduled_scan', { id });
}

/**
 * Run a scheduled scan immediately
 */
export async function runScheduledScanNow(id: number): Promise<void> {
  return safeInvoke<void>('run_scheduled_scan_now', { id });
}

export interface UserWhitelistEntry {
  id: number;
  fileHash: string;
  filePath: string | null;
  originalVerdict: string | null;
  createdAt: number;
}

/**
 * Get all user-whitelisted file entries
 */
export async function getUserWhitelist(): Promise<UserWhitelistEntry[]> {
  return safeInvoke<UserWhitelistEntry[]>('get_user_whitelist');
}

/**
 * Remove a file hash from the user whitelist
 */
export async function removeFromUserWhitelist(fileHash: string): Promise<void> {
  return safeInvoke<void>('remove_from_user_whitelist', { fileHash });
}

/**
 * Clear all user whitelist entries. Returns the number of entries removed.
 */
export async function clearUserWhitelist(): Promise<number> {
  return safeInvoke<number>('clear_user_whitelist');
}

/**
 * Ignore a threat: whitelist its hash, remove from verdicts, prevent future detections
 */
export async function ignoreThreat(fileHash: string): Promise<void> {
  return safeInvoke<void>('ignore_threat', { fileHash });
}

import type { FilePersistenceContext } from '../types/insights';

export async function getPersistenceForFile(filePath: string): Promise<FilePersistenceContext> {
  return safeInvoke<FilePersistenceContext>('get_persistence_for_file', { filePath });
}

import type {
  NetworkEvent,
  FirewallRule,
  ActiveConnection,
  NetworkThreatEvent,
} from '../types/network';

export async function getActiveConnections(): Promise<ActiveConnection[]> {
  return safeInvoke<ActiveConnection[]>('get_active_connections');
}

export async function getNetworkEvents(limit?: number): Promise<NetworkEvent[]> {
  return safeInvoke<NetworkEvent[]>('get_network_events', { limit: limit ?? 200 });
}

export async function setNetworkMonitoring(enabled: boolean): Promise<void> {
  return safeInvoke<void>('set_network_monitoring', { enabled });
}

export async function getFirewallRules(): Promise<FirewallRule[]> {
  return safeInvoke<FirewallRule[]>('get_firewall_rules');
}

export async function addFirewallRule(path: string, direction: string): Promise<string> {
  return safeInvoke<string>('add_firewall_rule', { path, direction });
}

export async function removeFirewallRule(id: number): Promise<void> {
  return safeInvoke<void>('remove_firewall_rule', { id });
}

export async function toggleFirewallRule(id: number): Promise<boolean> {
  return safeInvoke<boolean>('toggle_firewall_rule', { id });
}

export async function setAutoBlockMalware(enabled: boolean): Promise<void> {
  return safeInvoke<void>('set_auto_block_malware', { enabled });
}

export async function onNetworkThreat(
  handler: (event: NetworkThreatEvent) => void
): Promise<() => void> {
  return safeListen<NetworkThreatEvent>('network_threat_detected', (event) => {
    handler(event.payload);
  });
}

export async function onFirewallRuleCreated(
  handler: (event: FirewallRule) => void
): Promise<() => void> {
  return safeListen<FirewallRule>('firewall_rule_created', (event) => {
    handler(event.payload);
  });
}

/**
 * Open a URL in the system default browser via the Tauri opener plugin.
 */
export async function openExternalUrl(url: string): Promise<void> {
  await safeInvoke('plugin:opener|open_url', { url });
}

export interface AppUpdateInfo {
  currentVersion: string;
  latestVersion: string;
  downloadUrl: string;
  releasePageUrl: string;
  publishedAt: string | null;
}

export interface AppUpdateCheckResult {
  update: AppUpdateInfo | null;
  shouldNotify: boolean;
  error: string | null;
}

export async function checkAppUpdate(force = false): Promise<AppUpdateCheckResult> {
  return safeInvoke<AppUpdateCheckResult>('check_app_update', { force });
}

export async function dismissAppUpdate(version: string): Promise<void> {
  return safeInvoke<void>('dismiss_app_update', { version });
}
