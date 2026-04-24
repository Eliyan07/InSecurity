
export interface DashboardStats {
  totalScans: number;
  malwareDetected: number;
  suspiciousDetected: number;
  quarantinedCount: number;
  threatIntelCount: number;
  lastScanTime: number | null;
  protectionStatus: string;
  /** Active (unresolved) malware count - excludes quarantined files */
  activeMalware: number;
  /** Active (unresolved) suspicious count - excludes quarantined files */
  activeSuspicious: number;
}
