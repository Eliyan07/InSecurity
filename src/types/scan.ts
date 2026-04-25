// Re-export shared types from threatIntel for backwards compatibility
export type {
  YaraMatch,
  VtDetection,
  DetailedResults,
  BehaviorAnalysis,
  MLPrediction,
  ReputationScore,
  SignatureInfo,
  EmulationSummary,
  StaticAnalysisResult,
  NoveltyScore,
  DetailedScanResult,
} from './threatIntel';

export enum Verdict {
  CLEAN = "clean",
  SUSPICIOUS = "suspicious",
  MALWARE = "malware",
  UNKNOWN = "unknown",
}

// Import DetailedResults for use in ScanResult
import type { DetailedResults } from './threatIntel';

export interface ScanResult {
  threatId: string;
  fileHash: string;
  verdict: Verdict;
  confidence: number;
  threatLevel: "HIGH" | "MEDIUM" | "LOW";
  threatName?: string;
  scanTimeMs: number;
  filePath: string;
  // Detailed analysis results from the pipeline
  detailedResults?: DetailedResults;
}

export interface ThreatInfo {
  filePath: string;
  threatName?: string;
  verdict: string;
}

export interface ScanStatus {
  isScanning: boolean;
  currentFile?: string;
  filesScanned: number;
  filesRemaining: number;
  progressPercent: number;
  // New fields for enhanced feedback
  cleanCount: number;
  suspiciousCount: number;
  malwareCount: number;
  elapsedSeconds: number;
  lastThreat?: ThreatInfo;
}
