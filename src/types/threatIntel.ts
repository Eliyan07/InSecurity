// Detailed threat intelligence types that extend your existing ScanResult

export interface YaraMatch {
  rule_name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  description: string;
  category: string;
  offset?: number;
  matched_strings?: string[];
}

export interface BehaviorAnalysis {
  suspicious_behaviors: string[];
  behavior_score: number;
  api_indicators: string[];
  string_indicators: string[];
}

export interface MLPrediction {
  is_malware: boolean;
  confidence: number;
  malware_family?: string;
  model_version: string;
  model_available: boolean;
  verdict: 'malware' | 'suspicious' | 'clean' | 'unknown' | 'error';
  raw_score: number;
}

export interface VtDetection {
  engine_name: string;
  category: string;
  result?: string;
  detected?: boolean;
}

export interface ReputationScore {
  overall_score: number;
  threat_count: number;
  last_analysis_date: number;
  sources: string[];
  detections: VtDetection[];
  suggested_names: string[];
}

export interface SignatureInfo {
  is_signed: boolean;
  is_valid: boolean;
  signer_name?: string;
  is_trusted_publisher: boolean;
  issuer?: string;
  timestamp?: string;
}

export interface EmulationSummary {
  instructions_executed: number;
  detected_oep?: number;
  api_call_count: number;
  suspicious_behaviors: string[];
  unpacking_detected: boolean;
  memory_writes?: number;
  api_calls_made?: number;
  self_modifying_code?: boolean;
}

export interface StaticAnalysisResult {
  yara_matches?: YaraMatch[];
  entropy_score?: number;
  is_whitelisted?: boolean;
  is_blacklisted?: boolean;
  suspicious_characteristics?: string[];
}

export interface NoveltyScore {
  is_novel: boolean;
  anomaly_score: number;
  confidence: number;
}

export interface DetailedResults {
  static_analysis?: StaticAnalysisResult;
  ml_prediction?: MLPrediction;
  reputation_score?: ReputationScore;
  novelty_score?: NoveltyScore;
  behavior_analysis?: BehaviorAnalysis;
  emulation_result?: EmulationSummary;
  signature_info?: SignatureInfo;
}

// Extended scan result with detailed analysis
export interface DetailedScanResult {
  file_hash: string;
  file_path: string;
  verdict: 'Clean' | 'Suspicious' | 'Malware' | 'Unknown';
  confidence: number;
  threat_level: string;
  threat_name?: string;
  scan_time_ms: number;
  detailed_results: DetailedResults;
}