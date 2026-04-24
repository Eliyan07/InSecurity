/// Database models and data structures
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub id: i64,
    pub file_hash: String,
    pub file_path: String,
    pub verdict: String, // Clean, Suspicious, Malware
    pub confidence: f64,
    pub threat_level: String, // HIGH, MEDIUM, LOW
    pub threat_name: Option<String>,
    pub scan_time_ms: u64,
    pub scanned_at: i64,
    pub source: String, // "realtime", "manual", "posture"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistory {
    pub id: i64,
    pub scan_path: String,
    pub scan_type: String, // file, folder, real-time
    pub total_files: u32,
    pub clean_files: u32,
    pub suspicious_files: u32,
    pub malicious_files: u32,
    pub scan_duration_seconds: u64,
    pub started_at: i64,
    pub completed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: i64,
    pub file_hash: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub verdict: String,
    pub threat_level: String,
    pub reason: String,
    pub quarantined_at: i64,
    pub restored_at: Option<i64>,
    pub permanently_deleted: bool,
    pub file_size: u64,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReport {
    pub id: i64,
    pub provider: String,
    pub identifier: String, // file hash, url, ip, etc.
    pub data_json: String,
    pub fetched_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntel {
    pub id: i64,
    pub file_hash: String,
    pub threat_name: String,
    pub severity: String,
    pub family: Option<String>,
    pub first_seen: i64,
    pub last_updated: i64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelRecord {
    pub file_hash: String,
    pub threat_name: String,
    pub severity: String,
    pub family: Option<String>,
    pub first_seen: i64,
    pub last_updated: i64,
    pub source: String,
}

impl ThreatIntelRecord {
    pub fn new<S: Into<String>>(
        file_hash: S,
        threat_name: S,
        severity: S,
        family: Option<S>,
        first_seen: i64,
        last_updated: i64,
        source: S,
    ) -> Self {
        ThreatIntelRecord {
            file_hash: file_hash.into(),
            threat_name: threat_name.into(),
            severity: severity.into(),
            family: family.map(|s| s.into()),
            first_seen,
            last_updated,
            source: source.into(),
        }
    }
}

impl From<ThreatIntelRecord> for ThreatIntel {
    fn from(r: ThreatIntelRecord) -> Self {
        ThreatIntel {
            id: 0,
            file_hash: r.file_hash,
            threat_name: r.threat_name,
            severity: r.severity,
            family: r.family,
            first_seen: r.first_seen,
            last_updated: r.last_updated,
            source: r.source,
        }
    }
}

impl From<ThreatIntel> for ThreatIntelRecord {
    fn from(t: ThreatIntel) -> Self {
        ThreatIntelRecord {
            file_hash: t.file_hash,
            threat_name: t.threat_name,
            severity: t.severity,
            family: t.family,
            first_seen: t.first_seen,
            last_updated: t.last_updated,
            source: t.source,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExclusionType {
    Path,      // Exact path match
    Folder,    // Folder and all contents
    Extension, // File extension (e.g., ".log")
    Pattern,   // Glob pattern (e.g., "*.tmp")
}

impl std::fmt::Display for ExclusionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExclusionType::Path => write!(f, "path"),
            ExclusionType::Folder => write!(f, "folder"),
            ExclusionType::Extension => write!(f, "extension"),
            ExclusionType::Pattern => write!(f, "pattern"),
        }
    }
}

impl From<&str> for ExclusionType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "path" => ExclusionType::Path,
            "folder" => ExclusionType::Folder,
            "extension" => ExclusionType::Extension,
            "pattern" => ExclusionType::Pattern,
            _ => ExclusionType::Path,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exclusion {
    pub id: i64,
    pub exclusion_type: String,
    pub pattern: String,
    pub reason: Option<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
    /// HMAC signature for tamper detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

// =========================================================================
// Network Security models
// =========================================================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub id: i64,
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub event_type: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: i64,
    pub rule_name: String,
    pub executable_path: String,
    pub direction: String,
    pub action: String,
    pub reason: Option<String>,
    pub auto_created: bool,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousIp {
    pub id: i64,
    pub ip_address: String,
    pub threat_name: Option<String>,
    pub source: String,
    pub added_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkThreat {
    pub id: i64,
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub remote_ip: String,
    pub remote_port: u16,
    pub threat_name: String,
    pub protocol: String,
    pub detected_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Verdict tests
    // =========================================================================

    #[test]
    fn test_verdict_serialize_roundtrip() {
        let v = Verdict {
            id: 1,
            file_hash: "abc123".to_string(),
            file_path: "C:\\test\\file.exe".to_string(),
            verdict: "Malware".to_string(),
            confidence: 0.95,
            threat_level: "HIGH".to_string(),
            threat_name: Some("Trojan.Generic".to_string()),
            scan_time_ms: 150,
            scanned_at: 1700000000,
            source: "realtime".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let v2: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v2.id, 1);
        assert_eq!(v2.file_hash, "abc123");
        assert_eq!(v2.verdict, "Malware");
        assert!((v2.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(v2.threat_name, Some("Trojan.Generic".to_string()));
        assert_eq!(v2.source, "realtime");
    }

    #[test]
    fn test_verdict_clone() {
        let v = Verdict {
            id: 42,
            file_hash: "hash".to_string(),
            file_path: "/path".to_string(),
            verdict: "Clean".to_string(),
            confidence: 0.1,
            threat_level: "LOW".to_string(),
            threat_name: None,
            scan_time_ms: 10,
            scanned_at: 0,
            source: "manual".to_string(),
        };
        let cloned = v.clone();
        assert_eq!(cloned.id, v.id);
        assert_eq!(cloned.file_hash, v.file_hash);
        assert_eq!(cloned.threat_name, None);
    }

    #[test]
    fn test_verdict_optional_threat_name_none() {
        let json = r#"{
            "id": 1,
            "file_hash": "h",
            "file_path": "p",
            "verdict": "Clean",
            "confidence": 0.0,
            "threat_level": "LOW",
            "threat_name": null,
            "scan_time_ms": 0,
            "scanned_at": 0,
            "source": "realtime"
        }"#;
        let v: Verdict = serde_json::from_str(json).unwrap();
        assert!(v.threat_name.is_none());
    }

    // =========================================================================
    // ScanHistory tests
    // =========================================================================

    #[test]
    fn test_scan_history_serialize_roundtrip() {
        let sh = ScanHistory {
            id: 5,
            scan_path: "C:\\Users".to_string(),
            scan_type: "folder".to_string(),
            total_files: 1000,
            clean_files: 995,
            suspicious_files: 3,
            malicious_files: 2,
            scan_duration_seconds: 120,
            started_at: 1700000000,
            completed_at: 1700000120,
        };
        let json = serde_json::to_string(&sh).unwrap();
        let sh2: ScanHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(sh2.total_files, 1000);
        assert_eq!(sh2.clean_files, 995);
        assert_eq!(sh2.scan_duration_seconds, 120);
    }

    // =========================================================================
    // QuarantineRecord tests
    // =========================================================================

    #[test]
    fn test_quarantine_record_serialize_roundtrip() {
        let qr = QuarantineRecord {
            id: 10,
            file_hash: "deadbeef".to_string(),
            original_path: "C:\\bad\\virus.exe".to_string(),
            quarantine_path: "vault/deadbeef".to_string(),
            verdict: "Malware".to_string(),
            threat_level: "HIGH".to_string(),
            reason: "YARA match".to_string(),
            quarantined_at: 1700000000,
            restored_at: None,
            permanently_deleted: false,
            file_size: 4096,
            file_type: "exe".to_string(),
        };
        let json = serde_json::to_string(&qr).unwrap();
        let qr2: QuarantineRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(qr2.file_hash, "deadbeef");
        assert_eq!(qr2.restored_at, None);
        assert!(!qr2.permanently_deleted);
        assert_eq!(qr2.file_size, 4096);
    }

    #[test]
    fn test_quarantine_record_with_restored_at() {
        let qr = QuarantineRecord {
            id: 1,
            file_hash: "abc".to_string(),
            original_path: "/tmp/f".to_string(),
            quarantine_path: "v/abc".to_string(),
            verdict: "Suspicious".to_string(),
            threat_level: "MEDIUM".to_string(),
            reason: "test".to_string(),
            quarantined_at: 100,
            restored_at: Some(200),
            permanently_deleted: false,
            file_size: 0,
            file_type: "dll".to_string(),
        };
        let json = serde_json::to_string(&qr).unwrap();
        let qr2: QuarantineRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(qr2.restored_at, Some(200));
    }

    // =========================================================================
    // ExternalReport tests
    // =========================================================================

    #[test]
    fn test_external_report_serialize_roundtrip() {
        let er = ExternalReport {
            id: 1,
            provider: "VirusTotal".to_string(),
            identifier: "abc123".to_string(),
            data_json: r#"{"positives": 5}"#.to_string(),
            fetched_at: 1700000000,
        };
        let json = serde_json::to_string(&er).unwrap();
        let er2: ExternalReport = serde_json::from_str(&json).unwrap();
        assert_eq!(er2.provider, "VirusTotal");
        assert_eq!(er2.data_json, r#"{"positives": 5}"#);
    }

    // =========================================================================
    // ThreatIntel / ThreatIntelRecord tests
    // =========================================================================

    #[test]
    fn test_threat_intel_record_new() {
        let r = ThreatIntelRecord::new(
            "hash123",
            "Trojan.Test",
            "HIGH",
            Some("TrojanFamily"),
            100,
            200,
            "MalwareBazaar",
        );
        assert_eq!(r.file_hash, "hash123");
        assert_eq!(r.threat_name, "Trojan.Test");
        assert_eq!(r.severity, "HIGH");
        assert_eq!(r.family, Some("TrojanFamily".to_string()));
        assert_eq!(r.first_seen, 100);
        assert_eq!(r.last_updated, 200);
        assert_eq!(r.source, "MalwareBazaar");
    }

    #[test]
    fn test_threat_intel_record_new_no_family() {
        let r = ThreatIntelRecord::new(
            "hash456",
            "Generic.Malware",
            "MEDIUM",
            None::<&str>,
            50,
            100,
            "VirusTotal",
        );
        assert_eq!(r.family, None);
    }

    #[test]
    fn test_threat_intel_record_to_threat_intel() {
        let record = ThreatIntelRecord {
            file_hash: "abc".to_string(),
            threat_name: "Test".to_string(),
            severity: "LOW".to_string(),
            family: Some("TestFamily".to_string()),
            first_seen: 1,
            last_updated: 2,
            source: "src".to_string(),
        };
        let intel: ThreatIntel = record.into();
        assert_eq!(intel.id, 0); // Default ID
        assert_eq!(intel.file_hash, "abc");
        assert_eq!(intel.threat_name, "Test");
        assert_eq!(intel.family, Some("TestFamily".to_string()));
    }

    #[test]
    fn test_threat_intel_to_record() {
        let intel = ThreatIntel {
            id: 42,
            file_hash: "xyz".to_string(),
            threat_name: "Worm".to_string(),
            severity: "HIGH".to_string(),
            family: None,
            first_seen: 10,
            last_updated: 20,
            source: "feed".to_string(),
        };
        let record: ThreatIntelRecord = intel.into();
        // id is dropped in conversion
        assert_eq!(record.file_hash, "xyz");
        assert_eq!(record.threat_name, "Worm");
        assert_eq!(record.family, None);
    }

    #[test]
    fn test_threat_intel_roundtrip_conversion() {
        let original = ThreatIntelRecord::new("hash", "name", "sev", Some("fam"), 100, 200, "src");
        let intel: ThreatIntel = original.clone().into();
        let back: ThreatIntelRecord = intel.into();
        assert_eq!(back.file_hash, original.file_hash);
        assert_eq!(back.threat_name, original.threat_name);
        assert_eq!(back.severity, original.severity);
        assert_eq!(back.family, original.family);
        assert_eq!(back.first_seen, original.first_seen);
        assert_eq!(back.last_updated, original.last_updated);
        assert_eq!(back.source, original.source);
    }

    // =========================================================================
    // ExclusionType tests
    // =========================================================================

    #[test]
    fn test_exclusion_type_display() {
        assert_eq!(ExclusionType::Path.to_string(), "path");
        assert_eq!(ExclusionType::Folder.to_string(), "folder");
        assert_eq!(ExclusionType::Extension.to_string(), "extension");
        assert_eq!(ExclusionType::Pattern.to_string(), "pattern");
    }

    #[test]
    fn test_exclusion_type_from_str() {
        assert_eq!(ExclusionType::from("path"), ExclusionType::Path);
        assert_eq!(ExclusionType::from("folder"), ExclusionType::Folder);
        assert_eq!(ExclusionType::from("extension"), ExclusionType::Extension);
        assert_eq!(ExclusionType::from("pattern"), ExclusionType::Pattern);
    }

    #[test]
    fn test_exclusion_type_from_str_case_insensitive() {
        assert_eq!(ExclusionType::from("PATH"), ExclusionType::Path);
        assert_eq!(ExclusionType::from("Folder"), ExclusionType::Folder);
        assert_eq!(ExclusionType::from("EXTENSION"), ExclusionType::Extension);
        assert_eq!(ExclusionType::from("Pattern"), ExclusionType::Pattern);
    }

    #[test]
    fn test_exclusion_type_from_str_unknown_defaults_to_path() {
        assert_eq!(ExclusionType::from("unknown"), ExclusionType::Path);
        assert_eq!(ExclusionType::from(""), ExclusionType::Path);
        assert_eq!(ExclusionType::from("glob"), ExclusionType::Path);
    }

    #[test]
    fn test_exclusion_type_equality() {
        assert_eq!(ExclusionType::Path, ExclusionType::Path);
        assert_ne!(ExclusionType::Path, ExclusionType::Folder);
    }

    #[test]
    fn test_exclusion_type_serialize_roundtrip() {
        let types = vec![
            ExclusionType::Path,
            ExclusionType::Folder,
            ExclusionType::Extension,
            ExclusionType::Pattern,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let deserialized: ExclusionType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, t);
        }
    }

    // =========================================================================
    // Exclusion tests
    // =========================================================================

    #[test]
    fn test_exclusion_serialize_roundtrip() {
        let excl = Exclusion {
            id: 1,
            exclusion_type: "path".to_string(),
            pattern: "C:\\safe\\file.exe".to_string(),
            reason: Some("Known safe".to_string()),
            enabled: true,
            created_at: 1700000000,
            updated_at: 1700000000,
            signature: Some("sig123".to_string()),
        };
        let json = serde_json::to_string(&excl).unwrap();
        let excl2: Exclusion = serde_json::from_str(&json).unwrap();
        assert_eq!(excl2.id, 1);
        assert_eq!(excl2.pattern, "C:\\safe\\file.exe");
        assert_eq!(excl2.reason, Some("Known safe".to_string()));
        assert!(excl2.enabled);
        assert_eq!(excl2.signature, Some("sig123".to_string()));
    }

    #[test]
    fn test_exclusion_signature_skip_serializing_if_none() {
        let excl = Exclusion {
            id: 1,
            exclusion_type: "folder".to_string(),
            pattern: "C:\\safe".to_string(),
            reason: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            signature: None,
        };
        let json = serde_json::to_string(&excl).unwrap();
        // "signature" should not appear in the JSON when None
        assert!(!json.contains("signature"));
    }

    #[test]
    fn test_exclusion_disabled() {
        let excl = Exclusion {
            id: 2,
            exclusion_type: "extension".to_string(),
            pattern: ".log".to_string(),
            reason: None,
            enabled: false,
            created_at: 0,
            updated_at: 0,
            signature: None,
        };
        assert!(!excl.enabled);
    }
}
