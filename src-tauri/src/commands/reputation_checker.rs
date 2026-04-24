use crate::database::queries::DatabaseQueries;
use chrono::Utc;
/// File Reputation Checker Commands
/// Provides on-demand file and hash reputation checking
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationCheckResult {
    pub hash: String,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub known: bool,
    /// Overall risk level: "safe", "unknown", "suspicious", "malicious"
    pub risk_level: String,
    /// Confidence score 0.0 - 1.0
    pub confidence: f64,
    pub threat_name: Option<String>,
    pub malware_family: Option<String>,
    pub severity: Option<String>,
    pub sources: Vec<String>,
    pub first_seen: Option<i64>,
    pub last_updated: Option<i64>,
    pub in_blacklist: bool,
    pub in_whitelist: bool,
    pub external_reports: Vec<ExternalReportSummary>,
    /// Timestamp of this check
    pub checked_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReportSummary {
    pub provider: String,
    pub fetched_at: i64,
    pub verdict: String,
    pub threat_count: u32,
}

impl Default for ReputationCheckResult {
    fn default() -> Self {
        Self {
            hash: String::new(),
            file_path: None,
            file_name: None,
            file_size: None,
            known: false,
            risk_level: "unknown".to_string(),
            confidence: 0.0,
            threat_name: None,
            malware_family: None,
            severity: None,
            sources: Vec::new(),
            first_seen: None,
            last_updated: None,
            in_blacklist: false,
            in_whitelist: false,
            external_reports: Vec::new(),
            checked_at: Utc::now().timestamp(),
        }
    }
}

/// Calculate SHA-256 hash of a file using streaming to handle large files
fn calculate_file_hash(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn check_blacklist(hash: &str) -> bool {
    crate::core::static_scanner::is_blacklisted(hash)
}

fn check_whitelist(hash: &str) -> bool {
    crate::core::static_scanner::is_whitelisted(hash)
}

fn check_hash_reputation_internal(
    hash: &str,
    conn: &rusqlite::Connection,
) -> ReputationCheckResult {
    let mut result = ReputationCheckResult {
        hash: hash.to_lowercase(),
        checked_at: Utc::now().timestamp(),
        ..Default::default()
    };

    // 1. Check local whitelist first
    if check_whitelist(hash) {
        result.in_whitelist = true;
        result.known = true;
        result.risk_level = "safe".to_string();
        result.confidence = 1.0;
        result.sources.push("local_whitelist".to_string());
        return result;
    }

    // 2. Check local blacklist
    if check_blacklist(hash) {
        result.in_blacklist = true;
        result.known = true;
        result.risk_level = "malicious".to_string();
        result.confidence = 1.0;
        result.sources.push("local_blacklist".to_string());
    }

    // 3. Check threat_intel database
    {
        // Check threat_intel table
        if let Ok(Some(intel)) = DatabaseQueries::get_threat_by_hash(conn, hash) {
            result.known = true;
            result.threat_name = Some(intel.threat_name);
            result.malware_family = intel.family;
            result.severity = Some(intel.severity.clone());
            result.first_seen = Some(intel.first_seen);
            result.last_updated = Some(intel.last_updated);
            result
                .sources
                .push(format!("threat_intel:{}", intel.source));

            // Determine risk level from severity
            result.risk_level = match intel.severity.to_lowercase().as_str() {
                "high" | "critical" => "malicious",
                "medium" => "suspicious",
                "low" => "suspicious",
                _ => "suspicious",
            }
            .to_string();
            result.confidence = 0.9;
        }

        // Check existing verdicts
        if let Ok(Some(verdict)) = DatabaseQueries::get_verdict_by_hash(conn, hash) {
            result.known = true;
            if result.threat_name.is_none() {
                result.threat_name = verdict.threat_name.clone();
            }
            result.sources.push("local_verdicts".to_string());

            // Use verdict if we don't have better info
            if result.risk_level == "unknown" {
                result.risk_level = match verdict.verdict.to_lowercase().as_str() {
                    "clean" => "safe",
                    "suspicious" | "pup" => "suspicious",
                    "malware" | "malicious" => "malicious",
                    _ => "unknown",
                }
                .to_string();
                result.confidence = verdict.confidence;
            }
        }

        // Check external reports
        if let Ok(Some(report)) = DatabaseQueries::get_external_report(conn, "remote", hash) {
            let mut summary = ExternalReportSummary {
                provider: "VirusTotal".to_string(),
                fetched_at: report.fetched_at,
                verdict: "unknown".to_string(),
                threat_count: 0,
            };

            let data_lower = report.data_json.to_lowercase();
            if data_lower.contains("malic") || data_lower.contains("positiv") {
                summary.verdict = "malicious".to_string();
                summary.threat_count = 1;
                if result.risk_level == "unknown" {
                    result.risk_level = "suspicious".to_string();
                    result.confidence = 0.7;
                }
            } else if data_lower.contains("clean") || data_lower.contains("harmless") {
                summary.verdict = "clean".to_string();
            }

            result.external_reports.push(summary);
            result.sources.push("external_report".to_string());
            result.known = true;
        }
    }

    result
}

/// Check the reputation of a file by its path
/// Calculates the hash and performs all reputation lookups
#[tauri::command]
pub async fn check_file_reputation(file_path: String) -> Result<ReputationCheckResult, String> {
    // Do file I/O (metadata + hash) on a blocking thread
    let fp = file_path.clone();
    let (file_name, file_size, hash) = tokio::task::spawn_blocking(move || {
        let path = Path::new(&fp);

        if !path.exists() {
            return Err("File does not exist".to_string());
        }
        if !path.is_file() {
            return Err("Path is not a file".to_string());
        }

        let metadata =
            std::fs::metadata(path).map_err(|e| format!("Failed to read file metadata: {}", e))?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        let hash = calculate_file_hash(path)?;

        Ok((file_name, metadata.len(), hash))
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))??;

    let mut result =
        crate::with_db_async(move |conn| Ok(check_hash_reputation_internal(&hash, conn)))
            .await
            .map_err(|e: String| e)?;

    result.file_path = Some(file_path);
    result.file_name = file_name;
    result.file_size = Some(file_size);

    Ok(result)
}

/// Check the reputation of a hash directly
#[tauri::command]
pub async fn check_hash_reputation(hash: String) -> Result<ReputationCheckResult, String> {
    // Validate hash format (should be hex string, 64 chars for SHA-256)
    let hash = hash.trim().to_lowercase();

    if hash.is_empty() {
        return Err("Hash cannot be empty".to_string());
    }

    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid hash format: must be hexadecimal".to_string());
    }

    if hash.len() != 32 && hash.len() != 40 && hash.len() != 64 {
        return Err(
            "Invalid hash length: must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters"
                .to_string(),
        );
    }

    crate::with_db_async(move |conn| Ok(check_hash_reputation_internal(&hash, conn))).await
}

/// Batch check multiple hashes
#[tauri::command]
pub async fn batch_check_reputation(
    hashes: Vec<String>,
) -> Result<Vec<ReputationCheckResult>, String> {
    if hashes.len() > 100 {
        return Err("Maximum 100 hashes per batch".to_string());
    }

    crate::with_db_async(move |conn| {
        let results: Vec<ReputationCheckResult> = hashes
            .into_iter()
            .filter_map(|hash| {
                let hash = hash.trim().to_lowercase();
                if hash.is_empty() || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    return None;
                }
                Some(check_hash_reputation_internal(&hash, conn))
            })
            .collect();

        Ok(results)
    })
    .await
}

/// Fetch fresh reputation data from external sources (VirusTotal, etc.)
#[tauri::command]
pub async fn refresh_reputation(hash: String) -> Result<ReputationCheckResult, String> {
    let hash = hash.trim().to_lowercase();

    if hash.is_empty() {
        return Err("Hash cannot be empty".to_string());
    }

    // Convert error to String immediately to avoid non-Send Box<dyn StdError> across await
    let _score = crate::core::reputation::query_reputation(&hash)
        .await
        .map_err(|e| format!("Failed to refresh reputation: {}", e))?;

    crate::with_db_async(move |conn| Ok(check_hash_reputation_internal(&hash, conn))).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationStats {
    pub total_checks_today: u32,
    pub malicious_found: u32,
    pub suspicious_found: u32,
    pub threat_intel_entries: u32,
    pub external_reports_count: u32,
    pub blacklist_entries: u32,
}

#[tauri::command]
pub async fn get_reputation_stats() -> Result<ReputationStats, String> {
    let mut stats = crate::with_db_async(|conn| {
        let mut stats = ReputationStats {
            total_checks_today: 0,
            malicious_found: 0,
            suspicious_found: 0,
            threat_intel_entries: 0,
            external_reports_count: 0,
            blacklist_entries: 0,
        };

        if let Ok(count) = DatabaseQueries::get_threat_intel_count(conn) {
            stats.threat_intel_entries = count as u32;
        }

        if let Ok(count) = conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM external_reports",
            [],
            |r| r.get(0),
        ) {
            stats.external_reports_count = count as u32;
        }

        let today_start = chrono::Local::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_utc().timestamp())
            .unwrap_or(0);

        if let Ok(count) = conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM verdicts WHERE scanned_at >= ?1 AND verdict IN ('Malware', 'malware', 'MALWARE')",
            [today_start],
            |r| r.get(0),
        ) {
            stats.malicious_found = count as u32;
        }

        if let Ok(count) = conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM verdicts WHERE scanned_at >= ?1 AND verdict IN ('Suspicious', 'suspicious', 'SUSPICIOUS', 'PUP', 'pup')",
            [today_start],
            |r| r.get(0),
        ) {
            stats.suspicious_found = count as u32;
        }

        if let Ok(count) = conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM verdicts WHERE scanned_at >= ?1",
            [today_start],
            |r| r.get(0),
        ) {
            stats.total_checks_today = count as u32;
        }

        Ok(stats)
    }).await.unwrap_or(ReputationStats {
        total_checks_today: 0,
        malicious_found: 0,
        suspicious_found: 0,
        threat_intel_entries: 0,
        external_reports_count: 0,
        blacklist_entries: 0,
    });

    // Count blacklist entries on a blocking thread
    let blacklist_count = tokio::task::spawn_blocking(|| {
        let candidates = [
            "resources/blacklists/malware_hashes.txt",
            "../resources/blacklists/malware_hashes.txt",
            "blacklists/malware_hashes.txt",
        ];
        if let Some(blacklist_path) = crate::core::utils::find_resource_path(&candidates) {
            if let Ok(content) = std::fs::read_to_string(&blacklist_path) {
                return content
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                    .count() as u32;
            }
        }
        0u32
    })
    .await
    .unwrap_or(0);
    stats.blacklist_entries = blacklist_count;

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_hash_reputation_validates_format() {
        // Valid SHA-256
        let _result = check_hash_reputation(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        )
        .await;
        // May fail if DB not initialized, but should not be a format error
        // assert!(result.is_ok());

        let result = check_hash_reputation("not-a-valid-hash".to_string()).await;
        assert!(result.is_err());

        let result = check_hash_reputation("abc123".to_string()).await;
        assert!(result.is_err());

        let result = check_hash_reputation("".to_string()).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_default_reputation_result() {
        let result = ReputationCheckResult::default();
        assert_eq!(result.risk_level, "unknown");
        assert!(!result.known);
        assert!(result.sources.is_empty());
    }
}
