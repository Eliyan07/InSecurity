use crate::core::utils::is_dev_build_artifact_path;
use crate::database::DatabaseQueries;
/// Database commands exposed to frontend
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub file_hash: String,
    pub file_path: String,
    pub verdict: String,
    pub confidence: f64,
    pub threat_level: String,
    pub scanned_at: i64,
}

fn query_active_threats(conn: &rusqlite::Connection) -> Result<Vec<VerdictRecord>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT v.file_hash, v.file_path,
                CASE WHEN LOWER(v.verdict) = 'pup' THEN 'Suspicious' ELSE v.verdict END as verdict,
                v.confidence, v.threat_level, v.scanned_at
         FROM verdicts v
         WHERE v.rowid = (
             SELECT v2.rowid
             FROM verdicts v2
             WHERE COALESCE(NULLIF(v2.file_hash, ''), v2.file_path) =
                   COALESCE(NULLIF(v.file_hash, ''), v.file_path)
             ORDER BY v2.scanned_at DESC, v2.rowid DESC
             LIMIT 1
         )
         AND LOWER(v.verdict) IN ('malware', 'suspicious', 'pup')
         AND NOT EXISTS (
             SELECT 1 FROM quarantine q
             WHERE q.file_hash = v.file_hash
             AND q.permanently_deleted = 0
             AND q.restored_at IS NULL
         )
         ORDER BY v.scanned_at DESC",
        )
        .map_err(|e| format!("Query error: {}", e))?;

    let records = stmt
        .query_map([], |row| {
            Ok(VerdictRecord {
                file_hash: row.get(0)?,
                file_path: row.get(1)?,
                verdict: row.get(2)?,
                confidence: row.get(3)?,
                threat_level: row.get(4)?,
                scanned_at: row.get(5)?,
            })
        })
        .map_err(|e| format!("Query map error: {}", e))?;

    Ok(records
        .filter_map(|r| r.ok())
        .filter(|r| !is_dev_build_artifact_path(&r.file_path))
        .collect())
}

#[tauri::command]
pub async fn get_verdicts(_limit: u32) -> Result<Vec<VerdictRecord>, String> {
    let limit = if _limit == 0 { 100 } else { _limit };
    crate::with_db_async(
        move |conn| match DatabaseQueries::get_recent_verdicts(conn, limit) {
            Ok(rows) => {
                let records = rows
                    .into_iter()
                    .map(|r| VerdictRecord {
                        file_hash: r.file_hash,
                        file_path: r.file_path,
                        verdict: r.verdict,
                        confidence: r.confidence,
                        threat_level: r.threat_level,
                        scanned_at: r.scanned_at,
                    })
                    .collect();
                Ok(records)
            }
            Err(e) => Err(format!("DB error: {}", e)),
        },
    )
    .await
}

#[tauri::command]
pub async fn get_active_threats() -> Result<Vec<VerdictRecord>, String> {
    crate::with_db_async_readonly(|conn| {
        let results = query_active_threats(conn)?;
        log::info!("get_active_threats: returning {} threats", results.len());
        Ok(results)
    })
    .await
}

#[tauri::command]
pub async fn search_hash(_hash: String) -> Result<Option<VerdictRecord>, String> {
    crate::with_db_async(
        move |conn| match DatabaseQueries::get_verdict_by_hash(conn, &_hash) {
            Ok(Some(v)) => Ok(Some(VerdictRecord {
                file_hash: v.file_hash,
                file_path: v.file_path,
                verdict: v.verdict,
                confidence: v.confidence,
                threat_level: v.threat_level,
                scanned_at: v.scanned_at,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("DB error: {}", e)),
        },
    )
    .await
}

#[tauri::command]
pub async fn export_verdicts(_output_path: String) -> Result<String, String> {
    crate::with_db_async(move |conn| {
        let out = std::path::Path::new(&_output_path);
        match DatabaseQueries::get_recent_verdicts(conn, 10000) {
            Ok(rows) => {
                let count = rows.len();
                let mut wtr = csv::Writer::from_path(out).map_err(|e| e.to_string())?;
                for r in &rows {
                    wtr.serialize(r).map_err(|e| e.to_string())?;
                }
                wtr.flush().map_err(|e| e.to_string())?;
                Ok(format!("Exported {} records to {}", count, _output_path))
            }
            Err(e) => Err(format!("DB error: {}", e)),
        }
    })
    .await
}

#[tauri::command]
pub async fn export_verdicts_json(_output_path: String) -> Result<String, String> {
    crate::with_db_async(move |conn| {
        let out = std::path::Path::new(&_output_path);
        match DatabaseQueries::get_recent_verdicts(conn, 10000) {
            Ok(rows) => {
                let count = rows.len();
                let json = serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?;
                std::fs::write(out, json).map_err(|e| e.to_string())?;
                Ok(format!("Exported {} records to {}", count, _output_path))
            }
            Err(e) => Err(format!("DB error: {}", e)),
        }
    })
    .await
}

#[tauri::command]
pub fn get_downloads_path() -> Result<String, String> {
    dirs::download_dir()
        .map(|p| p.to_string_lossy().to_string())
        .ok_or_else(|| "Could not determine downloads directory".to_string())
}

#[tauri::command]
pub async fn clear_database() -> Result<(), String> {
    crate::with_db_async(|conn| {
        conn.execute("DELETE FROM verdicts", [])
            .map_err(|e| format!("DB error: {}", e))?;
        Ok(())
    })
    .await
}

/// Clear scan history (verdicts, cache, and reset counters)
#[tauri::command]
pub async fn clear_scan_history() -> Result<String, String> {
    let (cleared_verdicts, cleared_features) = crate::with_db_async(|conn| {
        let cv = conn
            .query_row("SELECT COUNT(*) FROM verdicts", [], |r| r.get::<_, u32>(0))
            .unwrap_or(0);

        conn.execute("DELETE FROM verdicts", [])
            .map_err(|e| format!("Failed to clear verdicts: {}", e))?;

        let cf = conn
            .query_row("SELECT COUNT(*) FROM features", [], |r| r.get::<_, u32>(0))
            .unwrap_or(0);
        conn.execute("DELETE FROM features", [])
            .map_err(|e| format!("Failed to clear features: {}", e))?;

        log::info!(
            "Cleared {} verdicts and {} feature records from database",
            cv,
            cf
        );
        Ok((cv, cf))
    })
    .await?;

    let cleared_cache: usize = if let Ok(mut cache) = crate::CACHE_MANAGER.lock() {
        let stats = cache.get_stats();
        let count = stats.total_entries;
        cache.get_cache_mut().clear();
        log::info!("Cleared {} entries from in-memory cache", count);
        count
    } else {
        0
    };

    crate::commands::scan::reset_counters();

    Ok(format!(
        "Cleared scan history: {} verdicts, {} cache entries, {} features",
        cleared_verdicts, cleared_cache, cleared_features
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_scans: u32,
    pub malware_detected: u32,
    pub suspicious_detected: u32,
    pub quarantined_count: u32,
    pub threat_intel_count: u32,
    pub last_scan_time: Option<i64>,
    pub protection_status: String,
    pub active_malware: u32,
    pub active_suspicious: u32,
}

#[tauri::command]
pub async fn get_dashboard_stats() -> Result<DashboardStats, String> {
    crate::with_db_async_readonly(|conn| {
                // Dashboard stats include all scan sources (real-time and manual) to give
                // a complete picture of system security state.
                let total_scans: u32 = conn
                    .query_row(
                        "SELECT COUNT(DISTINCT COALESCE(NULLIF(file_hash, ''), file_path)) FROM verdicts",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);

                // Count by verdict type - use latest verdict per file hash/path identity
                // so identical binaries copied into multiple locations do not inflate counts.
                let malware_detected: u32 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM (
                            SELECT 1
                            FROM verdicts v
                            WHERE v.rowid = (
                                SELECT v2.rowid
                                FROM verdicts v2
                                WHERE COALESCE(NULLIF(v2.file_hash, ''), v2.file_path) =
                                      COALESCE(NULLIF(v.file_hash, ''), v.file_path)
                                ORDER BY v2.scanned_at DESC, v2.rowid DESC
                                LIMIT 1
                            )
                            AND LOWER(v.verdict) = 'malware'
                        )",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);

                let suspicious_detected: u32 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM (
                            SELECT 1
                            FROM verdicts v
                            WHERE v.rowid = (
                                SELECT v2.rowid
                                FROM verdicts v2
                                WHERE COALESCE(NULLIF(v2.file_hash, ''), v2.file_path) =
                                      COALESCE(NULLIF(v.file_hash, ''), v.file_path)
                                ORDER BY v2.scanned_at DESC, v2.rowid DESC
                                LIMIT 1
                            )
                            AND LOWER(v.verdict) IN ('suspicious', 'pup')
                        )",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);

                let quarantined_count: u32 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM quarantine WHERE permanently_deleted = 0 AND restored_at IS NULL",
                        [],
                        |r| r.get(0)
                    )
                    .unwrap_or(0);

                let threat_intel_count: u32 = conn
                    .query_row("SELECT COUNT(*) FROM threat_intel", [], |r| r.get(0))
                    .unwrap_or(0);

                let last_scan_time: Option<i64> = conn
                    .query_row(
                        "SELECT MAX(scanned_at) FROM verdicts",
                        [],
                        |r| r.get(0),
                    )
                    .ok();

                // Keep dashboard counters aligned with the active-threat list below.
                let active_threats = query_active_threats(conn)?;
                let active_malware: u32 = active_threats
                    .iter()
                    .filter(|threat| threat.verdict.eq_ignore_ascii_case("malware"))
                    .count() as u32;
                let active_suspicious: u32 = active_threats
                    .iter()
                    .filter(|threat| threat.verdict.eq_ignore_ascii_case("suspicious"))
                    .count() as u32;

                let _active_threats = active_malware + active_suspicious;

                Ok(DashboardStats {
                    total_scans,
                    malware_detected,
                    suspicious_detected,
                    quarantined_count,
                    threat_intel_count,
                    last_scan_time,
                    protection_status: {
                        let cfg = crate::config::Settings::load();
                        if cfg.real_time_protection { "active" } else { "disabled" }
                    }.to_string(),
                    active_malware,
                    active_suspicious,
                })
    }).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullThreatInfo {
    // Basic verdict info
    pub file_hash: String,
    pub file_path: String,
    pub verdict: String,
    pub confidence: f64,
    pub threat_level: String,
    pub threat_name: Option<String>,
    pub scan_time_ms: i64,
    pub scanned_at: i64,

    // Threat intelligence from threat_intel table
    pub intel_threat_name: Option<String>,
    pub malware_family: Option<String>,
    pub severity: Option<String>,
    pub intel_source: Option<String>,
    pub first_seen: Option<i64>,
    pub last_updated: Option<i64>,

    // External reports summary
    pub external_reports: Vec<ExternalReportInfo>,

    // Related detections (files with same family/threat name)
    pub related_detections_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReportInfo {
    pub provider: String,
    pub fetched_at: i64,
    pub verdict: String,
    pub detection_count: Option<u32>,
}

/// Get comprehensive threat information for a file hash
/// This combines data from verdicts, threat_intel, and external_reports tables
#[tauri::command]
pub async fn get_full_threat_info(file_hash: String) -> Result<FullThreatInfo, String> {
    let hash = file_hash.trim().to_lowercase();

    if hash.is_empty() {
        return Err("File hash cannot be empty".to_string());
    }

    crate::with_db_async(move |conn| {
                let verdict_info = conn.query_row(
                    "SELECT file_hash, file_path, verdict, confidence, threat_level, threat_name, scan_time_ms, scanned_at
                     FROM verdicts WHERE file_hash = ?1 ORDER BY scanned_at DESC LIMIT 1",
                    [&hash],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, f64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                        ))
                    }
                ).map_err(|_| "No verdict found for this hash".to_string())?;

                // Get threat intel info
                let intel_info: Option<(String, Option<String>, String, String, i64, i64)> = conn.query_row(
                    "SELECT threat_name, family, severity, source, first_seen, last_updated
                     FROM threat_intel WHERE file_hash = ?1 ORDER BY last_updated DESC LIMIT 1",
                    [&hash],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    }
                ).ok();

                let mut external_reports = Vec::new();
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT source, fetched_at, data_json FROM external_reports WHERE file_hash = ?1 ORDER BY fetched_at DESC"
                ) {
                    if let Ok(rows) = stmt.query_map([&hash], |row| {
                        let source: String = row.get(0)?;
                        let fetched_at: i64 = row.get(1)?;
                        let data_json: String = row.get(2)?;

                        // Parse detection count from JSON if available
                        let detection_count = if data_json.contains("positives") {
                            // Try to extract positives count
                            data_json.find("positives")
                                .and_then(|pos| {
                                    let after = &data_json[pos..];
                                    after.find(|c: char| c.is_ascii_digit())
                                        .and_then(|start| {
                                            let num_str: String = after[start..].chars()
                                                .take_while(|c| c.is_ascii_digit())
                                                .collect();
                                            num_str.parse::<u32>().ok()
                                        })
                                })
                        } else {
                            None
                        };

                        let verdict = if data_json.to_lowercase().contains("malic") {
                            "malicious"
                        } else if data_json.to_lowercase().contains("clean") || data_json.to_lowercase().contains("harmless") {
                            "clean"
                        } else {
                            "unknown"
                        };

                        Ok(ExternalReportInfo {
                            provider: source,
                            fetched_at,
                            verdict: verdict.to_string(),
                            detection_count,
                        })
                    }) {
                        external_reports = rows.filter_map(|r| r.ok()).collect();
                    }
                }

                let related_count: u32 = if let Some((_, Some(ref family), _, _, _, _)) = intel_info {
                    conn.query_row(
                        "SELECT COUNT(*) FROM threat_intel WHERE family = ?1 AND file_hash != ?2",
                        [family, &hash],
                        |row| row.get::<_, u32>(0)
                    ).unwrap_or(0)
                } else {
                    0
                };

                Ok(FullThreatInfo {
                    file_hash: verdict_info.0,
                    file_path: verdict_info.1,
                    verdict: verdict_info.2,
                    confidence: verdict_info.3,
                    threat_level: verdict_info.4,
                    threat_name: verdict_info.5,
                    scan_time_ms: verdict_info.6,
                    scanned_at: verdict_info.7,
                    intel_threat_name: intel_info.as_ref().map(|i| i.0.clone()),
                    malware_family: intel_info.as_ref().and_then(|i| i.1.clone()),
                    severity: intel_info.as_ref().map(|i| i.2.clone()),
                    intel_source: intel_info.as_ref().map(|i| i.3.clone()),
                    first_seen: intel_info.as_ref().map(|i| i.4),
                    last_updated: intel_info.as_ref().map(|i| i.5),
                    external_reports,
                    related_detections_count: related_count,
                })
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // VerdictRecord tests
    // =========================================================================

    #[test]
    fn test_verdict_record_serialize_roundtrip() {
        let vr = VerdictRecord {
            file_hash: "abc123".to_string(),
            file_path: "C:\\test\\file.exe".to_string(),
            verdict: "Malware".to_string(),
            confidence: 0.97,
            threat_level: "HIGH".to_string(),
            scanned_at: 1700000000,
        };
        let json = serde_json::to_string(&vr).unwrap();
        let vr2: VerdictRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(vr2.file_hash, "abc123");
        assert_eq!(vr2.verdict, "Malware");
        assert!((vr2.confidence - 0.97).abs() < f64::EPSILON);
        assert_eq!(vr2.scanned_at, 1700000000);
    }

    #[test]
    fn test_verdict_record_clone() {
        let vr = VerdictRecord {
            file_hash: "hash".to_string(),
            file_path: "/path".to_string(),
            verdict: "Clean".to_string(),
            confidence: 0.5,
            threat_level: "LOW".to_string(),
            scanned_at: 0,
        };
        let cloned = vr.clone();
        assert_eq!(cloned.file_hash, vr.file_hash);
        assert_eq!(cloned.verdict, vr.verdict);
    }

    // =========================================================================
    // DashboardStats tests
    // =========================================================================

    #[test]
    fn test_dashboard_stats_serialize_roundtrip() {
        let stats = DashboardStats {
            total_scans: 100,
            malware_detected: 5,
            suspicious_detected: 10,
            quarantined_count: 3,
            threat_intel_count: 50,
            last_scan_time: Some(1700000000),
            protection_status: "active".to_string(),
            active_malware: 2,
            active_suspicious: 7,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let stats2: DashboardStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats2.total_scans, 100);
        assert_eq!(stats2.malware_detected, 5);
        assert_eq!(stats2.suspicious_detected, 10);
        assert_eq!(stats2.quarantined_count, 3);
        assert_eq!(stats2.threat_intel_count, 50);
        assert_eq!(stats2.last_scan_time, Some(1700000000));
        assert_eq!(stats2.protection_status, "active");
        assert_eq!(stats2.active_malware, 2);
        assert_eq!(stats2.active_suspicious, 7);
    }

    #[test]
    fn test_dashboard_stats_no_last_scan() {
        let stats = DashboardStats {
            total_scans: 0,
            malware_detected: 0,
            suspicious_detected: 0,
            quarantined_count: 0,
            threat_intel_count: 0,
            last_scan_time: None,
            protection_status: "disabled".to_string(),
            active_malware: 0,
            active_suspicious: 0,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("null") || json.contains("last_scan_time"));
    }

    #[test]
    fn test_query_active_threats_filters_dev_build_artifacts() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE verdicts (
                file_hash TEXT NOT NULL,
                file_path TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                threat_level TEXT NOT NULL,
                scanned_at INTEGER NOT NULL
            );
            CREATE TABLE quarantine (
                file_hash TEXT NOT NULL,
                permanently_deleted INTEGER NOT NULL DEFAULT 0,
                restored_at INTEGER
            );",
        )
        .unwrap();

        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "hash-dev",
                r"C:\Users\123\Desktop\rust_projects\antivirus_app\insecurity\src-tauri\target\release\app.exe",
                "Malware",
                0.98_f64,
                "HIGH",
                100_i64,
            ],
        ).unwrap();

        conn.execute(
            "INSERT INTO verdicts (file_hash, file_path, verdict, confidence, threat_level, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "hash-real",
                r"C:\Users\123\Desktop\Downloads\suspicious.exe",
                "Suspicious",
                0.76_f64,
                "MEDIUM",
                101_i64,
            ],
        ).unwrap();

        let threats = query_active_threats(&conn).unwrap();

        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].file_hash, "hash-real");
        assert_eq!(threats[0].verdict, "Suspicious");
    }

    // =========================================================================
    // FullThreatInfo tests
    // =========================================================================

    #[test]
    fn test_full_threat_info_serialize_roundtrip() {
        let info = FullThreatInfo {
            file_hash: "abc".to_string(),
            file_path: "/malware.exe".to_string(),
            verdict: "Malware".to_string(),
            confidence: 0.99,
            threat_level: "HIGH".to_string(),
            threat_name: Some("Trojan.Generic".to_string()),
            scan_time_ms: 200,
            scanned_at: 1700000000,
            intel_threat_name: Some("Trojan.Generic".to_string()),
            malware_family: Some("TrojanFamily".to_string()),
            severity: Some("critical".to_string()),
            intel_source: Some("MalwareBazaar".to_string()),
            first_seen: Some(1690000000),
            last_updated: Some(1700000000),
            external_reports: vec![ExternalReportInfo {
                provider: "VirusTotal".to_string(),
                fetched_at: 1700000000,
                verdict: "malicious".to_string(),
                detection_count: Some(42),
            }],
            related_detections_count: 5,
        };
        let json = serde_json::to_string(&info).unwrap();
        let info2: FullThreatInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info2.file_hash, "abc");
        assert_eq!(info2.malware_family, Some("TrojanFamily".to_string()));
        assert_eq!(info2.external_reports.len(), 1);
        assert_eq!(info2.external_reports[0].detection_count, Some(42));
        assert_eq!(info2.related_detections_count, 5);
    }

    #[test]
    fn test_full_threat_info_no_intel() {
        let info = FullThreatInfo {
            file_hash: "def".to_string(),
            file_path: "/unknown.exe".to_string(),
            verdict: "Suspicious".to_string(),
            confidence: 0.6,
            threat_level: "MEDIUM".to_string(),
            threat_name: None,
            scan_time_ms: 100,
            scanned_at: 1700000000,
            intel_threat_name: None,
            malware_family: None,
            severity: None,
            intel_source: None,
            first_seen: None,
            last_updated: None,
            external_reports: vec![],
            related_detections_count: 0,
        };
        let json = serde_json::to_string(&info).unwrap();
        let info2: FullThreatInfo = serde_json::from_str(&json).unwrap();
        assert!(info2.intel_threat_name.is_none());
        assert!(info2.malware_family.is_none());
        assert!(info2.external_reports.is_empty());
    }

    // =========================================================================
    // ExternalReportInfo tests
    // =========================================================================

    #[test]
    fn test_external_report_info_serialize() {
        let report = ExternalReportInfo {
            provider: "MalwareBazaar".to_string(),
            fetched_at: 1700000000,
            verdict: "unknown".to_string(),
            detection_count: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let report2: ExternalReportInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(report2.provider, "MalwareBazaar");
        assert_eq!(report2.detection_count, None);
    }
}
