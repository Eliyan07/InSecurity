use crate::core::quarantine_manager::{QuarantineEntry, QuarantineManager, QuarantineOptions};
use crate::core::tamper_protection::{log_audit_event, AuditEventType};
use crate::database::queries::DatabaseQueries;
/// Quarantine commands
use serde::{Deserialize, Serialize};

fn normalize_path_identity(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn validate_hash(hash: &str) -> Result<(), String> {
    let hash = hash.trim();
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
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineFileInfo {
    pub id: i64,
    pub file_hash: String,
    pub original_path: String,
    pub verdict: String,
    pub threat_level: String,
    pub quarantined_at: i64,
    pub file_size: u64,
    pub file_type: String,
}

impl From<crate::database::models::QuarantineRecord> for QuarantineFileInfo {
    fn from(record: crate::database::models::QuarantineRecord) -> Self {
        QuarantineFileInfo {
            id: record.id,
            file_hash: record.file_hash,
            original_path: record.original_path,
            verdict: record.verdict,
            threat_level: record.threat_level,
            quarantined_at: record.quarantined_at,
            file_size: record.file_size,
            file_type: record.file_type,
        }
    }
}

fn get_quarantine_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("insecurity")
        .join("quarantine")
        .to_string_lossy()
        .to_string()
}

#[tauri::command]
pub async fn quarantine_file_by_path(
    file_path: String,
    file_hash: String,
    verdict: String,
    threat_level: String,
) -> Result<QuarantineFileInfo, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use std::path::Path;

        let path = Path::new(&file_path);
        if !path.exists() {
            return Err(format!("File not found: {}", file_path));
        }

        let metadata = std::fs::metadata(&file_path)
            .map_err(|e| format!("Failed to read file metadata: {}", e))?;

        let file_size = metadata.len();
        let file_type = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("unknown")
            .to_string();

        let qm = QuarantineManager::new(&get_quarantine_path());
        let reason = format!("Manual quarantine from dashboard - {}", verdict);

        // FIX: Skip neutralization for manual quarantine from dashboard.
        // Manual quarantine is user-initiated - they don't need process killing
        // and persistence scrubbing, which adds 500ms+ of sleep plus process
        // enumeration overhead.
        let options = QuarantineOptions::new().skip_neutralization();

        let entry = qm
            .quarantine_file_with_options(
                &file_path,
                &file_hash,
                &verdict,
                &threat_level,
                &reason,
                options,
            )
            .map_err(|e| format!("Quarantine failed: {}", e))?;

        // FIX: Get the actual DB-assigned id back instead of using the timestamp
        // id from QuarantineEntry. The manager sets id = Utc::now().timestamp()
        // but the DB uses INTEGER PRIMARY KEY autoincrement - these don't match,
        // causing restore/delete-by-id to fail.
        let db_id = if let Ok(guard) = crate::DB.lock() {
            if let Some(ref conn) = *guard {
                let record = crate::database::models::QuarantineRecord {
                    id: 0, // DB assigns autoincrement
                    file_hash: entry.entry.file_hash.clone(),
                    original_path: entry.entry.original_path.clone(),
                    quarantine_path: entry.entry.quarantine_path.clone(),
                    verdict: entry.entry.verdict.clone(),
                    threat_level: entry.entry.threat_level.clone(),
                    reason: entry.entry.reason.clone(),
                    quarantined_at: entry.entry.quarantined_at,
                    restored_at: None,
                    permanently_deleted: false,
                    file_size,
                    file_type: file_type.clone(),
                };

                match DatabaseQueries::insert_quarantine(conn, &record) {
                    Ok(()) => conn.last_insert_rowid(),
                    Err(e) => {
                        log::warn!("Failed to insert quarantine record to DB: {}", e);
                        entry.entry.id // fallback to manager id
                    }
                }
            } else {
                entry.entry.id
            }
        } else {
            entry.entry.id
        };

        log::info!(
            "Quarantined file: {} (hash: {}, db_id: {})",
            file_path,
            file_hash,
            db_id
        );

        log_audit_event(
            AuditEventType::ThreatQuarantined,
            &format!("File quarantined: {} ({})", file_path, verdict),
            Some(&file_path),
            Some(&file_hash),
        );

        Ok(QuarantineFileInfo {
            id: db_id, // FIX: return DB id, not timestamp
            file_hash: entry.entry.file_hash,
            original_path: entry.entry.original_path,
            verdict: entry.entry.verdict,
            threat_level: entry.entry.threat_level,
            quarantined_at: entry.entry.quarantined_at,
            file_size,
            file_type,
        })
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

/// Ignore a detected threat (remove from verdicts table so it won't show in dashboard)
/// Also adds the file hash to the whitelist to prevent future false positive detections
/// and records the decision in user_whitelist so the user can review/undo it later.
#[tauri::command]
pub async fn ignore_threat(file_hash: String, file_path: Option<String>) -> Result<(), String> {
    validate_hash(&file_hash)?;
    let file_hash = file_hash.trim().to_lowercase();

    // Whitelist file I/O on blocking thread
    let hash_for_wl = file_hash.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::core::static_scanner::add_to_whitelist(&hash_for_wl) {
            log::warn!("Failed to add hash to whitelist: {}", e);
        } else {
            log::info!("Added hash {} to whitelist", hash_for_wl);
        }
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?;

    if let Ok(mut cache_guard) = crate::CACHE_MANAGER.lock() {
        cache_guard.invalidate(&file_hash);
    }

    let hash_clone = file_hash.clone();
    let requested_path = file_path.clone();
    let requested_path_norm = file_path.as_ref().map(|path| normalize_path_identity(path));
    crate::with_db_async(move |conn| {
        // Capture file_path and verdict from verdicts table before deleting.
        let (stored_file_path, original_verdict): (Option<String>, Option<String>) =
            if let Some(ref path_norm) = requested_path_norm {
                conn.query_row(
                    "SELECT file_path, verdict FROM verdicts
                     WHERE file_hash = ?1 AND LOWER(REPLACE(file_path, '/', '\\')) = ?2
                     ORDER BY scanned_at DESC, id DESC
                     LIMIT 1",
                    rusqlite::params![hash_clone, path_norm],
                    |row| Ok((row.get(0).ok(), row.get(1).ok())),
                )
                .unwrap_or((requested_path.clone(), None))
            } else {
                conn.query_row(
                    "SELECT file_path, verdict FROM verdicts
                     WHERE file_hash = ?1
                     ORDER BY scanned_at DESC, id DESC
                     LIMIT 1",
                    rusqlite::params![hash_clone],
                    |row| Ok((row.get(0).ok(), row.get(1).ok())),
                )
                .unwrap_or((None, None))
            };
        let whitelist_path = requested_path.or(stored_file_path);

        // Record in user_whitelist so user can review/undo from Settings
        let now = chrono::Utc::now().timestamp();
        let _ = conn.execute(
            "INSERT OR IGNORE INTO user_whitelist (file_hash, file_path, original_verdict, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![hash_clone, whitelist_path, original_verdict, now],
        );

        conn.execute(
            "DELETE FROM verdicts WHERE file_hash = ?1",
            rusqlite::params![hash_clone],
        ).map_err(|e| format!("Failed to remove verdict: {}", e))?;

        log::info!("Ignored threat with hash: {} (added to whitelist)", hash_clone);

        log_audit_event(
            AuditEventType::ThreatIgnored,
            &format!("Threat ignored and whitelisted: {}", hash_clone),
            None,
            Some(&hash_clone),
        );

        Ok(())
    }).await
}

#[tauri::command]
pub async fn delete_threat_file(file_path: String, file_hash: String) -> Result<(), String> {
    validate_hash(&file_hash)?;
    let file_hash = file_hash.trim().to_lowercase();

    let fp = file_path.clone();
    let fh = file_hash.clone();
    let requested_path_norm = normalize_path_identity(&file_path);
    tauri::async_runtime::spawn_blocking(move || {
        use std::fs;

        let canonical_path = match fs::canonicalize(&fp) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Ok(guard) = crate::DB.lock() {
                    if let Some(ref conn) = *guard {
                        let _ = conn.execute(
                            "DELETE FROM verdicts
                             WHERE file_hash = ?1
                             AND LOWER(REPLACE(file_path, '/', '\\')) = ?2",
                            rusqlite::params![fh, requested_path_norm],
                        );
                    }
                }
                log::info!("File already deleted, cleaned up verdict: {}", fp);
                return Ok(());
            }
            Err(e) => return Err(format!("Cannot resolve file path: {}", e)),
        };

        let path_str = canonical_path.to_string_lossy().to_lowercase();
        let canonical_path_norm = normalize_path_identity(&canonical_path.to_string_lossy());

        // SECURITY: Block deletion of system files using canonicalized path
        let blocked_patterns = [
            "\\windows\\",
            "\\system32\\",
            "\\syswow64\\",
            "\\programdata\\",
            "\\program files\\",
            "\\program files (x86)\\",
            "/usr/",
            "/bin/",
            "/sbin/",
            "/etc/",
            "/lib",
            "/boot/",
        ];

        for blocked in blocked_patterns {
            if path_str.contains(blocked) {
                return Err("Cannot delete system files for security reasons".to_string());
            }
        }

        if !canonical_path.is_file() {
            return Err("Path is not a regular file".to_string());
        }

        // FIX: Verify file hash before deletion to prevent deleting the wrong file
        // (e.g. if the path was reused by a different file since detection).
        let actual_hash = compute_sha256(&canonical_path)
            .map_err(|e| format!("Failed to hash file for verification: {}", e))?;

        if actual_hash != fh {
            log::warn!(
                "Hash mismatch for {}: expected {} but got {}. File may have changed since detection.",
                fp, fh, actual_hash
            );
            return Err(
                "File hash does not match the detected threat. The file may have been replaced since detection. \
                 Re-scan the file before taking action.".to_string()
            );
        }

        fs::remove_file(&canonical_path)
            .map_err(|e| format!("Failed to delete file: {}", e))?;

        if let Ok(guard) = crate::DB.lock() {
            if let Some(ref conn) = *guard {
                let _ = conn.execute(
                    "DELETE FROM verdicts
                     WHERE file_hash = ?1
                     AND LOWER(REPLACE(file_path, '/', '\\')) = ?2",
                    rusqlite::params![fh, canonical_path_norm],
                );
            }
        }

        log::info!("Deleted threat file: {} (hash: {})", fp, fh);

        log_audit_event(
            AuditEventType::ThreatDeleted,
            &format!("Threat file permanently deleted: {}", fp),
            Some(&fp),
            Some(&fh),
        );

        Ok(())
    }).await.map_err(|e| format!("Task join error: {}", e))?
}

/// Compute SHA-256 of a file for verification before destructive operations
fn compute_sha256(path: &std::path::Path) -> Result<String, std::io::Error> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[tauri::command]
pub async fn list_quarantined() -> Result<Vec<QuarantineFileInfo>, String> {
    crate::with_db_async_readonly(|conn| match DatabaseQueries::get_all_quarantined(conn) {
        Ok(records) => Ok(records.into_iter().map(QuarantineFileInfo::from).collect()),
        Err(e) => {
            log::error!("Failed to list quarantined files: {}", e);
            Err(format!("Database error: {}", e))
        }
    })
    .await
}

#[tauri::command]
pub async fn restore_file(id: i64) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let record = {
            let guard = crate::DB.lock().map_err(|e| format!("DB lock error: {}", e))?;
            let conn = guard.as_ref().ok_or("Database not available")?;

            let mut stmt = conn.prepare("SELECT id, file_hash, original_path, quarantine_path, verdict, threat_level, reason, quarantined_at, restored_at, permanently_deleted, file_size, file_type FROM quarantine WHERE id = ?1")
                .map_err(|e| format!("Query error: {}", e))?;

            stmt.query_row([id], |row| {
                Ok(crate::database::models::QuarantineRecord {
                    id: row.get(0)?,
                    file_hash: row.get(1)?,
                    original_path: row.get(2)?,
                    quarantine_path: row.get(3)?,
                    verdict: row.get(4)?,
                    threat_level: row.get(5)?,
                    reason: row.get(6)?,
                    quarantined_at: row.get(7)?,
                    restored_at: row.get(8)?,
                    permanently_deleted: row.get::<_, i32>(9)? != 0,
                    file_size: row.get(10)?,
                    file_type: row.get(11)?,
                })
            }).map_err(|e| format!("Record not found: {}", e))?
        };

        // SECURITY: Canonicalize path first to prevent TOCTOU and symlink attacks
        let restore_path = std::path::Path::new(&record.original_path);
        let canonical_path = if let Some(parent) = restore_path.parent() {
            if parent.exists() {
                parent.canonicalize()
                    .map(|p| p.join(restore_path.file_name().unwrap_or_default()))
                    .unwrap_or_else(|_| restore_path.to_path_buf())
            } else {
                restore_path.to_path_buf()
            }
        } else {
            restore_path.to_path_buf()
        };

        let path_lower = canonical_path.to_string_lossy().to_lowercase();
        let blocked_patterns = [
            "\\windows\\",
            "\\system32\\",
            "\\syswow64\\",
            "\\startup\\",
            "c:\\windows",
        ];

        for blocked in blocked_patterns {
            if path_lower.contains(blocked) || path_lower.starts_with(&blocked.replace("\\\\", "\\")) {
                return Err("Cannot restore to system directories for security reasons".to_string());
            }
        }

        let qm = QuarantineManager::new(&get_quarantine_path());
        let entry = QuarantineEntry {
            id: record.id,
            file_hash: record.file_hash,
            original_path: record.original_path,
            quarantine_path: record.quarantine_path,
            verdict: record.verdict,
            threat_level: record.threat_level,
            reason: record.reason,
            quarantined_at: record.quarantined_at,
            restored_at: record.restored_at,
            permanently_deleted: record.permanently_deleted,
            file_size: record.file_size,
            file_type: record.file_type,
            neutralization_result: None,
        };

        qm.restore_file(&entry).map_err(|e| format!("Restore failed: {}", e))?;

        if let Ok(guard) = crate::DB.lock() {
            if let Some(ref conn) = *guard {
                let now = chrono::Utc::now().timestamp();
                let _ = conn.execute(
                    "UPDATE quarantine SET restored_at = ?1 WHERE id = ?2",
                    rusqlite::params![now, id]
                );
            }
        }

        log::info!("Restored quarantined file id={}", id);

        log_audit_event(
            AuditEventType::FileRestored,
            &format!("Quarantined file restored: {}", entry.original_path),
            Some(&entry.original_path),
            Some(&entry.file_hash),
        );

        Ok(())
    }).await.map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn delete_quarantined_file(id: i64) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let record = {
            let guard = crate::DB.lock().map_err(|e| format!("DB lock error: {}", e))?;
            let conn = guard.as_ref().ok_or("Database not available")?;

            let mut stmt = conn.prepare("SELECT id, file_hash, original_path, quarantine_path, verdict, threat_level, reason, quarantined_at, restored_at, permanently_deleted, file_size, file_type FROM quarantine WHERE id = ?1")
                .map_err(|e| format!("Query error: {}", e))?;

            stmt.query_row([id], |row| {
                Ok(crate::database::models::QuarantineRecord {
                    id: row.get(0)?,
                    file_hash: row.get(1)?,
                    original_path: row.get(2)?,
                    quarantine_path: row.get(3)?,
                    verdict: row.get(4)?,
                    threat_level: row.get(5)?,
                    reason: row.get(6)?,
                    quarantined_at: row.get(7)?,
                    restored_at: row.get(8)?,
                    permanently_deleted: row.get::<_, i32>(9)? != 0,
                    file_size: row.get(10)?,
                    file_type: row.get(11)?,
                })
            }).map_err(|e| format!("Record not found: {}", e))?
        };

        let qm = QuarantineManager::new(&get_quarantine_path());
        let entry = QuarantineEntry {
            id: record.id,
            file_hash: record.file_hash,
            original_path: record.original_path,
            quarantine_path: record.quarantine_path,
            verdict: record.verdict,
            threat_level: record.threat_level,
            reason: record.reason,
            quarantined_at: record.quarantined_at,
            restored_at: record.restored_at,
            permanently_deleted: record.permanently_deleted,
            file_size: record.file_size,
            file_type: record.file_type,
            neutralization_result: None,
        };

        qm.delete_file(&entry).map_err(|e| format!("Delete failed: {}", e))?;

        if let Ok(guard) = crate::DB.lock() {
            if let Some(ref conn) = *guard {
                let _ = conn.execute(
                    "UPDATE quarantine SET permanently_deleted = 1 WHERE id = ?1",
                    rusqlite::params![id]
                );
            }
        }

        log::info!("Permanently deleted quarantined file id={}", id);
        Ok(())
    }).await.map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn get_quarantine_details(id: i64) -> Result<QuarantineFileInfo, String> {
    crate::with_db_async(move |conn| {
        let mut stmt = conn.prepare("SELECT id, file_hash, original_path, quarantine_path, verdict, threat_level, reason, quarantined_at, restored_at, permanently_deleted, file_size, file_type FROM quarantine WHERE id = ?1")
            .map_err(|e| format!("Query error: {}", e))?;

        let record = stmt.query_row([id], |row| {
            Ok(crate::database::models::QuarantineRecord {
                id: row.get(0)?,
                file_hash: row.get(1)?,
                original_path: row.get(2)?,
                quarantine_path: row.get(3)?,
                verdict: row.get(4)?,
                threat_level: row.get(5)?,
                reason: row.get(6)?,
                quarantined_at: row.get(7)?,
                restored_at: row.get(8)?,
                permanently_deleted: row.get::<_, i32>(9)? != 0,
                file_size: row.get(10)?,
                file_type: row.get(11)?,
            })
        }).map_err(|e| format!("Record not found: {}", e))?;

        Ok(QuarantineFileInfo::from(record))
    }).await
}

// ============================================================================
// User Whitelist Management
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserWhitelistEntry {
    pub id: i64,
    pub file_hash: String,
    pub file_path: Option<String>,
    pub original_verdict: Option<String>,
    pub created_at: i64,
}

#[tauri::command]
pub async fn get_user_whitelist() -> Result<Vec<UserWhitelistEntry>, String> {
    crate::with_db_async_readonly(|conn| {
        let mut stmt = conn.prepare(
            "SELECT id, file_hash, file_path, original_verdict, created_at FROM user_whitelist ORDER BY created_at DESC"
        ).map_err(|e| format!("Query error: {}", e))?;

        let entries = stmt.query_map([], |row| {
            Ok(UserWhitelistEntry {
                id: row.get(0)?,
                file_hash: row.get(1)?,
                file_path: row.get(2)?,
                original_verdict: row.get(3)?,
                created_at: row.get(4)?,
            })
        }).map_err(|e| format!("Query error: {}", e))?;

        entries.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to collect whitelist entries: {}", e))
    }).await
}

#[tauri::command]
pub async fn remove_from_user_whitelist(file_hash: String) -> Result<(), String> {
    validate_hash(&file_hash)?;
    let file_hash = file_hash.trim().to_lowercase();

    // Remove from in-memory whitelist set
    let hash_for_wl = file_hash.clone();
    tokio::task::spawn_blocking(move || {
        crate::core::static_scanner::remove_from_whitelist(&hash_for_wl);
        log::info!("Removed hash {} from in-memory whitelist", hash_for_wl);
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?;

    // Invalidate cache so re-scans pick up the change
    if let Ok(mut cache_guard) = crate::CACHE_MANAGER.lock() {
        cache_guard.invalidate(&file_hash);
    }

    let hash_clone = file_hash.clone();
    crate::with_db_async(move |conn| {
        conn.execute(
            "DELETE FROM user_whitelist WHERE file_hash = ?1",
            rusqlite::params![hash_clone],
        )
        .map_err(|e| format!("Failed to remove from user whitelist: {}", e))?;

        log::info!("Removed hash {} from user whitelist", hash_clone);

        log_audit_event(
            AuditEventType::ExclusionRemoved,
            &format!("User whitelist entry removed: {}", hash_clone),
            None,
            Some(&hash_clone),
        );

        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn clear_user_whitelist() -> Result<usize, String> {
    // Get all user-whitelisted hashes from the DB
    let db_hashes: Vec<String> = crate::with_db_async(|conn| {
        let mut stmt = conn
            .prepare("SELECT file_hash FROM user_whitelist")
            .map_err(|e| format!("Query error: {}", e))?;
        let hashes = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("Query error: {}", e))?
            .filter_map(|r| r.ok())
            .collect::<Vec<String>>();
        Ok(hashes)
    })
    .await?;

    if db_hashes.is_empty() {
        return Ok(0);
    }

    // Clear from memory + user whitelist file on disk
    let hashes_for_clear = db_hashes.clone();
    let removed = tokio::task::spawn_blocking(move || {
        crate::core::static_scanner::clear_user_whitelist(&hashes_for_clear)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?;

    // Invalidate cache for all cleared hashes
    if let Ok(mut cache_guard) = crate::CACHE_MANAGER.lock() {
        for hash in &db_hashes {
            cache_guard.invalidate(hash);
        }
    }

    // Delete all entries from DB
    crate::with_db_async(|conn| {
        conn.execute("DELETE FROM user_whitelist", [])
            .map_err(|e| format!("Failed to clear user whitelist: {}", e))?;
        Ok(())
    })
    .await?;

    log::info!("Cleared all user whitelist entries: {} removed", removed);

    log_audit_event(
        AuditEventType::ExclusionRemoved,
        &format!("All user whitelist entries cleared ({} entries)", removed),
        None,
        None,
    );

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hash_valid_md5() {
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427e").is_ok());
    }

    #[test]
    fn test_validate_hash_valid_sha1() {
        assert!(validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709").is_ok());
    }

    #[test]
    fn test_validate_hash_valid_sha256() {
        assert!(
            validate_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_hash_empty() {
        let result = validate_hash("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_validate_hash_whitespace_only() {
        let result = validate_hash("   ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_validate_hash_invalid_chars() {
        let result = validate_hash("xyz_not_hex_at_all_0123456789abcdef");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hexadecimal"));
    }

    #[test]
    fn test_validate_hash_wrong_length() {
        let result = validate_hash("abcdef1234"); // 10 chars = not 32/40/64
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid hash length"));
    }

    #[test]
    fn test_validate_hash_trims_whitespace() {
        assert!(validate_hash("  d41d8cd98f00b204e9800998ecf8427e  ").is_ok());
    }

    #[test]
    fn test_validate_hash_uppercase_hex() {
        assert!(validate_hash("D41D8CD98F00B204E9800998ECF8427E").is_ok());
    }

    #[test]
    fn test_validate_hash_mixed_case() {
        assert!(validate_hash("D41d8cD98F00b204E9800998ECf8427e").is_ok());
    }

    #[test]
    fn test_quarantine_file_info_from_record() {
        let record = crate::database::models::QuarantineRecord {
            id: 42,
            file_hash: "abc123".to_string(),
            original_path: "C:\\test\\malware.exe".to_string(),
            quarantine_path: "vault/abc123".to_string(),
            verdict: "Malware".to_string(),
            threat_level: "HIGH".to_string(),
            reason: "Detected by YARA".to_string(),
            quarantined_at: 1700000000,
            restored_at: None,
            permanently_deleted: false,
            file_size: 1024,
            file_type: "exe".to_string(),
        };
        let info = QuarantineFileInfo::from(record);
        assert_eq!(info.id, 42);
        assert_eq!(info.file_hash, "abc123");
        assert_eq!(info.original_path, "C:\\test\\malware.exe");
        assert_eq!(info.verdict, "Malware");
        assert_eq!(info.threat_level, "HIGH");
        assert_eq!(info.file_size, 1024);
        assert_eq!(info.file_type, "exe");
    }

    #[test]
    fn test_quarantine_file_info_serialization_camel_case() {
        let info = QuarantineFileInfo {
            id: 1,
            file_hash: "abc".to_string(),
            original_path: "/tmp/test".to_string(),
            verdict: "Clean".to_string(),
            threat_level: "LOW".to_string(),
            quarantined_at: 0,
            file_size: 0,
            file_type: "txt".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        // Should use camelCase (serde rename_all)
        assert!(json.contains("fileHash"));
        assert!(json.contains("originalPath"));
        assert!(json.contains("threatLevel"));
        assert!(json.contains("quarantinedAt"));
        assert!(json.contains("fileSize"));
        assert!(json.contains("fileType"));
    }
}
