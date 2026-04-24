//! Audit log commands for the frontend

use crate::core::tamper_protection::{AuditJournal, AUDIT_JOURNAL};
use serde::Serialize;

/// Audit entry for the frontend (without internal signature details)
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntryView {
    pub timestamp: i64,
    pub event_type: String,
    pub details: String,
    pub file_path: Option<String>,
}

/// Audit log verification result
#[derive(Debug, Clone, Serialize)]
pub struct AuditVerification {
    pub is_valid: bool,
    pub total_entries: usize,
    pub broken_links: Vec<usize>,
    pub message: String,
}

/// Get recent audit entries
#[tauri::command]
pub async fn get_audit_entries(limit: Option<usize>) -> Result<Vec<AuditEntryView>, String> {
    let limit = limit.unwrap_or(100);

    tokio::task::spawn_blocking(move || {
        let guard = AUDIT_JOURNAL
            .lock()
            .map_err(|e| format!("Failed to lock audit journal: {}", e))?;
        let journal = guard.as_ref().ok_or("Audit journal not initialized")?;
        let entries = journal.get_recent(limit)?;

        // Convert to frontend-friendly format (hide signatures)
        let views: Vec<AuditEntryView> = entries
            .into_iter()
            .map(|e| AuditEntryView {
                timestamp: e.timestamp,
                event_type: e.event_type,
                details: e.details,
                file_path: e.file_path,
            })
            .collect();

        // Return in reverse order (newest first)
        Ok(views.into_iter().rev().collect())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

/// Repair audit log by re-signing all entries with the current key.
/// Holds the global AUDIT_JOURNAL lock for the entire operation to prevent
/// concurrent log_event calls from racing with the file rewrite.
#[tauri::command]
pub async fn repair_audit_log() -> Result<AuditVerification, String> {
    tokio::task::spawn_blocking(|| {
        let mut guard = AUDIT_JOURNAL
            .lock()
            .map_err(|e| format!("Failed to lock audit journal: {}", e))?;
        let journal = guard.as_ref().ok_or("Audit journal not initialized")?;
        let (total, repaired) = journal.repair_chain()?;

        let message = if repaired == 0 {
            format!("Audit log is healthy: {} entries, no repairs needed", total)
        } else {
            format!(
                "Audit log repaired: {}/{} entries re-signed with current key",
                repaired, total
            )
        };

        // Re-initialize journal to pick up the new chain state
        if let Ok(new_journal) = AuditJournal::new() {
            *guard = Some(new_journal);
        }

        Ok(AuditVerification {
            is_valid: true,
            total_entries: total,
            broken_links: vec![],
            message,
        })
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

/// Verify audit log integrity
#[tauri::command]
pub async fn verify_audit_log() -> Result<AuditVerification, String> {
    tokio::task::spawn_blocking(|| {
        let guard = AUDIT_JOURNAL
            .lock()
            .map_err(|e| format!("Failed to lock audit journal: {}", e))?;
        let journal = guard.as_ref().ok_or("Audit journal not initialized")?;
        let (is_valid, total, broken) = journal.verify_chain()?;

        let message = if is_valid {
            format!("Audit log integrity verified: {} entries", total)
        } else {
            format!(
                "WARNING: Audit log may be tampered! {} broken chain links at entries: {:?}",
                broken.len(),
                broken
            )
        };

        Ok(AuditVerification {
            is_valid,
            total_entries: total,
            broken_links: broken,
            message,
        })
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_view_serialize() {
        let entry = AuditEntryView {
            timestamp: 1700000000,
            event_type: "scan".to_string(),
            details: "File scanned successfully".to_string(),
            file_path: Some("C:\\test\\file.exe".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"timestamp\":1700000000"));
        assert!(json.contains("\"event_type\":\"scan\""));
        assert!(json.contains("\"file_path\""));
    }

    #[test]
    fn test_audit_entry_view_serialize_no_file_path() {
        let entry = AuditEntryView {
            timestamp: 1700000000,
            event_type: "settings_change".to_string(),
            details: "ML threshold updated".to_string(),
            file_path: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"file_path\":null"));
    }

    #[test]
    fn test_audit_verification_serialize_valid() {
        let verification = AuditVerification {
            is_valid: true,
            total_entries: 100,
            broken_links: vec![],
            message: "Audit log integrity verified: 100 entries".to_string(),
        };
        let json = serde_json::to_string(&verification).unwrap();
        assert!(json.contains("\"is_valid\":true"));
        assert!(json.contains("\"total_entries\":100"));
        assert!(json.contains("\"broken_links\":[]"));
    }

    #[test]
    fn test_audit_verification_serialize_invalid() {
        let verification = AuditVerification {
            is_valid: false,
            total_entries: 50,
            broken_links: vec![3, 7, 12],
            message: "WARNING: Audit log may be tampered!".to_string(),
        };
        let json = serde_json::to_string(&verification).unwrap();
        assert!(json.contains("\"is_valid\":false"));
        assert!(json.contains("[3,7,12]"));
    }

    #[test]
    fn test_audit_entry_view_clone() {
        let entry = AuditEntryView {
            timestamp: 1700000000,
            event_type: "quarantine".to_string(),
            details: "File quarantined".to_string(),
            file_path: Some("C:\\test\\malware.exe".to_string()),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.timestamp, entry.timestamp);
        assert_eq!(cloned.event_type, entry.event_type);
        assert_eq!(cloned.file_path, entry.file_path);
    }

    #[test]
    fn test_audit_verification_clone() {
        let v = AuditVerification {
            is_valid: true,
            total_entries: 10,
            broken_links: vec![1],
            message: "test".to_string(),
        };
        let c = v.clone();
        assert_eq!(c.total_entries, 10);
        assert_eq!(c.broken_links, vec![1]);
    }
}
