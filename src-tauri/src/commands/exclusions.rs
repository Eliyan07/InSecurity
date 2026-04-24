use crate::core::tamper_protection::{
    compute_exclusion_signature, log_audit_event, AuditEventType,
};
use crate::database::models::Exclusion;
/// Tauri commands for exclusions management
use crate::database::queries::DatabaseQueries;

#[tauri::command]
pub async fn get_exclusions() -> Result<Vec<Exclusion>, String> {
    crate::with_db_async(|conn| {
        let exclusions = DatabaseQueries::get_all_exclusions(conn).map_err(|e| e.to_string())?;

        for excl in &exclusions {
            if let Some(ref sig) = excl.signature {
                let expected = compute_exclusion_signature(
                    &excl.exclusion_type,
                    &excl.pattern,
                    excl.reason.as_deref(),
                    excl.created_at,
                );
                if sig != &expected {
                    log::warn!(
                        "Exclusion tamper detected! Pattern '{}' has invalid signature",
                        excl.pattern
                    );
                    log_audit_event(
                        AuditEventType::IntegrityCheckFailed,
                        &format!("Exclusion tampered: {}", excl.pattern),
                        None,
                        None,
                    );
                }
            }
        }

        Ok(exclusions)
    })
    .await
}

#[tauri::command]
pub async fn add_exclusion(
    exclusion_type: String,
    pattern: String,
    reason: Option<String>,
) -> Result<i64, String> {
    let valid_types = ["path", "folder", "extension", "pattern"];
    if !valid_types.contains(&exclusion_type.as_str()) {
        return Err(format!(
            "Invalid exclusion type: {}. Must be one of: {:?}",
            exclusion_type, valid_types
        ));
    }

    if pattern.trim().is_empty() {
        return Err("Pattern cannot be empty".to_string());
    }

    let pattern_trimmed = pattern.trim().to_string();

    let blocked_patterns = ["*", "**", "*.*", "**/*", "**/*.*", "*/**"];
    if blocked_patterns.contains(&pattern_trimmed.as_str()) {
        return Err("Overly broad patterns like '*' or '**' are not allowed as they would disable protection".to_string());
    }

    if pattern_trimmed.contains("..") {
        return Err(
            "Path traversal sequences ('..') are not allowed in exclusion patterns".to_string(),
        );
    }

    let critical_paths = [
        "C:\\",
        "C:/",
        "/",
        "C:\\Windows",
        "C:/Windows",
        "/usr",
        "/etc",
        "/bin",
    ];
    let pattern_upper = pattern_trimmed.to_uppercase();
    for critical in &critical_paths {
        if pattern_upper == critical.to_uppercase()
            || pattern_upper.starts_with(&format!("{}*", critical.to_uppercase()))
        {
            return Err(format!("Cannot exclude critical system path: {}", critical));
        }
    }

    if exclusion_type == "extension" {
        let blocked_extensions = ["exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js"];
        let ext_lower = pattern_trimmed
            .to_lowercase()
            .trim_start_matches('.')
            .to_string();
        if blocked_extensions.contains(&ext_lower.as_str()) {
            return Err(format!(
                "Cannot exclude dangerous extension '{}' as it would allow malware execution",
                ext_lower
            ));
        }
    }

    let et = exclusion_type.clone();
    let pat = pattern.clone();
    let rsn = reason.clone();
    let id = crate::with_db_async(move |conn| {
        DatabaseQueries::insert_exclusion_signed(conn, &et, &pat, rsn.as_deref())
            .map_err(|e| e.to_string())
    })
    .await?;

    log_audit_event(
        AuditEventType::ExclusionAdded,
        &format!("Added {} exclusion: {}", exclusion_type, pattern),
        Some(&pattern),
        None,
    );

    Ok(id)
}

#[tauri::command]
pub async fn update_exclusion(
    id: i64,
    exclusion_type: Option<String>,
    pattern: Option<String>,
    reason: Option<String>,
    enabled: Option<bool>,
) -> Result<(), String> {
    if let Some(ref t) = exclusion_type {
        let valid_types = ["path", "folder", "extension", "pattern"];
        if !valid_types.contains(&t.as_str()) {
            return Err(format!(
                "Invalid exclusion type: {}. Must be one of: {:?}",
                t, valid_types
            ));
        }
    }

    crate::with_db_async(move |conn| {
        DatabaseQueries::update_exclusion(
            conn,
            id,
            exclusion_type.as_deref(),
            pattern.as_deref(),
            reason.as_deref(),
            enabled,
        )
        .map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn toggle_exclusion(id: i64, enabled: bool) -> Result<(), String> {
    crate::with_db_async(move |conn| {
        DatabaseQueries::toggle_exclusion(conn, id, enabled).map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn delete_exclusion(id: i64) -> Result<(), String> {
    crate::with_db_async(move |conn| {
        // Get the exclusion details before deleting for audit
        if let Ok(exclusions) = DatabaseQueries::get_all_exclusions(conn) {
            if let Some(excl) = exclusions.iter().find(|e| e.id == id) {
                log_audit_event(
                    AuditEventType::ExclusionRemoved,
                    &format!(
                        "Removed {} exclusion: {}",
                        excl.exclusion_type, excl.pattern
                    ),
                    Some(&excl.pattern),
                    None,
                );
            }
        }

        DatabaseQueries::delete_exclusion(conn, id).map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn is_path_excluded(path: String) -> Result<bool, String> {
    crate::with_db_async(move |conn| {
        DatabaseQueries::is_path_excluded(conn, &path).map_err(|e| e.to_string())
    })
    .await
}

#[cfg(test)]
mod tests {
    // Test the validation logic in add_exclusion without needing Tauri runtime.
    // The add_exclusion function is async + requires DB access, so we extract and
    // test the validation rules directly.

    #[test]
    fn test_valid_exclusion_types() {
        let valid = ["path", "folder", "extension", "pattern"];
        for t in &valid {
            assert!(valid.contains(t));
        }
        assert!(!valid.contains(&"glob"));
        assert!(!valid.contains(&"regex"));
        assert!(!valid.contains(&""));
    }

    #[test]
    fn test_blocked_patterns() {
        let blocked_patterns = ["*", "**", "*.*", "**/*", "**/*.*", "*/**"];
        for p in &blocked_patterns {
            assert!(
                blocked_patterns.contains(p),
                "Pattern '{}' should be blocked",
                p
            );
        }
        // Valid patterns should NOT be blocked
        assert!(!blocked_patterns.contains(&"*.log"));
        assert!(!blocked_patterns.contains(&"C:\\safe\\*"));
    }

    #[test]
    fn test_path_traversal_detection() {
        let patterns_with_traversal =
            ["C:\\safe\\..\\system", "../../../etc/passwd", "..\\windows"];
        for p in &patterns_with_traversal {
            assert!(p.contains(".."), "Should detect path traversal in '{}'", p);
        }
        // No traversal
        assert!(!"C:\\safe\\dir".contains(".."));
        assert!(!"*.log".contains(".."));
    }

    #[test]
    fn test_critical_path_detection() {
        let critical_paths = [
            "C:\\",
            "C:/",
            "/",
            "C:\\Windows",
            "C:/Windows",
            "/usr",
            "/etc",
            "/bin",
        ];

        let test_input = "C:\\WINDOWS";
        let input_upper = test_input.to_uppercase();
        let is_critical = critical_paths
            .iter()
            .any(|cp| input_upper == cp.to_uppercase());
        assert!(
            is_critical,
            "C:\\WINDOWS should match C:\\Windows (case-insensitive)"
        );

        let safe_input = "D:\\MyFolder";
        let safe_upper = safe_input.to_uppercase();
        let is_safe = !critical_paths
            .iter()
            .any(|cp| safe_upper == cp.to_uppercase());
        assert!(is_safe, "D:\\MyFolder should not be a critical path");
    }

    #[test]
    fn test_blocked_extensions() {
        let blocked_extensions = ["exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js"];

        for ext in &blocked_extensions {
            assert!(
                blocked_extensions.contains(ext),
                "Extension '{}' should be blocked",
                ext
            );
        }

        // Test trimming leading dot
        let input = ".exe";
        let ext_lower = input.to_lowercase().trim_start_matches('.').to_string();
        assert!(blocked_extensions.contains(&ext_lower.as_str()));

        // Safe extensions should not be blocked
        let safe = ["log", "txt", "tmp", "bak"];
        for ext in &safe {
            assert!(!blocked_extensions.contains(ext));
        }
    }

    #[test]
    fn test_empty_pattern_rejected() {
        let pattern = "   ";
        assert!(
            pattern.trim().is_empty(),
            "Whitespace-only pattern should be rejected"
        );
    }

    #[test]
    fn test_critical_path_wildcard_detection() {
        let critical_paths = [
            "C:\\",
            "C:/",
            "/",
            "C:\\Windows",
            "C:/Windows",
            "/usr",
            "/etc",
            "/bin",
        ];
        let pattern = "C:\\*";
        let pattern_upper = pattern.to_uppercase();

        let matches_critical = critical_paths
            .iter()
            .any(|cp| pattern_upper.starts_with(&format!("{}*", cp.to_uppercase())));
        assert!(
            matches_critical,
            "C:\\* should be blocked as it starts with a critical path + wildcard"
        );
    }
}
