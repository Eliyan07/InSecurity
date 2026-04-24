//! Windows Firewall Management
//! Creates and manages Windows Firewall block rules via `netsh advfirewall`
//! to prevent malware processes from communicating over the network.

use std::path::Path;
use std::process::Command;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use tauri::Emitter;

/// All rules created by this module are prefixed so they can be identified
/// and enumerated without colliding with user-created rules.
const RULE_PREFIX: &str = "Insecurity_Block_";

// ─── Public API ──────────────────────────────────────────────────────────────

/// Create a Windows Firewall block rule for the given executable.
///
/// * `exe_path`  - Full path to the executable to block.
/// * `direction` - `"in"`, `"out"`, or `"both"`.
///
/// Returns the generated rule name on success.
pub fn add_block_rule(exe_path: &str, direction: &str) -> Result<String, String> {
    let path = Path::new(exe_path);
    if !path.exists() {
        return Err(format!("Executable path does not exist: {}", exe_path));
    }

    let timestamp = chrono::Utc::now().timestamp();
    let unique_input = format!("{}|{}", exe_path, timestamp);
    let hash_suffix = sha2_short(&unique_input);
    let rule_name = format!("{}{}", RULE_PREFIX, hash_suffix);

    // Determine which directions to create rules for
    let directions: Vec<&str> = match direction.to_lowercase().as_str() {
        "in" => vec!["in"],
        "out" => vec!["out"],
        "both" => vec!["in", "out"],
        _ => vec!["out"], // default to outbound block
    };

    for dir in &directions {
        let suffix = if directions.len() > 1 {
            format!("{}_{}", rule_name, dir)
        } else {
            rule_name.clone()
        };

        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", suffix),
                &format!("dir={}", dir),
                "action=block",
                &format!("program={}", exe_path),
                "enable=yes",
            ])
            .output()
            .map_err(|e| format!("Failed to execute netsh: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "netsh add rule failed (dir={}): {}",
                dir,
                stderr.trim()
            ));
        }
    }

    log::info!(
        "Firewall block rule created: {} (exe={}, dir={})",
        rule_name,
        exe_path,
        direction
    );
    Ok(rule_name)
}

/// Remove a firewall rule by name.
/// Also attempts to remove the `{name}_in` / `{name}_out` variants
/// that are created when direction is "both".
pub fn remove_rule(rule_name: &str) -> Result<(), String> {
    run_netsh_delete(rule_name)?;

    // Try removing directional variants (ignore errors if they don't exist)
    let _ = run_netsh_delete(&format!("{}_in", rule_name));
    let _ = run_netsh_delete(&format!("{}_out", rule_name));

    log::info!("Firewall rule removed: {}", rule_name);
    Ok(())
}

/// Enable or disable an existing firewall rule.
pub fn set_rule_enabled(rule_name: &str, enabled: bool) -> Result<(), String> {
    let enable_str = if enabled { "yes" } else { "no" };

    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "set",
            "rule",
            &format!("name={}", rule_name),
            "new",
            &format!("enable={}", enable_str),
        ])
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Also try directional variants
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "set",
                "rule",
                &format!("name={}_in", rule_name),
                "new",
                &format!("enable={}", enable_str),
            ])
            .output();
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "set",
                "rule",
                &format!("name={}_out", rule_name),
                "new",
                &format!("enable={}", enable_str),
            ])
            .output();

        // If the base name failed, warn but don't hard-error
        // (one of the variants may have succeeded)
        log::warn!(
            "netsh set rule warning for {}: {}",
            rule_name,
            stderr.trim()
        );
    }

    log::info!(
        "Firewall rule {} {}",
        rule_name,
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

/// Automatically block a process that was identified as a threat.
/// Creates an outbound block rule, marks it as auto-created, emits
/// a front-end event, and logs an audit entry.
pub fn auto_block_process(
    exe_path: &str,
    threat_name: &str,
    app: &AppHandle,
) -> Result<String, String> {
    let reason = format!("Auto-blocked: {}", threat_name);
    let rule_name = add_block_rule(exe_path, "out")?;

    // Persist to DB as auto-created
    use crate::database::models::FirewallRule;
    use crate::database::queries::DatabaseQueries;
    let rule = FirewallRule {
        id: 0,
        rule_name: rule_name.clone(),
        executable_path: exe_path.to_string(),
        direction: "out".to_string(),
        action: "block".to_string(),
        reason: Some(reason.clone()),
        auto_created: true,
        enabled: true,
        created_at: chrono::Utc::now().timestamp(),
    };
    crate::with_db(|conn| {
        let _ = DatabaseQueries::insert_firewall_rule(conn, &rule);
        Some(())
    });

    // Emit event so the front-end can show a notification
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FirewallRuleCreated {
        rule_name: String,
        exe_path: String,
        threat_name: String,
    }

    let event = FirewallRuleCreated {
        rule_name: rule_name.clone(),
        exe_path: exe_path.to_string(),
        threat_name: threat_name.to_string(),
    };

    if let Err(e) = app.emit("firewall_rule_created", &event) {
        log::warn!("Failed to emit firewall_rule_created event: {}", e);
    }

    // Audit log
    crate::core::tamper_protection::log_audit_event(
        crate::core::tamper_protection::AuditEventType::ThreatDetected,
        &format!(
            "Auto-blocked network access for '{}': {}",
            exe_path, threat_name
        ),
        Some(exe_path),
        None,
    );

    log::info!(
        "Auto-blocked process {} (rule={}, threat={})",
        exe_path,
        rule_name,
        threat_name
    );
    Ok(rule_name)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Run `netsh advfirewall firewall delete rule name=<name>`.
fn run_netsh_delete(name: &str) -> Result<(), String> {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", name),
        ])
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("netsh delete rule failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Compute a short (12 hex char) fingerprint from an input string
/// using SHA-256. Deterministic for the same input.
fn sha2_short(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    // Take first 6 bytes = 12 hex chars
    hash.iter().take(6).map(|b| format!("{:02x}", b)).collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha2_short_deterministic() {
        let a = sha2_short("test input");
        let b = sha2_short("test input");
        assert_eq!(a, b);
        assert_eq!(a.len(), 12); // 6 bytes = 12 hex chars
    }

    #[test]
    fn test_sha2_short_different_inputs() {
        let a = sha2_short("input_a");
        let b = sha2_short("input_b");
        assert_ne!(a, b);
    }

    #[test]
    fn test_rule_name_generation() {
        let hash = sha2_short("C:\\malware.exe|1700000000");
        let rule_name = format!("{}{}", RULE_PREFIX, hash);
        assert!(rule_name.starts_with("Insecurity_Block_"));
        assert_eq!(rule_name.len(), RULE_PREFIX.len() + 12);
    }

    #[test]
    fn test_sha2_short_hex_only() {
        let result = sha2_short("anything");
        assert!(
            result.chars().all(|c| c.is_ascii_hexdigit()),
            "Expected only hex chars, got: {}",
            result
        );
    }
}
