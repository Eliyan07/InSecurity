/// Network security commands — network monitor, firewall
use crate::core::tamper_protection::{log_audit_event, AuditEventType};
use crate::database::models::{FirewallRule, NetworkEvent, NetworkThreat};
use crate::database::queries::DatabaseQueries;

// =========================================================================
// Network Monitor commands
// =========================================================================

#[tauri::command]
pub async fn get_active_connections(
) -> Result<Vec<crate::core::network_monitor::ActiveConnection>, String> {
    tokio::task::spawn_blocking(|| Ok(crate::core::network_monitor::get_active_connections()))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn get_network_events(limit: Option<u32>) -> Result<Vec<NetworkEvent>, String> {
    let lim = limit.unwrap_or(200);
    crate::with_db_async(move |conn| {
        DatabaseQueries::get_network_events(conn, lim).map_err(|e| format!("DB error: {}", e))
    })
    .await
}

#[tauri::command]
pub async fn get_network_threats(limit: Option<u32>) -> Result<Vec<NetworkThreat>, String> {
    let lim = limit.unwrap_or(200);
    crate::with_db_async(move |conn| {
        DatabaseQueries::get_network_threats(conn, lim).map_err(|e| format!("DB error: {}", e))
    })
    .await
}

#[tauri::command]
pub async fn set_network_monitoring(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let was = crate::core::network_monitor::is_monitor_enabled();
    crate::core::network_monitor::set_monitor_enabled(enabled);

    // If turning on for the first time this session, spawn the background thread
    if enabled && !was {
        crate::core::network_monitor::start_network_monitor(app);
    }

    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.network_monitoring_enabled = enabled;
        cfg.save();

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!(
                "Network monitoring {}",
                if enabled { "enabled" } else { "disabled" }
            ),
            None,
            None,
        );
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

// =========================================================================
// Firewall commands
// =========================================================================

#[tauri::command]
pub async fn get_firewall_rules() -> Result<Vec<FirewallRule>, String> {
    crate::with_db_async(|conn| {
        DatabaseQueries::get_firewall_rules(conn).map_err(|e| format!("DB error: {}", e))
    })
    .await
}

#[tauri::command]
pub async fn add_firewall_rule(path: String, direction: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let rule_name = crate::core::firewall::add_block_rule(&path, &direction)?;

        // Persist to DB using the migration-created schema
        let rule = FirewallRule {
            id: 0,
            rule_name: rule_name.clone(),
            executable_path: path.clone(),
            direction: direction.clone(),
            action: "block".to_string(),
            reason: Some("User-created rule".to_string()),
            auto_created: false,
            enabled: true,
            created_at: chrono::Utc::now().timestamp(),
        };
        crate::with_db(|conn| {
            if let Err(e) = DatabaseQueries::insert_firewall_rule(conn, &rule) {
                log::error!("Failed to persist firewall rule to DB: {}", e);
            }
            Some(())
        });

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!("Firewall rule created: {}", rule_name),
            None,
            None,
        );
        Ok(rule_name)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn remove_firewall_rule(id: i64) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let rule_name = crate::with_db_result::<String, String, _>(|conn| {
            DatabaseQueries::remove_firewall_rule_by_id(conn, id)
                .map_err(|e| format!("DB error: {}", e))
        })?;

        // Best-effort remove from Windows Firewall
        let _ = crate::core::firewall::remove_rule(&rule_name);

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!("Firewall rule removed: {}", rule_name),
            None,
            None,
        );
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn toggle_firewall_rule(id: i64) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || {
        let (rule_name, new_enabled) =
            crate::with_db_result::<(String, bool), String, _>(|conn| {
                DatabaseQueries::toggle_firewall_rule(conn, id)
                    .map_err(|e| format!("DB error: {}", e))
            })?;

        // Sync enable/disable in Windows Firewall
        let _ = crate::core::firewall::set_rule_enabled(&rule_name, new_enabled);

        Ok(new_enabled)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn set_auto_block_malware(enabled: bool) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.auto_block_malware_network = enabled;
        cfg.save();

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!(
                "Auto-block malware network access {}",
                if enabled { "enabled" } else { "disabled" }
            ),
            None,
            None,
        );
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}
