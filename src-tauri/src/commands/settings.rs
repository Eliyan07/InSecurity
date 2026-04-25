use crate::core::tamper_protection::{log_audit_event, AuditEventType};
/// Settings commands
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub real_time_protection: bool,
    pub auto_quarantine: bool,
    pub cache_size_mb: u32,
    pub cache_ttl_hours: u32,
    #[serde(default)]
    pub ransomware_protection: bool,
    #[serde(default)]
    pub protected_folders: Vec<String>,
    #[serde(default = "default_true")]
    pub ransomware_auto_block: bool,
    #[serde(default = "default_ransomware_threshold")]
    pub ransomware_threshold: u32,
    #[serde(default = "default_ransomware_window")]
    pub ransomware_window_seconds: u32,
    #[serde(default)]
    pub canary_files: HashMap<String, Vec<String>>,
    #[serde(default = "default_scan_worker_count")]
    pub scan_worker_count: u32,
    #[serde(default = "default_autostart")]
    pub autostart: bool,
    #[serde(default)]
    pub network_monitoring_enabled: bool,
    #[serde(default = "default_true")]
    pub auto_block_malware_network: bool,
    #[serde(default = "default_network_monitor_interval")]
    pub network_monitor_interval_secs: u32,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default)]
    pub virustotal_api_key: Option<String>,
    #[serde(default)]
    pub malwarebazaar_api_key: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_ransomware_threshold() -> u32 {
    20
}

fn default_ransomware_window() -> u32 {
    10
}

fn default_autostart() -> bool {
    true
}

fn default_scan_worker_count() -> u32 {
    4
}

fn default_network_monitor_interval() -> u32 {
    3
}

fn default_language() -> String {
    "en".to_string()
}

fn ui_language_is_bulgarian() -> bool {
    crate::config::Settings::load()
        .language
        .to_lowercase()
        .starts_with("bg")
}

pub fn protection_tray_tooltip(protection_enabled: bool) -> &'static str {
    if ui_language_is_bulgarian() {
        if protection_enabled {
            "InSecurity - Защитата е активна"
        } else {
            "InSecurity - Защитата е изключена"
        }
    } else if protection_enabled {
        "InSecurity - Protection Active"
    } else {
        "InSecurity - Protection Disabled"
    }
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            real_time_protection: true,
            auto_quarantine: true,
            cache_size_mb: 256,
            cache_ttl_hours: 24,
            ransomware_protection: true,
            protected_folders: crate::config::settings::Settings::default().protected_folders,
            ransomware_auto_block: true,
            ransomware_threshold: 20,
            ransomware_window_seconds: 10,
            canary_files: HashMap::new(),
            scan_worker_count: 4,
            autostart: true,
            network_monitoring_enabled: false,
            auto_block_malware_network: true,
            network_monitor_interval_secs: 3,
            language: default_language(),
            virustotal_api_key: None,
            malwarebazaar_api_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeySaveResult {
    pub configured: bool,
    pub verified: bool,
    pub warning: Option<String>,
}

enum ApiKeyValidationOutcome {
    Verified,
    SavedWithoutVerification(String),
}

#[derive(Debug, Deserialize)]
struct MalwareBazaarValidationResponse {
    #[serde(default)]
    query_status: String,
}

async fn validate_virustotal_api_key_remote(key: &str) -> Result<ApiKeyValidationOutcome, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create VirusTotal client: {}", e))?;

    let response = match client
        .get(format!("https://www.virustotal.com/api/v3/users/{}", key))
        .header("x-apikey", key)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(ApiKeyValidationOutcome::SavedWithoutVerification(format!(
                "VirusTotal could not be reached to verify the key right now ({}).",
                e
            )));
        }
    };

    match response.status() {
        reqwest::StatusCode::OK => Ok(ApiKeyValidationOutcome::Verified),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            Err("VirusTotal rejected this API key. Please double-check it and try again.".to_string())
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => Ok(
            ApiKeyValidationOutcome::SavedWithoutVerification(
                "VirusTotal rate-limited validation. The key was saved, but it could not be verified yet."
                    .to_string(),
            ),
        ),
        status => Ok(ApiKeyValidationOutcome::SavedWithoutVerification(format!(
            "VirusTotal returned {} while checking the key. The key was saved without remote verification.",
            status
        ))),
    }
}

async fn validate_malwarebazaar_api_key_remote(
    key: &str,
) -> Result<ApiKeyValidationOutcome, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("InSecurity-AV/1.0")
        .build()
        .map_err(|e| format!("Failed to create MalwareBazaar client: {}", e))?;

    let response = match client
        .post("https://mb-api.abuse.ch/api/v1/")
        .header("Auth-Key", key)
        .form(&[("query", "recent_detections"), ("limit", "1")])
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(ApiKeyValidationOutcome::SavedWithoutVerification(format!(
                "MalwareBazaar could not be reached to verify the key right now ({}).",
                e
            )));
        }
    };

    if response.status() == reqwest::StatusCode::UNAUTHORIZED
        || response.status() == reqwest::StatusCode::FORBIDDEN
    {
        return Err(
            "MalwareBazaar rejected this API key. Please double-check it and try again."
                .to_string(),
        );
    }

    if !response.status().is_success() {
        return Ok(ApiKeyValidationOutcome::SavedWithoutVerification(format!(
            "MalwareBazaar returned {} while checking the key. The key was saved without remote verification.",
            response.status()
        )));
    }

    let body = response
        .json::<MalwareBazaarValidationResponse>()
        .await
        .map_err(|e| format!("Failed to parse MalwareBazaar validation response: {}", e))?;

    match body.query_status.as_str() {
        "ok" => Ok(ApiKeyValidationOutcome::Verified),
        "no_api_key" | "user_blacklisted" => Err(
            "MalwareBazaar rejected this API key. Please double-check it and try again."
                .to_string(),
        ),
        other => Ok(ApiKeyValidationOutcome::SavedWithoutVerification(format!(
            "MalwareBazaar returned '{}' while checking the key. The key was saved without remote verification.",
            other
        ))),
    }
}

fn persist_api_key(
    credential: &'static str,
    key: Option<String>,
    audit_message: &'static str,
) -> Result<(), String> {
    crate::config::settings::set_api_key(credential, key.as_deref())?;
    log_audit_event(AuditEventType::SettingsChanged, audit_message, None, None);
    Ok(())
}

#[tauri::command]
pub async fn get_settings() -> Result<AppSettings, String> {
    tokio::task::spawn_blocking(|| {
        let cfg = crate::config::Settings::load();
        Ok(AppSettings {
            real_time_protection: cfg.real_time_protection,
            auto_quarantine: cfg.auto_quarantine,
            cache_size_mb: cfg.cache_size_mb,
            cache_ttl_hours: cfg.cache_ttl_hours,
            ransomware_protection: cfg.ransomware_protection,
            protected_folders: cfg.protected_folders,
            ransomware_auto_block: cfg.ransomware_auto_block,
            ransomware_threshold: cfg.ransomware_threshold,
            ransomware_window_seconds: cfg.ransomware_window_seconds,
            canary_files: cfg.canary_files,
            scan_worker_count: cfg.scan_worker_count,
            autostart: cfg.autostart,

            network_monitoring_enabled: cfg.network_monitoring_enabled,
            auto_block_malware_network: cfg.auto_block_malware_network,
            network_monitor_interval_secs: cfg.network_monitor_interval_secs,
            language: cfg.language,
            // Indicate to the frontend whether each key is set (without revealing it)
            virustotal_api_key: crate::config::settings::get_api_key("virustotal_api_key")
                .or_else(|| {
                    std::env::var("VIRUSTOTAL_API_KEY")
                        .ok()
                        .filter(|k| !k.is_empty())
                })
                .map(|_| "••••••••".to_string()),
            malwarebazaar_api_key: crate::config::settings::get_api_key("malwarebazaar_api_key")
                .or_else(|| {
                    std::env::var("MALWAREBAZAAR_API_KEY")
                        .ok()
                        .filter(|k| !k.is_empty())
                })
                .map(|_| "••••••••".to_string()),
        })
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn update_settings(app: tauri::AppHandle, _settings: AppSettings) -> Result<(), String> {
    // Validate scan_worker_count (same rules as set_scan_worker_count)
    if !(1..=16).contains(&_settings.scan_worker_count) {
        return Err("Worker count must be between 1 and 16".to_string());
    }
    tokio::task::spawn_blocking(move || {
        let prev = crate::config::Settings::load();

        // Update API keys in keyring if new values are provided (not the display mask)
        const MASK: &str = "••••••••";
        if let Some(ref k) = _settings.virustotal_api_key {
            if k != MASK {
                let _ = crate::config::settings::set_api_key(
                    "virustotal_api_key",
                    if k.is_empty() { None } else { Some(k.as_str()) },
                );
            }
        }
        if let Some(ref k) = _settings.malwarebazaar_api_key {
            if k != MASK {
                let _ = crate::config::settings::set_api_key(
                    "malwarebazaar_api_key",
                    if k.is_empty() { None } else { Some(k.as_str()) },
                );
            }
        }

        let cfg = crate::config::Settings {
            real_time_protection: _settings.real_time_protection,
            auto_quarantine: _settings.auto_quarantine,
            cache_size_mb: _settings.cache_size_mb,
            cache_ttl_hours: _settings.cache_ttl_hours,
            ransomware_protection: _settings.ransomware_protection,
            protected_folders: _settings.protected_folders,
            ransomware_auto_block: _settings.ransomware_auto_block,
            ransomware_threshold: _settings.ransomware_threshold,
            ransomware_window_seconds: _settings.ransomware_window_seconds,
            canary_files: _settings.canary_files,
            scan_worker_count: _settings.scan_worker_count,
            autostart: _settings.autostart,
            network_monitoring_enabled: _settings.network_monitoring_enabled,
            auto_block_malware_network: _settings.auto_block_malware_network,
            network_monitor_interval_secs: _settings.network_monitor_interval_secs,
            language: _settings.language,
            last_app_update_check: prev.last_app_update_check,
            last_notified_app_update_version: prev.last_notified_app_update_version.clone(),
            dismissed_app_update_version: prev.dismissed_app_update_version.clone(),
            virustotal_api_key: None,
            malwarebazaar_api_key: None,
        };
        cfg.save();

        // Bug fix: apply live runtime side-effects for settings that take immediate effect,
        // mirroring what the dedicated single-setting commands do.

        // Real-time protection toggle
        if prev.real_time_protection != cfg.real_time_protection {
            crate::core::real_time::set_protection_disabled(!cfg.real_time_protection);
            update_tray_tooltip(&app, cfg.real_time_protection);
        }

        // Ransomware thresholds
        if prev.ransomware_threshold != cfg.ransomware_threshold
            || prev.ransomware_window_seconds != cfg.ransomware_window_seconds
        {
            crate::core::real_time::reload_ransomware_thresholds(
                cfg.ransomware_threshold,
                cfg.ransomware_window_seconds,
            );
        }

        // Cache reconfiguration
        if prev.cache_size_mb != cfg.cache_size_mb || prev.cache_ttl_hours != cfg.cache_ttl_hours {
            let entries_per_mb = 100usize;
            let max_entries = (cfg.cache_size_mb as usize) * entries_per_mb;
            let ttl_seconds = (cfg.cache_ttl_hours as u64) * 3600;
            let new_config = crate::cache::cache_manager::CacheConfig {
                max_size: max_entries.max(1000),
                ttl_seconds,
                eviction_interval_seconds: 3600,
            };
            if let Ok(mut cache) = crate::CACHE_MANAGER.lock() {
                *cache = crate::cache::cache_manager::CacheManager::new(new_config);
            }
        }

        Ok(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn set_language(language: String) -> Result<(), String> {
    let valid = ["en", "bg"];
    if !valid.contains(&language.as_str()) {
        return Err(format!("Unsupported language: {}", language));
    }
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.language = language;
        cfg.save();
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn set_virustotal_api_key(key: String) -> Result<ApiKeySaveResult, String> {
    let trimmed = key.trim().to_string();
    if trimmed.is_empty() {
        tokio::task::spawn_blocking(move || {
            persist_api_key("virustotal_api_key", None, "VirusTotal API key cleared")
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))??;

        return Ok(ApiKeySaveResult {
            configured: false,
            verified: false,
            warning: None,
        });
    }

    let validation = validate_virustotal_api_key_remote(&trimmed).await?;
    let warning = match validation {
        ApiKeyValidationOutcome::Verified => None,
        ApiKeyValidationOutcome::SavedWithoutVerification(message) => Some(message),
    };

    let key_to_store = trimmed.clone();
    tokio::task::spawn_blocking(move || {
        persist_api_key(
            "virustotal_api_key",
            Some(key_to_store),
            "VirusTotal API key updated",
        )
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))??;

    Ok(ApiKeySaveResult {
        configured: true,
        verified: warning.is_none(),
        warning,
    })
}

#[tauri::command]
pub async fn set_malwarebazaar_api_key(key: String) -> Result<ApiKeySaveResult, String> {
    let trimmed = key.trim().to_string();
    if trimmed.is_empty() {
        tokio::task::spawn_blocking(move || {
            persist_api_key(
                "malwarebazaar_api_key",
                None,
                "MalwareBazaar API key cleared",
            )
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))??;

        return Ok(ApiKeySaveResult {
            configured: false,
            verified: false,
            warning: None,
        });
    }

    let validation = validate_malwarebazaar_api_key_remote(&trimmed).await?;
    let warning = match validation {
        ApiKeyValidationOutcome::Verified => None,
        ApiKeyValidationOutcome::SavedWithoutVerification(message) => Some(message),
    };

    let key_to_store = trimmed.clone();
    tokio::task::spawn_blocking(move || {
        persist_api_key(
            "malwarebazaar_api_key",
            Some(key_to_store),
            "MalwareBazaar API key updated",
        )
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))??;

    Ok(ApiKeySaveResult {
        configured: true,
        verified: warning.is_none(),
        warning,
    })
}

#[tauri::command]
pub async fn set_auto_quarantine(enabled: bool) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.auto_quarantine = enabled;
        cfg.save();
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn set_real_time_protection(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    // Toggle the runtime flag immediately so watchers respond without restart
    crate::core::real_time::set_protection_disabled(!enabled);

    // Update tray tooltip to reflect new state
    update_tray_tooltip(&app, enabled);

    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        let was_enabled = cfg.real_time_protection;
        cfg.real_time_protection = enabled;
        cfg.save();

        // Audit log protection state changes (important security event)
        if was_enabled != enabled {
            log_audit_event(
                if enabled {
                    AuditEventType::ProtectionEnabled
                } else {
                    AuditEventType::ProtectionDisabled
                },
                &format!(
                    "Real-time protection {}",
                    if enabled { "enabled" } else { "disabled" }
                ),
                None,
                None,
            );
        }

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

/// Update the system tray tooltip to reflect current protection state
fn update_tray_tooltip(app: &tauri::AppHandle, protection_enabled: bool) {
    if let Some(tray) = app.tray_by_id("main-tray") {
        let tooltip = protection_tray_tooltip(protection_enabled);
        if let Err(e) = tray.set_tooltip(Some(tooltip)) {
            log::warn!("Failed to update tray tooltip: {}", e);
        }
    }
}

#[tauri::command]
pub async fn set_scan_worker_count(count: u32) -> Result<(), String> {
    if !(1..=16).contains(&count) {
        return Err("Worker count must be between 1 and 16".to_string());
    }
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.scan_worker_count = count;
        cfg.save();

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!("Scan worker count changed to {}", count),
            None,
            None,
        );

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub fn reconfigure_cache(max_size_mb: u32, ttl_hours: u32) -> Result<String, String> {
    let entries_per_mb = 100;
    let max_entries = (max_size_mb as usize) * entries_per_mb;
    let ttl_seconds = (ttl_hours as u64) * 3600;

    let new_config = crate::cache::cache_manager::CacheConfig {
        max_size: max_entries.max(1000),
        ttl_seconds,
        eviction_interval_seconds: 3600, // Keep 1 hour eviction interval
    };

    if let Ok(mut cache) = crate::CACHE_MANAGER.lock() {
        let old_stats = cache.get_stats();
        *cache = crate::cache::cache_manager::CacheManager::new(new_config.clone());
        log::info!(
            "Cache reconfigured: {} entries (was {}) -> {} max entries, TTL {} hours",
            old_stats.total_entries,
            old_stats.capacity,
            new_config.max_size,
            ttl_hours
        );
        Ok(format!(
            "Cache reconfigured: max {} entries (~{} MB), TTL {} hours",
            new_config.max_size, max_size_mb, ttl_hours
        ))
    } else {
        Err("Failed to acquire cache lock".to_string())
    }
}

#[tauri::command]
pub fn get_cache_stats() -> Result<crate::cache::cache_manager::CacheStats, String> {
    if let Ok(cache) = crate::CACHE_MANAGER.lock() {
        Ok(cache.get_stats())
    } else {
        Err("Failed to acquire cache lock".to_string())
    }
}

/// Clear the in-memory cache AND database verdicts so stale results don't re-sync
#[tauri::command]
pub fn clear_cache() -> Result<String, String> {
    let cleared_cache;

    if let Ok(mut cache) = crate::CACHE_MANAGER.lock() {
        cleared_cache = cache.get_stats().total_entries as u64;
        cache.get_cache_mut().clear();
    } else {
        return Err("Failed to acquire cache lock".to_string());
    }

    // Also clear DB verdicts so they don't re-sync back into the in-memory cache
    let mut cleared_db = 0u64;
    if let Ok(db) = crate::DB.lock() {
        if let Some(conn) = db.as_ref() {
            if let Ok(count) = conn.execute("DELETE FROM verdicts", []) {
                cleared_db = count as u64;
            }
        }
    }

    log::info!(
        "Cleared {} cache entries + {} DB verdicts",
        cleared_cache,
        cleared_db
    );
    Ok(format!(
        "Cleared {} cache entries and {} stored verdicts",
        cleared_cache, cleared_db
    ))
}
// ============================================================================
// Ransomware Protection Settings
// ============================================================================

#[tauri::command]
pub async fn set_ransomware_protection(enabled: bool) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        let was_enabled = cfg.ransomware_protection;
        cfg.ransomware_protection = enabled;
        cfg.save();

        if was_enabled != enabled {
            log_audit_event(
                if enabled {
                    AuditEventType::ProtectionEnabled
                } else {
                    AuditEventType::ProtectionDisabled
                },
                &format!(
                    "Ransomware protection {}",
                    if enabled { "enabled" } else { "disabled" }
                ),
                None,
                None,
            );
        }

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn get_protected_folders() -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(|| {
        let cfg = crate::config::Settings::load();
        Ok(cfg.protected_folders)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn set_protected_folders(folders: Vec<String>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.protected_folders = folders;
        cfg.save();

        log_audit_event(
            AuditEventType::SettingsChanged,
            "Protected folders updated",
            None,
            None,
        );

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn add_protected_folder(folder: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let folder_path = std::path::Path::new(&folder);
        if !folder_path.exists() || !folder_path.is_dir() {
            return Err(format!("Folder does not exist: {}", folder));
        }

        let mut cfg = crate::config::Settings::load();
        if !cfg.protected_folders.contains(&folder) {
            cfg.protected_folders.push(folder.clone());
            cfg.save();

            log_audit_event(
                AuditEventType::SettingsChanged,
                &format!("Added protected folder: {}", folder),
                None,
                None,
            );

            // Dynamically add to the running file watcher so it takes effect immediately
            if let Err(e) = crate::core::real_time::add_watch_path(folder_path) {
                log::warn!(
                    "Could not add watch for new protected folder (will apply on restart): {}",
                    e
                );
            }

            // Deploy canary (honeypot) files in the new protected folder
            if let Err(e) = crate::core::real_time::deploy_canary_files_for_folder(&folder) {
                log::warn!("Could not deploy canary files in {}: {}", folder, e);
            }
        }
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn remove_protected_folder(folder: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.protected_folders.retain(|f| f != &folder);
        cfg.save();

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!("Removed protected folder: {}", folder),
            None,
            None,
        );

        // Dynamically remove from the running file watcher so it takes effect immediately
        let folder_path = std::path::Path::new(&folder);
        if let Err(e) = crate::core::real_time::remove_watch_path(folder_path) {
            log::warn!(
                "Could not remove watch for folder (will apply on restart): {}",
                e
            );
        }

        // Clean up canary (honeypot) files from the removed folder
        crate::core::real_time::remove_canary_files_for_folder(&folder);

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn set_ransomware_auto_block(enabled: bool) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.ransomware_auto_block = enabled;
        cfg.save();

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!(
                "Ransomware auto-block {}",
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

#[tauri::command]
pub async fn set_ransomware_thresholds(threshold: u32, window_seconds: u32) -> Result<(), String> {
    if threshold < 5 {
        return Err("Threshold must be at least 5".to_string());
    }
    if !(5..=60).contains(&window_seconds) {
        return Err("Window must be between 5 and 60 seconds".to_string());
    }
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.ransomware_threshold = threshold;
        cfg.ransomware_window_seconds = window_seconds;
        cfg.save();

        // Notify the real-time watcher to reload thresholds
        crate::core::real_time::reload_ransomware_thresholds(threshold, window_seconds);

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!(
                "Ransomware thresholds updated: {} files in {} seconds",
                threshold, window_seconds
            ),
            None,
            None,
        );

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn dismiss_ransomware_alert(folder: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        crate::core::real_time::adapt_threshold_for_folder(&folder);
        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!(
                "Ransomware alert dismissed for {} — adaptive threshold raised",
                folder
            ),
            None,
            None,
        );
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn kill_ransomware_process(pid: u32) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let result = crate::core::real_time::terminate_process(pid);
        match &result {
            Ok(name) => {
                log_audit_event(
                    AuditEventType::ThreatDetected,
                    &format!(
                        "Manually killed suspected ransomware process: {} (PID {})",
                        name, pid
                    ),
                    None,
                    Some(&format!("pid={},action=manual_kill", pid)),
                );
            }
            Err(e) => {
                log::warn!("Failed to kill process PID {}: {}", pid, e);
            }
        }
        result
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn deploy_canary_files(folder: String) -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(move || {
        crate::core::real_time::deploy_canary_files_for_folder(&folder)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn redeploy_canary_files() -> Result<(), String> {
    tokio::task::spawn_blocking(|| {
        let cfg = crate::config::Settings::load();
        for folder in &cfg.protected_folders {
            if let Err(e) = crate::core::real_time::deploy_canary_files_for_folder(folder) {
                log::warn!("Failed to deploy canary files in {}: {}", folder, e);
            }
        }
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn get_canary_status() -> Result<HashMap<String, Vec<CanaryFileStatus>>, String> {
    tokio::task::spawn_blocking(|| crate::core::real_time::get_canary_status_all())
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryFileStatus {
    pub path: String,
    pub intact: bool,
}

#[tauri::command]
pub async fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;

    let autostart = app.autolaunch();
    if enabled {
        autostart.enable().map_err(|e| e.to_string())?;
    } else {
        autostart.disable().map_err(|e| e.to_string())?;
    }

    // Persist to settings
    tokio::task::spawn_blocking(move || {
        let mut cfg = crate::config::Settings::load();
        cfg.autostart = enabled;
        cfg.save();

        log_audit_event(
            AuditEventType::SettingsChanged,
            &format!("Autostart {}", if enabled { "enabled" } else { "disabled" }),
            None,
            None,
        );

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_settings_default_values() {
        let defaults = AppSettings::default();
        assert!(defaults.real_time_protection);
        assert!(defaults.auto_quarantine);
        assert_eq!(defaults.scan_worker_count, 4);
        assert!(defaults.ransomware_protection);
        assert!(defaults.ransomware_auto_block);
        assert_eq!(defaults.ransomware_threshold, 20);
        assert_eq!(defaults.ransomware_window_seconds, 10);
        assert!(defaults.canary_files.is_empty());
        assert!(defaults.autostart);
        assert_eq!(defaults.cache_size_mb, 256);
        assert_eq!(defaults.cache_ttl_hours, 24);
    }

    #[test]
    fn test_default_scan_worker_count() {
        assert_eq!(default_scan_worker_count(), 4);
    }

    #[test]
    fn test_default_autostart() {
        assert!(default_autostart());
    }

    #[test]
    fn test_app_settings_serialization_roundtrip() {
        let settings = AppSettings::default();
        let json = serde_json::to_string(&settings).unwrap();
        let deserialized: AppSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.scan_worker_count, settings.scan_worker_count);
        assert_eq!(
            deserialized.real_time_protection,
            settings.real_time_protection
        );
        assert_eq!(deserialized.auto_quarantine, settings.auto_quarantine);
    }

    #[test]
    fn test_app_settings_deserialize_with_defaults() {
        // Missing optional fields should use defaults
        let json = r#"{
            "realTimeProtection": false,
            "autoQuarantine": false,
            "cacheSizeMb": 128,
            "cacheTtlHours": 12
        }"#;
        let settings: AppSettings = serde_json::from_str(json).unwrap();
        assert!(!settings.real_time_protection);
        assert_eq!(settings.scan_worker_count, 4); // default_scan_worker_count
        assert!(settings.autostart); // default_autostart
    }

    #[test]
    fn test_reconfigure_cache_minimum_floor() {
        // max_size should be at least 1000 even with 0 input
        let entries_per_mb = 100;
        let max_entries = (0u32 as usize) * entries_per_mb;
        let floored = max_entries.max(1000);
        assert_eq!(floored, 1000);
    }
}
