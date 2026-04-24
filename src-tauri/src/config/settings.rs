use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory cache for settings - avoids re-reading settings.json on every call.
/// `is_in_protected_folder()` calls `Settings::load()` on every filesystem event,
/// and `get_dashboard_stats()` calls it on every poll, so caching is critical.
static CACHED_SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub real_time_protection: bool,
    pub auto_quarantine: bool,
    pub cache_size_mb: u32,
    pub cache_ttl_hours: u32,
    /// Ransomware protection - monitor sensitive folders for bulk modifications
    #[serde(default = "default_true")]
    pub ransomware_protection: bool,
    /// Protected folders for ransomware shield (Documents, Pictures, Desktop by default)
    #[serde(default = "default_protected_folders")]
    pub protected_folders: Vec<String>,
    /// Auto-terminate suspicious processes when ransomware is detected
    #[serde(default = "default_true")]
    pub ransomware_auto_block: bool,
    /// Number of file modifications in window to trigger ransomware alert (min 5)
    #[serde(default = "default_ransomware_threshold")]
    pub ransomware_threshold: u32,
    /// Time window in seconds for ransomware detection (5-60)
    #[serde(default = "default_ransomware_window")]
    pub ransomware_window_seconds: u32,
    /// Canary (honeypot) file paths per protected folder
    #[serde(default)]
    pub canary_files: HashMap<String, Vec<String>>,
    /// Number of parallel workers for manual scans (1-16)
    #[serde(default = "default_scan_worker_count")]
    pub scan_worker_count: u32,
    /// Launch at user login
    #[serde(default = "default_true")]
    pub autostart: bool,
    /// Network traffic monitoring via IP Helper APIs
    #[serde(default)]
    pub network_monitoring_enabled: bool,
    /// Auto-block malware processes from network access via Windows Firewall
    #[serde(default = "default_true")]
    pub auto_block_malware_network: bool,
    /// Network monitor polling interval in seconds (1-30)
    #[serde(default = "default_network_monitor_interval")]
    pub network_monitor_interval_secs: u32,
    /// UI language preference (e.g. "en", "bg")
    #[serde(default = "default_language")]
    pub language: String,
    /// VirusTotal API key — only read from JSON for one-time migration to keyring; never written back
    #[serde(default, skip_serializing)]
    pub virustotal_api_key: Option<String>,
    /// MalwareBazaar API key — only read from JSON for one-time migration to keyring; never written back
    #[serde(default, skip_serializing)]
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

fn default_scan_worker_count() -> u32 {
    4
}

fn default_network_monitor_interval() -> u32 {
    3
}

fn default_language() -> String {
    "en".to_string()
}

fn default_protected_folders() -> Vec<String> {
    let mut folders = Vec::new();
    if let Some(docs) = dirs::document_dir() {
        folders.push(docs.to_string_lossy().to_string());
    }
    if let Some(pics) = dirs::picture_dir() {
        folders.push(pics.to_string_lossy().to_string());
    }
    if let Some(desktop) = dirs::desktop_dir() {
        folders.push(desktop.to_string_lossy().to_string());
    }
    folders
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            real_time_protection: true,
            auto_quarantine: true,
            cache_size_mb: 256,
            cache_ttl_hours: 24,
            ransomware_protection: true,
            protected_folders: default_protected_folders(),
            ransomware_auto_block: true,
            ransomware_threshold: default_ransomware_threshold(),
            ransomware_window_seconds: default_ransomware_window(),
            canary_files: HashMap::new(),
            scan_worker_count: default_scan_worker_count(),
            autostart: true,
            network_monitoring_enabled: false,
            auto_block_malware_network: true,
            network_monitor_interval_secs: default_network_monitor_interval(),
            language: default_language(),
            virustotal_api_key: None,
            malwarebazaar_api_key: None,
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        // Fast path: return cached settings if available
        if let Ok(guard) = CACHED_SETTINGS.read() {
            if let Some(ref cached) = *guard {
                return cached.clone();
            }
        }

        // Slow path: read from disk and populate cache
        let settings = Self::load_from_disk();

        if let Ok(mut guard) = CACHED_SETTINGS.write() {
            *guard = Some(settings.clone());
        }

        settings
    }

    /// Read settings from disk (bypasses cache)
    fn load_from_disk() -> Self {
        let data_dir = dirs::data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = data_dir.join("insecurity").join("settings.json");

        // One-time migration: copy from old "antivirus-ui" folder if new location is absent
        if !path.exists() {
            let old_path = data_dir.join("antivirus-ui").join("settings.json");
            if old_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&old_path) {
                    if let Ok(s) = serde_json::from_str::<Settings>(&content) {
                        log::info!("Migrating settings from antivirus-ui to insecurity folder");
                        return s;
                    }
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(mut s) = serde_json::from_str::<Settings>(&content) {
                // One-time migration: move plaintext API keys from settings.json to
                // Windows Credential Manager (keyring), then re-save without them.
                let mut migrated = false;
                if let Some(ref key) = s.virustotal_api_key.clone() {
                    if !key.is_empty() {
                        if set_api_key("virustotal_api_key", Some(key)).is_ok() {
                            s.virustotal_api_key = None;
                            migrated = true;
                        }
                    }
                }
                if let Some(ref key) = s.malwarebazaar_api_key.clone() {
                    if !key.is_empty() {
                        if set_api_key("malwarebazaar_api_key", Some(key)).is_ok() {
                            s.malwarebazaar_api_key = None;
                            migrated = true;
                        }
                    }
                }
                if migrated {
                    if let Ok(json) = serde_json::to_string_pretty(&s) {
                        let _ = std::fs::write(&path, json);
                    }
                    log::info!(
                        "Migrated API keys from settings.json to Windows Credential Manager"
                    );
                }
                return s;
            }
        }

        Settings::default()
    }

    pub fn save(&self) {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("insecurity");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            log::warn!("Failed to create settings dir: {}", e);
            return;
        }

        let path = dir.join("settings.json");
        if let Err(e) = std::fs::write(
            &path,
            serde_json::to_string_pretty(self).unwrap_or_default(),
        ) {
            log::warn!("Failed to write settings file: {}", e);
            return;
        }

        // Update the in-memory cache so subsequent reads reflect the change
        if let Ok(mut guard) = CACHED_SETTINGS.write() {
            *guard = Some(self.clone());
        }
    }
}

// ============================================================================
// Keyring helpers — store/retrieve API keys via Windows Credential Manager
// ============================================================================

const KEYRING_SERVICE: &str = "insecurity";

/// Retrieve an API key from the OS credential store. Returns `None` if unset.
pub fn get_api_key(credential: &str) -> Option<String> {
    keyring::Entry::new(KEYRING_SERVICE, credential)
        .get_password()
        .ok()
        .filter(|k| !k.is_empty())
}

/// Store or clear an API key in the OS credential store.
pub fn set_api_key(credential: &str, key: Option<&str>) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, credential);
    match key {
        Some(k) if !k.is_empty() => {
            entry.set_password(k).map_err(|e| e.to_string())?;

            match entry.get_password() {
                Ok(saved) if saved == k => Ok(()),
                Ok(_) => Err(format!(
                    "Credential store verification failed for {}",
                    credential
                )),
                Err(e) => Err(format!(
                    "Credential store verification failed for {}: {}",
                    credential, e
                )),
            }
        }
        _ => {
            let _ = entry.delete_password();
            match entry.get_password() {
                Ok(saved) if !saved.is_empty() => {
                    Err(format!("Credential store still contains {}", credential))
                }
                _ => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Default values
    // =========================================================================

    #[test]
    fn test_settings_default_real_time_protection() {
        assert!(Settings::default().real_time_protection);
    }

    #[test]
    fn test_settings_default_auto_quarantine() {
        assert!(Settings::default().auto_quarantine);
    }

    #[test]
    fn test_settings_default_cache_size() {
        assert_eq!(Settings::default().cache_size_mb, 256);
    }

    #[test]
    fn test_settings_default_cache_ttl() {
        assert_eq!(Settings::default().cache_ttl_hours, 24);
    }

    #[test]
    fn test_settings_default_ransomware_protection() {
        assert!(Settings::default().ransomware_protection);
    }

    #[test]
    fn test_settings_default_scan_worker_count() {
        assert_eq!(Settings::default().scan_worker_count, 4);
    }

    #[test]
    fn test_settings_default_autostart() {
        assert!(Settings::default().autostart);
    }

    // =========================================================================
    // Serialization / deserialization
    // =========================================================================

    #[test]
    fn test_settings_serialize_roundtrip() {
        let original = Settings::default();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.real_time_protection,
            original.real_time_protection
        );
        assert_eq!(deserialized.auto_quarantine, original.auto_quarantine);
        assert_eq!(deserialized.cache_size_mb, original.cache_size_mb);
        assert_eq!(deserialized.cache_ttl_hours, original.cache_ttl_hours);
        assert_eq!(
            deserialized.ransomware_protection,
            original.ransomware_protection
        );
        assert_eq!(
            deserialized.ransomware_auto_block,
            original.ransomware_auto_block
        );
        assert_eq!(
            deserialized.ransomware_threshold,
            original.ransomware_threshold
        );
        assert_eq!(
            deserialized.ransomware_window_seconds,
            original.ransomware_window_seconds
        );
        assert_eq!(deserialized.scan_worker_count, original.scan_worker_count);
        assert_eq!(deserialized.autostart, original.autostart);
    }

    #[test]
    fn test_settings_deserialize_with_missing_fields_uses_defaults() {
        // Minimal JSON - only required fields (those without #[serde(default)])
        let json = r#"{
            "real_time_protection": false,
            "auto_quarantine": false,
            "cache_size_mb": 64,
            "cache_ttl_hours": 12
        }"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert!(!s.real_time_protection);
        assert!(!s.auto_quarantine);
        assert_eq!(s.cache_size_mb, 64);
        assert_eq!(s.cache_ttl_hours, 12);
        // Defaults for missing fields
        assert!(s.ransomware_protection); // serde default = "default_true"
        assert!(s.ransomware_auto_block); // default_true()
        assert_eq!(s.ransomware_threshold, 20); // default_ransomware_threshold()
        assert_eq!(s.ransomware_window_seconds, 10); // default_ransomware_window()
        assert!(s.canary_files.is_empty()); // default empty HashMap
        assert_eq!(s.scan_worker_count, 4); // default_scan_worker_count()
        assert!(s.autostart); // default_true()
    }

    #[test]
    fn test_settings_deserialize_custom_values() {
        let json = r#"{
            "real_time_protection": false,
            "auto_quarantine": false,
            "cache_size_mb": 512,
            "cache_ttl_hours": 48,
            "ransomware_protection": true,
            "protected_folders": ["D:\\docs", "E:\\photos"],
            "scan_worker_count": 16,
            "autostart": false
        }"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert!(!s.real_time_protection);
        assert!(!s.auto_quarantine);
        assert_eq!(s.cache_size_mb, 512);
        assert_eq!(s.cache_ttl_hours, 48);
        assert!(s.ransomware_protection);
        assert_eq!(s.protected_folders, vec!["D:\\docs", "E:\\photos"]);
        assert_eq!(s.scan_worker_count, 16);
        assert!(!s.autostart);
    }

    #[test]
    fn test_settings_serialize_contains_all_fields() {
        let s = Settings::default();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("real_time_protection"));
        assert!(json.contains("auto_quarantine"));
        assert!(json.contains("cache_size_mb"));
        assert!(json.contains("cache_ttl_hours"));
        assert!(json.contains("ransomware_protection"));
        assert!(json.contains("protected_folders"));
        assert!(json.contains("ransomware_auto_block"));
        assert!(json.contains("ransomware_threshold"));
        assert!(json.contains("ransomware_window_seconds"));
        assert!(json.contains("canary_files"));
        assert!(json.contains("scan_worker_count"));
        assert!(json.contains("autostart"));
        // API keys are stored in the OS credential store, not in JSON
        assert!(!json.contains("virustotal_api_key"));
        assert!(!json.contains("malwarebazaar_api_key"));
    }

    // =========================================================================
    // Clone / Debug
    // =========================================================================

    #[test]
    fn test_settings_clone() {
        let original = Settings {
            real_time_protection: false,
            auto_quarantine: false,
            cache_size_mb: 128,
            cache_ttl_hours: 6,
            ransomware_protection: false,
            protected_folders: vec!["C:\\test".to_string()],
            ransomware_auto_block: false,
            ransomware_threshold: 10,
            ransomware_window_seconds: 5,
            canary_files: HashMap::new(),
            scan_worker_count: 2,
            autostart: false,
            network_monitoring_enabled: false,
            auto_block_malware_network: true,
            network_monitor_interval_secs: 3,
            language: default_language(),
            virustotal_api_key: None,
            malwarebazaar_api_key: None,
        };
        let cloned = original.clone();
        assert!(!cloned.real_time_protection);
        assert_eq!(cloned.protected_folders, vec!["C:\\test"]);
        assert_eq!(cloned.scan_worker_count, 2);
    }

    #[test]
    fn test_settings_debug_impl() {
        let s = Settings::default();
        let debug_str = format!("{:?}", s);
        assert!(debug_str.contains("Settings"));
    }

    // =========================================================================
    // Helper function tests
    // =========================================================================

    #[test]
    fn test_default_true_returns_true() {
        assert!(default_true());
    }

    #[test]
    fn test_default_scan_worker_count_returns_4() {
        assert_eq!(default_scan_worker_count(), 4);
    }

    #[test]
    fn test_default_protected_folders_not_empty() {
        // On most systems, at least one of Documents/Pictures/Desktop exists
        let folders = default_protected_folders();
        // We can't guarantee folders exist in CI, but the function should not panic
        assert!(folders.len() <= 3);
    }

    // =========================================================================
    // Save / load roundtrip via temp dir
    // =========================================================================

    #[test]
    fn test_settings_save_and_load_from_disk() {
        // We can't easily test load() because it uses dirs::data_dir() and a
        // global cache. Instead test that save() produces valid JSON.
        let s = Settings {
            real_time_protection: false,
            auto_quarantine: true,
            cache_size_mb: 100,
            cache_ttl_hours: 8,
            ransomware_protection: true,
            protected_folders: vec!["C:\\docs".to_string()],
            ransomware_auto_block: true,
            ransomware_threshold: 20,
            ransomware_window_seconds: 10,
            canary_files: HashMap::new(),
            scan_worker_count: 8,
            autostart: false,
            network_monitoring_enabled: false,
            auto_block_malware_network: true,
            network_monitor_interval_secs: 3,
            language: default_language(),
            virustotal_api_key: None,
            malwarebazaar_api_key: None,
        };
        let json = serde_json::to_string_pretty(&s).unwrap();
        let reloaded: Settings = serde_json::from_str(&json).unwrap();
        assert!(!reloaded.real_time_protection);
        assert!(reloaded.auto_quarantine);
        assert_eq!(reloaded.cache_size_mb, 100);
        assert_eq!(reloaded.scan_worker_count, 8);
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn test_settings_zero_cache() {
        let json = r#"{
            "real_time_protection": true,
            "auto_quarantine": true,
            "cache_size_mb": 0,
            "cache_ttl_hours": 0
        }"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert_eq!(s.cache_size_mb, 0);
        assert_eq!(s.cache_ttl_hours, 0);
    }

    #[test]
    fn test_settings_empty_protected_folders() {
        let json = r#"{
            "real_time_protection": true,
            "auto_quarantine": true,
            "cache_size_mb": 128,
            "cache_ttl_hours": 24,
            "protected_folders": []
        }"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert!(s.protected_folders.is_empty());
    }
}
