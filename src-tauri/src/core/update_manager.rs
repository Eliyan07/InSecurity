use super::rate_limiter::MALWARE_BAZAAR_RATE_LIMITER;
use super::threat_feed::{parse_feed_json, ThreatEntry};
use super::utils::{calculate_sha256, is_valid_md5, is_valid_sha1, is_valid_sha256};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
/// Update Manager Module
/// Handles auto-updates for threat intelligence from MalwareBazaar and other sources
use std::path::PathBuf;

/// Public key for verifying update signatures (Ed25519)
const UPDATE_PUBLIC_KEY_B64: &str = "MCowBQYDK2VwAyEAGVLkZK5XYS0mj6tYk8nxMWCH9M3jKH6wMOqPQYtJTEs=";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub hash: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSource {
    pub name: String,
    pub url: String,
    pub source_type: SourceType,
    pub enabled: bool,
    pub last_updated: Option<i64>,
    pub update_interval_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    HashList,
    YaraRules,
    ThreatFeed,
    MalwareBazaar,
}

#[derive(Debug, Deserialize)]
pub struct MalwareBazaarResponse {
    #[serde(default = "default_query_status")]
    pub query_status: String,
    #[serde(default)]
    pub data: Vec<MalwareBazaarEntry>,
}

fn default_query_status() -> String {
    "unknown".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MalwareBazaarEntry {
    pub sha256_hash: String,
    #[serde(default)]
    pub sha1_hash: Option<String>,
    #[serde(default)]
    pub md5_hash: Option<String>,
    #[serde(default)]
    pub file_type: Option<String>,
    #[serde(default)]
    pub file_type_mime: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub intelligence: Option<MalwareIntelligence>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MalwareIntelligence {
    #[serde(default)]
    pub clamav: Option<Vec<String>>,
    #[serde(default)]
    pub downloads: Option<String>,
    #[serde(default)]
    pub uploads: Option<String>,
    #[serde(default)]
    pub mail: Option<MalwareMailIntel>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MalwareMailIntel {
    #[serde(default)]
    pub generic: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResult {
    pub source: String,
    pub success: bool,
    pub entries_added: usize,
    pub entries_updated: usize,
    pub error: Option<String>,
    pub timestamp: i64,
}

pub struct UpdateManager {
    client: Client,

    sources: Vec<UpdateSource>,
    /// MalwareBazaar API key (required for API access)
    /// Set via MALWAREBAZAAR_API_KEY environment variable
    /// Get a free key at: https://auth.abuse.ch/
    api_key: Option<String>,
}

impl UpdateManager {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("insecurity");

        if let Err(e) = fs::create_dir_all(&data_dir) {
            log::warn!("Failed to create data directory {:?}: {}", data_dir, e);
        }

        let api_key = crate::config::settings::get_api_key("malwarebazaar_api_key")
            .or_else(|| std::env::var("MALWAREBAZAAR_API_KEY").ok());
        if api_key.is_none() {
            log::warn!("MALWAREBAZAAR_API_KEY not set - MalwareBazaar API will not work. Get a free key at https://auth.abuse.ch/");
        }

        let sources = vec![
            UpdateSource {
                name: "MalwareBazaar Recent".to_string(),
                url: "https://mb-api.abuse.ch/api/v1/".to_string(),
                source_type: SourceType::MalwareBazaar,
                enabled: true,
                last_updated: None,
                update_interval_hours: 6,
            },
            UpdateSource {
                name: "Abuse.ch Feodo Tracker".to_string(),
                url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
                source_type: SourceType::HashList,
                enabled: false,
                last_updated: None,
                update_interval_hours: 24,
            },
        ];

        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent("InSecurity-AV/1.0")
                .build()
                .unwrap_or_default(),
            sources,
            api_key,
        }
    }

    pub fn verify_update_signature(
        &self,
        data: &[u8],
        signature_b64: Option<&str>,
    ) -> VerificationResult {
        let hash = calculate_sha256(data);

        let Some(sig_b64) = signature_b64 else {
            return VerificationResult {
                verified: false,
                hash,
                error: Some("No signature provided".to_string()),
            };
        };

        let pub_key_bytes = match BASE64.decode(UPDATE_PUBLIC_KEY_B64) {
            Ok(bytes) => bytes,
            Err(e) => {
                return VerificationResult {
                    verified: false,
                    hash,
                    error: Some(format!("Failed to decode public key: {}", e)),
                };
            }
        };

        let key_bytes: [u8; 32] = match pub_key_bytes.get(pub_key_bytes.len().saturating_sub(32)..)
        {
            Some(slice) if slice.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(slice);
                arr
            }
            _ => {
                return VerificationResult {
                    verified: false,
                    hash,
                    error: Some("Invalid public key length".to_string()),
                };
            }
        };

        let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
            Ok(key) => key,
            Err(e) => {
                return VerificationResult {
                    verified: false,
                    hash,
                    error: Some(format!("Invalid public key: {}", e)),
                };
            }
        };

        let sig_bytes = match BASE64.decode(sig_b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                return VerificationResult {
                    verified: false,
                    hash,
                    error: Some(format!("Failed to decode signature: {}", e)),
                };
            }
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(sig) => sig,
            Err(e) => {
                return VerificationResult {
                    verified: false,
                    hash,
                    error: Some(format!("Invalid signature format: {}", e)),
                };
            }
        };

        match verifying_key.verify(data, &signature) {
            Ok(()) => VerificationResult {
                verified: true,
                hash,
                error: None,
            },
            Err(e) => VerificationResult {
                verified: false,
                hash,
                error: Some(format!("Signature verification failed: {}", e)),
            },
        }
    }

    pub fn verify_threat_intel_integrity(&self, entries: &[MalwareBazaarEntry]) -> bool {
        for entry in entries {
            if !is_valid_sha256(&entry.sha256_hash) {
                log::warn!("Invalid SHA256 hash format: {}", entry.sha256_hash);
                return false;
            }

            if let Some(ref md5) = entry.md5_hash {
                if !is_valid_md5(md5) {
                    log::warn!("Invalid MD5 hash format: {}", md5);
                    return false;
                }
            }

            if let Some(ref sha1) = entry.sha1_hash {
                if !is_valid_sha1(sha1) {
                    log::warn!("Invalid SHA1 hash format: {}", sha1);
                    return false;
                }
            }
        }
        true
    }

    pub fn verify_threat_feed_integrity(&self, entries: &[ThreatEntry]) -> bool {
        for entry in entries {
            if !is_valid_sha256(&entry.hash) {
                log::warn!("Invalid threat-feed SHA256 hash format: {}", entry.hash);
                return false;
            }

            if entry.name.trim().is_empty() {
                log::warn!(
                    "Threat-feed entry has an empty threat name for {}",
                    entry.hash
                );
                return false;
            }

            if entry.severity.trim().is_empty() {
                log::warn!("Threat-feed entry has an empty severity for {}", entry.hash);
                return false;
            }
        }

        true
    }

    pub async fn fetch_malwarebazaar_recent(
        &self,
        limit: u32,
    ) -> Result<Vec<MalwareBazaarEntry>, Box<dyn std::error::Error + Send + Sync>> {
        // Check rate limit before making request
        if let Some(wait_secs) = MALWARE_BAZAAR_RATE_LIMITER.acquire() {
            log::warn!(
                "MalwareBazaar rate limit exceeded, need to wait {} seconds",
                wait_secs
            );
            return Err(format!(
                "Rate limited: please wait {} seconds before retrying",
                wait_secs
            )
            .into());
        }

        let api_key = match &self.api_key {
            Some(key) => key.clone(),
            None => {
                log::warn!("MalwareBazaar API key not configured. Set MALWAREBAZAAR_API_KEY environment variable.");
                return Err("MalwareBazaar API key not configured. Get a free key at https://auth.abuse.ch/".into());
            }
        };

        let limit = limit.min(1000);

        let response = self
            .client
            .post("https://mb-api.abuse.ch/api/v1/")
            .header("Auth-Key", &api_key)
            .form(&[("query", "get_recent"), ("selector", &limit.to_string())])
            .send()
            .await?;

        let body = response.text().await?;

        let parsed: MalwareBazaarResponse = match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(e) => {
                log::warn!(
                    "Failed to parse MalwareBazaar response: {} - Body preview: {}",
                    e,
                    &body[..body.len().min(200)]
                );
                return Ok(Vec::new()); // Return empty list on parse error
            }
        };

        match parsed.query_status.as_str() {
            "ok" => Ok(parsed.data),
            "no_results" => Ok(Vec::new()),
            "unknown" => {
                log::debug!("MalwareBazaar returned unknown status (API may be unavailable)");
                Ok(Vec::new())
            }
            status => {
                log::warn!("MalwareBazaar API returned status: {}", status);
                Ok(Vec::new()) // Don't fail, just return empty
            }
        }
    }

    pub async fn fetch_malwarebazaar_by_tag(
        &self,
        tag: &str,
        limit: u32,
    ) -> Result<Vec<MalwareBazaarEntry>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(wait_secs) = MALWARE_BAZAAR_RATE_LIMITER.acquire() {
            log::warn!(
                "MalwareBazaar rate limit exceeded, need to wait {} seconds",
                wait_secs
            );
            return Err(format!(
                "Rate limited: please wait {} seconds before retrying",
                wait_secs
            )
            .into());
        }

        let api_key = match &self.api_key {
            Some(key) => key.clone(),
            None => return Err("MalwareBazaar API key not configured".into()),
        };

        let limit = limit.min(1000);

        let response = self
            .client
            .post("https://mb-api.abuse.ch/api/v1/")
            .header("Auth-Key", &api_key)
            .form(&[
                ("query", "get_taginfo"),
                ("tag", tag),
                ("limit", &limit.to_string()),
            ])
            .send()
            .await?;

        let body = response.text().await?;
        let parsed: MalwareBazaarResponse = match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Failed to parse MalwareBazaar tag response: {}", e);
                return Ok(Vec::new());
            }
        };

        match parsed.query_status.as_str() {
            "ok" => Ok(parsed.data),
            "no_results" | "unknown" => Ok(Vec::new()),
            _ => Ok(Vec::new()),
        }
    }

    pub async fn fetch_malwarebazaar_by_signature(
        &self,
        signature: &str,
        limit: u32,
    ) -> Result<Vec<MalwareBazaarEntry>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(wait_secs) = MALWARE_BAZAAR_RATE_LIMITER.acquire() {
            log::warn!(
                "MalwareBazaar rate limit exceeded, need to wait {} seconds",
                wait_secs
            );
            return Err(format!(
                "Rate limited: please wait {} seconds before retrying",
                wait_secs
            )
            .into());
        }

        let api_key = match &self.api_key {
            Some(key) => key.clone(),
            None => return Err("MalwareBazaar API key not configured".into()),
        };

        let limit = limit.min(1000);

        let response = self
            .client
            .post("https://mb-api.abuse.ch/api/v1/")
            .header("Auth-Key", &api_key)
            .form(&[
                ("query", "get_siginfo"),
                ("signature", signature),
                ("limit", &limit.to_string()),
            ])
            .send()
            .await?;

        let body = response.text().await?;
        let parsed: MalwareBazaarResponse = match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Failed to parse MalwareBazaar signature response: {}", e);
                return Ok(Vec::new());
            }
        };

        match parsed.query_status.as_str() {
            "ok" => Ok(parsed.data),
            "no_results" | "unknown" => Ok(Vec::new()),
            _ => Ok(Vec::new()),
        }
    }

    pub async fn update_threat_intel(
        &self,
        entries: &[MalwareBazaarEntry],
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        if !self.verify_threat_intel_integrity(entries) {
            return Err(
                "Threat intel integrity verification failed - possible tampering detected".into(),
            );
        }

        let normalized_entries: Vec<ThreatEntry> = entries.iter().map(ThreatEntry::from).collect();

        self.update_threat_feed_entries("MalwareBazaar", &normalized_entries)
            .await
    }

    pub async fn ingest_threat_feed_json(
        &self,
        source: &str,
        body: &str,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let entries = parse_feed_json(body)?;
        self.update_threat_feed_entries(source, &entries).await
    }

    pub async fn update_threat_feed_entries(
        &self,
        source: &str,
        entries: &[ThreatEntry],
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        if !self.verify_threat_feed_integrity(entries) {
            return Err(
                "Threat feed integrity verification failed - possible tampering detected".into(),
            );
        }

        let mut new_count = 0;
        if let Ok(guard) = crate::DB.lock() {
            if let Some(ref conn) = *guard {
                for entry in entries {
                    let hash_lower = entry.hash.to_lowercase();

                    let exists: bool = conn
                        .query_row(
                            "SELECT 1 FROM threat_intel WHERE file_hash = ?1",
                            [&hash_lower],
                            |_| Ok(true),
                        )
                        .unwrap_or(false);

                    let threat_name = entry.name.trim().to_string();
                    let severity = entry.severity.trim().to_lowercase();
                    let family = entry.family.clone();
                    let first_seen = entry.normalize_first_seen();
                    let now = Utc::now().timestamp();

                    let result = conn.execute(
                        "INSERT INTO threat_intel (file_hash, threat_name, severity, family, first_seen, last_updated, source)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                         ON CONFLICT(file_hash) DO UPDATE SET
                         threat_name = excluded.threat_name,
                         severity = excluded.severity,
                         family = excluded.family,
                         last_updated = excluded.last_updated,
                         source = excluded.source",
                        rusqlite::params![
                            &hash_lower,
                            &threat_name,
                            &severity,
                            family,
                            first_seen,
                            now,
                            source,
                        ],
                    );

                    if result.is_ok() {
                        let _ = conn.execute(
                            "INSERT OR IGNORE INTO blacklist (file_hash, threat_name, source, added_at)
                             VALUES (?1, ?2, ?3, ?4)",
                            rusqlite::params![&hash_lower, &threat_name, source, now],
                        );
                    }

                    if result.is_ok() && !exists {
                        new_count += 1;
                    }
                }
            }
        }

        Ok(new_count)
    }

    /// Record the current timestamp as `last_updated` on every configured source.
    /// Called by the commands layer after a successful update so that
    /// `get_update_stats()` returns a non-null `last_update` value.
    pub fn mark_all_sources_updated(&mut self) {
        let now = Utc::now().timestamp();
        for source in &mut self.sources {
            source.last_updated = Some(now);
        }
    }

    pub async fn run_full_update(&self) -> Vec<UpdateResult> {
        let mut results = Vec::new();

        log::info!("Fetching recent malware samples from MalwareBazaar...");
        match self.fetch_malwarebazaar_recent(100).await {
            Ok(entries) => {
                log::info!("Received {} entries from MalwareBazaar", entries.len());

                match self.update_threat_intel(&entries).await {
                    Ok(count) => {
                        log::info!("Threat intel updated: {} entries", count);
                        results.push(UpdateResult {
                            source: "MalwareBazaar".to_string(),
                            success: true,
                            entries_added: count,
                            entries_updated: 0,
                            error: None,
                            timestamp: Utc::now().timestamp(),
                        });

                        if let Err(e) = crate::core::static_scanner::refresh_blacklist() {
                            log::error!("Failed to refresh blacklist after update: {}", e);
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to update threat intel: {}", e);
                        results.push(UpdateResult {
                            source: "MalwareBazaar".to_string(),
                            success: false,
                            entries_added: 0,
                            entries_updated: 0,
                            error: Some(e.to_string()),
                            timestamp: Utc::now().timestamp(),
                        });
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to fetch from MalwareBazaar: {}", e);
                results.push(UpdateResult {
                    source: "MalwareBazaar".to_string(),
                    success: false,
                    entries_added: 0,
                    entries_updated: 0,
                    error: Some(e.to_string()),
                    timestamp: Utc::now().timestamp(),
                });
            }
        }

        results
    }

    pub async fn run_initial_seed(&self) -> Vec<UpdateResult> {
        let mut results = Vec::new();
        let mut total_added = 0usize;

        log::info!("Starting initial threat database seed from MalwareBazaar...");

        // 1. Fetch maximum recent samples (1000 - API limit)
        log::info!("Fetching 1000 recent malware samples...");
        match self.fetch_malwarebazaar_recent(1000).await {
            Ok(entries) => {
                log::info!("Received {} recent entries", entries.len());
                if let Ok(count) = self.update_threat_intel(&entries).await {
                    total_added += count;
                }
            }
            Err(e) => {
                log::error!("Failed to fetch recent samples: {}", e);
            }
        }

        // Rate limit between API calls
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // 2. Fetch major malware families (100 each = ~1500 more)
        let major_families = [
            "AgentTesla",
            "Emotet",
            "Formbook",
            "RedLine",
            "AsyncRAT",
            "Lokibot",
            "NanoCore",
            "Remcos",
            "njRAT",
            "QuasarRAT",
            "SnakeKeylogger",
            "AZORult",
            "Raccoon",
            "Vidar",
            "IcedID",
        ];

        for family in major_families {
            log::info!("Fetching {} samples...", family);
            match self.fetch_malwarebazaar_by_signature(family, 100).await {
                Ok(entries) if !entries.is_empty() => {
                    if let Ok(count) = self.update_threat_intel(&entries).await {
                        if count > 0 {
                            log::info!("Added {} {} hashes", count, family);
                            total_added += count;
                        }
                    }
                }
                Ok(_) => {
                    log::debug!("No {} samples found", family);
                }
                Err(e) => {
                    log::warn!("Failed to fetch {}: {}", family, e);
                }
            }

            // Rate limiting - be nice to the API
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        }

        // 3. Fetch by common malware tags
        let tags = ["exe", "dll", "ransomware", "trojan", "stealer"];

        for tag in tags {
            log::info!("Fetching samples tagged '{}'...", tag);
            match self.fetch_malwarebazaar_by_tag(tag, 200).await {
                Ok(entries) if !entries.is_empty() => {
                    if let Ok(count) = self.update_threat_intel(&entries).await {
                        if count > 0 {
                            log::info!("Added {} '{}' tagged hashes", count, tag);
                            total_added += count;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    log::warn!("Failed to fetch tag {}: {}", tag, e);
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        }

        log::info!(
            "Initial seed completed: {} total hashes added to DB",
            total_added
        );

        if let Err(e) = crate::core::static_scanner::refresh_blacklist() {
            log::error!("Failed to refresh blacklist after initial seed: {}", e);
        }

        results.push(UpdateResult {
            source: "InitialSeed-Total".to_string(),
            success: true,
            entries_added: total_added,
            entries_updated: 0,
            error: None,
            timestamp: Utc::now().timestamp(),
        });

        results
    }

    pub async fn run_automatic_update(&self) -> Vec<UpdateResult> {
        let mut results = Vec::new();
        let mut total_added = 0;

        log::info!("Automatic update: fetching recent malware samples...");
        match self.fetch_malwarebazaar_recent(500).await {
            Ok(entries) => {
                log::info!("Received {} entries from MalwareBazaar", entries.len());

                match self.update_threat_intel(&entries).await {
                    Ok(added) => {
                        total_added += added;
                        if added > 0 {
                            log::info!(
                                "Auto-update: {} new hashes added from recent samples",
                                added
                            );
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to update threat intel: {}", e);
                    }
                }
            }
            Err(e) => {
                log::error!("Auto-update failed to fetch from MalwareBazaar: {}", e);
                results.push(UpdateResult {
                    source: "AutoUpdate".to_string(),
                    success: false,
                    entries_added: 0,
                    entries_updated: 0,
                    error: Some(e.to_string()),
                    timestamp: Utc::now().timestamp(),
                });
            }
        }

        let priority_families = ["AgentTesla", "Emotet", "RedLine", "AsyncRAT"];

        for family in priority_families {
            match self.fetch_malwarebazaar_by_signature(family, 50).await {
                Ok(entries) if !entries.is_empty() => {
                    if let Ok(added) = self.update_threat_intel(&entries).await {
                        if added > 0 {
                            log::info!("Auto-update: {} new {} hashes", added, family);
                            total_added += added;
                        }
                    }
                }
                _ => {}
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        if total_added > 0 {
            use crate::core::static_scanner::refresh_blacklist;
            if let Err(e) = refresh_blacklist() {
                log::error!("Failed to refresh in-memory blacklist: {}", e);
            }
        }

        results.push(UpdateResult {
            source: "AutoUpdate".to_string(),
            success: true,
            entries_added: total_added,
            entries_updated: 0,
            error: None,
            timestamp: Utc::now().timestamp(),
        });

        results
    }

    pub fn get_stats(&self) -> UpdateStats {
        let blacklist_count = {
            use crate::core::static_scanner::BLACKLIST;
            BLACKLIST.read().map(|guard| guard.len()).unwrap_or(0)
        };

        let threat_intel_count = if let Ok(guard) = crate::DB.lock() {
            if let Some(ref conn) = *guard {
                conn.query_row("SELECT COUNT(*) FROM threat_intel", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap_or(0) as usize
            } else {
                0
            }
        } else {
            0
        };

        UpdateStats {
            blacklist_hash_count: blacklist_count,
            threat_intel_count,
            last_update: self.sources.iter().filter_map(|s| s.last_updated).max(),
            sources: self.sources.clone(),
        }
    }
}

impl Default for UpdateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStats {
    pub blacklist_hash_count: usize,
    pub threat_intel_count: usize,
    pub last_update: Option<i64>,
    pub sources: Vec<UpdateSource>,
}

pub static UPDATE_MANAGER: once_cell::sync::Lazy<std::sync::Mutex<UpdateManager>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(UpdateManager::new()));

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> UpdateManager {
        UpdateManager::new()
    }

    #[test]
    fn test_verify_signature_no_signature() {
        let mgr = make_manager();
        let result = mgr.verify_update_signature(b"hello", None);
        assert!(!result.verified);
        assert!(result.error.as_ref().unwrap().contains("No signature"));
        // Hash should still be computed
        assert!(!result.hash.is_empty());
    }

    #[test]
    fn test_verify_signature_invalid_base64_sig() {
        let mgr = make_manager();
        let result = mgr.verify_update_signature(b"data", Some("not-valid-base64!!!"));
        assert!(!result.verified);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_verify_signature_wrong_signature() {
        let mgr = make_manager();
        // Valid base64 but wrong signature (64 bytes of zeros)
        let fake_sig = BASE64.encode([0u8; 64]);
        let result = mgr.verify_update_signature(b"data", Some(&fake_sig));
        assert!(!result.verified);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_verify_signature_bad_sig_length() {
        let mgr = make_manager();
        // Valid base64, but not 64 bytes - invalid Ed25519 signature
        let short_sig = BASE64.encode([0u8; 32]);
        let result = mgr.verify_update_signature(b"data", Some(&short_sig));
        assert!(!result.verified);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_verify_integrity_empty_list() {
        let mgr = make_manager();
        assert!(mgr.verify_threat_intel_integrity(&[]));
    }

    #[test]
    fn test_verify_integrity_valid_entries() {
        let mgr = make_manager();
        let entries = vec![MalwareBazaarEntry {
            sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            sha1_hash: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
            md5_hash: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
            file_type: None,
            file_type_mime: None,
            signature: None,
            tags: None,
            intelligence: None,
        }];
        assert!(mgr.verify_threat_intel_integrity(&entries));
    }

    #[test]
    fn test_verify_integrity_invalid_sha256() {
        let mgr = make_manager();
        let entries = vec![MalwareBazaarEntry {
            sha256_hash: "not-a-valid-hash".to_string(),
            sha1_hash: None,
            md5_hash: None,
            file_type: None,
            file_type_mime: None,
            signature: None,
            tags: None,
            intelligence: None,
        }];
        assert!(!mgr.verify_threat_intel_integrity(&entries));
    }

    #[test]
    fn test_verify_integrity_invalid_md5() {
        let mgr = make_manager();
        let entries = vec![MalwareBazaarEntry {
            sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            sha1_hash: None,
            md5_hash: Some("zzzz".to_string()),
            file_type: None,
            file_type_mime: None,
            signature: None,
            tags: None,
            intelligence: None,
        }];
        assert!(!mgr.verify_threat_intel_integrity(&entries));
    }

    #[test]
    fn test_verify_integrity_invalid_sha1() {
        let mgr = make_manager();
        let entries = vec![MalwareBazaarEntry {
            sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            sha1_hash: Some("tooshort".to_string()),
            md5_hash: None,
            file_type: None,
            file_type_mime: None,
            signature: None,
            tags: None,
            intelligence: None,
        }];
        assert!(!mgr.verify_threat_intel_integrity(&entries));
    }

    #[test]
    fn test_verify_integrity_none_optional_hashes_ok() {
        let mgr = make_manager();
        let entries = vec![MalwareBazaarEntry {
            sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            sha1_hash: None,
            md5_hash: None,
            file_type: None,
            file_type_mime: None,
            signature: None,
            tags: None,
            intelligence: None,
        }];
        assert!(mgr.verify_threat_intel_integrity(&entries));
    }

    #[test]
    fn test_verify_threat_feed_integrity_valid_entries() {
        let mgr = make_manager();
        let entries = vec![ThreatEntry {
            hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            name: "AsyncRAT".to_string(),
            severity: "high".to_string(),
            family: Some("AsyncRAT".to_string()),
            first_seen: Some(1000),
        }];

        assert!(mgr.verify_threat_feed_integrity(&entries));
    }

    #[test]
    fn test_verify_threat_feed_integrity_invalid_hash() {
        let mgr = make_manager();
        let entries = vec![ThreatEntry {
            hash: "not-a-valid-hash".to_string(),
            name: "AsyncRAT".to_string(),
            severity: "high".to_string(),
            family: Some("AsyncRAT".to_string()),
            first_seen: Some(1000),
        }];

        assert!(!mgr.verify_threat_feed_integrity(&entries));
    }

    #[test]
    fn test_source_type_serialization() {
        let st = SourceType::MalwareBazaar;
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(json, "\"malwarebazaar\"");
        let deser: SourceType = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, SourceType::MalwareBazaar);
    }

    #[test]
    fn test_source_type_threat_feed_serialization() {
        let st = SourceType::ThreatFeed;
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(json, "\"threatfeed\"");
        let deser: SourceType = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, SourceType::ThreatFeed);
    }

    #[test]
    fn test_verification_result_serialization() {
        let vr = VerificationResult {
            verified: true,
            hash: "abc123".to_string(),
            error: None,
        };
        let json = serde_json::to_string(&vr).unwrap();
        let deser: VerificationResult = serde_json::from_str(&json).unwrap();
        assert!(deser.verified);
        assert!(deser.error.is_none());
    }

    #[test]
    fn test_update_result_serialization_roundtrip() {
        let ur = UpdateResult {
            source: "MalwareBazaar".to_string(),
            success: true,
            entries_added: 10,
            entries_updated: 5,
            error: None,
            timestamp: 1700000000,
        };
        let json = serde_json::to_string(&ur).unwrap();
        let deser: UpdateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.entries_added, 10);
        assert_eq!(deser.entries_updated, 5);
    }

    #[test]
    fn test_malware_bazaar_entry_deserialization() {
        let json = r#"{
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_type": "exe",
            "signature": "Emotet"
        }"#;
        let entry: MalwareBazaarEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.file_type, Some("exe".to_string()));
        assert_eq!(entry.signature, Some("Emotet".to_string()));
        assert!(entry.md5_hash.is_none());
    }

    #[test]
    fn test_malware_bazaar_response_default_query_status() {
        let json = r#"{"data": []}"#;
        let resp: MalwareBazaarResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.query_status, "unknown");
        assert!(resp.data.is_empty());
    }
}
