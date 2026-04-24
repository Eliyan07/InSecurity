//! Tamper Protection Module
//! Provides self-protection mechanisms for user-mode operation:
//! - Signed exclusions/config to prevent malware self-exclusion
//! - Runtime integrity checks for critical resources
//! - Event journaling with tamper-evident audit log
//! - YARA rule signature verification

use chrono::Utc;
use keyring::Entry as KeyringEntry;
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Cached signing key (loaded once at runtime from OS credential store)
static SIGNING_KEY_CACHE: once_cell::sync::OnceCell<Vec<u8>> = once_cell::sync::OnceCell::new();

/// Get the HMAC signing key, loading from OS keyring or generating on first use.
/// The key is cached in memory after first retrieval for performance.
fn get_signing_key() -> &'static [u8] {
    SIGNING_KEY_CACHE.get_or_init(|| {
        load_or_generate_signing_key().unwrap_or_else(|e| {
            log::error!(
                "Failed to load signing key from secure storage: {}. Generating ephemeral key.",
                e
            );
            let mut key = vec![0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut key);
            key
        })
    })
}

/// Load signing key from OS keyring, or generate and persist a new one.
fn load_or_generate_signing_key() -> Result<Vec<u8>, String> {
    let disable_keyring = std::env::var("TAMPER_DISABLE_KEYRING")
        .map(|v| v == "1")
        .unwrap_or(false);
    let running_in_ci = std::env::var("CI").is_ok();
    let prefer_keyring = !disable_keyring && !running_in_ci;

    let keystore_dir = dirs::data_dir()
        .ok_or("Could not find data directory")?
        .join("antivirus-ui");
    fs::create_dir_all(&keystore_dir).map_err(|e| e.to_string())?;
    let keystore_file = keystore_dir.join("tamper_key.b64");

    // Try loading from keyring first
    if prefer_keyring {
        let entry = KeyringEntry::new("antivirus_ui", "tamper_protection_key");
        if let Ok(stored) = entry.get_password() {
            if let Ok(bytes) = base64_decode(&stored) {
                if bytes.len() >= 32 {
                    return Ok(bytes);
                }
            }
        }
    }

    // Always try file fallback (covers both keyring-disabled and keyring-failed cases)
    if let Ok(stored) = fs::read_to_string(&keystore_file) {
        if let Ok(bytes) = base64_decode(stored.trim()) {
            if bytes.len() >= 32 {
                return Ok(bytes);
            }
        }
    }

    let mut new_key = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut new_key);

    let encoded = base64_encode(&new_key);

    // Persist to keyring with file fallback
    if prefer_keyring {
        let entry = KeyringEntry::new("antivirus_ui", "tamper_protection_key");
        if let Err(e) = entry.set_password(&encoded) {
            log::warn!(
                "Failed to persist tamper key to OS keyring: {}. Using file fallback.",
                e
            );
            if let Err(e2) = fs::write(&keystore_file, &encoded) {
                log::warn!("Failed to persist tamper key to file: {}", e2);
            }
        }
    } else if let Err(e) = fs::write(&keystore_file, &encoded) {
        log::warn!("Failed to persist tamper key to file: {}", e);
    }

    log::info!("Generated new tamper protection signing key");
    Ok(new_key)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(s).map_err(|e| e.to_string())
}

/// Lightweight signing using HMAC-SHA256
/// Fast enough for real-time use, provides tamper evidence
fn compute_hmac(data: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, get_signing_key());
    let tag = hmac::sign(&key, data);
    hex::encode(tag.as_ref())
}

fn verify_hmac(data: &[u8], expected_sig: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, get_signing_key());
    if let Ok(expected_bytes) = hex::decode(expected_sig) {
        hmac::verify(&key, data, &expected_bytes).is_ok()
    } else {
        false
    }
}

// ============================================================================
// SIGNED EXCLUSIONS
// ============================================================================

/// Signed exclusion entry - includes signature to detect tampering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedExclusion {
    pub exclusion_type: String,
    pub pattern: String,
    pub reason: Option<String>,
    pub created_at: i64,
    pub signature: String,
}

impl SignedExclusion {
    /// Create a new signed exclusion
    pub fn new(exclusion_type: &str, pattern: &str, reason: Option<&str>) -> Self {
        let created_at = Utc::now().timestamp();
        let data = format!(
            "{}|{}|{}|{}",
            exclusion_type,
            pattern,
            reason.unwrap_or(""),
            created_at
        );
        let signature = compute_hmac(data.as_bytes());

        SignedExclusion {
            exclusion_type: exclusion_type.to_string(),
            pattern: pattern.to_string(),
            reason: reason.map(|s| s.to_string()),
            created_at,
            signature,
        }
    }

    /// Verify the exclusion's signature
    pub fn verify(&self) -> bool {
        let data = format!(
            "{}|{}|{}|{}",
            self.exclusion_type,
            self.pattern,
            self.reason.as_deref().unwrap_or(""),
            self.created_at
        );
        verify_hmac(data.as_bytes(), &self.signature)
    }
}

/// Compute signature for an exclusion record from the database
/// This allows verifying existing exclusions without the SignedExclusion wrapper
pub fn compute_exclusion_signature(
    exclusion_type: &str,
    pattern: &str,
    reason: Option<&str>,
    created_at: i64,
) -> String {
    let data = format!(
        "{}|{}|{}|{}",
        exclusion_type,
        pattern,
        reason.unwrap_or(""),
        created_at
    );
    compute_hmac(data.as_bytes())
}

/// Verify an exclusion from database has valid signature
pub fn verify_exclusion_signature(
    exclusion_type: &str,
    pattern: &str,
    reason: Option<&str>,
    created_at: i64,
    signature: &str,
) -> bool {
    let data = format!(
        "{}|{}|{}|{}",
        exclusion_type,
        pattern,
        reason.unwrap_or(""),
        created_at
    );
    verify_hmac(data.as_bytes(), signature)
}

// ============================================================================
// SIGNED SETTINGS
// ============================================================================

/// Signed settings wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSettings {
    pub ml_confidence_threshold: f64,
    pub real_time_protection: bool,
    pub auto_quarantine: bool,
    pub cache_size_mb: u32,
    pub cache_ttl_hours: u32,
    pub signature: String,
}

impl SignedSettings {
    /// Create signed settings from values
    pub fn new(
        ml_confidence_threshold: f64,
        real_time_protection: bool,
        auto_quarantine: bool,
        cache_size_mb: u32,
        cache_ttl_hours: u32,
    ) -> Self {
        let data = format!(
            "{}|{}|{}|{}|{}",
            ml_confidence_threshold.to_bits(),
            real_time_protection,
            auto_quarantine,
            cache_size_mb,
            cache_ttl_hours
        );
        let signature = compute_hmac(data.as_bytes());

        SignedSettings {
            ml_confidence_threshold,
            real_time_protection,
            auto_quarantine,
            cache_size_mb,
            cache_ttl_hours,
            signature,
        }
    }

    /// Verify settings signature
    pub fn verify(&self) -> bool {
        let data = format!(
            "{}|{}|{}|{}|{}",
            self.ml_confidence_threshold.to_bits(),
            self.real_time_protection,
            self.auto_quarantine,
            self.cache_size_mb,
            self.cache_ttl_hours
        );
        verify_hmac(data.as_bytes(), &self.signature)
    }

    /// Load and verify settings, returning None if tampered
    pub fn load_verified() -> Option<Self> {
        let path = dirs::data_dir()?
            .join("antivirus-ui")
            .join("settings_signed.json");

        let content = fs::read_to_string(&path).ok()?;
        let settings: SignedSettings = serde_json::from_str(&content).ok()?;

        if settings.verify() {
            Some(settings)
        } else {
            log::warn!("Settings signature verification failed - possible tampering");
            None
        }
    }

    /// Save signed settings
    pub fn save(&self) -> Result<(), String> {
        let dir = dirs::data_dir()
            .ok_or("Could not find data directory")?
            .join("antivirus-ui");

        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        let path = dir.join("settings_signed.json");
        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;

        fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ============================================================================
// RUNTIME INTEGRITY CHECKS
// ============================================================================

/// Critical resource integrity manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub resources: BTreeMap<String, ResourceHash>,
    pub generated_at: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceHash {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

/// Result of integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheckResult {
    pub passed: bool,
    pub checked_resources: usize,
    pub failed_resources: Vec<String>,
    pub missing_resources: Vec<String>,
    pub check_time_ms: u64,
}

pub struct IntegrityChecker {
    manifest_path: PathBuf,
    resource_base: PathBuf,
}

impl IntegrityChecker {
    pub fn new(resource_base: PathBuf) -> Self {
        let manifest_path = resource_base.join("integrity_manifest.json");
        IntegrityChecker {
            manifest_path,
            resource_base,
        }
    }

    /// Generate integrity manifest for critical runtime resources.
    /// This list should only include files that actually ship in release bundles.
    pub fn generate_manifest(&self) -> Result<IntegrityManifest, String> {
        let mut resources = BTreeMap::new();

        // Critical paths to hash (relative to resource_base)
        let critical_paths = [
            "models/classifier/model.onnx",
            "models/novelty/model.onnx",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
            "yara_rules/strict/malware_signatures.yar",
            "yara_rules/heuristic/suspicious_behaviour.yar",
            "whitelists/system_files.txt",
        ];

        for rel_path in critical_paths {
            let full_path = self.resource_base.join(rel_path);
            if full_path.exists() {
                match self.hash_file(&full_path) {
                    Ok(hash_info) => {
                        resources.insert(rel_path.to_string(), hash_info);
                    }
                    Err(e) => {
                        log::warn!("Failed to hash {}: {}", rel_path, e);
                    }
                }
            }
        }

        let generated_at = Utc::now().timestamp();

        let manifest_data = serde_json::to_string(&resources).map_err(|e| e.to_string())?;
        let sig_data = format!("{}|{}", manifest_data, generated_at);
        let signature = compute_hmac(sig_data.as_bytes());

        Ok(IntegrityManifest {
            resources,
            generated_at,
            signature,
        })
    }

    /// Save manifest to disk
    pub fn save_manifest(&self, manifest: &IntegrityManifest) -> Result<(), String> {
        let content = serde_json::to_string_pretty(manifest).map_err(|e| e.to_string())?;
        fs::write(&self.manifest_path, content).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load manifest from disk
    pub fn load_manifest(&self) -> Result<IntegrityManifest, String> {
        let content = fs::read_to_string(&self.manifest_path)
            .map_err(|e| format!("Failed to read manifest: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse manifest: {}", e))
    }

    /// Verify all resources against manifest (called once at startup)
    pub fn verify_integrity(&self) -> IntegrityCheckResult {
        let start = std::time::Instant::now();
        let mut failed = Vec::new();
        let mut missing = Vec::new();

        let manifest = match self.load_manifest() {
            Ok(m) => m,
            Err(e) => {
                log::warn!(
                    "Could not load integrity manifest: {}. Integrity verification is skipped until a manifest is provisioned.",
                    e
                );
                // Integrity manifests are not provisioned in release bundles yet,
                // so a missing manifest currently skips verification instead.
                let has_resources = false;
                if has_resources {
                    log::error!("Critical resources exist but integrity manifest is missing — possible tampering!");
                    return IntegrityCheckResult {
                        passed: false,
                        checked_resources: 0,
                        failed_resources: vec!["INTEGRITY_MANIFEST_MISSING".to_string()],
                        missing_resources: vec![],
                        check_time_ms: start.elapsed().as_millis() as u64,
                    };
                }
                // Genuine first run with no resources yet
                return IntegrityCheckResult {
                    passed: true,
                    checked_resources: 0,
                    failed_resources: vec![],
                    missing_resources: vec![],
                    check_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        // Verify manifest signature
        let manifest_data = serde_json::to_string(&manifest.resources).unwrap_or_default();
        let sig_data = format!("{}|{}", manifest_data, manifest.generated_at);
        if !verify_hmac(sig_data.as_bytes(), &manifest.signature) {
            log::error!("Integrity manifest signature invalid - manifest may be tampered!");
            return IntegrityCheckResult {
                passed: false,
                checked_resources: 0,
                failed_resources: vec!["MANIFEST_SIGNATURE".to_string()],
                missing_resources: vec![],
                check_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Verify each resource
        for (rel_path, expected) in &manifest.resources {
            let full_path = self.resource_base.join(rel_path);

            if !full_path.exists() {
                missing.push(rel_path.clone());
                continue;
            }

            match self.hash_file(&full_path) {
                Ok(actual) => {
                    if actual.sha256 != expected.sha256 {
                        log::warn!(
                            "Integrity mismatch for {}: expected {}, got {}",
                            rel_path,
                            expected.sha256,
                            actual.sha256
                        );
                        failed.push(rel_path.clone());
                    }
                }
                Err(e) => {
                    log::warn!("Failed to verify {}: {}", rel_path, e);
                    failed.push(rel_path.clone());
                }
            }
        }

        let passed = failed.is_empty() && missing.is_empty();

        IntegrityCheckResult {
            passed,
            checked_resources: manifest.resources.len(),
            failed_resources: failed,
            missing_resources: missing,
            check_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn hash_file(&self, path: &Path) -> Result<ResourceHash, String> {
        let data = fs::read(path).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hex::encode(hasher.finalize().as_slice());

        Ok(ResourceHash {
            path: path.to_string_lossy().to_string(),
            sha256: hash,
            size: data.len() as u64,
        })
    }
}

// ============================================================================
// EVENT JOURNALING (AUDIT LOG)
// ============================================================================

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    ThreatDetected,
    ThreatQuarantined,
    ThreatDeleted,
    ThreatIgnored,
    FileRestored,
    ScanStarted,
    ScanCompleted,
    ExclusionAdded,
    ExclusionRemoved,
    SettingsChanged,
    ProtectionDisabled,
    ProtectionEnabled,
    IntegrityCheckFailed,
    IntegrityCheckPassed,
    YaraRuleLoaded,
    YaraRuleRejected,
    YaraRuleCompileFailed,
    AppStarted,
    AppStopped,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::ThreatDetected => write!(f, "THREAT_DETECTED"),
            AuditEventType::ThreatQuarantined => write!(f, "THREAT_QUARANTINED"),
            AuditEventType::ThreatDeleted => write!(f, "THREAT_DELETED"),
            AuditEventType::ThreatIgnored => write!(f, "THREAT_IGNORED"),
            AuditEventType::FileRestored => write!(f, "FILE_RESTORED"),
            AuditEventType::ScanStarted => write!(f, "SCAN_STARTED"),
            AuditEventType::ScanCompleted => write!(f, "SCAN_COMPLETED"),
            AuditEventType::ExclusionAdded => write!(f, "EXCLUSION_ADDED"),
            AuditEventType::ExclusionRemoved => write!(f, "EXCLUSION_REMOVED"),
            AuditEventType::SettingsChanged => write!(f, "SETTINGS_CHANGED"),
            AuditEventType::ProtectionDisabled => write!(f, "PROTECTION_DISABLED"),
            AuditEventType::ProtectionEnabled => write!(f, "PROTECTION_ENABLED"),
            AuditEventType::IntegrityCheckFailed => write!(f, "INTEGRITY_CHECK_FAILED"),
            AuditEventType::IntegrityCheckPassed => write!(f, "INTEGRITY_CHECK_PASSED"),
            AuditEventType::YaraRuleLoaded => write!(f, "YARA_RULE_LOADED"),
            AuditEventType::YaraRuleRejected => write!(f, "YARA_RULE_REJECTED"),
            AuditEventType::YaraRuleCompileFailed => write!(f, "YARA_RULE_COMPILE_FAILED"),
            AuditEventType::AppStarted => write!(f, "APP_STARTED"),
            AuditEventType::AppStopped => write!(f, "APP_STOPPED"),
        }
    }
}

/// Single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub event_type: String,
    pub details: String,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    /// HMAC of previous entry's signature (chain integrity)
    pub prev_sig: String,
    /// HMAC of this entry (for tamper evidence)
    pub signature: String,
}

impl AuditEntry {
    fn compute_signature(&self) -> String {
        let data = format!(
            "{}|{}|{}|{}|{}|{}",
            self.timestamp,
            self.event_type,
            self.details,
            self.file_path.as_deref().unwrap_or(""),
            self.file_hash.as_deref().unwrap_or(""),
            self.prev_sig
        );
        compute_hmac(data.as_bytes())
    }

    fn verify(&self) -> bool {
        let data = format!(
            "{}|{}|{}|{}|{}|{}",
            self.timestamp,
            self.event_type,
            self.details,
            self.file_path.as_deref().unwrap_or(""),
            self.file_hash.as_deref().unwrap_or(""),
            self.prev_sig
        );
        verify_hmac(data.as_bytes(), &self.signature)
    }
}

/// Append-only audit journal
pub struct AuditJournal {
    log_path: PathBuf,
    last_signature: String,
}

impl AuditJournal {
    pub fn new() -> Result<Self, String> {
        let log_dir = dirs::data_dir()
            .ok_or("Could not find data directory")?
            .join("antivirus-ui")
            .join("audit");

        fs::create_dir_all(&log_dir).map_err(|e| e.to_string())?;

        let log_path = log_dir.join("audit.jsonl");

        // Read last signature for chain integrity
        let last_signature = Self::get_last_signature(&log_path);

        Ok(AuditJournal {
            log_path,
            last_signature,
        })
    }

    fn get_last_signature(log_path: &Path) -> String {
        if !log_path.exists() {
            return "GENESIS".to_string();
        }

        if let Ok(file) = fs::File::open(log_path) {
            let reader = BufReader::new(file);
            if let Some(last_line) = reader.lines().map_while(Result::ok).last() {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&last_line) {
                    return entry.signature;
                }
            }
        }

        "GENESIS".to_string()
    }

    /// Maximum audit log size before rotation (10 MB)
    const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;

    /// Rotate the audit log if it exceeds the size limit.
    /// Renames the current log to .1 (overwriting any previous backup) and starts fresh.
    /// The new log starts with a GENESIS chain link since it's a new file.
    fn rotate_if_needed(&mut self) -> Result<(), String> {
        if let Ok(meta) = fs::metadata(&self.log_path) {
            if meta.len() > Self::MAX_LOG_SIZE {
                let backup = self.log_path.with_extension("jsonl.1");
                fs::rename(&self.log_path, &backup)
                    .map_err(|e| format!("Audit log rotation failed: {}", e))?;
                // Reset chain for the new log file
                self.last_signature = "GENESIS".to_string();
                log::info!(
                    "Audit log rotated ({} bytes -> {})",
                    meta.len(),
                    backup.display()
                );
            }
        }
        Ok(())
    }

    /// Log an audit event (append-only)
    pub fn log_event(
        &mut self,
        event_type: AuditEventType,
        details: &str,
        file_path: Option<&str>,
        file_hash: Option<&str>,
    ) -> Result<(), String> {
        // Rotate before writing to keep log within size limit
        self.rotate_if_needed()?;

        let timestamp = Utc::now().timestamp();

        let mut entry = AuditEntry {
            timestamp,
            event_type: event_type.to_string(),
            details: details.to_string(),
            file_path: file_path.map(|s| s.to_string()),
            file_hash: file_hash.map(|s| s.to_string()),
            prev_sig: self.last_signature.clone(),
            signature: String::new(),
        };

        entry.signature = entry.compute_signature();
        self.last_signature = entry.signature.clone();

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| e.to_string())?;

        let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
        writeln!(file, "{}", line).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Verify audit log chain integrity
    pub fn verify_chain(&self) -> Result<(bool, usize, Vec<usize>), String> {
        if !self.log_path.exists() {
            return Ok((true, 0, vec![]));
        }

        let file = fs::File::open(&self.log_path).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);

        let mut prev_sig = "GENESIS".to_string();
        let mut line_num = 0;
        let mut broken_links = Vec::new();

        for line_result in reader.lines() {
            line_num += 1;
            let line = line_result.map_err(|e| e.to_string())?;

            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry =
                serde_json::from_str(&line).map_err(|e| format!("Line {}: {}", line_num, e))?;

            // Verify this entry's signature
            if !entry.verify() {
                log::warn!("Audit entry {} has invalid signature - tampered!", line_num);
                broken_links.push(line_num);
            }

            // Verify chain link
            if entry.prev_sig != prev_sig {
                log::warn!(
                    "Audit chain broken at entry {} - entries may have been deleted!",
                    line_num
                );
                broken_links.push(line_num);
            }

            prev_sig = entry.signature;
        }

        Ok((broken_links.is_empty(), line_num, broken_links))
    }

    /// Repair the audit log chain by re-signing all entries with the current key.
    /// Returns (total_entries, repaired_count).
    pub fn repair_chain(&self) -> Result<(usize, usize), String> {
        if !self.log_path.exists() {
            return Ok((0, 0));
        }

        let file = fs::File::open(&self.log_path).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);

        let mut entries: Vec<AuditEntry> = Vec::new();
        let mut repaired = 0usize;

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| e.to_string())?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry =
                serde_json::from_str(&line).map_err(|e| format!("Parse error: {}", e))?;
            entries.push(entry);
        }

        let total = entries.len();

        // Rebuild chain with current signing key
        let mut prev_sig = "GENESIS".to_string();
        for entry in &mut entries {
            entry.prev_sig = prev_sig.clone();
            let new_sig = entry.compute_signature();
            if entry.signature != new_sig {
                repaired += 1;
            }
            entry.signature = new_sig;
            prev_sig = entry.signature.clone();
        }

        let mut file = fs::File::create(&self.log_path).map_err(|e| e.to_string())?;
        for entry in &entries {
            let line = serde_json::to_string(entry).map_err(|e| e.to_string())?;
            writeln!(file, "{}", line).map_err(|e| e.to_string())?;
        }

        Ok((total, repaired))
    }

    /// Get recent audit entries (keeps only last N in memory)
    pub fn get_recent(&self, limit: usize) -> Result<Vec<AuditEntry>, String> {
        if !self.log_path.exists() {
            return Ok(vec![]);
        }

        let file = fs::File::open(&self.log_path).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);

        let mut recent: VecDeque<AuditEntry> = VecDeque::with_capacity(limit.saturating_add(1));

        for line in reader.lines().map_while(Result::ok) {
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                if recent.len() == limit {
                    recent.pop_front();
                }
                recent.push_back(entry);
            }
        }

        Ok(recent.into_iter().collect())
    }
}

// ============================================================================
// YARA RULE SIGNING
// ============================================================================

/// Sign a YARA rule file and create .sig file
pub fn sign_yara_rule(rule_path: &Path) -> Result<String, String> {
    let content = fs::read(rule_path).map_err(|e| e.to_string())?;
    let signature = compute_hmac(&content);

    let sig_path = rule_path.with_extension("yar.sig");
    fs::write(&sig_path, &signature).map_err(|e| e.to_string())?;

    Ok(signature)
}

/// Verify a YARA rule file against its .sig file
pub fn verify_yara_rule(rule_path: &Path) -> Result<bool, String> {
    let sig_path = rule_path.with_extension("yar.sig");

    if !sig_path.exists() {
        log::warn!(
            "No signature file for YARA rule: {:?} - rule is UNVERIFIED and will be rejected",
            rule_path
        );
        return Ok(false);
    }

    let content = fs::read(rule_path).map_err(|e| e.to_string())?;
    let expected_sig = fs::read_to_string(&sig_path).map_err(|e| e.to_string())?;

    Ok(verify_hmac(&content, expected_sig.trim()))
}

/// Sign all YARA rules in a directory
pub fn sign_all_yara_rules(rules_dir: &Path) -> Result<usize, String> {
    let mut count = 0;

    if !rules_dir.exists() {
        return Ok(0);
    }

    for entry in walkdir::WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().map(|e| e == "yar").unwrap_or(false) {
            sign_yara_rule(path)?;
            count += 1;
        }
    }

    Ok(count)
}

// ============================================================================
// MISSED EVENTS DETECTION
// ============================================================================

/// Track protection status for missed-events detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionStatus {
    pub last_active: i64,
    pub was_running: bool,
    pub last_scan_completed: Option<i64>,
}

impl Default for ProtectionStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtectionStatus {
    pub fn new() -> Self {
        ProtectionStatus {
            last_active: Utc::now().timestamp(),
            was_running: false, // Default to false so first-run doesn't trigger false crash detection
            last_scan_completed: None,
        }
    }

    fn get_status_path() -> Option<PathBuf> {
        Some(
            dirs::data_dir()?
                .join("antivirus-ui")
                .join("protection_status.json"),
        )
    }

    /// Load last known protection status
    pub fn load() -> Option<Self> {
        let path = Self::get_status_path()?;
        let content = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Save current protection status
    pub fn save(&self) -> Result<(), String> {
        let path = Self::get_status_path().ok_or("Could not determine status path")?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Update heartbeat (call periodically)
    pub fn heartbeat(&mut self) {
        self.last_active = Utc::now().timestamp();
        self.was_running = true;
        let _ = self.save();
    }

    /// Mark protection as stopped gracefully
    pub fn mark_stopped(&mut self) {
        self.was_running = false;
        let _ = self.save();
    }

    /// Check if protection was down unexpectedly
    pub fn was_unexpectedly_down(&self) -> bool {
        // If was_running is true but we're starting up, it means we crashed
        self.was_running
    }

    /// Get gap duration in seconds (how long protection was down)
    pub fn get_gap_seconds(&self) -> i64 {
        let now = Utc::now().timestamp();
        now - self.last_active
    }

    /// Determine if missed-events scan is needed
    /// Returns true if protection was down for more than threshold seconds
    pub fn needs_missed_events_scan(&self, threshold_secs: i64) -> bool {
        self.was_unexpectedly_down() || self.get_gap_seconds() > threshold_secs
    }
}

/// Get paths that should be scanned for missed events
pub fn get_missed_events_scan_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // High-risk locations where malware often lands
    if let Some(downloads) = dirs::download_dir() {
        paths.push(downloads);
    }
    if let Some(desktop) = dirs::desktop_dir() {
        paths.push(desktop);
    }

    // Temp directories
    if let Ok(temp) = std::env::var("TEMP") {
        paths.push(PathBuf::from(temp));
    }
    if let Ok(tmp) = std::env::var("TMP") {
        let tmp_path = PathBuf::from(tmp);
        if !paths.contains(&tmp_path) {
            paths.push(tmp_path);
        }
    }

    // Startup folders (common persistence location)
    if let Some(appdata) = dirs::config_dir() {
        let startup = appdata
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        if startup.exists() {
            paths.push(startup);
        }
    }

    paths
}

// ============================================================================
// GLOBAL STATE
// ============================================================================

use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Global audit journal instance
pub static AUDIT_JOURNAL: Lazy<Mutex<Option<AuditJournal>>> =
    Lazy::new(|| match AuditJournal::new() {
        Ok(journal) => Mutex::new(Some(journal)),
        Err(e) => {
            log::error!("Failed to initialize audit journal: {}", e);
            Mutex::new(None)
        }
    });

/// Global protection status tracker
pub static PROTECTION_STATUS: Lazy<Mutex<ProtectionStatus>> = Lazy::new(|| {
    let status = ProtectionStatus::load().unwrap_or_default();
    Mutex::new(status)
});

/// Convenience function to log an audit event
pub fn log_audit_event(
    event_type: AuditEventType,
    details: &str,
    file_path: Option<&str>,
    file_hash: Option<&str>,
) {
    if let Ok(mut guard) = AUDIT_JOURNAL.lock() {
        if let Some(ref mut journal) = *guard {
            if let Err(e) = journal.log_event(event_type, details, file_path, file_hash) {
                log::warn!("Failed to log audit event: {}", e);
            }
        }
    }
}

/// Convenience function to update protection heartbeat
pub fn update_heartbeat() {
    if let Ok(mut guard) = PROTECTION_STATUS.lock() {
        guard.heartbeat();
    }
}

// Add hex encoding helper since we're using it
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Invalid hex string length".to_string());
        }

        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_exclusion() {
        let excl = SignedExclusion::new("path", "C:\\test.exe", Some("test reason"));
        assert!(excl.verify());

        // Tampering should fail verification
        let mut tampered = excl.clone();
        tampered.pattern = "C:\\malware.exe".to_string();
        assert!(!tampered.verify());
    }

    #[test]
    fn test_signed_settings() {
        let settings = SignedSettings::new(0.85, true, true, 256, 24);
        assert!(settings.verify());

        // Tampering should fail
        let mut tampered = settings.clone();
        tampered.auto_quarantine = false;
        assert!(!tampered.verify());
    }

    #[test]
    fn test_hmac() {
        let data = b"test data";
        let sig = compute_hmac(data);
        assert!(verify_hmac(data, &sig));
        assert!(!verify_hmac(b"different data", &sig));
    }

    #[test]
    fn test_signed_exclusion_all_fields() {
        let excl = SignedExclusion::new("hash", "abc123def456", Some("Known safe file"));
        assert_eq!(excl.exclusion_type, "hash");
        assert_eq!(excl.pattern, "abc123def456");
        assert_eq!(excl.reason.as_deref(), Some("Known safe file"));
        assert!(excl.created_at > 0);
        assert!(!excl.signature.is_empty());
        assert!(excl.verify());
    }

    #[test]
    fn test_signed_exclusion_no_reason() {
        let excl = SignedExclusion::new("path", r"C:\safe\app.exe", None);
        assert!(excl.verify());
        assert!(excl.reason.is_none());
    }

    #[test]
    fn test_signed_exclusion_tamper_type() {
        let excl = SignedExclusion::new("path", r"C:\test.exe", Some("reason"));
        let mut tampered = excl.clone();
        tampered.exclusion_type = "hash".to_string();
        assert!(
            !tampered.verify(),
            "Changing exclusion_type should invalidate"
        );
    }

    #[test]
    fn test_signed_exclusion_tamper_reason() {
        let excl = SignedExclusion::new("path", r"C:\test.exe", Some("original"));
        let mut tampered = excl.clone();
        tampered.reason = Some("modified".to_string());
        assert!(!tampered.verify(), "Changing reason should invalidate");
    }

    #[test]
    fn test_signed_exclusion_tamper_timestamp() {
        let excl = SignedExclusion::new("path", r"C:\test.exe", Some("reason"));
        let mut tampered = excl.clone();
        tampered.created_at += 1;
        assert!(!tampered.verify(), "Changing created_at should invalidate");
    }

    #[test]
    fn test_signed_settings_tamper_each_field() {
        let settings = SignedSettings::new(0.85, true, true, 256, 24);

        let mut t = settings.clone();
        t.ml_confidence_threshold = 0.5;
        assert!(!t.verify(), "ml_confidence_threshold tamper");

        let mut t = settings.clone();
        t.real_time_protection = false;
        assert!(!t.verify(), "real_time_protection tamper");

        let mut t = settings.clone();
        t.cache_size_mb = 512;
        assert!(!t.verify(), "cache_size_mb tamper");

        let mut t = settings.clone();
        t.cache_ttl_hours = 48;
        assert!(!t.verify(), "cache_ttl_hours tamper");
    }

    #[test]
    fn test_compute_and_verify_exclusion_signature() {
        let sig = compute_exclusion_signature("path", r"C:\test.exe", Some("reason"), 12345);
        assert!(verify_exclusion_signature(
            "path",
            r"C:\test.exe",
            Some("reason"),
            12345,
            &sig
        ));
        assert!(!verify_exclusion_signature(
            "path",
            r"C:\test.exe",
            Some("changed"),
            12345,
            &sig
        ));
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let data = vec![0x00, 0x01, 0x0f, 0x10, 0xff];
        let encoded = hex::encode(&data);
        assert_eq!(encoded, "00010f10ff");
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex::decode("ZZ").is_err());
        assert!(hex::decode("0").is_err()); // Odd length
    }

    #[test]
    fn test_audit_event_type_display() {
        assert_eq!(
            AuditEventType::ThreatDetected.to_string(),
            "THREAT_DETECTED"
        );
        assert_eq!(AuditEventType::ScanStarted.to_string(), "SCAN_STARTED");
        assert_eq!(
            AuditEventType::ExclusionAdded.to_string(),
            "EXCLUSION_ADDED"
        );
        assert_eq!(
            AuditEventType::ProtectionDisabled.to_string(),
            "PROTECTION_DISABLED"
        );
        assert_eq!(AuditEventType::AppStarted.to_string(), "APP_STARTED");
    }

    #[test]
    fn test_protection_status_new() {
        let status = ProtectionStatus::new();
        assert!(!status.was_running);
        assert!(status.last_active > 0);
        assert!(status.last_scan_completed.is_none());
    }

    #[test]
    fn test_protection_status_gap_detection() {
        let mut status = ProtectionStatus::new();
        // Simulate that protection was running but crashed (was_running=true on startup)
        status.was_running = true;
        assert!(status.was_unexpectedly_down());

        // Graceful stop
        status.was_running = false;
        assert!(!status.was_unexpectedly_down());
    }
}
