//! Quarantine Management
//! Handles encryption, storage, and recovery of quarantined files

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use keyring::Entry as KeyringEntry;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use tempfile::NamedTempFile;

use crate::core::threat_neutralizer::{NeutralizationResult, ThreatNeutralizer};

/// Cached encryption key - avoids re-running Argon2 KDF (~500ms) on every
/// quarantine/restore/delete operation.  Safe for the app lifetime because the
/// key material (password, keyring entry, or generated key) doesn't change.
static ENCRYPTION_KEY_CACHE: OnceLock<[u8; 32]> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: i64,
    pub file_hash: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub verdict: String,
    pub threat_level: String,
    pub reason: String,
    pub quarantined_at: i64,
    pub restored_at: Option<i64>,
    pub permanently_deleted: bool,
    pub file_size: u64,
    pub file_type: String,
    /// Details about threat neutralization performed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neutralization_result: Option<NeutralizationResult>,
}

/// Extended quarantine result that includes both the entry and neutralization details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineResult {
    pub entry: QuarantineEntry,
    pub neutralization: NeutralizationResult,
    /// Whether the file was successfully quarantined (may succeed even if neutralization had warnings)
    pub quarantine_success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::tempdir;

    #[test]
    #[serial]
    fn quarantine_roundtrip_encrypt_decrypt() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let src = dir.path().join("plain.bin");
        let data = b"secret-data-123";
        std::fs::write(&src, data).unwrap();

        let qm = QuarantineManager::new(base);
        let test_hash = "testhash12345678aabbccdd00112233";

        let result = qm
            .quarantine_file(
                src.to_str().unwrap(),
                test_hash,
                "malware",
                "high",
                "unit-test",
            )
            .expect("quarantine should succeed");

        // Verify encrypted file exists in vault
        assert!(Path::new(&result.entry.quarantine_path).exists());
        // Verify meta file exists alongside it
        let meta_path = format!("{}.meta", result.entry.quarantine_path);
        assert!(Path::new(&meta_path).exists());

        // Original should be gone
        assert!(!src.exists());

        qm.restore_file(&result.entry)
            .expect("restore should succeed");

        let restored = std::fs::read(&src).expect("restored file exists");
        assert_eq!(restored.as_slice(), data);
    }

    #[test]
    #[serial]
    fn quarantine_includes_neutralization_result() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let src = dir.path().join("test_malware.exe");
        std::fs::write(&src, b"fake malware content").unwrap();

        let qm = QuarantineManager::new(base);
        let result = qm
            .quarantine_file(
                src.to_str().unwrap(),
                "abc12345aabbccdd",
                "malware",
                "high",
                "test",
            )
            .expect("quarantine should succeed");

        assert!(result.neutralization.success || !result.neutralization.warnings.is_empty());
        assert!(result.quarantine_success);
    }

    #[test]
    #[serial]
    fn quarantine_aad_prevents_swap() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let src = dir.path().join("file_a.bin");
        std::fs::write(&src, b"file-a-content").unwrap();

        let qm = QuarantineManager::new(base);
        let result = qm
            .quarantine_file(
                src.to_str().unwrap(),
                "aaaa1111bbbb2222",
                "malware",
                "high",
                "test",
            )
            .expect("quarantine should succeed");

        // Tamper with metadata: change original_path (should break AAD)
        let mut tampered_entry = result.entry.clone();
        tampered_entry.original_path = "/some/other/path.exe".to_string();

        let restore_result = qm.restore_file(&tampered_entry);
        assert!(
            restore_result.is_err(),
            "Restore should fail when AAD doesn't match (metadata tampered)"
        );
    }

    #[test]
    #[serial]
    fn quarantine_unique_filenames_no_collision() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();

        // Create two files with same hash prefix
        let src1 = dir.path().join("file1.bin");
        let src2 = dir.path().join("file2.bin");
        std::fs::write(&src1, b"content-1").unwrap();
        std::fs::write(&src2, b"content-2").unwrap();

        let qm = QuarantineManager::new(base);

        // Same first 8 chars of hash
        let r1 = qm
            .quarantine_file(
                src1.to_str().unwrap(),
                "aabbccdd11111111",
                "malware",
                "high",
                "test1",
            )
            .expect("first quarantine should succeed");
        let r2 = qm
            .quarantine_file(
                src2.to_str().unwrap(),
                "aabbccdd22222222",
                "malware",
                "high",
                "test2",
            )
            .expect("second quarantine should succeed");

        // Vault paths should be different
        assert_ne!(r1.entry.quarantine_path, r2.entry.quarantine_path);
    }

    #[test]
    #[serial]
    fn skip_neutralization_option_works() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let src = dir.path().join("skip_test.exe");
        std::fs::write(&src, b"test content").unwrap();

        let qm = QuarantineManager::new(base);
        let options = QuarantineOptions::new().skip_neutralization();

        let result = qm
            .quarantine_file_with_options(
                src.to_str().unwrap(),
                "skip1234aabbccdd",
                "suspicious",
                "medium",
                "test",
                options,
            )
            .expect("quarantine with skip should succeed");

        assert!(result.quarantine_success);
        // Neutralization should be empty/default when skipped
        assert!(result.neutralization.processes_killed.is_empty());
        assert!(result.neutralization.persistence_removed.is_empty());
    }
}

pub struct QuarantineManager {
    vault_path: String,
    metadata_path: String,
}

#[derive(Serialize, Deserialize)]
struct QuarantineMeta {
    version: u8,
    alg: String,
    nonce_b64: String,
    /// AAD used for authenticated encryption - binds ciphertext to file identity.
    /// Format: "{file_hash}|{original_path}|{quarantined_at}"
    /// If someone swaps vault files or tampers with metadata, decryption fails.
    aad_b64: Option<String>,
    created_at: i64,
}

/// Generate a unique vault filename that avoids collisions.
/// Uses first 16 chars of hash + timestamp to be both identifiable and unique.
fn make_vault_stem(file_hash: &str, quarantined_at: i64) -> String {
    let hash_prefix: String = file_hash
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(16)
        .collect();

    if hash_prefix.is_empty() {
        format!("{}", quarantined_at)
    } else {
        format!("{}-{}", hash_prefix, quarantined_at)
    }
}

/// Build AAD string that binds ciphertext to the file's identity.
/// This prevents vault file swaps - if someone moves encrypted blobs
/// around or tampers with metadata, AES-GCM decryption will fail.
fn build_aad(file_hash: &str, original_path: &str, quarantined_at: i64) -> Vec<u8> {
    format!("{}|{}|{}", file_hash, original_path, quarantined_at).into_bytes()
}

impl QuarantineManager {
    pub fn new(base_path: &str) -> Self {
        let qm = QuarantineManager {
            vault_path: format!("{}/vault", base_path),
            metadata_path: format!("{}/metadata", base_path),
        };

        if let Err(e) = fs::create_dir_all(&qm.metadata_path) {
            log::warn!("Failed to create metadata path {}: {}", qm.metadata_path, e);
        } else {
            let salt_file = Path::new(&qm.metadata_path).join("master_salt");
            if !salt_file.exists() {
                let mut salt_bytes = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut salt_bytes);
                if let Err(e) = fs::write(&salt_file, salt_bytes) {
                    log::warn!("Failed to write master_salt: {}", e);
                }
            }
        }

        qm
    }

    /// Quarantine a file with full threat neutralization.
    ///
    /// For manual/dashboard quarantine, prefer `quarantine_file_with_options`
    /// with `skip_neutralization()` to avoid the process-kill + persistence-cleanup
    /// overhead (~500ms+ sleep + system enumeration).
    pub fn quarantine_file(
        &self,
        file_path: &str,
        file_hash: &str,
        verdict: &str,
        threat_level: &str,
        reason: &str,
    ) -> Result<QuarantineResult, Box<dyn std::error::Error>> {
        self.quarantine_file_with_options(
            file_path,
            file_hash,
            verdict,
            threat_level,
            reason,
            QuarantineOptions::new(),
        )
    }

    fn read_with_retry(
        path: &str,
        max_attempts: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut last_error = None;

        for attempt in 0..max_attempts {
            match fs::read(path) {
                Ok(content) => return Ok(content),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < max_attempts - 1 {
                        log::debug!("File read attempt {} failed, retrying...", attempt + 1);
                        std::thread::sleep(std::time::Duration::from_millis(
                            200 * (attempt as u64 + 1),
                        ));
                    }
                }
            }
        }

        Err(format!(
            "Failed to read file after {} attempts: {}",
            max_attempts,
            last_error.unwrap()
        )
        .into())
    }

    pub fn quarantine_file_with_options(
        &self,
        file_path: &str,
        file_hash: &str,
        verdict: &str,
        threat_level: &str,
        reason: &str,
        options: QuarantineOptions,
    ) -> Result<QuarantineResult, Box<dyn std::error::Error>> {
        // ============================================
        // STEP 1: NEUTRALIZE THE THREAT (if enabled)
        // ============================================
        let neutralization = if options.skip_neutralization {
            log::info!("Skipping threat neutralization as requested");
            NeutralizationResult::default()
        } else {
            log::info!("Beginning threat neutralization for: {}", file_path);
            let result = ThreatNeutralizer::neutralize(file_path);

            if !result.processes_killed.is_empty() {
                log::info!(
                    "Killed {} processes before quarantine: {:?}",
                    result.processes_killed.len(),
                    result
                        .processes_killed
                        .iter()
                        .map(|p| format!("{}({})", p.name, p.pid))
                        .collect::<Vec<_>>()
                );
            }

            if !result.persistence_removed.is_empty() {
                log::info!(
                    "Removed {} persistence entries: {:?}",
                    result.persistence_removed.len(),
                    result
                        .persistence_removed
                        .iter()
                        .map(|p| format!("{:?}:{}", p.persistence_type, p.location))
                        .collect::<Vec<_>>()
                );
            }

            for warning in &result.warnings {
                log::warn!("Neutralization warning: {}", warning);
            }

            result
        };

        // ============================================
        // STEP 2: QUARANTINE THE FILE
        // ============================================

        // Wait for processes to release file handles after kill
        if neutralization.processes_killed.len() > 5 {
            std::thread::sleep(std::time::Duration::from_millis(1000));
        } else if !neutralization.processes_killed.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        let file_content = Self::read_with_retry(file_path, options.read_retry_count)?;
        let file_metadata = fs::metadata(file_path)?;

        let key_bytes = match self.get_or_create_encryption_key() {
            Ok(k) => k,
            Err(e) => {
                log::error!(
                    "CRITICAL: Failed to obtain persistent quarantine key: {}. \
                    Quarantine operation aborted to prevent data loss. \
                    Set QUARANTINE_MASTER_PASSWORD env var or fix OS keyring access.",
                    e
                );
                return Err(format!(
                    "Cannot quarantine file: encryption key unavailable ({}). \
                    Set QUARANTINE_MASTER_PASSWORD environment variable or ensure OS keyring is accessible.",
                    e
                ).into());
            }
        };
        #[allow(deprecated)]
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from(nonce_bytes);

        let quarantined_at = chrono::Utc::now().timestamp();

        // FIX: Build AAD that binds ciphertext to file identity (hash + path + time).
        // This prevents vault file swap attacks - if someone rearranges encrypted
        // blobs or tampers with metadata, AES-GCM decryption will fail.
        let aad = build_aad(file_hash, file_path, quarantined_at);

        let encrypted_data = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &file_content,
                    aad: &aad,
                },
            )
            .map_err(|e| format!("Encryption failed: {}", e))?;

        fs::create_dir_all(&self.vault_path)?;
        let vault_dir = Path::new(&self.vault_path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(&self.vault_path));

        // FIX: Use hash prefix + timestamp for unique vault filenames.
        // Old approach used only first 8 chars of hash, which was collision-prone -
        // two files with similar hashes would overwrite each other in the vault.
        let stem = make_vault_stem(file_hash, quarantined_at);
        let quarantine_filename = format!("{}.enc", stem);
        let final_path = vault_dir.join(&quarantine_filename);

        let final_parent = final_path
            .parent()
            .ok_or("quarantine destination has no parent")?;
        let canon_final_parent = final_parent
            .canonicalize()
            .unwrap_or_else(|_| final_parent.to_path_buf());
        if !canon_final_parent.starts_with(&vault_dir) {
            return Err("quarantine destination escapes vault directory".into());
        }

        let tmp_name = format!(".tmp-{}-{}", stem, rand::random::<u64>());
        let tmp_path = vault_dir.join(&tmp_name);
        {
            let mut tmpf = fs::File::create(&tmp_path)?;
            tmpf.write_all(&encrypted_data)?;
            tmpf.flush()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        let quarantine_path = final_path.to_string_lossy().to_string();

        // FIX: Store AAD in metadata so restore can reconstruct it for decryption.
        // Also use explicit "{stem}.enc.meta" path construction instead of
        // with_extension() which can produce wrong results on edge-case filenames.
        let meta = QuarantineMeta {
            version: 2, // bumped: now includes AAD
            alg: "AES-256-GCM".to_string(),
            nonce_b64: general_purpose::STANDARD.encode(nonce_bytes),
            aad_b64: Some(general_purpose::STANDARD.encode(&aad)),
            created_at: quarantined_at,
        };
        let meta_path = vault_dir.join(format!("{}.enc.meta", stem));
        let meta_json = serde_json::to_vec_pretty(&meta)?;
        {
            let meta_parent = meta_path.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "metadata path has no parent",
                )
            })?;
            let mut tmpm = NamedTempFile::new_in(meta_parent)?;
            tmpm.write_all(&meta_json)?;
            tmpm.flush()?;
            tmpm.persist(&meta_path)?;
        }

        let entry = QuarantineEntry {
            id: quarantined_at, // NOTE: caller should replace with DB-assigned id
            file_hash: file_hash.to_string(),
            original_path: file_path.to_string(),
            quarantine_path: quarantine_path.clone(),
            verdict: verdict.to_string(),
            threat_level: threat_level.to_string(),
            reason: reason.to_string(),
            quarantined_at,
            restored_at: None,
            permanently_deleted: false,
            file_size: file_metadata.len(),
            file_type: Path::new(file_path)
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("unknown")
                .to_string(),
            neutralization_result: Some(neutralization.clone()),
        };

        fs::create_dir_all(&self.metadata_path)?;
        let meta_dir = Path::new(&self.metadata_path);
        let meta_file = meta_dir.join(format!("{}.json", stem));
        fs::write(&meta_file, serde_json::to_string_pretty(&entry)?)?;
        fs::remove_file(file_path)?;

        log::info!(
            "Successfully quarantined {} (killed {} processes, removed {} persistence entries)",
            file_path,
            neutralization.processes_killed.len(),
            neutralization.persistence_removed.len()
        );

        Ok(QuarantineResult {
            entry,
            neutralization,
            quarantine_success: true,
        })
    }

    pub fn restore_file(
        &self,
        quarantine_entry: &QuarantineEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let orig_path = Path::new(&quarantine_entry.original_path);

        let path_str = quarantine_entry.original_path.as_str();
        if path_str.contains("..") || path_str.contains("\\..") || path_str.contains("../") {
            return Err("Invalid restore path: path traversal detected".into());
        }

        if !orig_path.is_absolute() {
            return Err("Invalid restore path: must be absolute".into());
        }

        let forbidden_prefixes = [
            "/etc",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
            "/boot",
            "/lib",
            "/proc",
            "/sys",
            "C:\\Windows",
            "C:\\Program Files",
            "C:\\ProgramData",
        ];
        for prefix in &forbidden_prefixes {
            if path_str.to_lowercase().starts_with(&prefix.to_lowercase()) {
                return Err(format!("Cannot restore to protected system path: {}", prefix).into());
            }
        }

        let encrypted_content = fs::read(&quarantine_entry.quarantine_path)?;

        // FIX: Derive meta path explicitly instead of using with_extension(),
        // which can produce wrong results if quarantine_path has unusual extensions.
        let meta_path = PathBuf::from(format!("{}.meta", quarantine_entry.quarantine_path));

        // Fallback for old-format entries: try with_extension if explicit path doesn't exist
        let meta_path = if meta_path.exists() {
            meta_path
        } else {
            let fallback = Path::new(&quarantine_entry.quarantine_path).with_extension("enc.meta");
            if fallback.exists() {
                fallback
            } else {
                return Err(format!(
                    "Encryption metadata not found at {} or fallback",
                    meta_path.display()
                )
                .into());
            }
        };

        let meta_json = fs::read_to_string(&meta_path)?;
        let meta: QuarantineMeta = serde_json::from_str(&meta_json)?;

        let key_bytes = self.get_or_create_encryption_key()?;
        #[allow(deprecated)]
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let nonce_bytes = general_purpose::STANDARD.decode(&meta.nonce_b64)?;
        if nonce_bytes.len() != 12 {
            return Err("invalid nonce length".into());
        }
        let mut nb = [0u8; 12];
        nb.copy_from_slice(&nonce_bytes);
        let nonce = aes_gcm::Nonce::from(nb);

        // FIX: Decrypt with AAD if present (v2+ entries).
        // For v1 entries (no AAD), fall back to plain decryption for backward compat.
        let decrypted = if let Some(ref aad_b64) = meta.aad_b64 {
            let aad = general_purpose::STANDARD.decode(aad_b64)?;
            cipher.decrypt(
                &nonce,
                Payload {
                    msg: encrypted_content.as_ref(),
                    aad: &aad,
                },
            ).map_err(|e| format!(
                "Decryption failed (AAD mismatch - metadata or vault file may have been tampered with): {}", e
            ))?
        } else {
            // v1 backward compatibility: no AAD was used
            cipher
                .decrypt(&nonce, encrypted_content.as_ref())
                .map_err(|e| format!("Decryption failed: {}", e))?
        };

        let orig_path = Path::new(&quarantine_entry.original_path);
        if let Some(parent) = orig_path.parent() {
            fs::create_dir_all(parent)?;
            let tmp_name = format!(
                ".tmp-restore-{}-{}",
                quarantine_entry.file_hash.get(0..8).unwrap_or(""),
                rand::random::<u64>()
            );
            let tmp_path = parent.join(&tmp_name);
            {
                let mut tf = fs::File::create(&tmp_path)?;
                tf.write_all(&decrypted)?;
                tf.flush()?;
            }
            fs::rename(&tmp_path, orig_path)?;
        } else {
            fs::write(orig_path, &decrypted)?;
        }

        // Update entry metadata JSON if it exists
        // Use the stem from quarantine_path filename for consistency
        if let Some(enc_name) = Path::new(&quarantine_entry.quarantine_path).file_stem() {
            let stem = enc_name.to_string_lossy();
            let meta_dir = Path::new(&self.metadata_path);
            let meta_file = meta_dir.join(format!("{}.json", stem));
            if meta_file.exists() {
                if let Ok(content) = fs::read_to_string(&meta_file) {
                    if let Ok(mut qe) = serde_json::from_str::<QuarantineEntry>(&content) {
                        qe.restored_at = Some(chrono::Utc::now().timestamp());
                        let _ = fs::write(
                            &meta_file,
                            serde_json::to_string_pretty(&qe).unwrap_or_default(),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    pub fn delete_file(
        &self,
        quarantine_entry: &QuarantineEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::remove_file(&quarantine_entry.quarantine_path)?;

        // Clean up associated metadata files using the vault filename stem
        if let Some(enc_name) = Path::new(&quarantine_entry.quarantine_path).file_stem() {
            let stem = enc_name.to_string_lossy();

            // Entry metadata JSON
            let meta_file = Path::new(&self.metadata_path).join(format!("{}.json", stem));
            if meta_file.exists() {
                let _ = fs::remove_file(meta_file);
            }
        }

        // Encryption metadata (sits alongside .enc file)
        let enc_meta = PathBuf::from(format!("{}.meta", quarantine_entry.quarantine_path));
        if enc_meta.exists() {
            let _ = fs::remove_file(&enc_meta);
        }
        // Fallback: old format
        let enc_meta_old = Path::new(&quarantine_entry.quarantine_path).with_extension("enc.meta");
        if enc_meta_old.exists() {
            let _ = fs::remove_file(enc_meta_old);
        }

        Ok(())
    }

    pub fn list_quarantined(&self) -> Result<Vec<QuarantineEntry>, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();

        if !Path::new(&self.metadata_path).exists() {
            return Ok(entries);
        }

        for entry in fs::read_dir(&self.metadata_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "json") {
                let content = fs::read_to_string(&path)?;
                if let Ok(qe) = serde_json::from_str::<QuarantineEntry>(&content) {
                    entries.push(qe);
                }
            }
        }

        Ok(entries)
    }

    /// Public wrapper to pre-warm the encryption key cache at startup.
    /// Calling this early avoids a ~500ms Argon2 KDF penalty on the first
    /// quarantine or restore operation.
    pub fn warm_encryption_key(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.get_or_create_encryption_key()?;
        Ok(())
    }

    fn get_or_create_encryption_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        // Return cached key if available - avoids re-running Argon2 KDF
        // (~500ms with 15 MB memory cost) on every quarantine operation.
        if let Some(key) = ENCRYPTION_KEY_CACHE.get() {
            return Ok(*key);
        }

        // 1) Password-based KDF
        if let Ok(pw) = std::env::var("QUARANTINE_MASTER_PASSWORD") {
            let salt_file = Path::new(&self.metadata_path).join("master_salt");
            let salt_bytes: Vec<u8> = fs::read(&salt_file).unwrap_or_else(|_| {
                let mut s = vec![0u8; 16];
                rand::thread_rng().fill_bytes(&mut s);
                s
            });
            let mem_kib: u32 = std::env::var("QUARANTINE_ARGON2_MEM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15000);
            let t_cost: u32 = std::env::var("QUARANTINE_ARGON2_ITER")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3);
            let p_cost: u32 = std::env::var("QUARANTINE_ARGON2_PARALLEL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1);
            let params = Params::new(mem_kib, t_cost, p_cost, None)
                .map_err(|e| format!("invalid argon2 params: {}", e))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = [0u8; 32];
            argon2
                .hash_password_into(pw.as_bytes(), &salt_bytes, &mut key)
                .map_err(|e| format!("argon2 derive failed: {}", e))?;
            let _ = ENCRYPTION_KEY_CACHE.set(key);
            return Ok(key);
        }

        // 2) OS keyring or CI-friendly file fallback
        let disable_keyring = std::env::var("QUARANTINE_DISABLE_KEYRING")
            .map(|v| v == "1")
            .unwrap_or(false);
        let running_in_ci = std::env::var("CI").is_ok();
        let prefer_keyring = !disable_keyring && !running_in_ci;

        let keystore_file = Path::new(&self.metadata_path).join("quarantine_key.b64");

        if prefer_keyring {
            let entry = KeyringEntry::new("antivirus_ui", "quarantine_key");
            if let Ok(stored) = entry.get_password() {
                if let Ok(bytes) = general_purpose::STANDARD.decode(stored) {
                    let mut k = [0u8; 32];
                    for (i, b) in bytes.iter().enumerate().take(32) {
                        k[i] = *b;
                    }
                    let _ = ENCRYPTION_KEY_CACHE.set(k);
                    return Ok(k);
                }
            }
        } else if let Ok(stored) = fs::read_to_string(&keystore_file) {
            if let Ok(bytes) = general_purpose::STANDARD.decode(stored.trim()) {
                let mut k = [0u8; 32];
                for (i, b) in bytes.iter().enumerate().take(32) {
                    k[i] = *b;
                }
                let _ = ENCRYPTION_KEY_CACHE.set(k);
                return Ok(k);
            }
        }

        let mut new_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_key);
        let enc = general_purpose::STANDARD.encode(new_key);
        if prefer_keyring {
            let entry = KeyringEntry::new("antivirus_ui", "quarantine_key");
            if let Err(e) = entry.set_password(&enc) {
                log::warn!("Failed to persist quarantine key to OS keyring: {}", e);
                if let Err(e2) = fs::write(&keystore_file, &enc) {
                    log::warn!("Failed to persist fallback keystore file: {}", e2);
                }
            }
        } else if let Err(e) = fs::write(&keystore_file, &enc) {
            log::warn!("Failed to persist quarantine key to keystore file: {}", e);
        }
        let _ = ENCRYPTION_KEY_CACHE.set(new_key);
        Ok(new_key)
    }
}

#[derive(Debug, Clone, Default)]
pub struct QuarantineOptions {
    pub skip_neutralization: bool,
    pub read_retry_count: u32,
}

impl QuarantineOptions {
    pub fn new() -> Self {
        Self {
            skip_neutralization: false,
            read_retry_count: 3,
        }
    }

    pub fn skip_neutralization(mut self) -> Self {
        self.skip_neutralization = true;
        self
    }

    pub fn with_retry_count(mut self, count: u32) -> Self {
        self.read_retry_count = count;
        self
    }
}
