//! Static Analysis

use crate::core::utils::{calculate_entropy, find_resource_path};
use crate::core::yara_scanner::{scan_with_yara, YaraMatch};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    pub yara_matches: Vec<YaraMatch>,
    pub entropy_score: f64,
    pub is_whitelisted: bool,
    pub is_blacklisted: bool,
    pub suspicious_characteristics: Vec<String>,
}

pub fn perform_static_analysis(
    file_hash: &str,
    file_content: &[u8],
    file_type: &str,
    packer_flags: &[String],
    embedded_objects: &[String],
) -> Result<StaticAnalysisResult, Box<dyn std::error::Error>> {
    let is_whitelisted = check_whitelist(file_hash)?;
    let is_blacklisted = check_blacklist(file_hash)?;

    let entropy_score = calculate_entropy(file_content);

    let suspicious_characteristics =
        analyze_characteristics(file_content, file_type, packer_flags, embedded_objects)?;

    let yara_matches = scan_with_yara(file_content);

    log::info!(
        "Static analysis complete: {} YARA matches, entropy: {:.2}, suspicious: {}",
        yara_matches.len(),
        entropy_score,
        suspicious_characteristics.len()
    );

    Ok(StaticAnalysisResult {
        yara_matches,
        entropy_score,
        is_whitelisted,
        is_blacklisted,
        suspicious_characteristics,
    })
}

fn check_whitelist(_hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(WHITELIST
        .read()
        .map(|w| w.contains(&_hash.to_lowercase()))
        .unwrap_or(false))
}

fn check_blacklist(_hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(BLACKLIST
        .read()
        .map(|b| b.contains(&_hash.to_lowercase()))
        .unwrap_or(false))
}

pub static WHITELIST: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| RwLock::new(HashSet::new()));

/// Returns the path to the user-specific whitelist file (separate from system hashes).
fn user_whitelist_path() -> Option<std::path::PathBuf> {
    if cfg!(test) {
        return Some(
            std::env::temp_dir()
                .join("insecurity")
                .join("whitelists")
                .join("user_whitelist.txt"),
        );
    }

    dirs::data_dir()
        .or_else(|| std::env::current_dir().ok())
        .map(|d| {
            d.join("insecurity")
                .join("whitelists")
                .join("user_whitelist.txt")
        })
}

fn load_whitelist_file(path: &std::path::Path, set: &mut HashSet<String>) {
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let s = line.trim();
                if !s.is_empty() && !s.starts_with('#') {
                    set.insert(s.to_lowercase());
                }
            }
        }
    }
}

fn load_whitelist_entries() -> HashSet<String> {
    let mut set = HashSet::new();

    let path = find_resource_path(&[
        "resources/whitelists/system_files.txt",
        "src-tauri/resources/whitelists/system_files.txt",
    ]);
    if let Some(path) = path {
        load_whitelist_file(&path, &mut set);
    }

    // Also check generated system whitelist in data directory
    if let Some(data_dir) = dirs::data_dir() {
        let generated_path = data_dir
            .join("insecurity")
            .join("whitelists")
            .join("system_files.txt");
        load_whitelist_file(&generated_path, &mut set);
    }

    // Load user-whitelisted hashes from separate file
    if let Some(user_path) = user_whitelist_path() {
        load_whitelist_file(&user_path, &mut set);
    }

    log::info!("Whitelist loaded: {} entries", set.len());
    set
}

pub fn initialize_whitelist() {
    let entries = load_whitelist_entries();
    if let Ok(mut whitelist) = WHITELIST.write() {
        *whitelist = entries;
    }
}

pub fn refresh_whitelist() -> Result<usize, String> {
    let entries = load_whitelist_entries();
    let count = entries.len();
    if let Ok(mut whitelist) = WHITELIST.write() {
        *whitelist = entries;
        log::info!("Whitelist refreshed: {} entries", count);
        Ok(count)
    } else {
        Err("Failed to acquire whitelist write lock".to_string())
    }
}

pub fn add_to_whitelist(hash: &str) -> Result<(), String> {
    let hash_lower = hash.to_lowercase();

    if let Ok(mut whitelist) = WHITELIST.write() {
        whitelist.insert(hash_lower.clone());
    } else {
        return Err("Failed to acquire whitelist write lock".to_string());
    }

    // Write to user whitelist file (separate from system hashes)
    if let Some(user_path) = user_whitelist_path() {
        if let Some(parent) = user_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&user_path)
            .map_err(|e| e.to_string())?;

        writeln!(file, "{}", hash_lower).map_err(|e| e.to_string())?;
        log::info!("Added hash to user whitelist: {}", hash_lower);
    }

    Ok(())
}

/// Remove a hash from the in-memory whitelist and the on-disk user whitelist file.
/// The caller (remove_from_user_whitelist) handles the DB side.
pub fn remove_from_whitelist(hash: &str) {
    let hash_lower = hash.to_lowercase();
    if let Ok(mut whitelist) = WHITELIST.write() {
        whitelist.remove(&hash_lower);
    }

    // Remove from user whitelist file
    if let Some(user_path) = user_whitelist_path() {
        if user_path.exists() {
            if let Ok(content) = fs::read_to_string(&user_path) {
                let filtered: Vec<&str> = content
                    .lines()
                    .filter(|line| {
                        let trimmed = line.trim().to_lowercase();
                        !trimmed.is_empty() && trimmed != hash_lower
                    })
                    .collect();
                if let Err(e) = fs::write(&user_path, filtered.join("\n") + "\n") {
                    log::warn!("Failed to rewrite user whitelist file: {}", e);
                }
            }
        }
    }
}

/// Remove all user-whitelisted hashes from memory and truncate the user whitelist file.
/// Takes DB hashes as parameter to only remove user entries (not system hashes).
/// Returns the number of hashes removed from memory.
pub fn clear_user_whitelist(db_hashes: &[String]) -> usize {
    let hashes_lower: Vec<String> = db_hashes.iter().map(|h| h.to_lowercase()).collect();
    let mut removed = 0;

    if let Ok(mut whitelist) = WHITELIST.write() {
        for hash in &hashes_lower {
            if whitelist.remove(hash) {
                removed += 1;
            }
        }
    }

    if let Some(user_path) = user_whitelist_path() {
        if user_path.exists() {
            if let Err(e) = fs::write(&user_path, "") {
                log::warn!("Failed to clear user whitelist file: {}", e);
            }
        }
    }

    log::info!("Cleared {} user whitelist entries", removed);
    removed
}

/// Synchronize user whitelist file with database entries.
/// DB is source of truth - rewrites user_whitelist.txt to match.
/// Also scrubs any leaked user hashes from system_files.txt (migration cleanup).
pub fn sync_user_whitelist(db_hashes: &[String]) {
    let db_set: HashSet<String> = db_hashes.iter().map(|h| h.to_lowercase()).collect();

    // Rewrite user_whitelist.txt to match DB
    if let Some(user_path) = user_whitelist_path() {
        if let Some(parent) = user_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if !db_set.is_empty() {
            let mut lines: Vec<&str> = db_set.iter().map(|s| s.as_str()).collect();
            lines.sort();
            match fs::write(&user_path, lines.join("\n") + "\n") {
                Ok(_) => log::info!(
                    "Synced user whitelist file with DB: {} entries",
                    db_set.len()
                ),
                Err(e) => log::warn!("Failed to sync user whitelist file: {}", e),
            }
        } else if user_path.exists() {
            // DB is empty, clear the file
            let _ = fs::write(&user_path, "");
        }
    }

    // Ensure all DB hashes are in memory
    if let Ok(mut whitelist) = WHITELIST.write() {
        for hash in &db_set {
            whitelist.insert(hash.clone());
        }
    }

    // Migration: scrub any user hashes that leaked into system_files.txt
    if !db_set.is_empty() {
        if let Some(data_dir) = dirs::data_dir() {
            let system_path = data_dir
                .join("insecurity")
                .join("whitelists")
                .join("system_files.txt");
            if system_path.exists() {
                if let Ok(content) = fs::read_to_string(&system_path) {
                    let original_count = content.lines().count();
                    let cleaned: Vec<&str> = content
                        .lines()
                        .filter(|line| {
                            let trimmed = line.trim().to_lowercase();
                            trimmed.is_empty()
                                || trimmed.starts_with('#')
                                || !db_set.contains(&trimmed)
                        })
                        .collect();
                    if cleaned.len() < original_count {
                        let _ = fs::write(&system_path, cleaned.join("\n") + "\n");
                        log::info!(
                            "Cleaned {} user hashes from system_files.txt",
                            original_count - cleaned.len()
                        );
                    }
                }
            }
        }
    }
}

#[must_use]
pub fn get_whitelist_count() -> usize {
    WHITELIST.read().map(|w| w.len()).unwrap_or(0)
}

#[must_use]
pub fn is_whitelisted(hash: &str) -> bool {
    WHITELIST
        .read()
        .map(|w| w.contains(&hash.to_lowercase()))
        .unwrap_or(false)
}

#[must_use]
pub fn is_blacklisted(hash: &str) -> bool {
    BLACKLIST
        .read()
        .map(|b| b.contains(&hash.to_lowercase()))
        .unwrap_or(false)
}

pub static BLACKLIST: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| RwLock::new(HashSet::new()));

pub fn refresh_blacklist() -> Result<(), String> {
    refresh_blacklist_from_db();
    Ok(())
}

fn refresh_blacklist_from_db() {
    crate::with_db(|conn| {
        match crate::database::queries::DatabaseQueries::get_all_threat_hashes(conn) {
            Ok(hashes) => {
                if let Ok(mut blacklist) = BLACKLIST.write() {
                    blacklist.clear();
                    for hash in hashes {
                        blacklist.insert(hash.to_lowercase());
                    }
                    log::info!("Blacklist refreshed from DB: {} entries", blacklist.len());
                }
            }
            Err(e) => {
                log::error!("Failed to load blacklist from DB: {}", e);
            }
        }
        Some(())
    });
}

pub fn get_blacklist_count() -> usize {
    BLACKLIST.read().map(|b| b.len()).unwrap_or(0)
}

fn analyze_characteristics(
    content: &[u8],
    file_type: &str,
    packer_flags: &[String],
    embedded_objects: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut characteristics = Vec::new();

    // Only flag KNOWN MALICIOUS packers
    let malicious_packers: &[&str] = &[
        "themida",
        "vmprotect",
        "enigma",
        "obsidium",
        "pecompact",
        "petite",
        "mpress",
        "molebox",
        "crypter",
        "fsg",
        "upack",
        "nspack",
    ];

    for p in packer_flags {
        let lower = p.to_lowercase();
        if malicious_packers.iter().any(|mp| lower.contains(mp)) {
            characteristics.push(format!("malicious_packer:{}", p));
        }
    }

    // High entropy on packed PE is only suspicious if combined with malicious packer
    if file_type == "PE" && calculate_entropy(content) > 7.9 && !characteristics.is_empty() {
        characteristics.push("high_entropy_packed_pe".to_string());
    }

    let dangerous_embedded = [
        "exe", "scr", "pif", "com", "bat", "cmd", "ps1", "vbs", "js", "hta",
    ];
    for obj in embedded_objects {
        let lower = obj.to_lowercase();
        if dangerous_embedded.iter().any(|ext| lower.ends_with(ext)) {
            characteristics.push(format!("dangerous_embedded:{}", obj));
        }
    }

    if file_type == "PE" {
        let api_analysis = analyze_api_patterns(content);
        characteristics.extend(api_analysis);
    }

    Ok(characteristics)
}

fn analyze_api_patterns(content: &[u8]) -> Vec<String> {
    let mut findings = Vec::new();

    let mut injection_apis = 0;
    let mut anti_debug_apis = 0;
    let mut crypto_apis = 0;
    let mut keylogger_apis = 0;
    let mut network_download_apis = 0;
    let mut process_manipulation_apis = 0;

    let injection_patterns: &[&[u8]] = &[
        b"CreateRemoteThread",
        b"NtCreateThreadEx",
        b"RtlCreateUserThread",
        b"QueueUserAPC",
        b"SetThreadContext",
        b"NtQueueApcThread",
    ];

    let memory_patterns: &[&[u8]] = &[
        b"VirtualAllocEx",
        b"NtAllocateVirtualMemory",
        b"WriteProcessMemory",
        b"NtWriteVirtualMemory",
    ];

    let anti_debug_patterns: &[&[u8]] = &[
        b"IsDebuggerPresent",
        b"CheckRemoteDebuggerPresent",
        b"NtQueryInformationProcess",
        b"OutputDebugString",
    ];

    let keylogger_patterns: &[&[u8]] = &[
        b"GetAsyncKeyState",
        b"GetKeyboardState",
        b"SetWindowsHookExA",
        b"SetWindowsHookExW",
    ];

    let download_patterns: &[&[u8]] = &[
        b"URLDownloadToFile",
        b"InternetReadFile",
        b"WinHttpReadData",
    ];

    let crypto_patterns: &[&[u8]] = &[
        b"CryptEncrypt",
        b"CryptGenKey",
        b"CryptAcquireContext",
        b"BCryptEncrypt",
    ];

    for pattern in injection_patterns {
        if contains_api(content, pattern) {
            injection_apis += 1;
        }
    }

    for pattern in memory_patterns {
        if contains_api(content, pattern) {
            process_manipulation_apis += 1;
        }
    }

    for pattern in anti_debug_patterns {
        if contains_api(content, pattern) {
            anti_debug_apis += 1;
        }
    }

    for pattern in keylogger_patterns {
        if contains_api(content, pattern) {
            keylogger_apis += 1;
        }
    }

    for pattern in download_patterns {
        if contains_api(content, pattern) {
            network_download_apis += 1;
        }
    }

    for pattern in crypto_patterns {
        if contains_api(content, pattern) {
            crypto_apis += 1;
        }
    }

    // === DETECTION RULES ===

    // Rule 1: Process injection (need injection API + memory write + process manipulation)
    if injection_apis >= 1 && process_manipulation_apis >= 2 {
        findings.push("process_injection_capability".to_string());
    }

    // Rule 2: Keylogger pattern (keylogger API + not a typical input app)
    if keylogger_apis >= 2 {
        findings.push("keylogger_api_pattern".to_string());
    }

    // Rule 3: Dropper pattern (download + write + execute)
    if network_download_apis >= 1 && (injection_apis >= 1 || process_manipulation_apis >= 1) {
        findings.push("dropper_pattern".to_string());
    }

    // Rule 4: Ransomware pattern (crypto + file enumeration)
    if crypto_apis >= 2
        && contains_api(content, b"FindFirstFile")
        && contains_api(content, b"FindNextFile")
    {
        findings.push("ransomware_file_enum_pattern".to_string());
    }

    // Rule 5: Anti-analysis pattern (multiple anti-debug + packing indicators)
    if anti_debug_apis >= 3 {
        findings.push("heavy_anti_debug".to_string());
    }

    // Rule 6: Process hollowing pattern
    if contains_api(content, b"NtUnmapViewOfSection")
        && contains_api(content, b"VirtualAllocEx")
        && contains_api(content, b"WriteProcessMemory")
    {
        findings.push("process_hollowing_pattern".to_string());
    }

    // Rule 7: Shellcode execution pattern
    if contains_api(content, b"VirtualAlloc")
        && contains_api(content, b"VirtualProtect")
        && (contains_api(content, b"CreateThread") || contains_api(content, b"CallWindowProc"))
    {
        // This is actually common in legitimate software, so only flag with other indicators
        if injection_apis >= 1 || anti_debug_apis >= 2 {
            findings.push("potential_shellcode_execution".to_string());
        }
    }

    findings
}

fn contains_api(content: &[u8], api: &[u8]) -> bool {
    if api.is_empty() || content.len() < api.len() {
        return false;
    }

    // Check for ASCII version
    if content.windows(api.len()).any(|w| w == api) {
        return true;
    }

    // Check for wide string version (UTF-16LE: each char followed by 0x00)
    let wide_api: Vec<u8> = api.iter().flat_map(|&b| [b, 0u8]).collect();
    if content.len() >= wide_api.len()
        && content
            .windows(wide_api.len())
            .any(|w| w == wide_api.as_slice())
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = b"aaaaaaaaaa";
        let high_entropy = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09";

        assert!(calculate_entropy(low_entropy) < calculate_entropy(high_entropy));
    }

    #[test]
    fn test_whitelist_and_blacklist_loading() {
        let white_result = check_whitelist("nonexistent_hash_12345").unwrap();
        let black_result = check_blacklist("nonexistent_hash_67890").unwrap();
        assert!(
            !white_result,
            "Non-existent hash should not be in whitelist"
        );
        assert!(
            !black_result,
            "Non-existent hash should not be in blacklist"
        );
    }

    #[test]
    fn test_single_api_not_suspicious() {
        // VirtualAlloc alone should NOT trigger detection
        // Many legitimate apps use it
        let content = b"kernel32.dll VirtualAlloc VirtualFree HeapAlloc";
        let findings = analyze_api_patterns(content);
        assert!(
            findings.is_empty(),
            "Single API should not be suspicious: {:?}",
            findings
        );
    }

    #[test]
    fn test_legitimate_app_apis_not_suspicious() {
        // A typical app might use these APIs - should not be flagged
        let content = b"CreateFile ReadFile WriteFile CloseHandle VirtualAlloc VirtualFree GetProcAddress LoadLibrary";
        let findings = analyze_api_patterns(content);
        assert!(
            findings.is_empty(),
            "Legitimate APIs should not be suspicious: {:?}",
            findings
        );
    }

    #[test]
    fn test_process_injection_pattern_detected() {
        // Classic process injection pattern
        let content = b"OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread";
        let findings = analyze_api_patterns(content);
        assert!(
            findings.iter().any(|f| f.contains("injection")),
            "Should detect injection pattern: {:?}",
            findings
        );
    }

    #[test]
    fn test_keylogger_pattern_needs_multiple_apis() {
        // Single hook API is legitimate (used by accessibility software)
        let single_hook = b"SetWindowsHookExA GetModuleHandle";
        let findings1 = analyze_api_patterns(single_hook);
        assert!(
            !findings1.iter().any(|f| f.contains("keylogger")),
            "Single hook should not trigger keylogger detection"
        );

        // Multiple keylogger APIs together is suspicious
        let keylogger = b"SetWindowsHookExA GetAsyncKeyState GetKeyboardState";
        let findings2 = analyze_api_patterns(keylogger);
        assert!(
            findings2.iter().any(|f| f.contains("keylogger")),
            "Multiple keylogger APIs should be detected: {:?}",
            findings2
        );
    }

    #[test]
    fn test_crypto_alone_not_ransomware() {
        // Crypto APIs alone are used by many legitimate apps
        let crypto_only = b"CryptAcquireContext CryptGenKey CryptEncrypt CryptDecrypt";
        let findings = analyze_api_patterns(crypto_only);
        assert!(
            !findings.iter().any(|f| f.contains("ransomware")),
            "Crypto alone should not trigger ransomware: {:?}",
            findings
        );
    }

    #[test]
    fn test_ransomware_pattern_detected() {
        // Crypto + file enumeration = ransomware pattern
        let ransomware = b"CryptEncrypt CryptGenKey FindFirstFile FindNextFile DeleteFile";
        let findings = analyze_api_patterns(ransomware);
        assert!(
            findings.iter().any(|f| f.contains("ransomware")),
            "Should detect ransomware pattern: {:?}",
            findings
        );
    }

    #[test]
    fn test_process_hollowing_detected() {
        let hollowing = b"NtUnmapViewOfSection VirtualAllocEx WriteProcessMemory ResumeThread";
        let findings = analyze_api_patterns(hollowing);
        assert!(
            findings.iter().any(|f| f.contains("hollowing")),
            "Should detect process hollowing: {:?}",
            findings
        );
    }

    #[test]
    fn test_legitimate_packer_not_flagged() {
        // UPX is used by many legitimate apps
        let packer_flags = vec!["UPX".to_string()];
        let embedded = vec![];
        let content = b"MZ header content";

        let result = analyze_characteristics(content, "PE", &packer_flags, &embedded).unwrap();
        assert!(
            !result.iter().any(|c| c.contains("packer")),
            "UPX should not be flagged as malicious: {:?}",
            result
        );
    }

    #[test]
    fn test_malicious_packer_flagged() {
        let packer_flags = vec!["Themida".to_string()];
        let embedded = vec![];
        let content = b"MZ header content";

        let result = analyze_characteristics(content, "PE", &packer_flags, &embedded).unwrap();
        assert!(
            result.iter().any(|c| c.contains("malicious_packer")),
            "Themida should be flagged: {:?}",
            result
        );
    }

    #[test]
    fn test_contains_api_wide_string() {
        // Test wide string detection (UTF-16LE)
        let wide_virtual_alloc = b"V\x00i\x00r\x00t\x00u\x00a\x00l\x00A\x00l\x00l\x00o\x00c\x00";
        assert!(contains_api(wide_virtual_alloc, b"VirtualAlloc"));
    }

    // === Whitelist / Blacklist management ===

    #[test]
    #[serial]
    fn test_whitelist_add_and_check() {
        let test_hash = "aaaa27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        // Add to whitelist
        let _ = add_to_whitelist(test_hash);
        assert!(is_whitelisted(test_hash));
        // Cleanup
        remove_from_whitelist(test_hash);
    }

    #[test]
    #[serial]
    fn test_whitelist_case_insensitive() {
        let lower = "bbbb27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let upper = "BBBB27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
        let _ = add_to_whitelist(upper);
        assert!(is_whitelisted(lower), "Should find hash regardless of case");
        // Cleanup
        remove_from_whitelist(lower);
    }

    #[test]
    #[serial]
    fn test_remove_from_whitelist_memory() {
        let hash = "cccc27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let _ = add_to_whitelist(hash);
        assert!(is_whitelisted(hash));
        remove_from_whitelist(hash);
        assert!(!is_whitelisted(hash), "Should be removed from memory");
    }

    #[test]
    fn test_is_whitelisted_nonexistent() {
        assert!(!is_whitelisted(
            "nonexistent_hash_that_does_not_exist_00000000000000000000"
        ));
    }

    /// Regression test: after saving new hashes, initialize_whitelist() must
    /// reload them into memory so they take effect without an app restart.
    /// This covers the bug where spawn_whitelist_generator saved to disk but
    /// never called initialize_whitelist() afterward.
    #[test]
    #[serial]
    fn test_whitelist_reload_picks_up_disk_changes() {
        let hash = "eeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd";
        // Ensure it's not already there
        remove_from_whitelist(hash);
        assert!(
            !is_whitelisted(hash),
            "Hash should not be in whitelist initially"
        );

        // Simulate what spawn_whitelist_generator does: add to disk then reload
        let _ = add_to_whitelist(hash);
        // Clear the in-memory set to simulate a fresh load
        if let Ok(mut wl) = WHITELIST.write() {
            wl.clear();
        }
        assert!(
            !is_whitelisted(hash),
            "Hash should be gone after clearing memory"
        );

        // Now reload from disk - this is the call that was missing before the fix
        initialize_whitelist();
        assert!(
            is_whitelisted(hash),
            "Hash should be found after initialize_whitelist reloads from disk"
        );

        // Cleanup
        remove_from_whitelist(hash);
    }

    #[test]
    fn test_is_blacklisted_nonexistent() {
        assert!(!is_blacklisted(
            "nonexistent_hash_that_does_not_exist_00000000000000000000"
        ));
    }

    #[test]
    fn test_get_whitelist_count() {
        // Just verify it doesn't panic
        let _ = get_whitelist_count();
    }

    // === analyze_characteristics edge cases ===

    #[test]
    fn test_analyze_characteristics_empty_inputs() {
        let content: &[u8] = b"";
        let result = analyze_characteristics(content, "UNKNOWN", &[], &[]).unwrap();
        // Empty content, no packers, no embedded objects -> no suspicious characteristics
        assert!(
            result.is_empty(),
            "Empty inputs should produce no findings: {:?}",
            result
        );
    }

    #[test]
    fn test_analyze_characteristics_vmprotect_flagged() {
        let packer_flags = vec!["VMProtect".to_string()];
        let result = analyze_characteristics(b"MZ", "PE", &packer_flags, &[]).unwrap();
        assert!(
            result.iter().any(|c| c.contains("malicious_packer")),
            "VMProtect should be flagged: {:?}",
            result
        );
    }

    #[test]
    fn test_analyze_characteristics_embedded_objects() {
        let embedded = vec!["embedded_pe.exe".to_string()];
        let result = analyze_characteristics(b"MZ", "PE", &[], &embedded).unwrap();
        assert!(
            result.iter().any(|c| c.contains("embedded")),
            "Embedded objects should be noted: {:?}",
            result
        );
    }

    // === perform_static_analysis ===

    #[test]
    fn test_perform_static_analysis_basic() {
        let content = b"harmless test content with no suspicious patterns";
        let result = perform_static_analysis(
            "dddd27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            content,
            "UNKNOWN",
            &[],
            &[],
        )
        .unwrap();

        assert!(!result.is_whitelisted);
        assert!(!result.is_blacklisted);
        assert!(result.entropy_score >= 0.0);
    }

    // === contains_api edge cases ===

    #[test]
    fn test_contains_api_empty_content() {
        assert!(!contains_api(b"", b"VirtualAlloc"));
    }

    #[test]
    fn test_contains_api_exact_match() {
        assert!(contains_api(b"VirtualAlloc", b"VirtualAlloc"));
    }

    #[test]
    fn test_contains_api_shorter_than_api() {
        assert!(!contains_api(b"V", b"VirtualAlloc"));
    }
}
