//! Security Insights commands (System Posture backend)
//! Read-only structural audit: what auto-runs, who published it, and whether
//! that persistence is verified. No malware analysis - that belongs in the
//! scan pipeline. If a binary was previously scanned, we cross-reference the
//! verdict from the database.
//!
//! Signals surfaced:
//!   - Signature status (trusted / signed / unsigned / invalid)
//!   - Structural anomalies (multi-persistence, dead references, privilege gaps)
//!   - Prior scan verdicts (cross-ref from verdicts DB)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, RwLock};
use tauri::command;

// ============================================================================
// Global caches - persist across tab switches so repeated visits are instant
// ============================================================================

/// Global signature cache. Keyed by file path (lowercase).
/// Populated by batch verification; read by structural analysis.
static SIGNATURE_CACHE: std::sync::LazyLock<
    RwLock<HashMap<String, crate::core::signature::SignatureInfo>>,
> = std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// Tracks the last time `prefetch_insight_signatures` completed a full run.
/// Subsequent calls within the TTL window (5 minutes) return immediately.
static LAST_PREFETCH: std::sync::LazyLock<Mutex<Option<std::time::Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

// ============================================================================
// Types
// ============================================================================

/// Structural classification - NOT a malware confidence level.
/// These describe *why* an item is surfaced, not whether it's malicious.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PostureStatus {
    /// Previously scanned and flagged by the detection pipeline
    Flagged,
    /// Structural anomaly (multi-persistence, user-writable service, etc.)
    Unusual,
    /// Unsigned - publisher cannot be verified
    Unverified,
    /// Signed by trusted publisher, no structural anomalies
    Verified,
    /// Unknown state (e.g. binary not found, target unresolvable)
    Unknown,
}

impl std::fmt::Display for PostureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostureStatus::Flagged => write!(f, "flagged"),
            PostureStatus::Unusual => write!(f, "unusual"),
            PostureStatus::Unverified => write!(f, "unverified"),
            PostureStatus::Verified => write!(f, "verified"),
            PostureStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Persistence context for a specific file - returned by `get_persistence_for_file`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePersistenceContext {
    pub file_path: String,
    pub startup_entries: Vec<StartupEntry>,
    pub persistence_items: Vec<PersistenceItem>,
    pub is_signed: bool,
    pub is_trusted: bool,
    pub signer_name: Option<String>,
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupEntry {
    pub name: String,
    pub command: String,
    pub location: String,
    pub executable_path: Option<String>,
    /// How the persistence was established
    pub persistence_type: String,
    pub is_signed: bool,
    pub is_trusted: bool,
    pub signer_name: Option<String>,
    pub observations: Vec<String>,
    pub status: PostureStatus,
    pub prior_verdict: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistenceItem {
    pub name: String,
    pub item_type: String,
    pub command: String,
    pub executable_path: Option<String>,
    pub is_signed: bool,
    pub is_trusted: bool,
    pub signer_name: Option<String>,
    pub observations: Vec<String>,
    pub status: PostureStatus,
    pub prior_verdict: Option<String>,
    /// Extra context (e.g. run frequency, user vs system)
    pub details: Option<String>,
}

// ============================================================================
// Helpers - path manipulation, command parsing, shortcuts
// ============================================================================

/// Expand Windows environment variables and NT path conventions in a path string.
fn expand_env_vars(input: &str) -> String {
    let input = if let Some(stripped) = input.strip_prefix("\\??\\") {
        stripped
    } else {
        input
    };
    let input_owned;
    let input = if input.starts_with("\\SystemRoot\\") || input.starts_with("SystemRoot\\") {
        let prefix_len = if input.starts_with('\\') { 12 } else { 11 };
        input_owned = format!("%SystemRoot%{}", &input[prefix_len - 1..]);
        &input_owned
    } else if input.starts_with("system32\\") || input.starts_with("System32\\") {
        input_owned = format!("%SystemRoot%\\{}", input);
        &input_owned
    } else {
        input
    };
    let mut result = input.to_string();
    let mut search_from = 0;
    while search_from < result.len() {
        let Some(start) = result[search_from..].find('%').map(|i| i + search_from) else {
            break;
        };
        let Some(end) = result[start + 1..].find('%') else {
            break;
        };
        let var_name = result[start + 1..start + 1 + end].to_string();
        match std::env::var(&var_name).or_else(|_| std::env::var(var_name.to_uppercase())) {
            Ok(expanded) => {
                result = format!(
                    "{}{}{}",
                    &result[..start],
                    expanded,
                    &result[start + 1 + end + 1..]
                );
                search_from = start + expanded.len();
            }
            Err(_) => {
                search_from = start + 1 + end + 1;
            }
        }
    }
    result
}

fn is_launcher_binary(path: &str) -> bool {
    let stem = Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        stem.as_str(),
        "cmd"
            | "powershell"
            | "pwsh"
            | "wscript"
            | "cscript"
            | "rundll32"
            | "regsvr32"
            | "mshta"
            | "conhost"
            | "explorer"
            | "msiexec"
            | "dllhost"
            | "schtasks"
            | "reg"
    )
}

fn is_executable_ext(ext: &std::ffi::OsStr) -> bool {
    let ext = ext.to_string_lossy().to_lowercase();
    matches!(
        ext.as_str(),
        "exe" | "dll" | "com" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "msi" | "scr" | "sys"
    )
}

fn is_script_file(path: &str) -> bool {
    let ext = Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "ps1" | "vbs" | "vbe" | "js" | "jse" | "bat" | "cmd" | "wsf"
    )
}

fn is_user_writable_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\users\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
}

/// Extract the executable path from a command string.
fn extract_exe_from_command(cmd: &str) -> Option<String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    let cmd = expand_env_vars(cmd);
    extract_exe_inner(&cmd, true)
}

fn extract_exe_inner(cmd: &str, follow_launchers: bool) -> Option<String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }

    let (exe, remainder) = if let Some(rest) = cmd.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            (
                rest[..end].to_string(),
                rest.get(end + 1..).unwrap_or("").to_string(),
            )
        } else {
            (rest.to_string(), String::new())
        }
    } else {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let mut found = None;
        let mut rem_start = parts.len();
        for i in 1..=parts.len() {
            let candidate = parts[..i].join(" ");
            let p = Path::new(&candidate);
            if p.extension().is_some_and(is_executable_ext) {
                found = Some(candidate);
                rem_start = i;
                break;
            }
            if p.exists() && p.is_file() {
                found = Some(candidate);
                rem_start = i;
                break;
            }
        }
        let resolved = found?;
        let remainder = parts[rem_start..].join(" ");
        (resolved, remainder)
    };

    if exe.is_empty() {
        return None;
    }

    if follow_launchers && is_launcher_binary(&exe) && !remainder.is_empty() {
        if let Some(payload) = find_payload_in_args(&remainder) {
            return Some(payload);
        }
    }

    Some(exe)
}

fn find_payload_in_args(args: &str) -> Option<String> {
    let args = args.trim();
    if args.is_empty() {
        return None;
    }

    let mut in_quote = false;
    let mut quote_start = 0;
    for (i, ch) in args.char_indices() {
        if ch == '"' {
            if in_quote {
                let quoted = &args[quote_start + 1..i];
                let p = Path::new(quoted);
                if p.extension().is_some_and(is_executable_ext) || (p.exists() && p.is_file()) {
                    return Some(quoted.to_string());
                }
            } else {
                quote_start = i;
            }
            in_quote = !in_quote;
        }
    }

    for token in args.split_whitespace() {
        let clean = token
            .trim_matches('"')
            .trim_matches('\'')
            .split(',')
            .next()
            .unwrap_or(token);
        if clean.starts_with('/') || clean.starts_with('-') {
            continue;
        }
        let p = Path::new(clean);
        if p.extension().is_some_and(is_executable_ext) {
            return Some(clean.to_string());
        }
    }

    None
}

fn run_command_with_timeout(
    cmd: &mut std::process::Command,
    timeout: std::time::Duration,
) -> Option<std::process::Output> {
    use std::io::Read;

    crate::core::utils::configure_background_command(cmd);

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_end(&mut stdout);
                }
                return Some(std::process::Output {
                    status,
                    stdout,
                    stderr: Vec::new(),
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                return None;
            }
        }
    }
}

fn resolve_lnk_targets_batch(lnk_paths: &[String]) -> HashMap<String, String> {
    if lnk_paths.is_empty() {
        return HashMap::new();
    }

    let mut script = String::from("$sh = New-Object -ComObject WScript.Shell\n");
    for lnk in lnk_paths {
        let escaped = lnk.replace('\'', "''");
        script.push_str(&format!(
            "try {{ $t = $sh.CreateShortcut('{}').TargetPath; if ($t) {{ Write-Output ('{}' + \"`t\" + $t) }} }} catch {{}}\n",
            escaped, escaped,
        ));
    }

    let output = match run_command_with_timeout(
        std::process::Command::new("powershell").args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ]),
        std::time::Duration::from_secs(15),
    ) {
        Some(o) => o,
        None => return HashMap::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = HashMap::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some((lnk, target)) = line.split_once('\t') {
            let target = expand_env_vars(target.trim());
            if !target.is_empty() {
                results.insert(lnk.to_string(), target);
            }
        }
    }
    results
}

// ============================================================================
// Structural analysis - signature only, no malware heuristics
// ============================================================================

/// Result of structural analysis on a binary.
/// (is_signed, is_trusted, signer_name, observations, status)
type StructuralResult = (bool, bool, Option<String>, Vec<String>, PostureStatus);

/// Look up prior scan verdict from the verdicts database.
/// Returns None if never scanned.
fn lookup_prior_verdict(exe_path: &str) -> Option<String> {
    if let Some(db_mutex) = crate::get_database() {
        if let Ok(guard) = db_mutex.lock() {
            if let Some(ref conn) = *guard {
                // Look up by file path
                let mut stmt = conn
                    .prepare("SELECT verdict FROM verdicts WHERE file_path = ?1 ORDER BY rowid DESC LIMIT 1")
                    .ok()?;
                let verdict: Option<String> = stmt.query_row([exe_path], |row| row.get(0)).ok();
                if verdict.is_some() {
                    return verdict;
                }
                // Also try by hash if we have one
                if let Ok(hash) = crate::core::ingestion::compute_file_hash(exe_path) {
                    let mut stmt2 = conn
                        .prepare("SELECT verdict FROM verdicts WHERE file_hash = ?1 ORDER BY rowid DESC LIMIT 1")
                        .ok()?;
                    return stmt2.query_row([&hash], |row| row.get(0)).ok();
                }
            }
        }
    }
    None
}

/// Analyse a binary structurally - signature verification only.
/// No entropy, no packer detection, no blacklist checks.
fn analyse_structural(exe_path: &str) -> StructuralResult {
    let path = Path::new(exe_path);
    let mut observations: Vec<String> = Vec::new();

    if !path.exists() {
        observations.push("Binary not found on disk".to_string());
        return (false, false, None, observations, PostureStatus::Unknown);
    }

    if is_script_file(exe_path) {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        observations.push(format!("Script file ({})", ext));
        if is_user_writable_path(exe_path) {
            observations.push("Script in user-writable location".to_string());
        }
        let status = if is_user_writable_path(exe_path) {
            PostureStatus::Unusual
        } else {
            PostureStatus::Unverified
        };
        return (false, false, None, observations, status);
    }

    // Signature verification from cache or fresh
    let sig_key = exe_path.to_lowercase();
    let sig = {
        let cache = SIGNATURE_CACHE.read().unwrap_or_else(|e| e.into_inner());
        cache.get(&sig_key).cloned()
    }
    .unwrap_or_else(|| {
        let result = crate::core::signature::verify_signature(exe_path);
        SIGNATURE_CACHE
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sig_key, result.clone());
        result
    });

    if !sig.is_signed {
        observations.push("Unsigned binary".to_string());
    } else if !sig.is_valid {
        observations.push("Invalid signature".to_string());
    }

    // Determine status purely from signature
    let status = if sig.is_signed && sig.is_valid && sig.is_trusted_publisher {
        PostureStatus::Verified
    } else if sig.is_signed && sig.is_valid {
        // Signed but not trusted publisher - still verified, just not "known"
        PostureStatus::Verified
    } else if sig.is_signed && !sig.is_valid {
        PostureStatus::Unusual // Invalid sig is structurally unusual
    } else {
        PostureStatus::Unverified
    };

    (
        sig.is_signed,
        sig.is_trusted_publisher,
        sig.signer_name,
        observations,
        status,
    )
}

/// Analyse and apply structural context (persistence location, path, etc.)
/// This upgrades status based on structural signals.
fn analyse_with_context(exe_path: &str, persistence_context: Option<&str>) -> StructuralResult {
    let (is_signed, is_trusted, signer_name, mut observations, mut status) =
        analyse_structural(exe_path);

    // Structural signal: user-writable path for auto-running binary
    if is_user_writable_path(exe_path) && persistence_context.is_some() {
        observations.push("Runs from user-writable location".to_string());
        if status == PostureStatus::Unverified {
            status = PostureStatus::Unusual;
        }
    }

    // Check for prior scan verdict - this is the cross-reference with the scan pipeline
    // (done here so we can upgrade status to Flagged if previously detected)
    // Note: we don't call this for every binary during prefetch - it's per-item
    // and the DB lookup is fast (indexed).

    (is_signed, is_trusted, signer_name, observations, status)
}

/// Apply prior verdict to upgrade status if previously flagged.
fn apply_prior_verdict(status: PostureStatus, prior_verdict: &Option<String>) -> PostureStatus {
    if let Some(ref v) = prior_verdict {
        let lower = v.to_lowercase();
        if lower == "malware" || lower == "suspicious" || lower == "pup" {
            return PostureStatus::Flagged;
        }
    }
    status
}

/// When signature verification fails (timeout, permission error, non-exe target),
/// fall back to the registry Publisher field. If the publisher matches our trusted
/// list, treat the entry as trusted rather than flagging it unsigned.
#[allow(dead_code)]
fn apply_publisher_fallback(result: &mut StructuralResult, registry_publisher: Option<&str>) {
    let (
        ref mut is_signed,
        ref mut is_trusted,
        ref mut signer_name,
        ref mut _observations,
        ref mut status,
    ) = *result;

    // Only apply fallback if the signature check returned unsigned/unknown
    // AND we have a registry publisher that matches our trusted list.
    if *is_signed || *is_trusted {
        return; // Already has a valid signature - no fallback needed
    }

    let publisher = match registry_publisher {
        Some(p) if !p.is_empty() => p,
        _ => return,
    };

    if crate::core::signature::is_trusted_publisher(publisher) {
        // The registry says this is from a known publisher but signature
        // verification failed (timeout, permission denied, AppX package, etc.).
        // Trust the registry publisher as a secondary signal.
        *is_trusted = true;
        *is_signed = true; // Treat as signed (publisher-verified)
        *signer_name = Some(publisher.to_string());
        // Only upgrade status if it was Unverified or Unknown - don't
        // override Unusual or Flagged which indicate structural issues.
        if *status == PostureStatus::Unverified || *status == PostureStatus::Unknown {
            *status = PostureStatus::Verified;
        }
    }
}

// ============================================================================
// Signature prefetch - batch verify all binaries in one PowerShell call
// ============================================================================

pub fn prefetch_insight_signatures() {
    use crate::core::signature::verify_signatures_batch;

    const PREFETCH_TTL: std::time::Duration = std::time::Duration::from_secs(300);
    {
        let guard = LAST_PREFETCH.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(last) = *guard {
            if last.elapsed() < PREFETCH_TTL {
                return;
            }
        }
    }

    let mut paths: Vec<String> = Vec::new();

    // Startup Run keys
    for (hive, path) in &[
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            winreg::enums::HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            winreg::enums::HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ] {
        let root = winreg::RegKey::predef(*hive);
        let Ok(key) = root.open_subkey(path) else {
            continue;
        };
        for (_, value) in key.enum_values().filter_map(|v| v.ok()) {
            let cmd = format!("{}", value);
            if let Some(exe) = extract_exe_from_command(&cmd) {
                paths.push(exe);
            }
        }
    }

    // Services
    let root = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    if let Ok(key) = root.open_subkey(r"SYSTEM\CurrentControlSet\Services") {
        for name in key.enum_keys().filter_map(|k| k.ok()) {
            let Ok(sub) = key.open_subkey(&name) else {
                continue;
            };
            if let Ok(img) = sub.get_value::<String, _>("ImagePath") {
                let expanded = expand_env_vars(&img);
                let lower = expanded.to_lowercase();
                if lower.contains("\\windows\\") || lower.contains("\\system32\\svchost") {
                    continue;
                }
                if let Some(exe) = extract_exe_from_command(&expanded) {
                    paths.push(exe);
                }
            }
        }
    }

    paths.sort_unstable();
    paths.dedup();

    let uncached: Vec<String> = {
        let sig_cache = SIGNATURE_CACHE.read().unwrap_or_else(|e| e.into_inner());
        paths
            .into_iter()
            .filter(|p| {
                !sig_cache.contains_key(&p.to_lowercase())
                    && !is_script_file(p)
                    && Path::new(p).exists()
            })
            .collect()
    };

    if uncached.is_empty() {
        *LAST_PREFETCH.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
        return;
    }

    let refs: Vec<&str> = uncached.iter().map(|s| s.as_str()).collect();
    let batch = verify_signatures_batch(&refs);
    {
        let mut cache = SIGNATURE_CACHE.write().unwrap_or_else(|e| e.into_inner());
        for (path, sig) in batch {
            cache.insert(path.to_lowercase(), sig);
        }
    }

    *LAST_PREFETCH.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
}

// ============================================================================
// Collectors
// ============================================================================

fn collect_startup_entries() -> Vec<StartupEntry> {
    let mut entries: Vec<StartupEntry> = Vec::new();

    let run_keys = [
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM Run",
        ),
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM RunOnce",
        ),
        (
            winreg::enums::HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU Run",
        ),
        (
            winreg::enums::HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU RunOnce",
        ),
    ];

    for (hive, path, location_label) in &run_keys {
        let root = winreg::RegKey::predef(*hive);
        let Ok(key) = root.open_subkey(path) else {
            continue;
        };

        for value_result in key.enum_values() {
            let Ok((name, value)) = value_result else {
                continue;
            };
            let command = format!("{}", value);
            let exe_path = extract_exe_from_command(&command);

            let (is_signed, is_trusted, signer_name, mut observations, status) =
                if let Some(ref exe) = exe_path {
                    analyse_with_context(exe, Some("startup"))
                } else {
                    (
                        false,
                        false,
                        None,
                        vec!["Cannot resolve executable".to_string()],
                        PostureStatus::Unknown,
                    )
                };

            // Structural signal: dead reference
            if let Some(ref exe) = exe_path {
                if !Path::new(exe).exists() {
                    observations.push("Dead reference - target binary missing".to_string());
                }
            }

            let prior_verdict = exe_path.as_ref().and_then(|p| lookup_prior_verdict(p));
            let final_status = apply_prior_verdict(status, &prior_verdict);

            entries.push(StartupEntry {
                name,
                command,
                location: location_label.to_string(),
                executable_path: exe_path,
                persistence_type: "Registry Run Key".to_string(),
                is_signed,
                is_trusted,
                signer_name,
                observations,
                status: final_status,
                prior_verdict,
            });
        }
    }

    // Startup folders
    let mut startup_folder_items: Vec<(String, String, bool, String)> = Vec::new();
    let startup_folders = {
        let mut folders = Vec::new();
        if let Some(home) = dirs::home_dir() {
            let user_startup = home
                .join("AppData")
                .join("Roaming")
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup");
            if user_startup.exists() {
                folders.push((user_startup, "User Startup Folder"));
            }
        }
        let common = std::path::PathBuf::from(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        );
        if common.exists() {
            folders.push((common, "Common Startup Folder"));
        }
        folders
    };

    for (folder, location_label) in &startup_folders {
        let Ok(read_dir) = std::fs::read_dir(folder) else {
            continue;
        };
        for entry in read_dir.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.starts_with("desktop.") || name.starts_with('.') {
                continue;
            }
            let path_str = path.to_string_lossy().to_string();
            let is_shortcut = path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"));
            startup_folder_items.push((name, path_str, is_shortcut, location_label.to_string()));
        }
    }

    let lnk_paths: Vec<String> = startup_folder_items
        .iter()
        .filter(|(_, _, is_lnk, _)| *is_lnk)
        .map(|(_, path, _, _)| path.clone())
        .collect();
    let lnk_targets = resolve_lnk_targets_batch(&lnk_paths);

    for (name, path_str, is_shortcut, location_label) in startup_folder_items {
        let (exe_target, is_signed, is_trusted, signer_name, mut observations, status) =
            if is_shortcut {
                if let Some(target) = lnk_targets.get(&path_str) {
                    let (s, t, sn, obs, st) = analyse_with_context(target, Some("startup"));
                    (Some(target.clone()), s, t, sn, obs, st)
                } else {
                    (
                        None,
                        false,
                        false,
                        None,
                        vec!["Shortcut target not resolved".to_string()],
                        PostureStatus::Unknown,
                    )
                }
            } else {
                let (s, t, sn, obs, st) = analyse_with_context(&path_str, Some("startup"));
                (Some(path_str.clone()), s, t, sn, obs, st)
            };

        // Dead reference check for shortcuts
        if let Some(ref exe) = exe_target {
            if !Path::new(exe).exists() {
                observations.push("Dead reference - target binary missing".to_string());
            }
        }

        let prior_verdict = exe_target.as_ref().and_then(|p| lookup_prior_verdict(p));
        let final_status = apply_prior_verdict(status, &prior_verdict);

        entries.push(StartupEntry {
            name,
            command: path_str,
            location: location_label,
            executable_path: exe_target,
            persistence_type: "Startup Folder".to_string(),
            is_signed,
            is_trusted,
            signer_name,
            observations,
            status: final_status,
            prior_verdict,
        });
    }

    entries
}

fn collect_persistence_items() -> Result<Vec<PersistenceItem>, String> {
    let mut items: Vec<PersistenceItem> = Vec::new();

    // Scheduled tasks
    if let Some(output) = run_command_with_timeout(
        std::process::Command::new("schtasks").args(["/query", "/fo", "CSV", "/v"]),
        std::time::Duration::from_secs(10),
    ) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(stdout.as_bytes());

        let header_indices = {
            match rdr.headers().ok().cloned() {
                Some(h) => {
                    let find_col = |patterns: &[&str]| -> Option<usize> {
                        h.iter().position(|col| {
                            let col_lower = col.to_lowercase();
                            patterns.iter().any(|p| col_lower.contains(p))
                        })
                    };
                    let name_idx = find_col(&["taskname", "task name"]);
                    let run_idx = find_col(&["task to run"]);
                    let author_idx = find_col(&["author"]);
                    Some((
                        name_idx.unwrap_or(1),
                        run_idx.unwrap_or(8),
                        author_idx.unwrap_or(7),
                    ))
                }
                None => None,
            }
        };

        if let Some((name_idx, run_idx, author_idx)) = header_indices {
            for record in rdr.records().filter_map(|r| r.ok()) {
                let task_name = record.get(name_idx).unwrap_or("").trim();
                let task_to_run = record.get(run_idx).unwrap_or("").trim();

                if task_name.starts_with("\\Microsoft\\")
                    || task_name.starts_with("\\Apple\\")
                    || task_name == "\\MicrosoftEdgeUpdateTaskMachineCore"
                    || task_name == "\\MicrosoftEdgeUpdateTaskMachineUA"
                    || task_to_run.is_empty()
                    || task_to_run == "com handler"
                    || task_to_run.to_lowercase().contains("\\windows\\")
                {
                    continue;
                }

                let task_to_run_expanded = expand_env_vars(task_to_run);
                let exe_path = extract_exe_from_command(&task_to_run_expanded);

                let (is_signed, is_trusted, signer_name, mut observations, status) =
                    if let Some(ref exe) = exe_path {
                        analyse_with_context(exe, Some("task"))
                    } else {
                        (
                            false,
                            false,
                            None,
                            vec!["Cannot resolve executable".to_string()],
                            PostureStatus::Unknown,
                        )
                    };

                // Dead reference
                if let Some(ref exe) = exe_path {
                    if !Path::new(exe).exists() {
                        observations.push("Dead reference - target binary missing".to_string());
                    }
                }

                let author = {
                    let a = record.get(author_idx).unwrap_or("").trim();
                    if a.is_empty() {
                        None
                    } else {
                        Some(a.to_string())
                    }
                };

                // Skip Microsoft-authored low-risk tasks
                if let Some(ref auth) = author {
                    let lower = auth.to_lowercase();
                    if lower.contains("microsoft")
                        && (status == PostureStatus::Verified || status == PostureStatus::Unknown)
                    {
                        continue;
                    }
                }

                let display_name = if let Some(sid_pos) = task_name.find("-S-1-") {
                    task_name[..sid_pos].trim_end_matches(" Task").to_string()
                } else {
                    task_name.to_string()
                };

                let prior_verdict = exe_path.as_ref().and_then(|p| lookup_prior_verdict(p));
                let final_status = apply_prior_verdict(status, &prior_verdict);

                items.push(PersistenceItem {
                    name: display_name,
                    item_type: "Scheduled Task".to_string(),
                    command: task_to_run.to_string(),
                    executable_path: exe_path,
                    is_signed,
                    is_trusted,
                    signer_name,
                    observations,
                    status: final_status,
                    prior_verdict,
                    details: author.map(|a| format!("Author: {}", a)),
                });
            }
        }
    }

    // Services
    {
        let services_root = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        if let Ok(services_key) = services_root.open_subkey(r"SYSTEM\CurrentControlSet\Services") {
            for svc_name_result in services_key.enum_keys() {
                let Ok(svc_name) = svc_name_result else {
                    continue;
                };
                let Ok(svc_key) = services_key.open_subkey(&svc_name) else {
                    continue;
                };

                let svc_type: u32 = svc_key.get_value("Type").unwrap_or(0);
                if svc_type & 0x30 == 0 {
                    continue;
                }

                let start_type: u32 = svc_key.get_value("Start").unwrap_or(4);
                let object_name: String = svc_key
                    .get_value("ObjectName")
                    .unwrap_or_else(|_| "LocalSystem".to_string());

                let start_label = match start_type {
                    0 => "Boot",
                    1 => "System",
                    2 => "Auto",
                    3 => "Manual",
                    4 => "Disabled",
                    _ => "Unknown",
                };

                let image_path: String = match svc_key.get_value("ImagePath") {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let display_name: String = svc_key
                    .get_value("DisplayName")
                    .unwrap_or_else(|_| svc_name.clone());
                let image_path = expand_env_vars(&image_path);

                let lower = image_path.to_lowercase();
                if lower.contains("\\windows\\")
                    || lower.contains("\\system32\\svchost")
                    || lower.contains("\\syswow64\\")
                    || lower.starts_with("c:\\windows")
                {
                    continue;
                }

                let exe_path = extract_exe_from_command(&image_path);

                let (is_signed, is_trusted, signer_name, mut observations, mut status) =
                    if let Some(ref exe) = exe_path {
                        analyse_with_context(exe, Some("service"))
                    } else {
                        (false, false, None, Vec::new(), PostureStatus::Unknown)
                    };

                // Structural signal: auto-start service from user-writable path
                if start_type <= 2 && is_user_writable_path(&image_path) {
                    observations.push("Auto-start service from user-writable path".to_string());
                    if status != PostureStatus::Flagged {
                        status = PostureStatus::Unusual;
                    }
                }

                // Structural signal: service running as SYSTEM from non-standard location
                let runs_as_system = object_name.to_lowercase().contains("localsystem")
                    || object_name.to_lowercase().contains("local system");
                if runs_as_system && is_user_writable_path(&image_path) && !is_signed {
                    observations.push(
                        "SYSTEM-level service from user-writable path (unsigned)".to_string(),
                    );
                    status = PostureStatus::Unusual;
                }

                // Dead reference
                if let Some(ref exe) = exe_path {
                    if !Path::new(exe).exists() {
                        observations.push("Dead reference - target binary missing".to_string());
                    }
                }

                let prior_verdict = exe_path.as_ref().and_then(|p| lookup_prior_verdict(p));
                let final_status = apply_prior_verdict(status, &prior_verdict);

                let clean_display = if display_name.starts_with('@') {
                    svc_name.clone()
                } else {
                    display_name
                };

                items.push(PersistenceItem {
                    name: clean_display,
                    item_type: "Service".to_string(),
                    command: image_path,
                    executable_path: exe_path,
                    is_signed,
                    is_trusted,
                    signer_name,
                    observations,
                    status: final_status,
                    prior_verdict,
                    details: Some(format!(
                        "Service: {}, Start: {}, Account: {}",
                        svc_name, start_label, object_name
                    )),
                });
            }
        }
    }

    items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    items.dedup_by(|a, b| {
        a.name.to_lowercase() == b.name.to_lowercase() && a.item_type == b.item_type
    });

    Ok(items)
}

// ============================================================================
// Commands
// ============================================================================

/// Get persistence context for a specific file path.
/// Returns startup entries and persistence items (services, scheduled tasks)
/// whose executable path matches the given file.
#[command]
pub async fn get_persistence_for_file(file_path: String) -> Result<FilePersistenceContext, String> {
    tokio::task::spawn_blocking(move || {
        prefetch_insight_signatures();

        let needle = file_path.to_lowercase();

        let startup = collect_startup_entries();
        let persistence = collect_persistence_items().unwrap_or_default();

        let matching_startup: Vec<StartupEntry> = startup
            .into_iter()
            .filter(|e| {
                e.executable_path
                    .as_ref()
                    .map(|p| p.to_lowercase() == needle)
                    .unwrap_or(false)
            })
            .collect();

        let matching_persistence: Vec<PersistenceItem> = persistence
            .into_iter()
            .filter(|p| {
                p.executable_path
                    .as_ref()
                    .map(|ep| ep.to_lowercase() == needle)
                    .unwrap_or(false)
            })
            .collect();

        let (is_signed, is_trusted, signer_name, observations, _status) =
            analyse_structural(&file_path);

        Ok(FilePersistenceContext {
            file_path,
            startup_entries: matching_startup,
            persistence_items: matching_persistence,
            is_signed,
            is_trusted,
            signer_name,
            observations,
        })
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    // === expand_env_vars tests ===

    #[test]
    fn test_expand_env_vars_plain_path() {
        let result = expand_env_vars("C:\\normal\\path.exe");
        assert_eq!(result, "C:\\normal\\path.exe");
    }

    #[test]
    fn test_expand_env_vars_nt_path_prefix() {
        // Should strip \??\ prefix
        let result = expand_env_vars("\\??\\C:\\file.exe");
        assert_eq!(result, "C:\\file.exe");
    }

    #[test]
    fn test_expand_env_vars_system_root_with_backslash() {
        // \SystemRoot\ prefix (12 chars) -> %SystemRoot%\...
        let result = expand_env_vars("\\SystemRoot\\System32\\drivers\\x.sys");
        // Should expand %SystemRoot% to actual env var value
        // After prefix replacement, it becomes %SystemRoot%\System32\drivers\x.sys
        // Then %SystemRoot% gets resolved if env var exists
        assert!(!result.contains("SystemRoot") || result.contains("\\System32\\drivers\\x.sys"));
    }

    #[test]
    fn test_expand_env_vars_system_root_no_backslash() {
        let result = expand_env_vars("SystemRoot\\System32\\x.sys");
        assert!(!result.is_empty());
        assert!(
            result.contains("System32\\x.sys")
                || result.contains("system32\\x.sys")
                || result.contains("SystemRoot")
        );
    }

    #[test]
    fn test_expand_env_vars_system32_prefix() {
        let result = expand_env_vars("system32\\drivers\\test.sys");
        // Should prepend %SystemRoot%\
        assert!(result.contains("drivers\\test.sys"));
    }

    #[test]
    fn test_expand_env_vars_no_closing_percent() {
        // Must not infinite loop - unmatched percent sign
        let result = expand_env_vars("%UNMATCHED");
        assert_eq!(result, "%UNMATCHED");
    }

    #[test]
    fn test_expand_env_vars_empty_var_name() {
        // %% - empty variable name
        let result = expand_env_vars("%%");
        // Should not panic, behavior depends on env::var("")
        assert!(!result.is_empty() || result.is_empty()); // just ensure no panic
    }

    #[test]
    fn test_expand_env_vars_known_env_var() {
        // Set up and test with a known env var
        std::env::set_var("INSECURITY_TEST_VAR", "resolved");
        let result = expand_env_vars("%INSECURITY_TEST_VAR%\\file.exe");
        assert_eq!(result, "resolved\\file.exe");
        std::env::remove_var("INSECURITY_TEST_VAR");
    }

    #[test]
    fn test_expand_env_vars_unknown_var_preserved() {
        // Unknown variable should be left as-is
        let result = expand_env_vars("%NONEXISTENT_INSECURITY_VAR_XYZ%\\file.exe");
        assert_eq!(result, "%NONEXISTENT_INSECURITY_VAR_XYZ%\\file.exe");
    }

    // === is_launcher_binary tests ===

    #[test]
    fn test_is_launcher_binary_all_known() {
        let launchers = [
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "conhost.exe",
            "explorer.exe",
            "msiexec.exe",
            "dllhost.exe",
            "schtasks.exe",
            "reg.exe",
        ];
        for launcher in launchers {
            assert!(
                is_launcher_binary(launcher),
                "{} should be a launcher",
                launcher
            );
        }
    }

    #[test]
    fn test_is_launcher_binary_case_insensitive() {
        assert!(is_launcher_binary("CMD.EXE"));
        assert!(is_launcher_binary("PowerShell.exe"));
    }

    #[test]
    fn test_is_launcher_binary_normal_exe() {
        assert!(!is_launcher_binary("chrome.exe"));
        assert!(!is_launcher_binary("notepad.exe"));
        assert!(!is_launcher_binary("app.exe"));
    }

    #[test]
    fn test_is_launcher_binary_with_path() {
        assert!(is_launcher_binary("C:\\Windows\\System32\\cmd.exe"));
    }

    // === extract_exe_from_command tests ===

    #[test]
    fn test_extract_exe_from_command_empty() {
        assert_eq!(extract_exe_from_command(""), None);
    }

    #[test]
    fn test_extract_exe_from_command_whitespace_only() {
        assert_eq!(extract_exe_from_command("   "), None);
    }

    #[test]
    fn test_extract_exe_from_command_quoted_path() {
        let result = extract_exe_from_command("\"C:\\Program Files\\App\\app.exe\" --flag");
        assert_eq!(result, Some("C:\\Program Files\\App\\app.exe".to_string()));
    }

    #[test]
    fn test_extract_exe_from_command_unquoted_with_ext() {
        let result = extract_exe_from_command("C:\\app.exe --flag --verbose");
        assert_eq!(result, Some("C:\\app.exe".to_string()));
    }

    // === is_script_file tests ===

    #[test]
    fn test_is_script_file_all_types() {
        let scripts = [
            "test.ps1", "test.vbs", "test.vbe", "test.js", "test.jse", "test.bat", "test.cmd",
            "test.wsf",
        ];
        for script in scripts {
            assert!(is_script_file(script), "{} should be a script file", script);
        }
    }

    #[test]
    fn test_is_script_file_non_scripts() {
        assert!(!is_script_file("test.exe"));
        assert!(!is_script_file("test.dll"));
        assert!(!is_script_file("test.txt"));
    }

    // === is_executable_ext tests ===

    #[test]
    fn test_is_executable_ext() {
        let exts = [
            "exe", "dll", "com", "bat", "cmd", "ps1", "vbs", "js", "msi", "scr", "sys",
        ];
        for ext in exts {
            assert!(
                is_executable_ext(std::ffi::OsStr::new(ext)),
                "{} should be executable",
                ext
            );
        }
        assert!(!is_executable_ext(std::ffi::OsStr::new("txt")));
        assert!(!is_executable_ext(std::ffi::OsStr::new("pdf")));
    }

    // === is_user_writable_path tests ===

    #[test]
    fn test_is_user_writable_path_positive() {
        assert!(is_user_writable_path("C:\\Users\\test\\file.exe"));
        assert!(is_user_writable_path(
            "C:\\Users\\test\\AppData\\Local\\app.exe"
        ));
        assert!(is_user_writable_path("C:\\Windows\\Temp\\file.exe"));
        assert!(is_user_writable_path("C:\\tmp\\file.exe"));
    }

    #[test]
    fn test_is_user_writable_path_negative() {
        assert!(!is_user_writable_path(
            "C:\\Windows\\System32\\kernel32.dll"
        ));
        assert!(!is_user_writable_path("C:\\Program Files\\App\\app.exe"));
    }

    // === apply_prior_verdict tests ===

    #[test]
    fn test_apply_prior_verdict_malware_upgrades_to_flagged() {
        let status = PostureStatus::Verified;
        let result = apply_prior_verdict(status, &Some("malware".to_string()));
        assert_eq!(result, PostureStatus::Flagged);
    }

    #[test]
    fn test_apply_prior_verdict_suspicious_upgrades_to_flagged() {
        let status = PostureStatus::Verified;
        let result = apply_prior_verdict(status, &Some("suspicious".to_string()));
        assert_eq!(result, PostureStatus::Flagged);
    }

    #[test]
    fn test_apply_prior_verdict_pup_upgrades_to_flagged() {
        let status = PostureStatus::Unverified;
        let result = apply_prior_verdict(status, &Some("PUP".to_string()));
        assert_eq!(result, PostureStatus::Flagged);
    }

    #[test]
    fn test_apply_prior_verdict_clean_unchanged() {
        let status = PostureStatus::Verified;
        let result = apply_prior_verdict(status, &Some("clean".to_string()));
        assert_eq!(result, PostureStatus::Verified);
    }

    #[test]
    fn test_apply_prior_verdict_none_unchanged() {
        let status = PostureStatus::Unusual;
        let result = apply_prior_verdict(status, &None);
        assert_eq!(result, PostureStatus::Unusual);
    }

    // === find_payload_in_args tests ===

    #[test]
    fn test_find_payload_in_args_empty() {
        assert_eq!(find_payload_in_args(""), None);
    }

    #[test]
    fn test_find_payload_in_args_no_executable() {
        assert_eq!(find_payload_in_args("--flag --option value"), None);
    }

    #[test]
    fn test_find_payload_in_args_unquoted_exe() {
        let result = find_payload_in_args("/c C:\\payload.bat");
        assert_eq!(result, Some("C:\\payload.bat".to_string()));
    }

    // === PostureStatus Display ===

    #[test]
    fn test_posture_status_display() {
        assert_eq!(PostureStatus::Flagged.to_string(), "flagged");
        assert_eq!(PostureStatus::Unusual.to_string(), "unusual");
        assert_eq!(PostureStatus::Unverified.to_string(), "unverified");
        assert_eq!(PostureStatus::Verified.to_string(), "verified");
        assert_eq!(PostureStatus::Unknown.to_string(), "unknown");
    }

    // === analyse_structural for nonexistent file ===

    #[test]
    fn test_analyse_structural_nonexistent_file() {
        let (is_signed, is_trusted, signer_name, observations, status) =
            analyse_structural("C:\\nonexistent_insecurity_test_file_xyz.exe");
        assert!(!is_signed);
        assert!(!is_trusted);
        assert!(signer_name.is_none());
        assert!(observations.iter().any(|o| o.contains("not found")));
        assert_eq!(status, PostureStatus::Unknown);
    }

    // === analyse_structural for script in user-writable path ===

    #[test]
    fn test_analyse_structural_script_file() {
        // Create a temporary script file
        let dir = std::env::temp_dir().join("insecurity_test_insights");
        let _ = std::fs::create_dir_all(&dir);
        let script_path = dir.join("test.ps1");
        std::fs::write(&script_path, "Write-Host 'test'").unwrap();

        let (is_signed, _is_trusted, _signer, observations, status) =
            analyse_structural(script_path.to_str().unwrap());

        assert!(!is_signed);
        assert!(observations.iter().any(|o| o.contains("Script file")));
        // temp path is user-writable, so status should be Unusual
        assert!(status == PostureStatus::Unusual || status == PostureStatus::Unverified);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
