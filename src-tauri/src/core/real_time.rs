use notify::Watcher;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Result as NotifyResult};
use serde::Serialize;
use std::collections::hash_map::Entry;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use sysinfo::{ProcessRefreshKind, System, UpdateKind};
use tauri::AppHandle;
use tauri::Emitter;

use crate::cache::cache_manager::CacheConfig;
use crate::commands::scan::set_current_file;
use crate::core::pipeline::ScanResult;
use crate::core::utils::{is_dev_build_artifact_path, is_scannable_file, is_system_path};
use crate::core::DetectionPipeline;
use crate::database::models::Verdict as DbVerdict;
use crate::database::queries::DatabaseQueries;
use chrono::Utc;

// ── Notification rate-limiter ──────────────────────────────────────────
// Prevents toast-notification spam when many threats arrive in a burst
// (e.g. extracting an archive containing several malicious files).
//
// Rules:
//  • Same threat identity (normalized path + hash when available) → suppressed
//    for NOTIFICATION_DEDUP_SECS seconds
//  • Global cap of MAX_NOTIFICATIONS_PER_WINDOW in a sliding window
//  • When the cap is hit the extras are counted and a single
//    "N more threats detected" summary is sent when the window expires.
const NOTIFICATION_DEDUP_SECS: u64 = 60;
const MAX_NOTIFICATIONS_PER_WINDOW: usize = 5;
const NOTIFICATION_WINDOW_SECS: u64 = 30;

struct NotificationLimiter {
    /// notification identity → last-notification Instant
    recent: std::collections::HashMap<String, Instant>,
    /// timestamps of notifications sent inside the current window
    window_timestamps: Vec<Instant>,
    /// count of suppressed notifications since last summary
    suppressed_count: u32,
    /// when we last sent a "…more threats" summary
    last_summary: Option<Instant>,
}

impl NotificationLimiter {
    fn new() -> Self {
        Self {
            recent: std::collections::HashMap::new(),
            window_timestamps: Vec::new(),
            suppressed_count: 0,
            last_summary: None,
        }
    }

    /// Returns `true` if this notification should be shown.
    fn should_notify(&mut self, key: &str) -> bool {
        let now = Instant::now();

        // --- per-file dedup ---
        if let Some(last) = self.recent.get(key) {
            if now.duration_since(*last) < Duration::from_secs(NOTIFICATION_DEDUP_SECS) {
                log::debug!("Notification suppressed (dedup) for: {}", key);
                self.suppressed_count += 1;
                return false;
            }
        }

        // --- sliding-window rate limit ---
        self.window_timestamps
            .retain(|t| now.duration_since(*t) < Duration::from_secs(NOTIFICATION_WINDOW_SECS));

        if self.window_timestamps.len() >= MAX_NOTIFICATIONS_PER_WINDOW {
            log::debug!("Notification suppressed (rate limit) for: {}", key);
            self.suppressed_count += 1;
            return false;
        }

        // --- housekeep old dedup entries every ~60 s ---
        if self.recent.len() > 200 {
            let cutoff = now - Duration::from_secs(NOTIFICATION_DEDUP_SECS);
            self.recent.retain(|_, v| *v > cutoff);
        }

        self.recent.insert(key.to_string(), now);
        self.window_timestamps.push(now);
        true
    }

    /// If notifications were suppressed, returns the count so the caller
    /// can fire a single "N more threats" summary toast.
    fn take_suppressed(&mut self) -> u32 {
        let n = self.suppressed_count;
        self.suppressed_count = 0;
        n
    }

    /// `true` when enough time has passed to send another summary toast.
    fn should_send_summary(&mut self) -> bool {
        let now = Instant::now();
        match self.last_summary {
            Some(t) if now.duration_since(t) < Duration::from_secs(NOTIFICATION_WINDOW_SECS) => {
                false
            }
            _ => {
                self.last_summary = Some(now);
                true
            }
        }
    }
}

static NOTIFICATION_LIMITER: OnceLock<Mutex<NotificationLimiter>> = OnceLock::new();

fn get_notification_limiter() -> &'static Mutex<NotificationLimiter> {
    NOTIFICATION_LIMITER.get_or_init(|| Mutex::new(NotificationLimiter::new()))
}

fn ui_language_is_bulgarian() -> bool {
    crate::config::Settings::load()
        .language
        .to_lowercase()
        .starts_with("bg")
}

fn localized_threat_notification(result: &ScanResult, file_name: &str) -> Option<(String, String)> {
    let is_bg = ui_language_is_bulgarian();
    let threat_name = result.threat_name.as_deref().unwrap_or(if is_bg {
        "Неизвестна заплаха"
    } else {
        "Unknown threat"
    });

    match result.verdict {
        crate::core::pipeline::Verdict::Malware => Some(if is_bg {
            (
                "InSecurity - Открита заплаха".to_string(),
                format!(
                    "Защитата в реално време блокира зловреден файл.\nФайл: {}\nЗаплаха: {}\nУвереност: {:.0}%",
                    file_name,
                    threat_name,
                    result.confidence * 100.0
                ),
            )
        } else {
            (
                "InSecurity - Threat Detected".to_string(),
                format!(
                    "Real-time protection blocked a malicious file.\nFile: {}\nThreat: {}\nConfidence: {:.0}%",
                    file_name,
                    threat_name,
                    result.confidence * 100.0
                ),
            )
        }),
        crate::core::pipeline::Verdict::Suspicious => Some(if is_bg {
            (
                "InSecurity - Открит подозрителен файл".to_string(),
                format!(
                    "Открит и маркиран е подозрителен файл.\nФайл: {}\nЗаплаха: {}\nУвереност: {:.0}%",
                    file_name,
                    threat_name,
                    result.confidence * 100.0
                ),
            )
        } else {
            (
                "InSecurity - Suspicious File Detected".to_string(),
                format!(
                    "A suspicious file was detected and flagged.\nFile: {}\nThreat: {}\nConfidence: {:.0}%",
                    file_name,
                    threat_name,
                    result.confidence * 100.0
                ),
            )
        }),
        _ => None,
    }
}

fn localized_suppressed_summary(count: u32) -> (String, String) {
    if ui_language_is_bulgarian() {
        let body = if count == 1 {
            "Открита е още 1 заплаха.\nОтворете InSecurity за подробности.".to_string()
        } else {
            format!(
                "Открити са още {} заплахи.\nОтворете InSecurity за подробности.",
                count
            )
        };
        ("InSecurity - Няколко заплахи".to_string(), body)
    } else {
        (
            "InSecurity - Multiple Threats".to_string(),
            format!(
                "{} additional threat{} detected.\nOpen InSecurity for details.",
                count,
                if count == 1 { "" } else { "s" }
            ),
        )
    }
}

/// Limit concurrent realtime scan tasks to prevent resource exhaustion
/// under rapid file change scenarios (e.g., extract archive, ransomware attack)
static ACTIVE_SCAN_COUNT: AtomicUsize = AtomicUsize::new(0);
const MAX_CONCURRENT_SCANS: usize = 8; // Balance between responsiveness and resource usage

/// When true, the user has disabled real-time protection via Settings.
/// Unlike `REALTIME_PAUSED` (which pauses during manual scans), this is a
/// persistent user preference that suppresses all file-watcher and process-
/// monitor scanning until re-enabled.
static PROTECTION_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Check if the user has disabled real-time protection in settings.
pub fn is_protection_disabled() -> bool {
    PROTECTION_DISABLED.load(Ordering::SeqCst)
}

/// Set the real-time protection disabled flag (called from settings command).
pub fn set_protection_disabled(disabled: bool) {
    PROTECTION_DISABLED.store(disabled, Ordering::SeqCst);
    log::info!(
        "Real-time protection {}",
        if disabled {
            "disabled by user"
        } else {
            "re-enabled by user"
        }
    );
}

/// Global handle to the file watcher so new paths can be added at runtime
static GLOBAL_WATCHER: OnceLock<Arc<Mutex<RecommendedWatcher>>> = OnceLock::new();

/// Dynamically add a watch path to the running file watcher.
/// Called when the user adds a new protected folder via settings.
pub fn add_watch_path(path: &Path) -> Result<(), String> {
    let watcher_arc = GLOBAL_WATCHER
        .get()
        .ok_or_else(|| "File watcher not initialized yet".to_string())?;
    let mut watcher = watcher_arc
        .lock()
        .map_err(|e| format!("Watcher lock poisoned: {}", e))?;
    watcher
        .watch(path, RecursiveMode::Recursive)
        .map_err(|e| format!("Failed to watch {:?}: {}", path, e))?;
    log::info!("Dynamically added watch path: {:?}", path);
    Ok(())
}

/// Dynamically remove a watch path from the running file watcher.
/// Called when the user removes a protected folder via settings.
pub fn remove_watch_path(path: &Path) -> Result<(), String> {
    let watcher_arc = GLOBAL_WATCHER
        .get()
        .ok_or_else(|| "File watcher not initialized yet".to_string())?;
    let mut watcher = watcher_arc
        .lock()
        .map_err(|e| format!("Watcher lock poisoned: {}", e))?;
    watcher
        .unwatch(path)
        .map_err(|e| format!("Failed to unwatch {:?}: {}", path, e))?;
    log::info!("Dynamically removed watch path: {:?}", path);
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct RealtimeScanEvent {
    pub file_path: String,
    #[serde(flatten)]
    pub result: ScanResult,
}

/// Resolve the absolute path to the app icon for use in notifications.
/// On Windows, this sets the `appLogoOverride` in the toast notification,
/// showing the InSecurity icon instead of the default terminal/PowerShell icon.
fn resolve_notification_icon() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;

    // Dev mode: exe is in src-tauri/target/debug/
    let dev_icon = exe_dir.join("../../icons/icon.png");
    if dev_icon.exists() {
        return Some(dev_icon.canonicalize().ok()?.to_string_lossy().to_string());
    }

    // Production: icons may be alongside the exe or in a resources subfolder
    for candidate in [
        exe_dir.join("icons/icon.png"),
        exe_dir.join("icon.png"),
        exe_dir.join("../resources/icons/icon.png"),
    ] {
        if candidate.exists() {
            return Some(candidate.canonicalize().ok()?.to_string_lossy().to_string());
        }
    }

    None
}

/// Send a native OS notification when a threat is detected during real-time scanning.
/// Shows a Windows toast notification similar to Windows Defender / other AV software.
/// Rate-limited to avoid spamming the user when many threats arrive at once.
fn send_threat_notification(
    app: &AppHandle,
    notification_identity: &str,
    file_path: &str,
    result: &ScanResult,
) {
    use tauri_plugin_notification::NotificationExt;

    // ── Rate-limit / dedup check ──
    let dedup_key = if notification_identity.trim().is_empty() {
        file_path
    } else {
        notification_identity
    };
    if let Ok(mut limiter) = get_notification_limiter().lock() {
        if !limiter.should_notify(dedup_key) {
            // Fire a summary toast if enough suppressed notifications have piled up
            send_suppressed_summary(app, &mut limiter);
            return;
        }
    }

    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file_path);

    let Some((title, body)) = localized_threat_notification(result, file_name) else {
        return;
    };

    let mut builder = app.notification().builder().title(&title).body(&body);

    if let Some(icon_path) = resolve_notification_icon() {
        builder = builder.icon(icon_path);
    }

    if let Err(e) = builder.show() {
        log::warn!("Failed to send threat notification: {}", e);
    }
}

/// If several notifications were suppressed by the rate limiter, send a
/// single summary toast so the user still knows things are happening.
fn send_suppressed_summary(app: &AppHandle, limiter: &mut NotificationLimiter) {
    let n = limiter.take_suppressed();
    if n == 0 || !limiter.should_send_summary() {
        // Put the count back if we can't send yet
        if n > 0 {
            limiter.suppressed_count += n;
        }
        return;
    }

    use tauri_plugin_notification::NotificationExt;
    let (title, body) = localized_suppressed_summary(n);

    let mut builder = app.notification().builder().title(&title).body(&body);

    if let Some(icon_path) = resolve_notification_icon() {
        builder = builder.icon(icon_path);
    }

    if let Err(e) = builder.show() {
        log::warn!("Failed to send summary notification: {}", e);
    }
}

/// Shared post-scan handler: persist verdict to DB, update cache, emit event to frontend.
/// Used by both the file watcher and process monitor to avoid code duplication.
fn handle_realtime_scan_result(
    result: ScanResult,
    file_path: &str,
    app: &AppHandle,
    cache: &Arc<std::sync::Mutex<crate::cache::cache_manager::CacheManager>>,
) {
    let verdict_str = format!("{:?}", result.verdict);

    // --- Native OS notification for threats (like real AV software) ---
    // Only notify for actual threats (Malware/Suspicious), not Unknown
    // (Unknown includes unreadable files, files too large to scan, etc.)
    if matches!(
        result.verdict,
        crate::core::pipeline::Verdict::Malware | crate::core::pipeline::Verdict::Suspicious
    ) {
        let notification_identity = threat_notification_identity(file_path, &result.file_hash);
        send_threat_notification(app, &notification_identity, file_path, &result);
    }

    let rec = DbVerdict {
        id: 0,
        file_hash: result.file_hash.clone(),
        file_path: file_path.to_string(),
        verdict: verdict_str.clone(),
        confidence: result.confidence,
        threat_level: result.threat_level.clone(),
        threat_name: result.threat_name.clone(),
        scan_time_ms: result.scan_time_ms,
        scanned_at: Utc::now().timestamp(),
        source: "realtime".to_string(),
    };
    crate::database::batcher::enqueue_verdict(rec);

    if let Ok(mut lock) = cache.lock() {
        let local_cache = lock.get_cache_mut();
        let now_ts = Utc::now().timestamp() as u64;
        local_cache.set(
            result.file_hash.clone(),
            crate::cache::hash_cache::CachedVerdict {
                verdict: verdict_str,
                confidence: result.confidence,
                timestamp: now_ts,
                ttl_seconds: CacheConfig::default().ttl_seconds,
                last_accessed: now_ts,
                threat_name: result.threat_name.clone(),
            },
        );
    } else {
        log::warn!("Realtime cache mutex poisoned; skipping cache write");
    }

    let event = RealtimeScanEvent {
        file_path: file_path.to_string(),
        result,
    };
    if let Err(e) = app.emit("realtime_scan_result", event) {
        log::warn!("Failed to emit realtime_scan_result: {}", e);
    }
}

/// Ransomware detection - tracks bulk file modifications in protected folders
#[derive(Debug, Clone, Serialize)]
pub struct RansomwareAlert {
    pub folder: String,
    pub modification_count: u32,
    pub time_window_seconds: u32,
    pub sample_files: Vec<String>,
    pub alert_level: String,
    pub suspected_processes: Vec<ProcessInfo>,
    pub processes_killed: Vec<String>,
    pub average_entropy: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
}

/// Global mutable state for live threshold reloading.
/// The watcher thread reads this on every event instead of re-loading Settings.
static RANSOMWARE_THRESHOLD: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(20);
static RANSOMWARE_WINDOW: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(10);
const NON_CANARY_ALERT_MIN_AVG_ENTROPY: f64 = 7.4;
const NON_CANARY_OUTSIDE_FOLDER_MIN_WRITTEN_BYTES: u64 = 8 * 1024 * 1024;
const NON_CANARY_INSIDE_FOLDER_MIN_WRITTEN_BYTES: u64 = 1 * 1024 * 1024;

/// Adaptive per-folder threshold overrides (folder -> (threshold, expiry Instant))
/// Set when user dismisses a false positive; expires after 1 hour.
static ADAPTIVE_THRESHOLDS: OnceLock<Mutex<std::collections::HashMap<String, (u32, Instant)>>> =
    OnceLock::new();

fn get_adaptive_thresholds() -> &'static Mutex<std::collections::HashMap<String, (u32, Instant)>> {
    ADAPTIVE_THRESHOLDS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Called from settings command when user changes thresholds at runtime.
pub fn reload_ransomware_thresholds(threshold: u32, window_seconds: u32) {
    RANSOMWARE_THRESHOLD.store(threshold, Ordering::SeqCst);
    RANSOMWARE_WINDOW.store(window_seconds, Ordering::SeqCst);
    log::info!(
        "Ransomware thresholds reloaded: {} files in {} seconds",
        threshold,
        window_seconds
    );
}

/// Called when user dismisses a false-positive alert — temporarily raise the
/// threshold for that folder by 50% for 1 hour.
pub fn adapt_threshold_for_folder(folder: &str) {
    let base = RANSOMWARE_THRESHOLD.load(Ordering::SeqCst);
    let adapted = base + base / 2; // +50%
    let expiry = Instant::now() + Duration::from_secs(3600);
    if let Ok(mut map) = get_adaptive_thresholds().lock() {
        map.insert(folder.to_string(), (adapted, expiry));
    }
    log::info!(
        "Adaptive threshold for {}: {} (expires in 1 hour)",
        folder,
        adapted
    );
}

/// Get the effective threshold for a folder (base or adapted if active).
fn effective_threshold_for(folder: &str) -> u32 {
    let base = RANSOMWARE_THRESHOLD.load(Ordering::SeqCst);
    if let Ok(mut map) = get_adaptive_thresholds().lock() {
        if let Some((adapted, expiry)) = map.get(folder) {
            if Instant::now() < *expiry {
                return *adapted;
            } else {
                map.remove(folder);
            }
        }
    }
    base
}

/// Track file modifications per folder for ransomware detection.
/// Uses cooldown-based suppression: after an alert fires, further alerts for
/// the same folder are suppressed for `cooldown_seconds`. The counter keeps
/// incrementing so the next alert fires immediately once the cooldown expires.
///
/// Enhanced with entropy tracking and adaptive thresholds.
struct FolderModificationTracker {
    counts: std::collections::HashMap<String, (u32, Instant)>,
    window_seconds: u64,
    cooldown_seconds: u64,
    alert_cooldowns: std::collections::HashMap<String, Instant>,
    /// Rolling entropy samples per folder (last N file entropies)
    recent_entropies: std::collections::HashMap<String, Vec<f64>>,
}

impl FolderModificationTracker {
    fn new(window_seconds: u64) -> Self {
        Self {
            counts: std::collections::HashMap::new(),
            window_seconds,
            cooldown_seconds: 30,
            alert_cooldowns: std::collections::HashMap::new(),
            recent_entropies: std::collections::HashMap::new(),
        }
    }

    /// Update the tracker's window from the global atomic (called when settings change).
    fn sync_window(&mut self) {
        self.window_seconds = RANSOMWARE_WINDOW.load(Ordering::SeqCst) as u64;
    }

    /// Record a file's entropy for a folder.
    fn record_entropy(&mut self, folder: &str, entropy: f64) {
        let entries = self.recent_entropies.entry(folder.to_string()).or_default();
        entries.push(entropy);
        // Keep last 50 entropy samples
        if entries.len() > 50 {
            entries.drain(0..entries.len() - 50);
        }
    }

    /// Get average entropy for recently modified files in a folder.
    fn average_entropy(&self, folder: &str) -> f64 {
        self.recent_entropies
            .get(folder)
            .map(|ents| {
                if ents.is_empty() {
                    0.0
                } else {
                    ents.iter().sum::<f64>() / ents.len() as f64
                }
            })
            .unwrap_or(0.0)
    }

    /// Track a file modification. Returns Some(count) when an alert should fire.
    /// Uses per-folder adaptive thresholds.
    fn track_modification(&mut self, folder: &str) -> Option<u32> {
        let now = Instant::now();

        // Update count for this folder
        let current_count = match self.counts.get_mut(folder) {
            Some((count, window_start)) => {
                if now.duration_since(*window_start) > Duration::from_secs(self.window_seconds) {
                    // Window expired — reset
                    *count = 1;
                    *window_start = now;
                    // Also clear entropy samples for fresh window
                    self.recent_entropies.remove(folder);
                } else {
                    *count += 1;
                }
                *count
            }
            None => {
                self.counts.insert(folder.to_string(), (1, now));
                1
            }
        };

        let threshold = effective_threshold_for(folder);
        if current_count < threshold {
            return None;
        }

        // Threshold exceeded — check entropy to reduce false positives.
        // If average entropy is below 7.0 AND we don't have extremely high
        // individual samples (>7.9), this is likely a benign bulk operation.
        let avg_ent = self.average_entropy(folder);
        if avg_ent < 7.0 && avg_ent > 0.0 {
            // Low entropy — probably not ransomware (build, install, unzip)
            log::debug!(
                "Ransomware threshold hit ({} files in {}) but avg entropy {:.2} is below 7.0 — suppressing",
                current_count, folder, avg_ent
            );
            return None;
        }

        // Threshold exceeded — check cooldown before alerting
        if let Some(cooldown_start) = self.alert_cooldowns.get(folder) {
            if now.duration_since(*cooldown_start) < Duration::from_secs(self.cooldown_seconds) {
                return None; // Still in cooldown, suppress alert but keep counting
            }
        }

        // Fire alert and start cooldown
        self.alert_cooldowns.insert(folder.to_string(), now);
        // Reset counter so we track the next batch
        if let Some((count, window_start)) = self.counts.get_mut(folder) {
            *count = 0;
            *window_start = now;
        }
        Some(current_count)
    }
}

/// Normalize a path for comparison: unify slashes and strip trailing separators.
fn normalize_path_for_comparison(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn path_is_within_folder(path_norm: &str, folder_norm: &str) -> bool {
    path_norm.starts_with(folder_norm)
        && (path_norm.len() == folder_norm.len()
            || path_norm.as_bytes().get(folder_norm.len()) == Some(&b'\\'))
}

fn threat_notification_identity(file_path: &str, file_hash: &str) -> String {
    let normalized_path = normalize_path_for_comparison(file_path);
    let normalized_hash = file_hash.trim().to_lowercase();

    match (normalized_path.is_empty(), normalized_hash.is_empty()) {
        (false, false) => format!("{}|{}", normalized_path, normalized_hash),
        (false, true) => normalized_path,
        (true, false) => normalized_hash,
        (true, true) => file_path.to_string(),
    }
}

/// Check if a path is within a protected folder.
/// Uses normalized path comparison to handle mixed slashes and trailing separators.
fn is_in_protected_folder(path: &str) -> Option<String> {
    let cfg = crate::config::Settings::load();
    if !cfg.ransomware_protection {
        return None;
    }

    let path_norm = normalize_path_for_comparison(path);
    for folder in &cfg.protected_folders {
        let folder_norm = normalize_path_for_comparison(folder);
        // Ensure match is at a directory boundary, not a partial name
        // e.g. "C:\Users\Doc" must not match "C:\Users\Documents\file.txt"
        if path_is_within_folder(&path_norm, &folder_norm) {
            return Some(folder.clone());
        }
    }
    None
}

// ── Shannon entropy ────────────────────────────────────────────────────
/// Compute the Shannon entropy (0.0–8.0 for bytes) of the given data.
/// Values >7.0 are typical for encrypted/compressed content.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Compute the entropy of a file by reading its last 8KB.
/// Returns 0.0 on read failure.
fn file_entropy(path: &str) -> f64 {
    use std::io::{Read, Seek, SeekFrom};
    const SAMPLE_SIZE: u64 = 8192;
    let Ok(mut f) = std::fs::File::open(path) else {
        return 0.0;
    };
    let Ok(meta) = f.metadata() else { return 0.0 };
    let file_len = meta.len();
    if file_len == 0 {
        return 0.0;
    }
    // Read from near the end of the file (encrypted data is there)
    let offset = if file_len > SAMPLE_SIZE {
        file_len - SAMPLE_SIZE
    } else {
        0
    };
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return 0.0;
    }
    let mut buf = vec![0u8; SAMPLE_SIZE.min(file_len) as usize];
    if f.read_exact(&mut buf).is_err() {
        // Try reading however much is available
        let _ = f.seek(SeekFrom::Start(offset));
        buf.clear();
        let _ = f.read_to_end(&mut buf);
    }
    shannon_entropy(&buf)
}

/// Check if a file has a common document extension (ransomware targets).
#[allow(dead_code)]
fn is_document_extension(path: &str) -> bool {
    let lower = path.to_lowercase();
    const DOC_EXTS: &[&str] = &[
        ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".pdf", ".txt", ".rtf", ".odt", ".ods",
        ".odp", ".csv", ".json", ".xml", ".html", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
        ".mp3", ".mp4", ".zip", ".rar", ".7z",
    ];
    DOC_EXTS.iter().any(|ext| lower.ends_with(ext))
}

// ── Developer tool detection ───────────────────────────────────────────

/// Developer tool process names that commonly perform bulk file operations.
/// Used alongside is_trusted_publisher_path() to suppress false positives.
const KNOWN_DEV_TOOL_PROCESSES: &[&str] = &[
    "git.exe",
    "node.exe",
    "code.exe",
    "code - insiders.exe",
    "cursor.exe",
    "windsurf.exe",
    "githubdesktop.exe",
    "cargo.exe",
    "rustc.exe",
    "python.exe",
    "python3.exe",
    "dotnet.exe",
    "msbuild.exe",
    "javac.exe",
    "npm.exe",
    "npx.exe",
    "bun.exe",
    "deno.exe",
    "go.exe",
    "claude.exe",
];

/// Additional trusted paths specific to developer toolchains.
/// These are standard install locations that is_trusted_publisher_path() doesn't cover.
const DEV_TOOLCHAIN_PATHS: &[&str] = &[
    "\\.cargo\\",
    "\\.rustup\\",
    "\\.nvm\\",
    "\\.volta\\",
    "\\.pyenv\\",
    "\\.goenv\\",
    "\\scoop\\",
    "\\chocolatey\\",
    "\\appdata\\local\\programs\\", // Electron app user-install location (VS Code, Cursor, etc.)
];

const USER_WRITABLE_SUSPECT_PATH_MARKERS: &[&str] = &[
    "\\users\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\tmp\\",
];

/// Check if a process is a known developer tool running from a trusted install path.
/// Reuses is_trusted_publisher_path() from utils.rs for general path validation,
/// plus dev toolchain paths (e.g. .cargo, .rustup) to prevent spoofing.
fn is_known_dev_tool(proc: &ProcessInfo) -> bool {
    let name_lower = proc.name.to_lowercase();
    if !KNOWN_DEV_TOOL_PROCESSES
        .iter()
        .any(|&tool| name_lower == tool)
    {
        return false;
    }
    // Check standard install paths (Program Files, AppData, etc.)
    if crate::core::utils::is_trusted_publisher_path(&proc.exe_path) {
        return true;
    }
    // Check dev toolchain paths (.cargo, .rustup, etc.)
    let path_lower = proc.exe_path.to_lowercase();
    DEV_TOOLCHAIN_PATHS.iter().any(|&p| path_lower.contains(p))
}

fn is_trusted_ransomware_suspect(proc: &ProcessInfo) -> bool {
    if crate::core::utils::is_trusted_publisher_path(&proc.exe_path) {
        return true;
    }

    let sig = crate::core::signature::verify_signature(&proc.exe_path);
    matches!(
        sig.trust_level,
        crate::core::signature::TrustLevel::PublisherAllowlist
            | crate::core::signature::TrustLevel::PublisherMatch
            | crate::core::signature::TrustLevel::CA
    )
}

fn is_user_writable_ransomware_suspect_path(path: &str) -> bool {
    let path_lower = normalize_path_for_comparison(path);
    USER_WRITABLE_SUSPECT_PATH_MARKERS
        .iter()
        .any(|marker| path_lower.contains(marker))
}

fn has_actionable_non_canary_write_signal(
    exe_path: &str,
    protected_folder: &str,
    written_bytes: u64,
) -> bool {
    let exe_norm = normalize_path_for_comparison(exe_path);
    let folder_norm = normalize_path_for_comparison(protected_folder);
    let inside_protected_folder = path_is_within_folder(&exe_norm, &folder_norm);

    if !inside_protected_folder && !is_user_writable_ransomware_suspect_path(&exe_norm) {
        return false;
    }

    let min_required_writes = if inside_protected_folder {
        NON_CANARY_INSIDE_FOLDER_MIN_WRITTEN_BYTES
    } else {
        NON_CANARY_OUTSIDE_FOLDER_MIN_WRITTEN_BYTES
    };

    written_bytes >= min_required_writes
}

fn is_benign_ransomware_suspect(proc: &ProcessInfo) -> bool {
    is_known_dev_tool(proc) || is_trusted_ransomware_suspect(proc)
}

fn filter_actionable_ransomware_suspects(suspects: Vec<ProcessInfo>) -> Vec<ProcessInfo> {
    suspects
        .into_iter()
        .filter(|proc| !is_benign_ransomware_suspect(proc))
        .collect()
}

fn should_emit_non_canary_ransomware_alert(
    modification_count: u32,
    effective_threshold: u32,
    average_entropy: f64,
    suspects: &[ProcessInfo],
) -> bool {
    modification_count >= effective_threshold
        && average_entropy >= NON_CANARY_ALERT_MIN_AVG_ENTROPY
        && !suspects.is_empty()
}

// ── Process identification & termination ───────────────────────────────

/// Identify processes that may be responsible for rapid file modifications
/// in a protected folder. Uses sysinfo to snap current processes and
/// filters by executable paths that are NOT system paths.
fn identify_modifying_processes(folder: &str) -> Vec<ProcessInfo> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        ProcessRefreshKind::new()
            .with_exe(UpdateKind::Always)
            .with_disk_usage(),
    );

    let folder_norm = normalize_path_for_comparison(folder);
    let mut suspects: Vec<ProcessInfo> = Vec::new();

    for (pid, process) in sys.processes() {
        // Ignore PID 0 / 4 (System)
        let pid_u32 = pid.as_u32();
        if pid_u32 <= 4 {
            continue;
        }

        let exe_path = match process.exe() {
            Some(p) => match p.to_str() {
                Some(s) => s.to_string(),
                None => continue,
            },
            None => continue,
        };

        // Skip system / known-safe processes
        if crate::core::utils::is_system_path(&exe_path) {
            continue;
        }

        let disk = process.disk_usage();
        if !has_actionable_non_canary_write_signal(&exe_path, folder, disk.written_bytes) {
            continue;
        }

        let name = process.name().to_string_lossy().to_string();
        suspects.push(ProcessInfo {
            pid: pid_u32,
            name,
            exe_path: exe_path.clone(),
        });
    }

    // Sort: processes with exe outside the protected folder first.
    suspects.sort_by_key(|p| {
        let norm = normalize_path_for_comparison(&p.exe_path);
        if path_is_within_folder(&norm, &folder_norm) {
            1
        } else {
            0
        }
    });

    // Limit to top 10 suspects
    suspects.truncate(10);
    suspects
}

/// Terminate a process by PID using the Windows API.
/// Returns the process name on success.
pub fn terminate_process(pid: u32) -> Result<String, String> {
    // First look up the process name via sysinfo
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        ProcessRefreshKind::new().with_exe(UpdateKind::Always),
    );
    let proc_name = sys
        .process(sysinfo::Pid::from_u32(pid))
        .map(|p| p.name().to_string_lossy().to_string())
        .unwrap_or_else(|| format!("PID {}", pid));

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if handle == 0 {
                return Err(format!(
                    "Failed to open process {} (PID {}): access denied or process exited",
                    proc_name, pid
                ));
            }
            let result = TerminateProcess(handle, 1);
            CloseHandle(handle);
            if result == 0 {
                return Err(format!(
                    "Failed to terminate process {} (PID {})",
                    proc_name, pid
                ));
            }
        }
        log::warn!(
            "🔪 Terminated suspected ransomware process: {} (PID {})",
            proc_name,
            pid
        );
        Ok(proc_name)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(format!(
            "Process termination not implemented on this platform (PID {})",
            pid
        ))
    }
}

/// Attempt to kill a list of suspected processes. Returns names of successfully killed processes.
fn auto_kill_suspects(suspects: &[ProcessInfo]) -> Vec<String> {
    let mut killed = Vec::new();
    for proc in suspects {
        // Safety: never kill explorer.exe, svchost, our own process
        let name_lower = proc.name.to_lowercase();
        if name_lower == "explorer.exe"
            || name_lower == "svchost.exe"
            || name_lower == "csrss.exe"
            || name_lower == "lsass.exe"
            || name_lower == "services.exe"
            || name_lower == "winlogon.exe"
            || name_lower == "system"
            || name_lower == "dwm.exe"
        {
            log::debug!(
                "Skipping protected system process: {} (PID {})",
                proc.name,
                proc.pid
            );
            continue;
        }
        // Don't kill ourselves
        if proc.pid == std::process::id() {
            continue;
        }
        // Never kill known developer tools (git, node, code, etc.)
        if is_known_dev_tool(proc) {
            log::debug!(
                "Skipping known developer tool: {} (PID {})",
                proc.name,
                proc.pid
            );
            continue;
        }
        match terminate_process(proc.pid) {
            Ok(name) => {
                crate::core::log_audit_event(
                    crate::core::AuditEventType::ThreatDetected,
                    &format!(
                        "Auto-killed suspected ransomware process: {} (PID {})",
                        name, proc.pid
                    ),
                    None,
                    Some(&format!("pid={},action=auto_kill", proc.pid)),
                );
                killed.push(name);
            }
            Err(e) => {
                log::warn!("Failed to auto-kill PID {}: {}", proc.pid, e);
            }
        }
    }
    killed
}

// ── Canary / honeypot files ────────────────────────────────────────────

/// Magic marker bytes written at the start of canary files so we can detect tampering.
const CANARY_MAGIC: &[u8; 16] = b"INSEC_CANARY_V1\0";

/// Filenames used for canary files — mimic common lock/temp files that ransomware
/// will encrypt but users won't interact with.
const CANARY_NAMES: &[&str] = &[
    ".~lock.budget_2026.xlsx#",
    ".~$important_notes.docx",
    "._backup_manifest.dat",
];

/// Deploy canary (honeypot) files in a protected folder.
/// Returns the list of created canary file paths.
pub fn deploy_canary_files_for_folder(folder: &str) -> Result<Vec<String>, String> {
    let folder_path = std::path::Path::new(folder);
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err(format!("Folder does not exist: {}", folder));
    }

    let mut created = Vec::new();
    for name in CANARY_NAMES {
        let canary_path = folder_path.join(name);
        if canary_path.exists() {
            // Already exists — verify it's still intact
            if verify_canary_file(canary_path.to_str().unwrap_or("")) {
                created.push(canary_path.to_string_lossy().to_string());
                continue;
            }
            // Tampered — recreate
        }

        // Create canary file: magic header + low-entropy padding that looks like a document
        let mut content = Vec::with_capacity(1024);
        content.extend_from_slice(CANARY_MAGIC);
        // Add some realistic-looking but identifiable content
        let padding =
            b"This document contains quarterly financial projections and budget allocations. \
            Please do not modify or delete this file. Last updated: 2026-01-15. \
            Department: Finance. Classification: Internal. Version: 3.2.1. \
            All figures are preliminary and subject to revision. \
            Contact: admin@company.example for questions.";
        for _ in 0..4 {
            content.extend_from_slice(padding);
        }

        match std::fs::write(&canary_path, &content) {
            Ok(_) => {
                // Try to set hidden attribute on Windows
                #[cfg(target_os = "windows")]
                {
                    // Set FILE_ATTRIBUTE_HIDDEN via `attrib` command (simple approach)
                    let _ = std::process::Command::new("attrib")
                        .args(["+H", "+S", canary_path.to_str().unwrap_or("")])
                        .output();
                }
                created.push(canary_path.to_string_lossy().to_string());
                log::info!("Deployed canary file: {:?}", canary_path);
            }
            Err(e) => {
                log::warn!("Failed to create canary file {:?}: {}", canary_path, e);
            }
        }
    }

    // Persist canary paths to settings
    if !created.is_empty() {
        let mut cfg = crate::config::Settings::load();
        cfg.canary_files.insert(folder.to_string(), created.clone());
        cfg.save();
    }

    Ok(created)
}

/// Verify that a canary file's magic header is intact.
/// Returns false if the file is missing, unreadable, or the header was changed.
pub fn verify_canary_file(path: &str) -> bool {
    let Ok(content) = std::fs::read(path) else {
        return false;
    };
    if content.len() < CANARY_MAGIC.len() {
        return false;
    }
    &content[..CANARY_MAGIC.len()] == CANARY_MAGIC
}

/// Check if a path is a known canary file.
fn is_canary_file(path: &str) -> bool {
    let cfg = crate::config::Settings::load();
    let path_norm = normalize_path_for_comparison(path);
    for canary_paths in cfg.canary_files.values() {
        for canary in canary_paths {
            if normalize_path_for_comparison(canary) == path_norm {
                return true;
            }
        }
    }
    false
}

/// Remove canary files from a folder (called when unprotecting a folder).
pub fn remove_canary_files_for_folder(folder: &str) {
    let mut cfg = crate::config::Settings::load();
    if let Some(canary_paths) = cfg.canary_files.remove(folder) {
        for path in &canary_paths {
            if let Err(e) = std::fs::remove_file(path) {
                log::debug!("Could not remove canary file {:?}: {}", path, e);
            }
        }
        cfg.save();
        log::info!("Removed canary files from {}", folder);
    }
}

/// Get canary file status for all protected folders.
pub fn get_canary_status_all() -> Result<
    std::collections::HashMap<String, Vec<crate::commands::settings::CanaryFileStatus>>,
    String,
> {
    let cfg = crate::config::Settings::load();
    let mut result = std::collections::HashMap::new();
    for (folder, canary_paths) in &cfg.canary_files {
        let statuses: Vec<crate::commands::settings::CanaryFileStatus> = canary_paths
            .iter()
            .map(|p| crate::commands::settings::CanaryFileStatus {
                path: p.clone(),
                intact: verify_canary_file(p),
            })
            .collect();
        result.insert(folder.clone(), statuses);
    }
    Ok(result)
}

pub fn start_realtime_watcher(app: AppHandle, watch_paths: Vec<PathBuf>) -> Result<(), String> {
    let (tx, rx): (
        std::sync::mpsc::Sender<NotifyResult<Event>>,
        Receiver<NotifyResult<Event>>,
    ) = channel();

    let watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| format!("Failed to create watcher: {}", e))?;

    let watcher = Arc::new(Mutex::new(watcher));

    // Register initial watch paths
    {
        let mut w = watcher
            .lock()
            .map_err(|e| format!("Watcher lock error: {}", e))?;
        for path in watch_paths.iter() {
            if path.exists() {
                if let Err(e) = w.watch(path, RecursiveMode::Recursive) {
                    log::warn!("Failed to watch {:?}: {}", path, e);
                } else {
                    log::info!("Watching path for real-time protection: {:?}", path);
                }
            }
        }
    }

    // Store in global so add_watch_path() can access it later
    let _ = GLOBAL_WATCHER.set(Arc::clone(&watcher));

    std::thread::spawn(move || {
        let _watcher = watcher; // keep alive

        let cache = Arc::clone(&crate::CACHE_MANAGER);

        // debouncing state: map of canonical path string -> last event timestamp
        let mut pending_scans: std::collections::HashMap<String, Instant> =
            std::collections::HashMap::new();
        const DEBOUNCE_MS: u64 = 500;
        let mut last_cleanup = Instant::now();

        // Ransomware detection: track bulk modifications using configurable thresholds
        let cfg = crate::config::Settings::load();
        RANSOMWARE_THRESHOLD.store(cfg.ransomware_threshold, Ordering::SeqCst);
        RANSOMWARE_WINDOW.store(cfg.ransomware_window_seconds, Ordering::SeqCst);
        let mut ransomware_tracker =
            FolderModificationTracker::new(cfg.ransomware_window_seconds as u64);
        let mut recent_modified_files: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        const CLEANUP_INTERVAL_SECS: u64 = 60;

        log::info!("Real-time file watcher thread started, waiting for events...");

        for res in rx.iter() {
            if last_cleanup.elapsed() >= Duration::from_secs(CLEANUP_INTERVAL_SECS) {
                let cutoff = Instant::now() - Duration::from_secs(10);
                pending_scans.retain(|_, v| *v > cutoff);
                last_cleanup = Instant::now();
            }

            match res {
                Ok(event) => {
                    log::debug!("File system event received: {:?}", event.kind);
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            if let Some(path_buf) = event.paths.first() {
                                if path_buf.exists() && path_buf.is_file() {
                                    let path_str = match path_buf.to_str() {
                                        Some(s) => s.to_string(),
                                        None => continue,
                                    };

                                    // Ransomware detection: check if in protected folder
                                    if let Some(protected_folder) =
                                        is_in_protected_folder(&path_str)
                                    {
                                        // ── Canary file tripwire ──
                                        // If a canary file was modified, this is near-certain ransomware.
                                        // Fire immediately with no threshold or cooldown.
                                        if is_canary_file(&path_str)
                                            && !verify_canary_file(&path_str)
                                        {
                                            log::warn!(
                                                "🚨🚨 CANARY TRIPWIRE: Honeypot file tampered in {}! File: {}",
                                                protected_folder, path_str
                                            );

                                            let suspects = filter_actionable_ransomware_suspects(
                                                identify_modifying_processes(&protected_folder),
                                            );
                                            let cfg_snap = crate::config::Settings::load();
                                            let killed = if cfg_snap.ransomware_auto_block {
                                                auto_kill_suspects(&suspects)
                                            } else {
                                                Vec::new()
                                            };

                                            let alert = RansomwareAlert {
                                                folder: protected_folder.clone(),
                                                modification_count: 1,
                                                time_window_seconds: 0,
                                                sample_files: vec![path_str.clone()],
                                                alert_level: "CRITICAL_CANARY".to_string(),
                                                suspected_processes: suspects,
                                                processes_killed: killed,
                                                average_entropy: file_entropy(&path_str),
                                            };

                                            let _ = app.emit("ransomware_alert", &alert);

                                            // Always send native notification for canary tripwire (bypass rate limit)
                                            {
                                                use tauri_plugin_notification::NotificationExt;
                                                let body = format!(
                                                    "🚨 CRITICAL: Hidden decoy file tampered!\nFolder: {}\nFile: {}\nThis is a strong indicator of active ransomware.",
                                                    protected_folder, path_str.split('\\').last().unwrap_or(&path_str)
                                                );
                                                let mut builder = app
                                                    .notification()
                                                    .builder()
                                                    .title(
                                                        "InSecurity - Ransomware Canary Triggered!",
                                                    )
                                                    .body(&body);
                                                if let Some(icon_path) = resolve_notification_icon()
                                                {
                                                    builder = builder.icon(icon_path);
                                                }
                                                let _ = builder.show();
                                            }

                                            crate::core::log_audit_event(
                                                crate::core::AuditEventType::ThreatDetected,
                                                &format!(
                                                    "CANARY TRIPWIRE: honeypot file tampered in {}",
                                                    protected_folder
                                                ),
                                                None,
                                                Some(&format!(
                                                    "alert_level=CRITICAL_CANARY,folder={}",
                                                    protected_folder
                                                )),
                                            );
                                            continue; // Skip normal scan for canary files
                                        }

                                        // ── Normal bulk-modification tracking ──
                                        // Sync window from global atomics (in case settings changed)
                                        ransomware_tracker.sync_window();

                                        // Track file for recent modifications list
                                        recent_modified_files
                                            .entry(protected_folder.clone())
                                            .or_default()
                                            .push(path_str.clone());

                                        // Keep only last 50 modified files per folder
                                        if let Some(files) =
                                            recent_modified_files.get_mut(&protected_folder)
                                        {
                                            if files.len() > 50 {
                                                files.drain(0..files.len() - 50);
                                            }
                                        }

                                        // Record entropy of modified file
                                        let ent = file_entropy(&path_str);
                                        ransomware_tracker.record_entropy(&protected_folder, ent);

                                        // Non-canary alerts must still pass the folder threshold.
                                        let alert_count = ransomware_tracker
                                            .track_modification(&protected_folder);

                                        if let Some(count) = alert_count {
                                            let window_secs =
                                                RANSOMWARE_WINDOW.load(Ordering::SeqCst);
                                            log::warn!(
                                                "🚨 RANSOMWARE ALERT: {} files modified in {} within {} seconds! (avg entropy: {:.2})",
                                                count, protected_folder, window_secs,
                                                ransomware_tracker.average_entropy(&protected_folder)
                                            );

                                            let sample_files = recent_modified_files
                                                .get(&protected_folder)
                                                .map(|f| f.iter().rev().take(5).cloned().collect())
                                                .unwrap_or_default();

                                            let current_avg_ent = ransomware_tracker
                                                .average_entropy(&protected_folder);
                                            let suspects = filter_actionable_ransomware_suspects(
                                                identify_modifying_processes(&protected_folder),
                                            );
                                            let effective_threshold =
                                                effective_threshold_for(&protected_folder);
                                            if !should_emit_non_canary_ransomware_alert(
                                                count,
                                                effective_threshold,
                                                current_avg_ent,
                                                &suspects,
                                            ) {
                                                let suppression_reason = if suspects.is_empty() {
                                                    format!(
                                                        "no actionable suspects remain after trusted/dev filtering in {}",
                                                        protected_folder
                                                    )
                                                } else {
                                                    format!(
                                                        "avg entropy {:.2} is below non-canary alert threshold {:.2} in {}",
                                                        current_avg_ent,
                                                        NON_CANARY_ALERT_MIN_AVG_ENTROPY,
                                                        protected_folder
                                                    )
                                                };
                                                log::info!(
                                                    "Non-canary ransomware alert suppressed - {}",
                                                    suppression_reason
                                                );
                                                continue;
                                            }

                                            // Trusted-process suppression: if every suspect is a
                                            // trusted-signed executable (PublisherAllowlist / PublisherMatch / CA)
                                            // this is almost certainly a benign bulk operation (build, install, etc.)
                                            // Skip canary alerts — those always fire.
                                            if !suspects.is_empty() && suspects.iter().all(|p| {
                                                let sig = crate::core::signature::verify_signature(&p.exe_path);
                                                matches!(
                                                    sig.trust_level,
                                                    crate::core::signature::TrustLevel::PublisherAllowlist
                                                    | crate::core::signature::TrustLevel::PublisherMatch
                                                    | crate::core::signature::TrustLevel::CA
                                                )
                                            }) {
                                                log::info!(
                                                    "Ransomware alert suppressed — all {} suspects are trusted-signed executables in {}",
                                                    suspects.len(), protected_folder
                                                );
                                                continue;
                                            }

                                            // Developer tool suppression: if any suspect is a known
                                            // dev tool (git, node, code, etc.) running from a trusted
                                            // install path, suppress the alert. Canary alerts are NOT
                                            // affected — those always fire above this code path.
                                            if suspects.iter().any(|p| is_known_dev_tool(p)) {
                                                log::info!(
                                                    "Ransomware alert suppressed — developer tool detected among suspects in {}",
                                                    protected_folder
                                                );
                                                continue;
                                            }

                                            log::warn!(
                                                "Potential ransomware-like activity: {} files modified in {} within {} seconds (avg entropy: {:.2}, suspects: {})",
                                                count,
                                                protected_folder,
                                                window_secs,
                                                current_avg_ent,
                                                suspects.len()
                                            );

                                            // Auto-block: terminate suspects if enabled
                                            let cfg_snap = crate::config::Settings::load();
                                            let killed = if cfg_snap.ransomware_auto_block {
                                                auto_kill_suspects(&suspects)
                                            } else {
                                                Vec::new()
                                            };

                                            let avg_ent = ransomware_tracker
                                                .average_entropy(&protected_folder);

                                            let alert = RansomwareAlert {
                                                folder: protected_folder.clone(),
                                                modification_count: count,
                                                time_window_seconds: window_secs,
                                                sample_files,
                                                alert_level: "HEURISTIC".to_string(),
                                                suspected_processes: suspects,
                                                processes_killed: killed.clone(),
                                                average_entropy: avg_ent,
                                            };

                                            // Emit alert to frontend
                                            if let Err(e) = app.emit("ransomware_alert", &alert) {
                                                log::warn!(
                                                    "Failed to emit ransomware alert: {}",
                                                    e
                                                );
                                            }

                                            // Native OS notification for ransomware (rate-limited)
                                            {
                                                let ransomware_key =
                                                    format!("ransomware::{}", protected_folder);
                                                let should_send = get_notification_limiter()
                                                    .lock()
                                                    .map(|mut lim| {
                                                        lim.should_notify(&ransomware_key)
                                                    })
                                                    .unwrap_or(true);

                                                if should_send {
                                                    use tauri_plugin_notification::NotificationExt;
                                                    let killed_msg = if !killed.is_empty() {
                                                        format!(
                                                            "\nProcesses terminated: {}",
                                                            killed.join(", ")
                                                        )
                                                    } else {
                                                        String::new()
                                                    };
                                                    let body = format!(
                                                        "Rapid bulk file modifications detected!\nFolder: {}\n{} files changed in {} seconds.\nAvg entropy: {:.1}/8.0{}",
                                                        protected_folder, count, window_secs, avg_ent, killed_msg
                                                    );
                                                    let mut builder = app.notification()
                                                        .builder()
                                                        .title("InSecurity - Possible Ransomware-Like Activity")
                                                        .body(&body);

                                                    if let Some(icon_path) =
                                                        resolve_notification_icon()
                                                    {
                                                        builder = builder.icon(icon_path);
                                                    }

                                                    if let Err(e) = builder.show() {
                                                        log::warn!("Failed to send ransomware notification: {}", e);
                                                    }
                                                } else {
                                                    log::debug!("Ransomware notification suppressed (rate limit) for {}", protected_folder);
                                                }
                                            }

                                            // Log to audit journal
                                            crate::core::log_audit_event(
                                                crate::core::AuditEventType::ThreatDetected,
                                                &format!("Possible ransomware-like behavior detected: {} bulk modifications in {} (entropy: {:.2}, killed: {})",
                                                    count, protected_folder, avg_ent, killed.len()),
                                                None,
                                                Some(&format!("alert_level={},folder={},entropy={:.2},processes_killed={}",
                                                    alert.alert_level, protected_folder, avg_ent, killed.len())),
                                            );
                                        }
                                    }

                                    // Skip file scanning if protection is disabled by user or paused for manual scan
                                    // (Ransomware tracking above is gated by its own ransomware_protection setting)
                                    if is_protection_disabled()
                                        || crate::commands::scan::is_realtime_paused()
                                    {
                                        continue;
                                    }

                                    // Use entry API to avoid TOCTOU race condition
                                    let now = Instant::now();
                                    let should_scan = match pending_scans.entry(path_str.clone()) {
                                        Entry::Occupied(mut e) => {
                                            if now.duration_since(*e.get())
                                                >= Duration::from_millis(DEBOUNCE_MS)
                                            {
                                                e.insert(now);
                                                true
                                            } else {
                                                // Skip duplicate/bounce event
                                                false
                                            }
                                        }
                                        Entry::Vacant(e) => {
                                            e.insert(now);
                                            true
                                        }
                                    };

                                    if !should_scan {
                                        continue;
                                    }

                                    // Rate limiting: skip if too many concurrent scans
                                    // This prevents resource exhaustion under rapid file changes
                                    let current_count = ACTIVE_SCAN_COUNT.load(Ordering::Relaxed);
                                    if current_count >= MAX_CONCURRENT_SCANS {
                                        log::debug!(
                                            "Rate limit: skipping {} (active scans: {})",
                                            path_str,
                                            current_count
                                        );
                                        continue;
                                    }

                                    // Increment before spawn (approximate - race is acceptable for rate limiting)
                                    ACTIVE_SCAN_COUNT.fetch_add(1, Ordering::Relaxed);

                                    // Spawn an async scan task to avoid blocking the watcher
                                    let app_clone = app.clone();
                                    let path_clone = path_str.clone();
                                    let cache_clone = Arc::clone(&cache);
                                    tauri::async_runtime::spawn(async move {
                                        // Ensure we decrement the counter when task completes
                                        struct ScanGuard;
                                        impl Drop for ScanGuard {
                                            fn drop(&mut self) {
                                                ACTIVE_SCAN_COUNT.fetch_sub(1, Ordering::Relaxed);
                                            }
                                        }
                                        let _guard = ScanGuard;

                                        // Double-check pause/disabled state in case it changed between event receive and spawn
                                        if is_protection_disabled()
                                            || crate::commands::scan::is_realtime_paused()
                                        {
                                            log::trace!("Skipping file scan (protection disabled or manual scan): {}", path_clone);
                                            return;
                                        }

                                        if !is_scannable_file(&path_clone) {
                                            log::debug!(
                                                "Skipping non-scannable file type: {}",
                                                path_clone
                                            );
                                            return;
                                        }

                                        if is_system_path(&path_clone) {
                                            log::debug!("Skipping system/app path: {}", path_clone);
                                            return;
                                        }

                                        if is_dev_build_artifact_path(&path_clone) {
                                            log::debug!(
                                                "Skipping developer/build artifact path: {}",
                                                path_clone
                                            );
                                            return;
                                        }

                                        if let Some(db_mutex) = crate::get_database() {
                                            if let Ok(guard) = db_mutex.lock() {
                                                if let Some(ref conn) = *guard {
                                                    if let Ok(true) =
                                                        DatabaseQueries::is_path_excluded(
                                                            conn,
                                                            &path_clone,
                                                        )
                                                    {
                                                        log::debug!(
                                                            "Skipping excluded path: {}",
                                                            path_clone
                                                        );
                                                        return;
                                                    }
                                                }
                                            }
                                        }

                                        set_current_file(&path_clone);
                                        log::info!("Starting scan for: {}", path_clone);

                                        match DetectionPipeline::scan_file(&path_clone).await {
                                            Ok(result) => {
                                                log::info!("Scan completed for {} - verdict: {:?}, confidence: {}", 
                                                    path_clone, result.verdict, result.confidence);
                                                handle_realtime_scan_result(
                                                    result,
                                                    &path_clone,
                                                    &app_clone,
                                                    &cache_clone,
                                                );
                                            }
                                            Err(e) => log::warn!("Realtime scan failed: {}", e),
                                        }
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => log::warn!("Watch event error: {}", e),
            }
        }
    });

    Ok(())
}

pub fn start_process_monitor(app: AppHandle) -> Result<(), String> {
    log::info!("Starting process monitor for real-time protection");

    std::thread::spawn(move || {
        let cache = Arc::clone(&crate::CACHE_MANAGER);
        let mut sys = System::new();
        // Track (PID, exe_path) pairs to detect PID reuse with different executables
        let mut known_processes: std::collections::HashMap<u32, String> =
            std::collections::HashMap::new();
        let mut scanned_paths: HashSet<String> = HashSet::new();

        // Memory management: limit scanned_paths to prevent unbounded growth
        const MAX_SCANNED_PATHS: usize = 10000;
        const PATHS_CLEANUP_INTERVAL_SECS: u64 = 600;
        let mut last_paths_cleanup = Instant::now();

        // Initial scan of all running processes
        sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            ProcessRefreshKind::new().with_exe(UpdateKind::Always),
        );

        for (pid, process) in sys.processes() {
            if let Some(exe_path) = process.exe() {
                if let Some(path_str) = exe_path.to_str() {
                    known_processes.insert(pid.as_u32(), path_str.to_string());
                    scanned_paths.insert(path_str.to_string());
                }
            }
        }

        log::info!(
            "Process monitor initialized with {} known processes",
            known_processes.len()
        );

        const POLL_INTERVAL_MS: u64 = 3000; // 3s - good balance between detection speed and CPU usage
        const FULL_SCAN_INTERVAL_SECS: u64 = 300;
        let mut last_full_scan = Instant::now();

        loop {
            std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));

            // Skip process scanning if protection is disabled or paused for manual scan
            if is_protection_disabled() {
                log::trace!("Process monitor paused - protection disabled by user");
                continue;
            }
            if crate::commands::scan::is_realtime_paused() {
                log::trace!("Process monitor paused during manual scan");
                continue;
            }

            if last_paths_cleanup.elapsed() >= Duration::from_secs(PATHS_CLEANUP_INTERVAL_SECS)
                || scanned_paths.len() > MAX_SCANNED_PATHS
            {
                log::debug!(
                    "Clearing scanned_paths cache ({} entries)",
                    scanned_paths.len()
                );
                scanned_paths.clear();
                last_paths_cleanup = Instant::now();
            }

            sys.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::All,
                ProcessRefreshKind::new().with_exe(UpdateKind::Always),
            );

            let do_full_scan =
                last_full_scan.elapsed() >= Duration::from_secs(FULL_SCAN_INTERVAL_SECS);
            if do_full_scan {
                last_full_scan = Instant::now();
                log::debug!("Performing full process scan");
            }

            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();

                let exe_path = match process.exe() {
                    Some(p) => p,
                    None => continue,
                };

                let path_str = match exe_path.to_str() {
                    Some(s) => s.to_string(),
                    None => continue,
                };

                // Check if this is a new process or if PID was reused with a different executable
                let is_new = match known_processes.get(&pid_u32) {
                    None => true,
                    Some(known_path) => known_path != &path_str, // PID reused with different exe = treat as new
                };

                if is_new {
                    known_processes.insert(pid_u32, path_str.clone());
                }

                if !is_new && !do_full_scan && scanned_paths.contains(&path_str) {
                    continue;
                }

                if is_system_path(&path_str) {
                    scanned_paths.insert(path_str.clone());
                    continue;
                }

                if is_dev_build_artifact_path(&path_str) {
                    scanned_paths.insert(path_str.clone());
                    continue;
                }

                if is_new {
                    log::info!("New process detected: {} (PID: {})", path_str, pid_u32);
                }

                let app_clone = app.clone();
                let path_clone = path_str.clone();
                let cache_clone = Arc::clone(&cache);

                tauri::async_runtime::spawn(async move {
                    // Check exclusions
                    if let Some(db_mutex) = crate::get_database() {
                        if let Ok(guard) = db_mutex.lock() {
                            if let Some(ref conn) = *guard {
                                if let Ok(true) =
                                    DatabaseQueries::is_path_excluded(conn, &path_clone)
                                {
                                    return;
                                }
                            }
                        }
                    }

                    set_current_file(&path_clone);

                    match DetectionPipeline::scan_file(&path_clone).await {
                        Ok(result) => {
                            handle_realtime_scan_result(
                                result,
                                &path_clone,
                                &app_clone,
                                &cache_clone,
                            );
                        }
                        Err(e) => {
                            log::debug!("Process scan skipped/failed for {}: {}", path_clone, e)
                        }
                    }
                });

                scanned_paths.insert(path_str);
            }

            let current_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
            known_processes.retain(|pid, _| current_pids.contains(pid));
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Shannon entropy ────────────────────────────────────────────────

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_shannon_entropy_single_byte_repeated() {
        // All same byte → zero entropy
        let data = vec![0xAA; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_shannon_entropy_two_values_equal() {
        // Two byte values equally distributed → entropy = 1.0
        let mut data = Vec::new();
        for _ in 0..500 {
            data.push(0x00);
            data.push(0xFF);
        }
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.01, "Expected ~1.0, got {}", e);
    }

    #[test]
    fn test_shannon_entropy_uniform_distribution() {
        // All 256 byte values equally → entropy = 8.0 (maximum)
        let mut data = Vec::new();
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "Expected ~8.0, got {}", e);
    }

    #[test]
    fn test_shannon_entropy_text_content() {
        // Typical English text: entropy around 3.5-5.0
        let data = b"The quick brown fox jumps over the lazy dog. This is a sample text for entropy testing purposes.";
        let e = shannon_entropy(data);
        assert!(e > 3.0 && e < 6.0, "Expected 3-6 for text, got {}", e);
    }

    // ── Path normalization ─────────────────────────────────────────────

    #[test]
    fn test_normalize_path_basic() {
        assert_eq!(
            normalize_path_for_comparison("C:\\Users\\Documents"),
            "c:\\users\\documents"
        );
    }

    #[test]
    fn test_normalize_path_forward_slashes() {
        assert_eq!(
            normalize_path_for_comparison("C:/Users/Documents"),
            "c:\\users\\documents"
        );
    }

    #[test]
    fn test_normalize_path_trailing_separator() {
        assert_eq!(
            normalize_path_for_comparison("C:\\Users\\Documents\\"),
            "c:\\users\\documents"
        );
    }

    #[test]
    fn test_normalize_path_mixed_slashes() {
        assert_eq!(
            normalize_path_for_comparison("C:/Users\\Documents/Work\\"),
            "c:\\users\\documents\\work"
        );
    }

    #[test]
    fn test_path_is_within_folder_respects_boundaries() {
        assert!(path_is_within_folder(
            "c:\\users\\123\\documents\\report.docx",
            "c:\\users\\123\\documents"
        ));
        assert!(!path_is_within_folder(
            "c:\\users\\123\\documents-old\\report.docx",
            "c:\\users\\123\\documents"
        ));
    }

    #[test]
    fn test_threat_notification_identity_distinguishes_same_hash_different_paths() {
        let first = threat_notification_identity("C:\\Users\\123\\Downloads\\same.exe", "deadbeef");
        let second = threat_notification_identity("D:\\Archive\\same.exe", "deadbeef");

        assert_ne!(first, second);
        assert!(first.contains("deadbeef"));
        assert!(second.contains("deadbeef"));
    }

    // ── Document extension detection ───────────────────────────────────

    #[test]
    fn test_is_document_extension_docx() {
        assert!(is_document_extension("C:\\Users\\report.docx"));
        assert!(is_document_extension("C:\\Users\\report.DOCX"));
    }

    #[test]
    fn test_is_document_extension_various() {
        assert!(is_document_extension("file.pdf"));
        assert!(is_document_extension("photo.jpg"));
        assert!(is_document_extension("data.xlsx"));
        assert!(is_document_extension("archive.zip"));
        assert!(is_document_extension("notes.txt"));
    }

    #[test]
    fn test_is_not_document_extension() {
        assert!(!is_document_extension("program.exe"));
        assert!(!is_document_extension("library.dll"));
        assert!(!is_document_extension("script.py"));
        assert!(!is_document_extension("noextension"));
    }

    // ── NotificationLimiter ────────────────────────────────────────────

    #[test]
    fn test_notification_limiter_first_notification_allowed() {
        let mut limiter = NotificationLimiter::new();
        assert!(limiter.should_notify("test_file.exe"));
    }

    #[test]
    fn test_notification_limiter_dedup_same_file() {
        let mut limiter = NotificationLimiter::new();
        assert!(limiter.should_notify("file.exe")); // First: allowed
        assert!(!limiter.should_notify("file.exe")); // Immediate repeat: suppressed
    }

    #[test]
    fn test_notification_limiter_different_files_allowed() {
        let mut limiter = NotificationLimiter::new();
        assert!(limiter.should_notify("file1.exe"));
        assert!(limiter.should_notify("file2.exe"));
        assert!(limiter.should_notify("file3.exe"));
    }

    #[test]
    fn test_notification_limiter_rate_limit() {
        let mut limiter = NotificationLimiter::new();
        // Fill up the window (MAX_NOTIFICATIONS_PER_WINDOW = 5)
        for i in 0..MAX_NOTIFICATIONS_PER_WINDOW {
            assert!(limiter.should_notify(&format!("file{}.exe", i)));
        }
        // Next one should be rate-limited
        assert!(!limiter.should_notify("one_too_many.exe"));
    }

    #[test]
    fn test_notification_limiter_suppressed_count() {
        let mut limiter = NotificationLimiter::new();
        assert!(limiter.should_notify("file.exe"));
        assert!(!limiter.should_notify("file.exe")); // suppressed
        assert!(!limiter.should_notify("file.exe")); // suppressed again
        assert_eq!(limiter.take_suppressed(), 2);
        assert_eq!(limiter.take_suppressed(), 0); // reset after take
    }

    #[test]
    fn test_notification_limiter_summary_cooldown() {
        let mut limiter = NotificationLimiter::new();
        assert!(limiter.should_send_summary()); // First summary: allowed
        assert!(!limiter.should_send_summary()); // Immediately after: suppressed
    }

    // ── FolderModificationTracker ──────────────────────────────────────

    #[test]
    fn test_tracker_below_threshold_no_alert() {
        let mut tracker = FolderModificationTracker::new(10);
        // Default global threshold is 20
        for _ in 0..5 {
            assert!(tracker.track_modification("C:\\Users\\Documents").is_none());
        }
    }

    #[test]
    fn test_tracker_suppresses_low_entropy_threshold_hit() {
        let original_threshold = RANSOMWARE_THRESHOLD.load(Ordering::SeqCst);
        RANSOMWARE_THRESHOLD.store(5, Ordering::SeqCst);

        let mut tracker = FolderModificationTracker::new(10);
        for _ in 0..5 {
            tracker.record_entropy("C:\\Users\\Documents", 4.72);
            assert!(tracker.track_modification("C:\\Users\\Documents").is_none());
        }

        RANSOMWARE_THRESHOLD.store(original_threshold, Ordering::SeqCst);
    }

    #[test]
    fn test_non_canary_alert_requires_actionable_suspect() {
        let suspects: Vec<ProcessInfo> = Vec::new();
        assert!(!should_emit_non_canary_ransomware_alert(
            20, 20, 7.9, &suspects,
        ));
    }

    #[test]
    fn test_non_canary_alert_requires_high_entropy() {
        let suspects = vec![ProcessInfo {
            pid: 4242,
            name: "weird.exe".to_string(),
            exe_path: "C:\\Users\\test\\Downloads\\weird.exe".to_string(),
        }];
        assert!(!should_emit_non_canary_ransomware_alert(
            20, 20, 7.1, &suspects,
        ));
    }

    #[test]
    fn test_non_canary_alert_fires_with_threshold_entropy_and_suspect() {
        let suspects = vec![ProcessInfo {
            pid: 4242,
            name: "weird.exe".to_string(),
            exe_path: "C:\\Users\\test\\Downloads\\weird.exe".to_string(),
        }];
        assert!(should_emit_non_canary_ransomware_alert(
            20, 20, 7.9, &suspects,
        ));
    }

    #[test]
    fn test_tracker_records_entropy() {
        let mut tracker = FolderModificationTracker::new(10);
        tracker.record_entropy("folder", 7.5);
        tracker.record_entropy("folder", 7.8);
        tracker.record_entropy("folder", 7.2);
        let avg = tracker.average_entropy("folder");
        assert!((avg - 7.5).abs() < 0.01, "Expected ~7.5, got {}", avg);
    }

    #[test]
    fn test_tracker_average_entropy_unknown_folder() {
        let tracker = FolderModificationTracker::new(10);
        assert_eq!(tracker.average_entropy("nonexistent"), 0.0);
    }

    #[test]
    fn test_tracker_entropy_buffer_limit() {
        let mut tracker = FolderModificationTracker::new(10);
        // Push more than 50 entropy samples
        for i in 0..60 {
            tracker.record_entropy("folder", i as f64 * 0.1);
        }
        let entries = tracker.recent_entropies.get("folder").unwrap();
        assert_eq!(entries.len(), 50, "Should cap at 50 entropy samples");
    }

    // ── Canary file verification ───────────────────────────────────────

    #[test]
    fn test_canary_magic_length() {
        assert_eq!(CANARY_MAGIC.len(), 16);
        assert_eq!(&CANARY_MAGIC[..15], b"INSEC_CANARY_V1");
        assert_eq!(CANARY_MAGIC[15], 0); // null terminator
    }

    #[test]
    fn test_canary_names_are_hidden_files() {
        for name in CANARY_NAMES {
            assert!(
                name.starts_with('.') || name.starts_with("._"),
                "Canary file '{}' should be a hidden file (starts with .)",
                name
            );
        }
    }

    #[test]
    fn test_verify_canary_nonexistent_file() {
        assert!(!verify_canary_file("C:\\nonexistent\\path\\canary.dat"));
    }

    #[test]
    fn test_verify_canary_valid_file() {
        let dir = std::env::temp_dir().join("insecurity_test_canary");
        let _ = std::fs::create_dir_all(&dir);
        let canary_path = dir.join("test_canary.dat");

        // Write valid canary content
        let mut content = Vec::new();
        content.extend_from_slice(CANARY_MAGIC);
        content.extend_from_slice(b"padding data here");
        std::fs::write(&canary_path, &content).unwrap();

        assert!(verify_canary_file(canary_path.to_str().unwrap()));

        // Clean up
        let _ = std::fs::remove_file(&canary_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_verify_canary_tampered_file() {
        let dir = std::env::temp_dir().join("insecurity_test_canary_tampered");
        let _ = std::fs::create_dir_all(&dir);
        let canary_path = dir.join("test_canary_tampered.dat");

        // Write tampered content (wrong magic)
        std::fs::write(&canary_path, b"TAMPERED_CONTENT_HERE_AAAA").unwrap();
        assert!(!verify_canary_file(canary_path.to_str().unwrap()));

        // Clean up
        let _ = std::fs::remove_file(&canary_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_verify_canary_too_short() {
        let dir = std::env::temp_dir().join("insecurity_test_canary_short");
        let _ = std::fs::create_dir_all(&dir);
        let canary_path = dir.join("test_canary_short.dat");

        // Write content shorter than CANARY_MAGIC
        std::fs::write(&canary_path, b"SHORT").unwrap();
        assert!(!verify_canary_file(canary_path.to_str().unwrap()));

        // Clean up
        let _ = std::fs::remove_file(&canary_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // ── Protection toggle ──────────────────────────────────────────────

    #[test]
    fn test_protection_disabled_toggle() {
        // Save original state
        let original = is_protection_disabled();

        set_protection_disabled(true);
        assert!(is_protection_disabled());

        set_protection_disabled(false);
        assert!(!is_protection_disabled());

        // Restore
        set_protection_disabled(original);
    }

    // ── Ransomware threshold reloading ─────────────────────────────────

    #[test]
    fn test_reload_ransomware_thresholds() {
        let original_threshold = RANSOMWARE_THRESHOLD.load(Ordering::SeqCst);
        let original_window = RANSOMWARE_WINDOW.load(Ordering::SeqCst);

        reload_ransomware_thresholds(50, 30);
        assert_eq!(RANSOMWARE_THRESHOLD.load(Ordering::SeqCst), 50);
        assert_eq!(RANSOMWARE_WINDOW.load(Ordering::SeqCst), 30);

        // Restore
        reload_ransomware_thresholds(original_threshold, original_window);
    }

    #[test]
    fn test_adaptive_threshold_for_folder() {
        let original = RANSOMWARE_THRESHOLD.load(Ordering::SeqCst);
        RANSOMWARE_THRESHOLD.store(20, Ordering::SeqCst);

        adapt_threshold_for_folder("C:\\TestFolder");
        let effective = effective_threshold_for("C:\\TestFolder");
        assert_eq!(effective, 30, "Should be base (20) + 50% = 30");

        // Unknown folder should get base threshold
        let base = effective_threshold_for("C:\\SomeOtherFolder");
        assert_eq!(base, 20);

        // Restore
        RANSOMWARE_THRESHOLD.store(original, Ordering::SeqCst);
    }

    // ── Developer tool detection ──────────────────────────────────────

    #[test]
    fn test_is_known_dev_tool_git_program_files() {
        let proc = ProcessInfo {
            pid: 1234,
            name: "git.exe".to_string(),
            exe_path: "C:\\Program Files\\Git\\cmd\\git.exe".to_string(),
        };
        assert!(is_known_dev_tool(&proc));
    }

    #[test]
    fn test_is_known_dev_tool_node_program_files() {
        let proc = ProcessInfo {
            pid: 5678,
            name: "node.exe".to_string(),
            exe_path: "C:\\Program Files\\nodejs\\node.exe".to_string(),
        };
        assert!(is_known_dev_tool(&proc));
    }

    #[test]
    fn test_is_known_dev_tool_vscode_appdata() {
        let proc = ProcessInfo {
            pid: 9999,
            name: "code.exe".to_string(),
            exe_path: "C:\\Users\\test\\AppData\\Local\\Programs\\Microsoft VS Code\\code.exe"
                .to_string(),
        };
        assert!(is_known_dev_tool(&proc));
    }

    #[test]
    fn test_is_known_dev_tool_spoofed_name_untrusted_path() {
        // Malware naming itself git.exe in Downloads should NOT pass
        let proc = ProcessInfo {
            pid: 6666,
            name: "git.exe".to_string(),
            exe_path: "C:\\Users\\test\\Downloads\\git.exe".to_string(),
        };
        assert!(!is_known_dev_tool(&proc));
    }

    #[test]
    fn test_is_known_dev_tool_unknown_process_trusted_path() {
        // Unknown process name in trusted path should NOT pass
        let proc = ProcessInfo {
            pid: 7777,
            name: "random_app.exe".to_string(),
            exe_path: "C:\\Program Files\\SomeApp\\random_app.exe".to_string(),
        };
        assert!(!is_known_dev_tool(&proc));
    }

    #[test]
    fn test_is_benign_ransomware_suspect_program_files_process() {
        let proc = ProcessInfo {
            pid: 7778,
            name: "msedgewebview2.exe".to_string(),
            exe_path:
                "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\146.0.3856.109\\msedgewebview2.exe"
                    .to_string(),
        };
        assert!(is_benign_ransomware_suspect(&proc));
    }

    #[test]
    fn test_filter_actionable_ransomware_suspects_keeps_only_untrusted_entries() {
        let filtered = filter_actionable_ransomware_suspects(vec![
            ProcessInfo {
                pid: 1001,
                name: "WidgetService.exe".to_string(),
                exe_path:
                    "C:\\Program Files\\WindowsApps\\Microsoft.WidgetsPlatformRuntime_1.6.14.0_x64__8wekyb3d8bbwe\\WidgetService\\WidgetService.exe"
                        .to_string(),
            },
            ProcessInfo {
                pid: 1002,
                name: "weird.exe".to_string(),
                exe_path: "C:\\Users\\test\\Downloads\\weird.exe".to_string(),
            },
        ]);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "weird.exe");
    }

    #[test]
    fn test_non_canary_write_signal_requires_user_writable_or_protected_folder_path() {
        assert!(!has_actionable_non_canary_write_signal(
            "C:\\Program Files\\SomeApp\\app.exe",
            "C:\\Users\\123\\Documents",
            NON_CANARY_OUTSIDE_FOLDER_MIN_WRITTEN_BYTES * 2
        ));
    }

    #[test]
    fn test_non_canary_write_signal_requires_stronger_writes_outside_folder() {
        assert!(!has_actionable_non_canary_write_signal(
            "C:\\Users\\123\\Downloads\\weird.exe",
            "C:\\Users\\123\\Documents",
            NON_CANARY_OUTSIDE_FOLDER_MIN_WRITTEN_BYTES - 1
        ));
        assert!(has_actionable_non_canary_write_signal(
            "C:\\Users\\123\\Downloads\\weird.exe",
            "C:\\Users\\123\\Documents",
            NON_CANARY_OUTSIDE_FOLDER_MIN_WRITTEN_BYTES
        ));
    }

    #[test]
    fn test_non_canary_write_signal_allows_protected_folder_writer_at_lower_threshold() {
        assert!(has_actionable_non_canary_write_signal(
            "C:\\Users\\123\\Documents\\odd-tool.exe",
            "C:\\Users\\123\\Documents",
            NON_CANARY_INSIDE_FOLDER_MIN_WRITTEN_BYTES
        ));
    }

    #[test]
    fn test_is_known_dev_tool_case_insensitive() {
        let proc = ProcessInfo {
            pid: 8888,
            name: "Git.EXE".to_string(),
            exe_path: "C:\\Program Files\\Git\\cmd\\git.exe".to_string(),
        };
        assert!(is_known_dev_tool(&proc));
    }

    #[test]
    fn test_is_known_dev_tool_cargo_in_cargo_dir() {
        let proc = ProcessInfo {
            pid: 1111,
            name: "cargo.exe".to_string(),
            exe_path: "C:\\Users\\test\\.cargo\\bin\\cargo.exe".to_string(),
        };
        assert!(
            is_known_dev_tool(&proc),
            ".cargo is a known dev toolchain path"
        );
    }

    #[test]
    fn test_is_known_dev_tool_rustc_in_rustup() {
        let proc = ProcessInfo {
            pid: 2222,
            name: "rustc.exe".to_string(),
            exe_path: "C:\\Users\\test\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\bin\\rustc.exe".to_string(),
        };
        assert!(is_known_dev_tool(&proc));
    }
}
