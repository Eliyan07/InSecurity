// ============================================================================
// Single File Scan (for System Posture "Scan this binary" button)
// ============================================================================

/// Result of scanning a single file, returned to the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleFileScanResult {
    pub file_path: String,
    pub file_hash: String,
    pub verdict: String,
    pub confidence: f64,
    pub threat_level: String,
    pub threat_name: Option<String>,
    pub scan_time_ms: u64,
}

/// Scan a single file through the full detection pipeline.
/// Used by System Posture's "Scan this binary" button.
///
/// This does NOT use the manual scan machinery (IS_SCANNING, counters, etc.)
/// because it's a quick one-off analysis, not a folder scan. It runs the file
/// through the full pipeline (with cache bypass) and returns the result directly.
///
/// The verdict is persisted to the DB so System Posture shows it on next refresh.
#[tauri::command]
pub async fn scan_single_file(file_path: String) -> Result<SingleFileScanResult, String> {
    use crate::core::pipeline::DetectionPipeline;

    log::info!("scan_single_file called for: {}", file_path);

    let path = std::path::PathBuf::from(&file_path);
    if !path.exists() {
        return Err(format!("File not found: {}", file_path));
    }
    if !path.is_file() {
        return Err(format!("Not a file: {}", file_path));
    }

    // Run through the full detection pipeline (bypass_cache = true for fresh analysis)
    let result = DetectionPipeline::scan_file_with_options(&file_path, true)
        .await
        .map_err(|e| format!("Scan failed: {}", e))?;

    let verdict_str = format!("{:?}", result.verdict);

    // Persist to DB so System Posture picks up the verdict on next refresh
    let rec = crate::database::models::Verdict {
        id: 0,
        file_hash: result.file_hash.clone(),
        file_path: file_path.clone(),
        verdict: verdict_str.clone(),
        confidence: result.confidence,
        threat_level: result.threat_level.clone(),
        threat_name: result.threat_name.clone(),
        scan_time_ms: result.scan_time_ms,
        scanned_at: Utc::now().timestamp(),
        source: "posture".to_string(),
    };
    crate::database::batcher::enqueue_verdict(rec);

    log::info!(
        "scan_single_file result for {}: verdict={}, confidence={:.2}",
        file_path,
        verdict_str,
        result.confidence
    );

    Ok(SingleFileScanResult {
        file_path,
        file_hash: result.file_hash,
        verdict: verdict_str,
        confidence: result.confidence,
        threat_level: result.threat_level,
        threat_name: result.threat_name,
        scan_time_ms: result.scan_time_ms,
    })
}
use chrono::Utc;
use futures::stream::{self, StreamExt};
/// Scan commands exposed to frontend
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use tauri::Emitter;
use walkdir::WalkDir;

static IS_SCANNING: AtomicBool = AtomicBool::new(false);

static FILES_SCANNED: AtomicU32 = AtomicU32::new(0);

static FILES_REMAINING: AtomicU32 = AtomicU32::new(0);

static CURRENT_FILE: RwLock<Option<String>> = RwLock::new(None);

static TOTAL_FILES: AtomicU32 = AtomicU32::new(0);

static CLEAN_COUNT: AtomicU32 = AtomicU32::new(0);
static SUSPICIOUS_COUNT: AtomicU32 = AtomicU32::new(0);
static MALWARE_COUNT: AtomicU32 = AtomicU32::new(0);

static SCAN_START_TIME: AtomicU64 = AtomicU64::new(0);

static LAST_THREAT: RwLock<Option<ThreatInfo>> = RwLock::new(None);

/// Track the current scan type
static CURRENT_SCAN_TYPE: RwLock<Option<String>> = RwLock::new(None);

/// Track whether this is a manual scan (vs real-time)
static IS_MANUAL_SCAN: AtomicBool = AtomicBool::new(false);

/// Generation counter - incremented on each new scan to detect stale tasks
static SCAN_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Signal real-time protection to pause during manual scans
/// Real-time threads should check this and skip low-priority scans
pub static REALTIME_PAUSED: AtomicBool = AtomicBool::new(false);

/// Check if real-time protection should pause for manual scan
pub fn is_realtime_paused() -> bool {
    REALTIME_PAUSED.load(Ordering::SeqCst)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatInfo {
    pub file_path: String,
    pub threat_name: Option<String>,
    pub verdict: String,
}

pub fn scan_started() {
    // IMPORTANT: Set REALTIME_PAUSED first to ensure process monitor and file watcher
    // pause before we mark the scan as started. This prevents a race condition where
    // real-time scans could interfere with the manual scan's state initialization.
    REALTIME_PAUSED.store(true, Ordering::SeqCst);
    IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
    IS_SCANNING.store(true, Ordering::SeqCst);
    log::info!(
        "Manual scan started - pausing real-time protection (file watching + process monitor)"
    );
    // Initialize counters and state
    scan_started_internal();
}

/// Internal scan state initialization (for counters/state only)
/// Called when IS_SCANNING is already set (e.g., via compare_exchange)
fn scan_started_internal() {
    // Set pause/manual flags (idempotent if already set)
    REALTIME_PAUSED.store(true, Ordering::SeqCst);
    IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
    // Bump generation so any previous scan task knows it's stale
    SCAN_GENERATION.fetch_add(1, Ordering::SeqCst);
    FILES_SCANNED.store(0, Ordering::SeqCst);
    FILES_REMAINING.store(0, Ordering::SeqCst);
    TOTAL_FILES.store(0, Ordering::SeqCst);
    CLEAN_COUNT.store(0, Ordering::SeqCst);
    SUSPICIOUS_COUNT.store(0, Ordering::SeqCst);
    MALWARE_COUNT.store(0, Ordering::SeqCst);
    SCAN_START_TIME.store(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        Ordering::SeqCst,
    );
    if let Ok(mut file) = CURRENT_FILE.write() {
        *file = None;
    }
    if let Ok(mut threat) = LAST_THREAT.write() {
        *threat = None;
    }
}

pub fn scan_stopped() {
    // Clear scanning state first, then resume real-time protection last
    // This ensures real-time doesn't see stale manual scan state
    IS_SCANNING.store(false, Ordering::SeqCst);
    IS_MANUAL_SCAN.store(false, Ordering::SeqCst);
    // Resume real-time protection (file watching + process monitor) after manual scan completes
    REALTIME_PAUSED.store(false, Ordering::SeqCst);
    log::info!("Manual scan stopped - resuming real-time protection");
    if let Ok(mut file) = CURRENT_FILE.write() {
        *file = None;
    }
    if let Ok(mut scan_type) = CURRENT_SCAN_TYPE.write() {
        *scan_type = None;
    }
}

pub fn reset_counters() {
    FILES_SCANNED.store(0, Ordering::SeqCst);
    FILES_REMAINING.store(0, Ordering::SeqCst);
    TOTAL_FILES.store(0, Ordering::SeqCst);
    CLEAN_COUNT.store(0, Ordering::SeqCst);
    SUSPICIOUS_COUNT.store(0, Ordering::SeqCst);
    MALWARE_COUNT.store(0, Ordering::SeqCst);
    if let Ok(mut threat) = LAST_THREAT.write() {
        *threat = None;
    }
}

/// Set the current file being scanned (only during manual scans)
pub fn set_current_file(path: &str) {
    // Only update during manual scan to avoid real-time scans overwriting current file
    if !IS_MANUAL_SCAN.load(Ordering::SeqCst) {
        return;
    }

    if let Ok(mut file) = CURRENT_FILE.write() {
        *file = Some(path.to_string());
    }
}

/// Increment scanned file count (only during manual scans)
pub fn increment_scanned() {
    // Only update during manual scan to avoid real-time scans affecting counts
    if !IS_MANUAL_SCAN.load(Ordering::SeqCst) {
        return;
    }

    let _ = FILES_SCANNED.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_add(1))
    });

    let remaining = FILES_REMAINING.load(Ordering::SeqCst);
    if remaining > 0 {
        let _ = FILES_REMAINING.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            Some(v.saturating_sub(1))
        });
    }
}

/// Record a scan result verdict for statistics (only during manual scans)
pub fn record_verdict(verdict: &str, file_path: &str, threat_name: Option<&str>) {
    // Only update manual scan counters during a manual scan
    if !IS_MANUAL_SCAN.load(Ordering::SeqCst) {
        return;
    }

    match verdict.to_lowercase().as_str() {
        "clean" => {
            let _ = CLEAN_COUNT.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });
        }
        "suspicious" | "pup" => {
            let _ = SUSPICIOUS_COUNT.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });
            if let Ok(mut last) = LAST_THREAT.write() {
                *last = Some(ThreatInfo {
                    file_path: file_path.to_string(),
                    threat_name: threat_name.map(|s| s.to_string()),
                    verdict: verdict.to_string(),
                });
            }
        }
        "malware" => {
            let _ = MALWARE_COUNT.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });
            if let Ok(mut last) = LAST_THREAT.write() {
                *last = Some(ThreatInfo {
                    file_path: file_path.to_string(),
                    threat_name: threat_name.map(|s| s.to_string()),
                    verdict: verdict.to_string(),
                });
            }
        }
        _ => {}
    }
}

pub fn set_total_files(total: u32) {
    TOTAL_FILES.store(total, Ordering::SeqCst);
    FILES_REMAINING.store(total, Ordering::SeqCst);
}

pub fn is_scanning() -> bool {
    IS_SCANNING.load(Ordering::SeqCst)
}

#[tauri::command]
pub fn get_scan_status() -> Result<ScanStatus, String> {
    let current_file = CURRENT_FILE.read().ok().and_then(|guard| guard.clone());

    let files_scanned = FILES_SCANNED.load(Ordering::SeqCst);
    let files_remaining = FILES_REMAINING.load(Ordering::SeqCst);
    let total_files = TOTAL_FILES.load(Ordering::SeqCst);

    // Cap progress at 100% - files_scanned can sometimes exceed total if files are added dynamically
    let progress_percent = if total_files > 0 {
        ((files_scanned as f64 / total_files as f64) * 100.0).min(100.0)
    } else if IS_SCANNING.load(Ordering::SeqCst) {
        -1.0
    } else {
        0.0
    };

    let start_time = SCAN_START_TIME.load(Ordering::SeqCst);
    let elapsed_seconds = if start_time > 0 && IS_SCANNING.load(Ordering::SeqCst) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        ((now - start_time) / 1000) as u32
    } else {
        0
    };

    let last_threat = LAST_THREAT.read().ok().and_then(|guard| guard.clone());

    let scan_type = CURRENT_SCAN_TYPE
        .read()
        .ok()
        .and_then(|guard| guard.clone());

    Ok(ScanStatus {
        is_scanning: IS_SCANNING.load(Ordering::SeqCst),
        current_file,
        files_scanned,
        files_remaining,
        total_files,
        progress_percent,
        clean_count: CLEAN_COUNT.load(Ordering::SeqCst),
        suspicious_count: SUSPICIOUS_COUNT.load(Ordering::SeqCst),
        malware_count: MALWARE_COUNT.load(Ordering::SeqCst),
        elapsed_seconds,
        last_threat,
        scan_type,
        files_per_second: if elapsed_seconds > 0 {
            files_scanned as f64 / elapsed_seconds as f64
        } else {
            0.0
        },
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStatus {
    pub is_scanning: bool,
    pub current_file: Option<String>,
    pub files_scanned: u32,
    pub files_remaining: u32,
    pub total_files: u32,
    pub progress_percent: f64,
    pub clean_count: u32,
    pub suspicious_count: u32,
    pub malware_count: u32,
    pub elapsed_seconds: u32,
    pub last_threat: Option<ThreatInfo>,
    pub scan_type: Option<String>,
    pub files_per_second: f64,
}

// ============================================================================
// Scan Types and Commands
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanType {
    Quick,
    Full,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub scan_type: ScanType,
    pub custom_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub total_files: u32,
    pub clean_count: u32,
    pub suspicious_count: u32,
    pub malware_count: u32,
    pub elapsed_seconds: u32,
    pub scan_type: String,
}

/// Get paths for quick scan (common malware locations)
/// Designed to complete in 1-3 minutes by focusing on high-risk, low-volume locations
/// Unlike full scans, this avoids large cache folders and deep directories
fn get_quick_scan_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs::home_dir() {
        // Downloads folder - #1 malware entry point
        paths.push(home.join("Downloads"));
        // Desktop - common drop location
        paths.push(home.join("Desktop"));
    }

    // User Startup folder - common persistence mechanism (small folder)
    if let Some(home) = dirs::home_dir() {
        let startup = home
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        if startup.exists() {
            paths.push(startup);
        }
    }

    // Common Startup folder (all users) - usually just a few files
    let common_startup =
        std::path::PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup");
    if common_startup.exists() {
        paths.push(common_startup);
    }

    // Public folders (shared access, common malware drop location)
    let public_downloads = std::path::PathBuf::from(r"C:\Users\Public\Downloads");
    let public_desktop = std::path::PathBuf::from(r"C:\Users\Public\Desktop");
    if public_downloads.exists() {
        paths.push(public_downloads);
    }
    if public_desktop.exists() {
        paths.push(public_desktop);
    }

    // NOTE: Skipping TEMP folder - it often contains symlinks/junctions that lead to
    // Program Files, BuildTools, etc. which inflates scan count and slows down quick scan

    paths
}

/// Get paths for full scan - comprehensive system scan
/// Includes user profile, program files, and key system locations
/// This is thorough but takes 15-60+ minutes
fn get_full_scan_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    // User profile - all user data
    if let Some(home) = dirs::home_dir() {
        paths.push(home);
    }

    // Program Files - installed applications
    if let Ok(pf) = std::env::var("ProgramFiles") {
        let pf_path = std::path::PathBuf::from(&pf);
        if pf_path.exists() {
            paths.push(pf_path);
        }
    }

    // Program Files (x86) - 32-bit applications on 64-bit Windows
    if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
        let pf86_path = std::path::PathBuf::from(&pf86);
        if pf86_path.exists() {
            paths.push(pf86_path);
        }
    }

    // ProgramData - application data
    let program_data = std::path::PathBuf::from(r"C:\ProgramData");
    if program_data.exists() {
        paths.push(program_data);
    }

    // Public user folder
    let public = std::path::PathBuf::from(r"C:\Users\Public");
    if public.exists() {
        paths.push(public);
    }

    // NOTE: We intentionally skip C:\Windows to avoid scanning system files
    // which are protected by Windows and rarely contain user-installed malware
    // Enterprise AVs do scan Windows folder but it adds significant time

    paths
}

/// Collect scannable files from paths
/// `max_file_size` - if set, files larger than this (bytes) are skipped.
/// Quick scan uses this to avoid hashing large ISOs/installers that dominate scan time.
fn collect_files(
    paths: &[std::path::PathBuf],
    max_depth: Option<usize>,
    max_file_size: Option<u64>,
) -> Vec<String> {
    use crate::core::utils::is_scannable_file;

    // Directories to always skip - they add thousands of files and never contain real malware
    let skip_dirs: &[&str] = &[
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".tox",
        ".venv",
        "venv",
        ".mypy_cache",
        ".pytest_cache",
        ".cargo",
        ".rustup",
        "target",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "obj",
        "bin",
        ".gradle",
        ".m2",
        ".npm",
        ".yarn",
        ".pnpm-store",
        "site-packages",
        "Lib",
        "Include",
    ];

    let mut files = Vec::new();

    for base_path in paths {
        let walker = if let Some(depth) = max_depth {
            WalkDir::new(base_path).max_depth(depth).follow_links(false)
        } else {
            WalkDir::new(base_path).follow_links(false)
        };

        for entry in walker
            .into_iter()
            .filter_entry(|e| {
                // Skip known non-malware directories to reduce scan count
                if e.file_type().is_dir() {
                    if let Some(name) = e.file_name().to_str() {
                        if skip_dirs.contains(&name) {
                            return false;
                        }
                    }
                }
                true
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                // Skip files larger than max_file_size (quick scan optimization)
                if let Some(max_size) = max_file_size {
                    if let Ok(metadata) = path.metadata() {
                        if metadata.len() > max_size {
                            continue;
                        }
                    }
                }
                if let Some(path_str) = path.to_str() {
                    if is_scannable_file(path_str) {
                        files.push(path_str.to_string());
                    }
                }
            }
        }
    }

    files
}

/// Start a folder/directory scan
#[tauri::command]
pub async fn start_scan(
    app: tauri::AppHandle,
    scan_type: String,
    custom_path: Option<String>,
) -> Result<(), String> {
    use crate::core::pipeline::DetectionPipeline;

    log::info!(
        "start_scan called: type={}, custom_path={:?}",
        scan_type,
        custom_path
    );

    // Atomically check and set IS_SCANNING to prevent race condition
    // compare_exchange returns Err if current value != expected (false), meaning scan already running
    if IS_SCANNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        log::warn!("Scan blocked: IS_SCANNING is already true (atomic check)");
        return Err("A scan is already in progress. If this seems incorrect, try resetting the scan state from Settings.".to_string());
    }

    // Validate paths synchronously so we can return errors to the frontend immediately
    let paths: Vec<std::path::PathBuf> = match scan_type.to_lowercase().as_str() {
        "quick" => get_quick_scan_paths(),
        "full" => get_full_scan_paths(),
        "custom" => {
            if let Some(path) = custom_path {
                let custom_path = std::path::PathBuf::from(&path);
                if !custom_path.exists() {
                    IS_SCANNING.store(false, Ordering::SeqCst);
                    return Err(format!("Path does not exist: {}", path));
                }
                if !custom_path.is_dir() && !custom_path.is_file() {
                    IS_SCANNING.store(false, Ordering::SeqCst);
                    return Err(format!("Path is not a file or directory: {}", path));
                }
                vec![custom_path]
            } else {
                IS_SCANNING.store(false, Ordering::SeqCst);
                return Err("Custom scan requires a path".to_string());
            }
        }
        _ => {
            IS_SCANNING.store(false, Ordering::SeqCst);
            return Err(format!("Unknown scan type: {}", scan_type));
        }
    };

    if paths.is_empty() {
        IS_SCANNING.store(false, Ordering::SeqCst);
        log::warn!("No valid scan paths found for scan type: {}", scan_type);
        return Err("No valid paths to scan".to_string());
    }

    // Initialize scan state immediately so the frontend can start polling right away
    // IS_SCANNING is already true from compare_exchange above
    scan_started_internal();

    // Store the current scan type so the UI can display it during file collection
    if let Ok(mut st) = CURRENT_SCAN_TYPE.write() {
        *st = Some(scan_type.clone());
    }

    // Return immediately to the frontend - file collection and scanning happen in the background
    // This prevents the UI from freezing during the (potentially long) file collection phase
    let scan_type_clone = scan_type.clone();
    let is_quick_scan = scan_type.to_lowercase() == "quick";
    let max_depth = if is_quick_scan { Some(2) } else { None };

    let app_for_panic = app.clone();
    let scan_type_for_panic = scan_type_clone.clone();
    // Capture the generation so this task can detect if a newer scan superseded it
    let my_generation = SCAN_GENERATION.load(Ordering::SeqCst);
    tauri::async_runtime::spawn(async move {
        let result = tokio::task::spawn(async move {
            // Phase 1: Collect files (can be slow for full scans)
            // Quick scan skips files > 50MB to avoid hashing large ISOs/installers
            let max_file_size: Option<u64> = if is_quick_scan {
                Some(50_000_000)
            } else {
                None
            };
            log::info!(
                "Collecting files from {} paths (depth: {:?}, max_file_size: {:?})",
                paths.len(),
                max_depth,
                max_file_size
            );

            // Detect single-file custom scan (skip directory walking)
            let is_single_file = paths.len() == 1 && paths[0].is_file();

            let files = match tauri::async_runtime::spawn_blocking(move || {
                if is_single_file {
                    // Single file - no need to walk directories
                    if let Some(path_str) = paths[0].to_str() {
                        vec![path_str.to_string()]
                    } else {
                        Vec::new()
                    }
                } else {
                    collect_files(&paths, max_depth, max_file_size)
                }
            })
            .await
            {
                Ok(files) => files,
                Err(e) => {
                    log::error!("Failed to collect files: {}", e);
                    if SCAN_GENERATION.load(Ordering::SeqCst) != my_generation {
                        log::info!("File collection failed but scan was superseded - skipping");
                        return;
                    }
                    scan_stopped();
                    let summary = ScanSummary {
                        total_files: 0,
                        clean_count: 0,
                        suspicious_count: 0,
                        malware_count: 0,
                        elapsed_seconds: 0,
                        scan_type: scan_type_clone,
                    };
                    let _ = app.emit("scan-complete", &summary);
                    return;
                }
            };

            log::info!("Found {} scannable files", files.len());

            if files.is_empty() {
                log::info!("No scannable files found - completing with 0 files");
                if SCAN_GENERATION.load(Ordering::SeqCst) != my_generation {
                    log::info!("Empty scan was superseded - skipping");
                    return;
                }
                scan_stopped();
                let summary = ScanSummary {
                    total_files: 0,
                    clean_count: 0,
                    suspicious_count: 0,
                    malware_count: 0,
                    elapsed_seconds: 0,
                    scan_type: scan_type_clone,
                };
                let _ = app.emit("scan-complete", &summary);
                return;
            }

            // Phase 2: Set total and start scanning
            set_total_files(files.len() as u32);
            log::info!(
                "Starting {} scan with {} files",
                scan_type_clone,
                files.len()
            );

            let per_file_timeout = if is_quick_scan {
                std::time::Duration::from_secs(30)
            } else {
                std::time::Duration::from_secs(60)
            };

            // Read worker count from settings; clamp to [1, 32]
            let concurrency = crate::config::settings::Settings::load()
                .scan_worker_count
                .clamp(1, 16) as usize;
            log::info!("Scan concurrency: {} workers", concurrency);

            let app_ref = &app;

            stream::iter(files)
                .take_while(|_| {
                    let dominated = SCAN_GENERATION.load(Ordering::SeqCst) != my_generation;
                    let scanning = IS_SCANNING.load(Ordering::SeqCst);
                    async move { scanning && !dominated }
                })
                .map(|file_path| {
                    let timeout = per_file_timeout;
                    async move {
                        set_current_file(&file_path);

                        let scan_result = tokio::time::timeout(timeout, async {
                            if is_quick_scan {
                                DetectionPipeline::scan_file_quick(&file_path).await
                            } else {
                                // Cache enabled for full scans - unchanged files get
                                // instant cache hits on repeat scans (24h TTL)
                                DetectionPipeline::scan_file_with_options(&file_path, false).await
                            }
                        })
                        .await;

                        match scan_result {
                            Ok(Ok(result)) => {
                                let verdict_str = format!("{:?}", result.verdict);
                                record_verdict(
                                    &verdict_str,
                                    &file_path,
                                    result.threat_name.as_deref(),
                                );

                                let rec = crate::database::models::Verdict {
                                    id: 0,
                                    file_hash: result.file_hash.clone(),
                                    file_path: file_path.clone(),
                                    verdict: verdict_str,
                                    confidence: result.confidence,
                                    threat_level: result.threat_level.clone(),
                                    threat_name: result.threat_name.clone(),
                                    scan_time_ms: result.scan_time_ms,
                                    scanned_at: Utc::now().timestamp(),
                                    source: "manual".to_string(),
                                };
                                crate::database::batcher::enqueue_verdict(rec);

                                if result.verdict != crate::core::pipeline::Verdict::Clean {
                                    let _ = app_ref.emit("scan-result", &result);
                                }
                            }
                            Ok(Err(e)) => {
                                log::warn!("Failed to scan {}: {}", file_path, e);
                                // this file is simply not counted in any verdict bucket
                            }
                            Err(_) => {
                                log::warn!(
                                    "Scan timed out after {}s for: {}",
                                    timeout.as_secs(),
                                    file_path
                                );
                                // Don't record as "Clean" - timeouts are not verified clean files
                            }
                        }

                        increment_scanned();
                    }
                })
                .buffer_unordered(concurrency)
                .collect::<()>()
                .await;

            // Check if this scan was superseded by a newer one
            let current_gen = SCAN_GENERATION.load(Ordering::SeqCst);
            if current_gen != my_generation {
                log::info!(
                    "Scan generation {} superseded by {} - discarding results",
                    my_generation,
                    current_gen
                );
                return;
            }

            if !IS_SCANNING.load(Ordering::SeqCst) {
                log::info!("Scan cancelled");
            }

            // Build summary
            let total = TOTAL_FILES.load(Ordering::SeqCst);
            let scanned = FILES_SCANNED.load(Ordering::SeqCst);
            let summary = ScanSummary {
                total_files: std::cmp::max(total, scanned),
                clean_count: CLEAN_COUNT.load(Ordering::SeqCst),
                suspicious_count: SUSPICIOUS_COUNT.load(Ordering::SeqCst),
                malware_count: MALWARE_COUNT.load(Ordering::SeqCst),
                elapsed_seconds: {
                    let start = SCAN_START_TIME.load(Ordering::SeqCst);
                    if start > 0 {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        ((now - start) / 1000) as u32
                    } else {
                        0
                    }
                },
                scan_type: scan_type_clone,
            };

            scan_stopped();
            let _ = app.emit("scan-complete", &summary);
            log::info!("Scan completed: {:?}", summary);
        })
        .await;

        // Check generation again for the panic handler
        let current_gen = SCAN_GENERATION.load(Ordering::SeqCst);
        if let Err(e) = result {
            log::error!("Scan task panicked: {}", e);
            if current_gen != my_generation {
                log::info!("Panicked scan was superseded - not emitting stale summary");
                return;
            }
            if IS_SCANNING.load(Ordering::SeqCst) {
                scan_stopped();
            }
            let total = TOTAL_FILES.load(Ordering::SeqCst);
            let scanned = FILES_SCANNED.load(Ordering::SeqCst);
            let summary = ScanSummary {
                total_files: std::cmp::max(total, scanned),
                clean_count: CLEAN_COUNT.load(Ordering::SeqCst),
                suspicious_count: SUSPICIOUS_COUNT.load(Ordering::SeqCst),
                malware_count: MALWARE_COUNT.load(Ordering::SeqCst),
                elapsed_seconds: 0,
                scan_type: scan_type_for_panic,
            };
            let _ = app_for_panic.emit("scan-complete", &summary);
        }
    });

    Ok(())
}

#[tauri::command]
pub fn cancel_scan() -> Result<(), String> {
    if !IS_SCANNING.load(Ordering::SeqCst) {
        return Err("No scan in progress".to_string());
    }

    log::info!("Cancelling scan...");
    scan_stopped();
    Ok(())
}

/// Force reset scan state - use when scan gets stuck
#[tauri::command]
pub fn force_reset_scan() -> Result<(), String> {
    log::warn!("Force resetting scan state");
    scan_stopped();
    reset_counters();
    SCAN_START_TIME.store(0, Ordering::SeqCst);
    Ok(())
}

/// Pick a folder for custom scan (opens native folder dialog)
#[tauri::command]
pub async fn pick_scan_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let folder = app
        .dialog()
        .file()
        .set_title("Select folder to scan")
        .blocking_pick_folder();

    match folder {
        Some(path) => Ok(Some(path.to_string())),
        None => Ok(None),
    }
}

/// Pick a file for custom scan (opens native file dialog)
#[tauri::command]
pub async fn pick_scan_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let file = app
        .dialog()
        .file()
        .set_title("Select file to scan")
        .blocking_pick_file();

    match file {
        Some(path) => Ok(Some(path.to_string())),
        None => Ok(None),
    }
}

// ============================================================================
// Export Scan Report
// ============================================================================

/// Scan report for export
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub report_generated_at: String,
    pub scan_type: String,
    pub scan_duration_seconds: u32,
    pub total_files_scanned: u32,
    pub clean_count: u32,
    pub suspicious_count: u32,
    pub malware_count: u32,
    pub threats: Vec<ThreatDetail>,
    pub system_info: SystemInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatDetail {
    pub file_path: String,
    pub file_hash: String,
    pub verdict: String,
    pub threat_level: String,
    pub threat_name: Option<String>,
    pub confidence: f64,
    pub detected_at: String,
    pub detection_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub os_version: String,
    pub computer_name: String,
    pub app_version: String,
}

/// Export scan report as JSON
#[tauri::command]
pub async fn export_scan_report(output_path: String) -> Result<String, String> {
    use chrono::{DateTime, Utc};

    let scan_type = CURRENT_SCAN_TYPE
        .read()
        .ok()
        .and_then(|t| t.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let elapsed = {
        let start = SCAN_START_TIME.load(Ordering::SeqCst);
        if start > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            ((now - start) / 1000) as u32
        } else {
            0
        }
    };

    // Get threats from database on a blocking thread
    let threats: Vec<ThreatDetail> = crate::with_db_async(|conn| {
        use crate::database::queries::DatabaseQueries;
        match DatabaseQueries::get_recent_verdicts(conn, 1000) {
            Ok(rows) => Ok(rows
                .iter()
                .filter(|r| r.verdict != "Clean")
                .map(|r| {
                    let detected_at = DateTime::<Utc>::from_timestamp(r.scanned_at, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                    let mut reasons = Vec::new();
                    if r.confidence > 0.8 {
                        reasons.push("High ML confidence score".to_string());
                    }
                    if r.threat_level == "HIGH" {
                        reasons.push("Critical threat indicators detected".to_string());
                    }

                    ThreatDetail {
                        file_path: r.file_path.clone(),
                        file_hash: r.file_hash.clone(),
                        verdict: r.verdict.clone(),
                        threat_level: r.threat_level.clone(),
                        threat_name: r.threat_name.clone(),
                        confidence: r.confidence,
                        detected_at,
                        detection_reasons: reasons,
                    }
                })
                .collect()),
            Err(_) => Ok(Vec::new()),
        }
    })
    .await
    .unwrap_or_default();

    let report = ScanReport {
        report_generated_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        scan_type,
        scan_duration_seconds: elapsed,
        total_files_scanned: TOTAL_FILES.load(Ordering::SeqCst),
        clean_count: CLEAN_COUNT.load(Ordering::SeqCst),
        suspicious_count: SUSPICIOUS_COUNT.load(Ordering::SeqCst),
        malware_count: MALWARE_COUNT.load(Ordering::SeqCst),
        threats,
        system_info: SystemInfo {
            os_version: std::env::consts::OS.to_string(),
            computer_name: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "Unknown".to_string()),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };

    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Failed to serialize report: {}", e))?;

    let op = output_path.clone();
    tokio::task::spawn_blocking(move || {
        std::fs::write(&op, json).map_err(|e| format!("Failed to write report: {}", e))
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))??;

    Ok(format!("Report exported to {}", output_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Helper to reset all global state before each test.
    /// Since these tests share statics, run them serially (`cargo test -- --test-threads=1`)
    /// or accept that interleaving may occur.
    fn reset_all() {
        IS_SCANNING.store(false, Ordering::SeqCst);
        IS_MANUAL_SCAN.store(false, Ordering::SeqCst);
        REALTIME_PAUSED.store(false, Ordering::SeqCst);
        FILES_SCANNED.store(0, Ordering::SeqCst);
        FILES_REMAINING.store(0, Ordering::SeqCst);
        TOTAL_FILES.store(0, Ordering::SeqCst);
        CLEAN_COUNT.store(0, Ordering::SeqCst);
        SUSPICIOUS_COUNT.store(0, Ordering::SeqCst);
        MALWARE_COUNT.store(0, Ordering::SeqCst);
        SCAN_START_TIME.store(0, Ordering::SeqCst);
        if let Ok(mut f) = CURRENT_FILE.write() {
            *f = None;
        }
        if let Ok(mut t) = LAST_THREAT.write() {
            *t = None;
        }
        if let Ok(mut s) = CURRENT_SCAN_TYPE.write() {
            *s = None;
        }
    }

    // =========================================================================
    // record_verdict
    // =========================================================================

    #[test]
    #[serial]
    fn test_record_verdict_clean() {
        reset_all();
        IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
        record_verdict("Clean", "/tmp/file.txt", None);
        assert_eq!(CLEAN_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(SUSPICIOUS_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(MALWARE_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[serial]
    fn test_record_verdict_malware() {
        reset_all();
        IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
        record_verdict("Malware", "/tmp/bad.exe", Some("Trojan.Gen"));
        assert_eq!(MALWARE_COUNT.load(Ordering::SeqCst), 1);
        let last = LAST_THREAT.read().unwrap();
        assert!(last.is_some());
        let threat = last.as_ref().unwrap();
        assert_eq!(threat.verdict, "Malware");
        assert_eq!(threat.threat_name.as_deref(), Some("Trojan.Gen"));
    }

    #[test]
    #[serial]
    fn test_record_verdict_suspicious() {
        reset_all();
        IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
        record_verdict("Suspicious", "/tmp/sus.exe", None);
        assert_eq!(SUSPICIOUS_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[serial]
    fn test_record_verdict_pup() {
        reset_all();
        IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
        record_verdict("PUP", "/tmp/pup.exe", None);
        assert_eq!(SUSPICIOUS_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[serial]
    fn test_record_verdict_case_insensitive() {
        reset_all();
        IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
        record_verdict("CLEAN", "/tmp/a.txt", None);
        record_verdict("clean", "/tmp/b.txt", None);
        assert_eq!(CLEAN_COUNT.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[serial]
    fn test_record_verdict_unknown_category() {
        reset_all();
        IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
        record_verdict("Unknown", "/tmp/x.txt", None);
        assert_eq!(CLEAN_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(SUSPICIOUS_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(MALWARE_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[serial]
    fn test_record_verdict_skipped_when_not_manual_scan() {
        reset_all();
        // IS_MANUAL_SCAN is false by default
        record_verdict("Clean", "/tmp/file.txt", None);
        assert_eq!(CLEAN_COUNT.load(Ordering::SeqCst), 0);
    }

    // =========================================================================
    // set_total_files / reset_counters
    // =========================================================================

    #[test]
    #[serial]
    fn test_set_total_files() {
        reset_all();
        set_total_files(100);
        assert_eq!(TOTAL_FILES.load(Ordering::SeqCst), 100);
        assert_eq!(FILES_REMAINING.load(Ordering::SeqCst), 100);
    }

    #[test]
    #[serial]
    fn test_reset_counters() {
        reset_all();
        IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
        set_total_files(50);
        record_verdict("Clean", "/a", None);
        record_verdict("Malware", "/b", Some("Bad"));
        reset_counters();
        assert_eq!(CLEAN_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(MALWARE_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(TOTAL_FILES.load(Ordering::SeqCst), 0);
    }

    // =========================================================================
    // increment_scanned
    // =========================================================================

    #[test]
    #[serial]
    fn test_increment_scanned() {
        reset_all();
        IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
        set_total_files(10);
        increment_scanned();
        increment_scanned();
        assert_eq!(FILES_SCANNED.load(Ordering::SeqCst), 2);
        assert_eq!(FILES_REMAINING.load(Ordering::SeqCst), 8);
    }

    #[test]
    #[serial]
    fn test_increment_scanned_skipped_outside_manual() {
        reset_all();
        set_total_files(10);
        increment_scanned();
        assert_eq!(FILES_SCANNED.load(Ordering::SeqCst), 0);
    }

    // =========================================================================
    // scan_started / scan_stopped lifecycle
    // =========================================================================

    #[test]
    #[serial]
    fn test_scan_lifecycle() {
        reset_all();
        assert!(!is_scanning());
        assert!(!is_realtime_paused());

        scan_started();
        assert!(is_scanning());
        assert!(is_realtime_paused());
        assert!(IS_MANUAL_SCAN.load(Ordering::SeqCst));

        scan_stopped();
        assert!(!is_scanning());
        assert!(!is_realtime_paused());
        assert!(!IS_MANUAL_SCAN.load(Ordering::SeqCst));
    }

    // =========================================================================
    // Serialization
    // =========================================================================

    #[test]
    fn test_scan_status_serialization_camel_case() {
        let status = ScanStatus {
            is_scanning: true,
            current_file: Some("/tmp/test.exe".to_string()),
            files_scanned: 10,
            files_remaining: 90,
            total_files: 100,
            progress_percent: 10.0,
            clean_count: 8,
            suspicious_count: 1,
            malware_count: 1,
            elapsed_seconds: 5,
            last_threat: None,
            scan_type: Some("quick".to_string()),
            files_per_second: 2.0,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("isScanning"));
        assert!(json.contains("currentFile"));
        assert!(json.contains("filesScanned"));
        assert!(json.contains("progressPercent"));
        assert!(json.contains("filesPerSecond"));
    }

    #[test]
    fn test_scan_summary_serialization() {
        let summary = ScanSummary {
            total_files: 100,
            clean_count: 95,
            suspicious_count: 3,
            malware_count: 2,
            elapsed_seconds: 60,
            scan_type: "full".to_string(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let deser: ScanSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.total_files, 100);
        assert_eq!(deser.scan_type, "full");
    }

    #[test]
    fn test_scan_type_deserialization() {
        let json = r#""quick""#;
        let st: ScanType = serde_json::from_str(json).unwrap();
        assert!(matches!(st, ScanType::Quick));
    }

    #[test]
    fn test_threat_info_serialization() {
        let threat = ThreatInfo {
            file_path: "/tmp/bad.exe".to_string(),
            threat_name: Some("Trojan.Gen".to_string()),
            verdict: "Malware".to_string(),
        };
        let json = serde_json::to_string(&threat).unwrap();
        assert!(json.contains("filePath"));
        assert!(json.contains("threatName"));
    }

    #[test]
    fn test_single_file_scan_result_serialization() {
        let result = SingleFileScanResult {
            file_path: "/test.exe".to_string(),
            file_hash: "abc123".to_string(),
            verdict: "Clean".to_string(),
            confidence: 0.95,
            threat_level: "NONE".to_string(),
            threat_name: None,
            scan_time_ms: 42,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: SingleFileScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.confidence, 0.95);
        assert_eq!(deser.scan_time_ms, 42);
    }
}
