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

    let result = DetectionPipeline::scan_file_with_options(&file_path, true)
        .await
        .map_err(|e| format!("Scan failed: {}", e))?;

    let verdict_str = format!("{:?}", result.verdict);

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
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use tauri::Emitter;
use walkdir::WalkDir;

static IS_SCANNING: AtomicBool = AtomicBool::new(false);
pub(crate) const SCAN_IN_PROGRESS_ERROR: &str =
    "A scan is already in progress. If this seems incorrect, try resetting the scan state from Settings.";

static FILES_SCANNED: AtomicU32 = AtomicU32::new(0);

static FILES_REMAINING: AtomicU32 = AtomicU32::new(0);

static CURRENT_FILE: RwLock<Option<String>> = RwLock::new(None);

static TOTAL_FILES: AtomicU32 = AtomicU32::new(0);

static CLEAN_COUNT: AtomicU32 = AtomicU32::new(0);
static SUSPICIOUS_COUNT: AtomicU32 = AtomicU32::new(0);
static MALWARE_COUNT: AtomicU32 = AtomicU32::new(0);

static SCAN_START_TIME: AtomicU64 = AtomicU64::new(0);

static LAST_THREAT: RwLock<Option<ThreatInfo>> = RwLock::new(None);

static CURRENT_SCAN_TYPE: RwLock<Option<String>> = RwLock::new(None);
static LAST_COMPLETED_SCAN_TYPE: RwLock<Option<String>> = RwLock::new(None);

static IS_MANUAL_SCAN: AtomicBool = AtomicBool::new(false);

static SCAN_GENERATION: AtomicU64 = AtomicU64::new(0);

pub static REALTIME_PAUSED: AtomicBool = AtomicBool::new(false);

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
    REALTIME_PAUSED.store(true, Ordering::SeqCst);
    IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
    IS_SCANNING.store(true, Ordering::SeqCst);
    log::info!(
        "Manual scan started - pausing real-time protection (file watching + process monitor)"
    );
    scan_started_internal();
}

fn scan_started_internal() {
    REALTIME_PAUSED.store(true, Ordering::SeqCst);
    IS_MANUAL_SCAN.store(true, Ordering::SeqCst);
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
    IS_SCANNING.store(false, Ordering::SeqCst);
    IS_MANUAL_SCAN.store(false, Ordering::SeqCst);
    REALTIME_PAUSED.store(false, Ordering::SeqCst);
    log::info!("Manual scan stopped - resuming real-time protection");
    if let Ok(mut file) = CURRENT_FILE.write() {
        *file = None;
    }
    if let Ok(mut scan_type) = CURRENT_SCAN_TYPE.write() {
        if let Ok(mut last_type) = LAST_COMPLETED_SCAN_TYPE.write() {
            *last_type = scan_type.clone();
        }
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

pub fn set_current_file(path: &str) {
    if !IS_MANUAL_SCAN.load(Ordering::SeqCst) {
        return;
    }

    if let Ok(mut file) = CURRENT_FILE.write() {
        *file = Some(path.to_string());
    }
}

pub fn increment_scanned() {
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

pub fn record_verdict(verdict: &str, file_path: &str, threat_name: Option<&str>) {
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

pub(crate) fn is_scan_in_progress_error(err: &str) -> bool {
    err == SCAN_IN_PROGRESS_ERROR
}

#[tauri::command]
pub fn get_scan_status() -> Result<ScanStatus, String> {
    let current_file = CURRENT_FILE.read().ok().and_then(|guard| guard.clone());

    let files_scanned = FILES_SCANNED.load(Ordering::SeqCst);
    let files_remaining = FILES_REMAINING.load(Ordering::SeqCst);
    let total_files = TOTAL_FILES.load(Ordering::SeqCst);

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

fn get_quick_scan_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs::home_dir() {
        paths.push(home.join("Downloads"));
        paths.push(home.join("Desktop"));
    }

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

    let common_startup =
        std::path::PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup");
    if common_startup.exists() {
        paths.push(common_startup);
    }

    let public_downloads = std::path::PathBuf::from(r"C:\Users\Public\Downloads");
    let public_desktop = std::path::PathBuf::from(r"C:\Users\Public\Desktop");
    if public_downloads.exists() {
        paths.push(public_downloads);
    }
    if public_desktop.exists() {
        paths.push(public_desktop);
    }

    paths
}

fn get_full_scan_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs::home_dir() {
        paths.push(home);
    }

    if let Ok(pf) = std::env::var("ProgramFiles") {
        let pf_path = std::path::PathBuf::from(&pf);
        if pf_path.exists() {
            paths.push(pf_path);
        }
    }

    if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
        let pf86_path = std::path::PathBuf::from(&pf86);
        if pf86_path.exists() {
            paths.push(pf86_path);
        }
    }

    let program_data = std::path::PathBuf::from(r"C:\ProgramData");
    if program_data.exists() {
        paths.push(program_data);
    }

    let public = std::path::PathBuf::from(r"C:\Users\Public");
    if public.exists() {
        paths.push(public);
    }

    paths
}

fn collect_files(
    paths: &[std::path::PathBuf],
    max_depth: Option<usize>,
    max_file_size: Option<u64>,
) -> Vec<String> {
    use crate::core::utils::is_scannable_file;
    use crate::core::yara_scanner::{file_contains_eicar_test_marker, is_eicar_candidate_path};

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
                if let Some(max_size) = max_file_size {
                    if let Ok(metadata) = path.metadata() {
                        if metadata.len() > max_size {
                            continue;
                        }
                    }
                }
                if let Some(path_str) = path.to_str() {
                    let should_scan = if is_scannable_file(path_str) {
                        true
                    } else if is_eicar_candidate_path(path_str) {
                        true
                    } else if path == base_path.as_path() {
                        file_contains_eicar_test_marker(path_str)
                    } else {
                        false
                    };

                    if should_scan {
                        files.push(path_str.to_string());
                    }
                }
            }
        }
    }

    files
}

fn normalize_scan_type(scan_type: &str) -> Result<String, String> {
    let normalized = scan_type.trim().to_lowercase();
    match normalized.as_str() {
        "quick" | "full" | "custom" | "external" => Ok(normalized),
        _ => Err(format!("Unknown scan type: {}", scan_type)),
    }
}

fn resolve_scan_paths(
    scan_type: &str,
    custom_path: Option<String>,
) -> Result<Vec<std::path::PathBuf>, String> {
    match scan_type {
        "quick" => Ok(get_quick_scan_paths()),
        "full" => Ok(get_full_scan_paths()),
        "custom" => {
            let path = custom_path.ok_or_else(|| "Custom scan requires a path".to_string())?;
            let custom_path = std::path::PathBuf::from(&path);
            if !custom_path.exists() {
                return Err(format!("Path does not exist: {}", path));
            }
            if !custom_path.is_dir() && !custom_path.is_file() {
                return Err(format!("Path is not a file or directory: {}", path));
            }
            Ok(vec![custom_path])
        }
        "external" => {
            let path =
                custom_path.ok_or_else(|| "External scan requires a mounted path".to_string())?;
            let external_path = std::path::PathBuf::from(&path);
            if !external_path.exists() {
                return Err(format!("Path does not exist: {}", path));
            }
            if !external_path.is_dir() {
                return Err(format!("External scan requires a directory path: {}", path));
            }
            Ok(vec![external_path])
        }
        _ => Err(format!("Unknown scan type: {}", scan_type)),
    }
}

fn external_scan_category_priority(path: &std::path::Path) -> u8 {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_lowercase();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    if file_name == "autorun.inf" {
        return 0;
    }

    let executable_like = [
        "exe",
        "dll",
        "sys",
        "drv",
        "ocx",
        "scr",
        "cpl",
        "msi",
        "msp",
        "mst",
        "msix",
        "msixbundle",
        "appx",
        "appxbundle",
        "msu",
        "com",
        "pif",
        "jar",
        "class",
        "war",
        "ear",
        "lnk",
        "url",
    ];
    if executable_like.contains(&extension.as_str())
        || crate::core::utils::is_probable_installer_path(&path.to_string_lossy())
    {
        return 1;
    }

    let script_like = [
        "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sct",
        "reg", "docm", "xlsm", "pptm", "dotm", "xltm", "potm", "doc", "xls", "ppt",
    ];
    if script_like.contains(&extension.as_str()) {
        return 2;
    }

    let archive_like = ["zip", "rar", "7z", "cab", "iso", "img"];
    if archive_like.contains(&extension.as_str()) {
        return 3;
    }

    4
}

fn sort_external_scan_files(files: &mut [String], root_path: &std::path::Path) {
    files.sort_by_key(|file_path| {
        let path = std::path::Path::new(file_path);
        let parent_is_root = path
            .parent()
            .map(|parent| parent == root_path)
            .unwrap_or(false);
        let root_priority = if parent_is_root { 0 } else { 1 };
        let category_priority = external_scan_category_priority(path);
        let tie_breaker = file_path.to_lowercase();
        (root_priority, category_priority, tie_breaker)
    });
}

pub(crate) fn start_scan_internal(
    app: tauri::AppHandle,
    scan_type: String,
    custom_path: Option<String>,
) -> Result<(), String> {
    use crate::core::pipeline::DetectionPipeline;

    let normalized_scan_type = normalize_scan_type(&scan_type)?;

    log::info!(
        "start_scan called: type={}, custom_path={:?}",
        normalized_scan_type,
        custom_path
    );

    if IS_SCANNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        log::warn!("Scan blocked: IS_SCANNING is already true (atomic check)");
        return Err(SCAN_IN_PROGRESS_ERROR.to_string());
    }

    let paths = match resolve_scan_paths(&normalized_scan_type, custom_path) {
        Ok(paths) => paths,
        Err(err) => {
            IS_SCANNING.store(false, Ordering::SeqCst);
            return Err(err);
        }
    };

    if paths.is_empty() {
        IS_SCANNING.store(false, Ordering::SeqCst);
        log::warn!(
            "No valid scan paths found for scan type: {}",
            normalized_scan_type
        );
        return Err("No valid paths to scan".to_string());
    }

    scan_started_internal();

    if let Ok(mut st) = CURRENT_SCAN_TYPE.write() {
        *st = Some(normalized_scan_type.clone());
    }

    let scan_type_clone = normalized_scan_type.clone();
    let is_quick_scan = normalized_scan_type == "quick";
    let is_external_scan = normalized_scan_type == "external";
    let max_depth = if is_quick_scan { Some(2) } else { None };

    let app_for_panic = app.clone();
    let scan_type_for_panic = scan_type_clone.clone();
    let my_generation = SCAN_GENERATION.load(Ordering::SeqCst);
    tauri::async_runtime::spawn(async move {
        let result = tokio::task::spawn(async move {
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

            let is_single_file = paths.len() == 1 && paths[0].is_file();
            let external_root = if is_external_scan && paths.len() == 1 && paths[0].is_dir() {
                Some(paths[0].clone())
            } else {
                None
            };

            let files = match tauri::async_runtime::spawn_blocking(move || {
                if is_single_file {
                    if let Some(path_str) = paths[0].to_str() {
                        vec![path_str.to_string()]
                    } else {
                        Vec::new()
                    }
                } else {
                    let mut files = collect_files(&paths, max_depth, max_file_size);
                    if let Some(root_path) = external_root.as_deref() {
                        sort_external_scan_files(&mut files, root_path);
                    }
                    files
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

            let concurrency = crate::config::settings::Settings::load()
                .scan_worker_count
                .clamp(1, 16) as usize;
            log::info!("Scan concurrency: {} workers", concurrency);

            let app_ref = &app;
            let verdict_source = if is_external_scan {
                "external_media"
            } else {
                "manual"
            };

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
                                    source: verdict_source.to_string(),
                                };
                                crate::database::batcher::enqueue_verdict(rec);

                                if result.verdict != crate::core::pipeline::Verdict::Clean {
                                    let _ = app_ref.emit("scan-result", &result);
                                }
                            }
                            Ok(Err(e)) => {
                                log::warn!("Failed to scan {}: {}", file_path, e);
                            }
                            Err(_) => {
                                log::warn!(
                                    "Scan timed out after {}s for: {}",
                                    timeout.as_secs(),
                                    file_path
                                );
                            }
                        }

                        increment_scanned();
                    }
                })
                .buffer_unordered(concurrency)
                .collect::<()>()
                .await;

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

/// Start a folder/directory scan
#[tauri::command]
pub async fn start_scan(
    app: tauri::AppHandle,
    scan_type: String,
    custom_path: Option<String>,
) -> Result<(), String> {
    start_scan_internal(app, scan_type, custom_path)
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

#[tauri::command]
pub fn force_reset_scan() -> Result<(), String> {
    log::warn!("Force resetting scan state");
    scan_stopped();
    reset_counters();
    SCAN_START_TIME.store(0, Ordering::SeqCst);
    Ok(())
}

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

fn verdict_to_threat_detail(verdict: &crate::database::models::Verdict) -> ThreatDetail {
    use chrono::{DateTime, Utc};

    let detected_at = DateTime::<Utc>::from_timestamp(verdict.scanned_at, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let mut reasons = Vec::new();
    if verdict.confidence > 0.8 {
        reasons.push("High ML confidence score".to_string());
    }
    if verdict.threat_level == "HIGH" {
        reasons.push("Critical threat indicators detected".to_string());
    }

    ThreatDetail {
        file_path: verdict.file_path.clone(),
        file_hash: verdict.file_hash.clone(),
        verdict: verdict.verdict.clone(),
        threat_level: verdict.threat_level.clone(),
        threat_name: verdict.threat_name.clone(),
        confidence: verdict.confidence,
        detected_at,
        detection_reasons: reasons,
    }
}

#[tauri::command]
pub async fn get_last_manual_scan_threats(limit: Option<u32>) -> Result<Vec<ThreatDetail>, String> {
    let scan_start_ms = SCAN_START_TIME.load(Ordering::SeqCst);
    if scan_start_ms == 0 {
        return Ok(Vec::new());
    }

    let scan_start_seconds = (scan_start_ms / 1000) as i64;
    let max_items = limit.unwrap_or(500).clamp(1, 5_000);

    Ok(crate::with_db_async(move |conn| {
        let mut stmt = conn
            .prepare(
                r#"SELECT id, file_hash, file_path, verdict, confidence, threat_level, threat_name, scan_time_ms, scanned_at, source
                   FROM verdicts
                   WHERE source = 'manual'
                     AND verdict != 'Clean'
                     AND scanned_at >= ?1
                   ORDER BY scanned_at DESC, id DESC
                   LIMIT ?2"#,
            )
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map(rusqlite::params![scan_start_seconds, max_items as i64], |row| {
                Ok(crate::database::models::Verdict {
                    id: row.get(0)?,
                    file_hash: row.get(1)?,
                    file_path: row.get(2)?,
                    verdict: row.get(3)?,
                    confidence: row.get(4)?,
                    threat_level: row.get(5)?,
                    threat_name: row.get(6)?,
                    scan_time_ms: row.get(7)?,
                    scanned_at: row.get(8)?,
                    source: row.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?;

        let verdicts = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;

        Ok(verdicts
            .iter()
            .map(verdict_to_threat_detail)
            .collect::<Vec<_>>())
    })
    .await
    .map_err(|e| e.to_string())?)
}

#[tauri::command]
pub async fn export_scan_report(output_path: String) -> Result<String, String> {
    use chrono::Utc;

    let scan_type = CURRENT_SCAN_TYPE
        .read()
        .ok()
        .and_then(|t| t.clone())
        .or_else(|| LAST_COMPLETED_SCAN_TYPE.read().ok().and_then(|t| t.clone()))
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

    let scan_start_seconds = (SCAN_START_TIME.load(Ordering::SeqCst) / 1000) as i64;

    let threats: Vec<ThreatDetail> = crate::with_db_async(move |conn| {
        let mut stmt = conn
            .prepare(
                r#"SELECT id, file_hash, file_path, verdict, confidence, threat_level, threat_name, scan_time_ms, scanned_at, source
                   FROM verdicts
                   WHERE source = 'manual'
                     AND LOWER(verdict) IN ('malware', 'suspicious', 'pup')
                     AND scanned_at >= ?1
                   ORDER BY scanned_at DESC, id DESC
                   LIMIT 1000"#,
            )
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([scan_start_seconds], |row| {
                Ok(crate::database::models::Verdict {
                    id: row.get(0)?,
                    file_hash: row.get(1)?,
                    file_path: row.get(2)?,
                    verdict: row.get(3)?,
                    confidence: row.get(4)?,
                    threat_level: row.get(5)?,
                    threat_name: row.get(6)?,
                    scan_time_ms: row.get(7)?,
                    scanned_at: row.get(8)?,
                    source: row.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?;

        let verdicts = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;

        Ok(verdicts
            .iter()
            .map(verdict_to_threat_detail)
            .collect::<Vec<_>>())
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
    use tempfile::tempdir;

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
        if let Ok(mut s) = LAST_COMPLETED_SCAN_TYPE.write() {
            *s = None;
        }
    }

    // =========================================================================
    // Scan type helpers
    // =========================================================================

    #[test]
    fn test_normalize_scan_type_accepts_external() {
        assert_eq!(normalize_scan_type("EXTERNAL").unwrap(), "external");
    }

    #[test]
    fn test_resolve_external_scan_path_requires_directory() {
        let dir = tempdir().unwrap();
        let resolved =
            resolve_scan_paths("external", Some(dir.path().to_string_lossy().to_string())).unwrap();

        assert_eq!(resolved, vec![dir.path().to_path_buf()]);
    }

    #[test]
    fn test_sort_external_scan_files_prioritizes_root_and_risky_extensions() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let mut files = vec![
            root.join("docs")
                .join("note.txt")
                .to_string_lossy()
                .to_string(),
            root.join("archive.zip").to_string_lossy().to_string(),
            root.join("autorun.inf").to_string_lossy().to_string(),
            root.join("setup.msi").to_string_lossy().to_string(),
            root.join("docs")
                .join("script.ps1")
                .to_string_lossy()
                .to_string(),
        ];

        sort_external_scan_files(&mut files, root);

        let ordered_names: Vec<String> = files
            .iter()
            .map(|path| {
                std::path::Path::new(path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();

        assert_eq!(
            ordered_names,
            vec![
                "autorun.inf",
                "setup.msi",
                "archive.zip",
                "script.ps1",
                "note.txt"
            ]
        );
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

    #[test]
    fn test_collect_files_includes_standard_eicar_filename() {
        let dir = tempdir().unwrap();
        let eicar_path = dir.path().join("eicar.com.txt");
        std::fs::write(
            &eicar_path,
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        let collected = collect_files(&[dir.path().to_path_buf()], None, None);

        assert!(collected
            .iter()
            .any(|path| path == &eicar_path.to_string_lossy()));
    }

    #[test]
    fn test_collect_files_includes_single_custom_eicar_file_even_without_eicar_name() {
        let dir = tempdir().unwrap();
        let eicar_path = dir.path().join("sample.txt");
        std::fs::write(
            &eicar_path,
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        let collected = collect_files(&[eicar_path.clone()], None, None);

        assert_eq!(collected, vec![eicar_path.to_string_lossy().to_string()]);
    }
}
