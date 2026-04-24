pub mod cache;
pub mod commands;
pub mod config;
/// Malware Detection Pipeline - Rust Backend
pub mod core;
pub mod database;
pub mod errors;
pub mod ml;

use rusqlite::Connection;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
#[cfg_attr(mobile, tauri::mobile_entry_point)]
use tauri::Manager;

use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS},
    System::Threading::CreateMutexW,
    UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE},
};

/// Thread-safe storage for Tauri resource directory path
/// This replaces the unsafe std::env::set_var approach
static TAURI_RESOURCE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Global ONNX classifier (loaded once at startup, shared across spawn_blocking tasks).
/// `ort::Session` is Send + Sync; the Option is None when model.onnx is not found.
pub static ONNX_CLASSIFIER: OnceLock<Option<std::sync::Arc<ml::OnnxClassifier>>> = OnceLock::new();

/// Global ONNX novelty detector (IsolationForest).
/// None when model.onnx is not found or conversion script has not been run.
pub static NOVELTY_MODEL: OnceLock<Option<std::sync::Arc<ml::OnnxNoveltyDetector>>> =
    OnceLock::new();

/// When true, the app is allowed to fully exit (set by tray Quit action).
/// Default false - closing the window just hides to tray.
static ALLOW_EXIT: AtomicBool = AtomicBool::new(false);

/// Process-wide guard that keeps the named single-instance mutex alive.
#[cfg(target_os = "windows")]
static SINGLE_INSTANCE_MUTEX: OnceLock<isize> = OnceLock::new();

/// Get the Tauri resource directory path (thread-safe)
pub fn get_resource_dir() -> Option<&'static PathBuf> {
    TAURI_RESOURCE_DIR.get()
}

#[cfg(target_os = "windows")]
fn encode_wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(target_os = "windows")]
fn focus_existing_window() {
    let title = encode_wide("InSecurity");
    let hwnd = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
    if hwnd != 0 {
        unsafe {
            ShowWindow(hwnd, SW_RESTORE);
            let _ = SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(target_os = "windows")]
fn acquire_single_instance_guard() -> Result<bool, String> {
    let mutex_name = encode_wide("Local\\com.insecurity.antivirus.single_instance");
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr()) };

    if handle == 0 {
        return Err(format!("CreateMutexW failed with error {}", unsafe {
            GetLastError()
        }));
    }

    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe {
            CloseHandle(handle);
        }
        return Ok(false);
    }

    let _ = SINGLE_INSTANCE_MUTEX.set(handle);
    Ok(true)
}

// Global database connection
static DB: once_cell::sync::Lazy<Mutex<Option<Connection>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

/// Get a reference to the global database mutex for use by internal modules
/// Returns None if the database hasn't been initialized yet
pub fn get_database() -> Option<&'static Mutex<Option<Connection>>> {
    Some(&DB)
}

/// Execute a function with a database connection
/// This is a helper to reduce boilerplate for DB access patterns
/// Returns None if the database is not available or the closure returns None
pub fn with_db<T, F>(f: F) -> Option<T>
where
    F: FnOnce(&Connection) -> Option<T>,
{
    DB.lock().ok().and_then(|guard| guard.as_ref().and_then(f))
}

/// Execute a function with a database connection, returning a Result
/// This is a helper for operations that can fail
pub fn with_db_result<T, E, F>(f: F) -> Result<T, E>
where
    E: From<String>,
    F: FnOnce(&Connection) -> Result<T, E>,
{
    match DB.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(conn) => f(conn),
            None => Err(E::from("Database not initialized".to_string())),
        },
        Err(e) => Err(E::from(format!("Database lock error: {}", e))),
    }
}

/// Execute a blocking DB operation on a separate thread pool to avoid blocking the UI.
/// Use this for commands that involve DB or file I/O operations.
pub async fn with_db_async<T, F>(f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || match DB.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(conn) => f(conn),
            None => Err("Database not initialized".to_string()),
        },
        Err(e) => Err(format!("Database lock error: {}", e)),
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

/// Execute a read-only DB operation with a **separate** connection.
/// This opens a fresh read-only connection to the same database,
/// completely bypassing the global DB Mutex. Use this for read-only
/// queries (e.g. list_quarantined, get_dashboard_stats) that should
/// never block behind long-running write operations or heavy tasks
/// that also use spawn_blocking (like insight signature verification).
///
/// SQLite in WAL mode supports concurrent readers, so this is safe.
/// Uses a persistent pooled connection to avoid reopening + PRAGMA overhead.
static READ_DB: once_cell::sync::Lazy<Mutex<Option<Connection>>> =
    once_cell::sync::Lazy::new(|| {
        let db_path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("insecurity")
            .join("database.db");

        let conn = Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        );

        match conn {
            Ok(c) => {
                let _ = c.execute_batch(
                    "PRAGMA busy_timeout=5000;
                     PRAGMA journal_mode=WAL;",
                );
                Mutex::new(Some(c))
            }
            Err(e) => {
                log::error!("Failed to open read-only DB pool connection: {}", e);
                Mutex::new(None)
            }
        }
    });

pub async fn with_db_async_readonly<T, F>(f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || match READ_DB.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(conn) => f(conn),
            None => Err("Read-only DB not initialized".to_string()),
        },
        Err(e) => Err(format!("Read DB lock error: {}", e)),
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

pub fn run() {
    #[cfg(target_os = "windows")]
    match acquire_single_instance_guard() {
        Ok(true) => {}
        Ok(false) => {
            log::info!("Another InSecurity instance is already running; focusing existing window");
            focus_existing_window();
            return;
        }
        Err(e) => {
            log::warn!(
                "Failed to initialize single-instance guard (continuing without it): {}",
                e
            );
        }
    }

    let db_path = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("insecurity")
        .join("database.db");

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            log::warn!("Failed to create DB dir: {}", e);
        });
    }

    match Connection::open(&db_path) {
        Ok(conn) => {
            // CRITICAL: Configure SQLite for concurrent access
            // WAL mode allows readers and writers to operate simultaneously
            // busy_timeout prevents immediate SQLITE_BUSY errors when the DB is locked
            if let Err(e) = conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA busy_timeout=5000;
                 PRAGMA synchronous=NORMAL;",
            ) {
                log::warn!("Failed to set SQLite pragmas: {}", e);
            } else {
                log::info!("SQLite configured: WAL mode, 5s busy timeout, NORMAL sync");
            }

            let migrator = database::Migrator::new(&conn);
            match migrator.migrate_to_latest() {
                Ok(applied) => {
                    if applied > 0 {
                        log::info!("Applied {} database migration(s)", applied);
                    }
                    log::info!(
                        "Database schema at version {}",
                        migrator.current_version().unwrap_or(0)
                    );
                }
                Err(e) => {
                    log::error!(
                        "Database migration failed: {}. Falling back to legacy init.",
                        e
                    );

                    if let Err(e) = database::schema::DatabaseSchema::init(&conn) {
                        log::error!("Failed to init DB schema: {}", e);
                    }
                }
            }

            match DB.lock() {
                Ok(mut g) => {
                    *g = Some(conn);
                    log::info!("Database initialized at {:?}", db_path);

                    crate::database::batcher::init();
                }
                Err(e) => {
                    log::error!("DB mutex poisoned, could not set connection: {}", e);
                }
            }

            // Defer backfill to background - it's a migration that doesn't affect reads
            std::thread::spawn(|| {
                if let Ok(guard) = DB.lock() {
                    if let Some(ref conn) = *guard {
                        if let Err(e) = crate::database::schema::backfill_files_from_existing(conn)
                        {
                            log::warn!("Backfill files migration failed: {}", e);
                        } else {
                            log::info!("Backfill files migration completed (best-effort)");
                        }
                    }
                }
            });

            // Defer blacklist + whitelist loading to a background thread.
            // Real-time protection starts after setup() returns, so these will
            // typically finish before the first FS event arrives (< 200ms).
            std::thread::spawn(|| {
                if let Err(e) = crate::core::static_scanner::refresh_blacklist() {
                    log::error!("Failed to load blacklist from DB at startup: {}", e);
                } else {
                    log::info!("In-memory blacklist loaded from database");
                }

                crate::core::static_scanner::initialize_whitelist();
                log::info!("In-memory whitelist initialized");

                // Sync user whitelist file with DB (reconcile orphans from old versions)
                if let Ok(guard) = crate::DB.lock() {
                    if let Some(ref conn) = *guard {
                        match conn.prepare("SELECT file_hash FROM user_whitelist") {
                            Ok(mut stmt) => {
                                let hashes: Vec<String> =
                                    match stmt.query_map([], |row| row.get::<_, String>(0)) {
                                        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
                                        Err(e) => {
                                            log::warn!(
                                                "Failed to query user_whitelist for sync: {}",
                                                e
                                            );
                                            Vec::new()
                                        }
                                    };
                                crate::core::static_scanner::sync_user_whitelist(&hashes);
                            }
                            Err(e) => log::warn!("Could not sync user whitelist: {}", e),
                        }
                    }
                }
            });

            // Pre-warm quarantine encryption key in background.
            // Argon2 KDF costs ~500ms; doing this now avoids a cold-start
            // penalty the first time the user opens the Quarantine page.
            std::thread::spawn(|| {
                use crate::core::quarantine_manager::QuarantineManager;
                let qpath = dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("insecurity")
                    .join("quarantine");
                let qm = QuarantineManager::new(&qpath.to_string_lossy());
                match qm.warm_encryption_key() {
                    Ok(_) => log::info!("Quarantine encryption key pre-warmed"),
                    Err(e) => log::warn!("Failed to pre-warm quarantine key: {}", e),
                }
            });

            // Pre-warm insight signature cache in background.
            // This runs the batch PowerShell verification (~2-5s) at startup
            // so the Insights page loads near-instantly when the user opens it.
            std::thread::spawn(|| {
                crate::commands::insights::prefetch_insight_signatures();
                log::info!("Insight signature cache pre-warmed");
            });
        }
        Err(e) => {
            log::error!("Failed to open database {}: {}", db_path.display(), e);
        }
    }

    // =========================================================================
    // TAMPER PROTECTION: Startup checks
    // =========================================================================

    // Log app start for audit trail
    crate::core::log_audit_event(
        crate::core::AuditEventType::AppStarted,
        "Application started",
        None,
        None,
    );

    // Check if protection was unexpectedly down (crash/kill detection)
    let needs_missed_scan = {
        let status_guard = crate::core::tamper_protection::PROTECTION_STATUS.lock();
        if let Ok(status) = status_guard {
            let needs_scan = status.needs_missed_events_scan(300); // 5 min threshold
            if status.was_unexpectedly_down() {
                log::warn!(
                    "Protection was unexpectedly terminated! Gap: {}s",
                    status.get_gap_seconds()
                );
                crate::core::log_audit_event(
                    crate::core::AuditEventType::IntegrityCheckFailed,
                    &format!(
                        "Unexpected shutdown detected. Gap: {}s",
                        status.get_gap_seconds()
                    ),
                    None,
                    None,
                );
            }
            needs_scan
        } else {
            false
        }
    };

    // Defer integrity check to a background thread - doesn't need to block startup
    if let Some(res_dir) = TAURI_RESOURCE_DIR.get() {
        let res_dir = res_dir.clone();
        std::thread::spawn(move || {
            let checker = crate::core::IntegrityChecker::new(res_dir);
            let result = checker.verify_integrity();
            if !result.passed {
                log::error!(
                    "INTEGRITY CHECK FAILED! Failed: {:?}, Missing: {:?}",
                    result.failed_resources,
                    result.missing_resources
                );
                crate::core::log_audit_event(
                    crate::core::AuditEventType::IntegrityCheckFailed,
                    &format!("Resource tampering detected: {:?}", result.failed_resources),
                    None,
                    None,
                );
            } else if result.checked_resources > 0 {
                log::info!(
                    "Integrity check passed ({} resources verified in {}ms)",
                    result.checked_resources,
                    result.check_time_ms
                );
                crate::core::log_audit_event(
                    crate::core::AuditEventType::IntegrityCheckPassed,
                    &format!(
                        "{} resources verified in {}ms",
                        result.checked_resources, result.check_time_ms
                    ),
                    None,
                    None,
                );
            }
        });
    }

    // Initialize the ONNX classifier (Rust-native, no Python/OpenMP dependency).
    // Must happen before the Tauri file watcher starts so that the first
    // spawn_blocking ML task finds the classifier ready.
    {
        let candidates = [
            "resources/models/classifier/model.onnx",
            "../resources/models/classifier/model.onnx",
        ];
        let clf = match crate::core::utils::find_resource_path(&candidates) {
            Some(p) => {
                let path_str = p.to_string_lossy().to_string();
                match ml::OnnxClassifier::load(&path_str) {
                    Ok(clf) => {
                        log::info!("ONNX classifier loaded from {}", path_str);
                        Some(std::sync::Arc::new(clf))
                    }
                    Err(e) => {
                        log::warn!("ONNX classifier load failed: {}", e);
                        None
                    }
                }
            }
            None => {
                log::warn!("model.onnx not found — run scripts/convert_to_onnx.py to generate it");
                None
            }
        };
        if ONNX_CLASSIFIER.set(clf).is_err() {
            log::warn!("ONNX_CLASSIFIER was already set");
        }
    }

    // Initialize ONNX novelty detector (IsolationForest).
    // Requires running `python scripts/convert_novelty_to_onnx.py` once.
    {
        let candidates = [
            "resources/models/novelty/model.onnx",
            "../resources/models/novelty/model.onnx",
        ];
        let novelty_clf = match crate::core::utils::find_resource_path(&candidates) {
            Some(p) => {
                let path_str = p.to_string_lossy().to_string();
                match ml::OnnxNoveltyDetector::load(&path_str) {
                    Ok(det) => {
                        log::info!("ONNX novelty detector loaded from {}", path_str);
                        Some(std::sync::Arc::new(det))
                    }
                    Err(e) => {
                        log::warn!("ONNX novelty detector load failed: {}", e);
                        None
                    }
                }
            }
            None => {
                log::warn!(
                    "novelty model.onnx not found — run scripts/convert_novelty_to_onnx.py to generate it"
                );
                None
            }
        };
        if NOVELTY_MODEL.set(novelty_clf).is_err() {
            log::warn!("NOVELTY_MODEL was already set");
        }
    }

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ));

    let app_builder = builder
        .setup(move |app| {
            if let Ok(res) = app.path().resource_dir() {
                // Store in thread-safe OnceLock instead of unsafe env var
                if TAURI_RESOURCE_DIR.set(res.clone()).is_err() {
                    log::warn!("TAURI_RESOURCE_DIR was already set");
                }
                log::info!("TAURI_RESOURCE_DIR set to {:?}", res);
            } else if let Err(e) = app.path().resource_dir() {
                log::warn!("Failed to resolve resource_dir from Tauri path API: {}", e);
            }

            let cfg = crate::config::settings::Settings::load();

            // Always start the file watcher and process monitor threads.
            // If real-time protection is disabled in settings, the threads
            // will idle (checking PROTECTION_DISABLED flag) until re-enabled,
            // so the user can toggle protection at runtime without restarting.
            if !cfg.real_time_protection {
                crate::core::real_time::set_protection_disabled(true);
            }

            {
                let mut watch_paths = Vec::new();
                if let Some(d) = dirs::download_dir() {
                    watch_paths.push(d);
                }
                if let Some(d) = dirs::desktop_dir() {
                    watch_paths.push(d);
                }
                if let Some(d) = dirs::home_dir() {
                    watch_paths.push(d);
                }

                // Include user-configured protected folders that aren't already
                // covered by an existing watch path (e.g. folders on other drives)
                for folder in &cfg.protected_folders {
                    let folder_path = PathBuf::from(folder);
                    let already_covered = watch_paths.iter().any(|wp| folder_path.starts_with(wp));
                    if !already_covered && folder_path.exists() {
                        log::info!("Adding protected folder to watch paths: {:?}", folder_path);
                        watch_paths.push(folder_path);
                    }
                }

                // Load configurable ransomware thresholds from settings
                crate::core::real_time::reload_ransomware_thresholds(
                    cfg.ransomware_threshold,
                    cfg.ransomware_window_seconds,
                );

                // Deploy canary/honeypot files in protected folders
                for folder in &cfg.protected_folders {
                    match crate::core::real_time::deploy_canary_files_for_folder(folder) {
                        Ok(paths) => {
                            if !paths.is_empty() {
                                log::info!("Deployed {} canary files in {}", paths.len(), folder);
                            }
                        }
                        Err(e) => log::warn!("Failed to deploy canary files in {}: {}", folder, e),
                    }
                }

                if !watch_paths.is_empty() {
                    match crate::core::start_realtime_watcher(app.handle().clone(), watch_paths) {
                        Ok(_) => log::info!("Real-time file watcher started"),
                        Err(e) => log::warn!("Failed to start real-time file watcher: {}", e),
                    }
                }

                match crate::core::start_process_monitor(app.handle().clone()) {
                    Ok(_) => log::info!("Process monitor started"),
                    Err(e) => log::warn!("Failed to start process monitor: {}", e),
                }
            }

            if cfg.real_time_protection {
                log::info!("Real-time protection started successfully");

                // Log protection enabled in audit
                crate::core::log_audit_event(
                    crate::core::AuditEventType::ProtectionEnabled,
                    "Real-time protection enabled",
                    None,
                    None,
                );
            } else {
                log::info!("Real-time protection is disabled in settings (watchers idle)");
            }

            // Start protection heartbeat (updates every 60s to track uptime)
            spawn_protection_heartbeat();

            // If protection was unexpectedly down, scan high-risk directories
            if needs_missed_scan {
                log::warn!("Protection was down - starting missed-events scan");
                spawn_missed_events_scan(app.handle().clone());
            }

            spawn_initial_threat_seed();
            spawn_whitelist_generator();

            // Pre-warm the YARA-X compiler in background so the first scan
            // doesn't pay the rule compilation cost.
            std::thread::spawn(|| {
                let _ = crate::core::yara_scanner::get_rule_count(); // Forces Lazy init of YARA_SCANNER
                log::info!("YARA-X rules compiled in background");
            });

            spawn_automatic_threat_updates();

            // Start the scheduled scan checker
            spawn_scheduled_scan_checker(app.handle().clone());

            // --- Network security startup ---
            {
                let settings = crate::config::Settings::load();

                // Seed network monitor defaults in background
                std::thread::spawn(|| {
                    crate::core::network_monitor::seed_default_malicious_ips();
                });

                // If network monitoring was enabled, start the monitor thread
                if settings.network_monitoring_enabled {
                    crate::core::network_monitor::set_monitor_enabled(true);
                    crate::core::network_monitor::start_network_monitor(app.handle().clone());
                    log::info!("Network monitor started (enabled in settings)");
                }
            }

            // --- System tray icon + menu ---
            {
                use tauri::menu::{MenuBuilder, MenuItemBuilder};
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

                let current_settings = crate::config::Settings::load();
                let ui_in_bg = current_settings.language.to_lowercase().starts_with("bg");
                let show_item = MenuItemBuilder::with_id(
                    "show",
                    if ui_in_bg {
                        "Отвори InSecurity"
                    } else {
                        "Open InSecurity"
                    },
                )
                .build(app)?;
                let quit_item =
                    MenuItemBuilder::with_id("quit", if ui_in_bg { "Изход" } else { "Quit" })
                        .build(app)?;
                let tray_menu = MenuBuilder::new(app)
                    .item(&show_item)
                    .separator()
                    .item(&quit_item)
                    .build()?;

                let icon = app
                    .default_window_icon()
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing default window icon"))?;

                TrayIconBuilder::with_id("main-tray")
                    .icon(icon)
                    .tooltip(crate::commands::settings::protection_tray_tooltip(
                        current_settings.real_time_protection,
                    ))
                    .menu(&tray_menu)
                    .on_menu_event(|app, event| match event.id().as_ref() {
                        "show" => {
                            if let Some(win) = app.get_webview_window("main") {
                                let _ = win.show();
                                let _ = win.unminimize();
                                let _ = win.set_focus();
                            }
                        }
                        "quit" => {
                            ALLOW_EXIT.store(true, Ordering::SeqCst);
                            app.exit(0);
                        }
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            let app = tray.app_handle();
                            if let Some(win) = app.get_webview_window("main") {
                                let _ = win.show();
                                let _ = win.unminimize();
                                let _ = win.set_focus();
                            }
                        }
                    })
                    .build(app)?;
            }

            // --- Autostart: sync registry with settings ---
            {
                use tauri_plugin_autostart::ManagerExt;
                let autostart_mgr = app.autolaunch();
                let cfg = crate::config::settings::Settings::load();
                if cfg.autostart {
                    if !autostart_mgr.is_enabled().unwrap_or(false) {
                        if let Err(e) = autostart_mgr.enable() {
                            log::warn!("Failed to enable autostart: {}", e);
                        }
                    }
                } else {
                    let _ = autostart_mgr.disable();
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan::get_scan_status,
            commands::scan::start_scan,
            commands::scan::cancel_scan,
            commands::scan::force_reset_scan,
            commands::scan::pick_scan_folder,
            commands::scan::pick_scan_file,
            commands::scan::export_scan_report,
            commands::database::get_verdicts,
            commands::database::get_active_threats,
            commands::database::search_hash,
            commands::database::export_verdicts,
            commands::database::export_verdicts_json,
            commands::database::get_downloads_path,
            commands::database::clear_database,
            commands::database::get_dashboard_stats,
            commands::database::get_full_threat_info,
            commands::reputation::update_reputation,
            commands::reputation::get_file_reputation,
            commands::quarantine::list_quarantined,
            commands::quarantine::restore_file,
            commands::quarantine::delete_quarantined_file,
            commands::quarantine::get_quarantine_details,
            commands::quarantine::quarantine_file_by_path,
            commands::quarantine::ignore_threat,
            commands::quarantine::delete_threat_file,
            commands::quarantine::get_user_whitelist,
            commands::quarantine::remove_from_user_whitelist,
            commands::quarantine::clear_user_whitelist,
            commands::settings::get_settings,
            commands::settings::update_settings,
            commands::settings::set_auto_quarantine,
            commands::settings::set_real_time_protection,
            commands::settings::reconfigure_cache,
            commands::settings::get_cache_stats,
            commands::settings::clear_cache,
            commands::settings::set_scan_worker_count,
            commands::settings::set_ransomware_protection,
            commands::settings::get_protected_folders,
            commands::settings::set_protected_folders,
            commands::settings::add_protected_folder,
            commands::settings::remove_protected_folder,
            commands::settings::set_ransomware_auto_block,
            commands::settings::set_ransomware_thresholds,
            commands::settings::dismiss_ransomware_alert,
            commands::settings::kill_ransomware_process,
            commands::settings::deploy_canary_files,
            commands::settings::redeploy_canary_files,
            commands::settings::get_canary_status,
            commands::database::clear_scan_history,
            commands::updates::get_update_stats,
            commands::updates::run_threat_update,
            commands::updates::preview_malwarebazaar_recent,
            commands::updates::preview_threat_feed_json,
            commands::updates::fetch_malware_by_signature,
            commands::updates::fetch_malware_by_tag,
            commands::updates::import_threat_feed_json,
            commands::updates::add_to_blacklist,
            commands::updates::check_hash_malwarebazaar,
            commands::exclusions::get_exclusions,
            commands::exclusions::add_exclusion,
            commands::exclusions::update_exclusion,
            commands::exclusions::toggle_exclusion,
            commands::exclusions::delete_exclusion,
            commands::exclusions::is_path_excluded,
            commands::reputation_checker::check_file_reputation,
            commands::reputation_checker::check_hash_reputation,
            commands::reputation_checker::batch_check_reputation,
            commands::reputation_checker::refresh_reputation,
            commands::reputation_checker::get_reputation_stats,
            commands::feedback::report_false_positive,
            commands::feedback::report_false_negative,
            commands::feedback::get_ml_feedback_stats,
            commands::feedback::check_ml_retrain_status,
            commands::feedback::get_threshold_adjustment,
            commands::scheduled_scans::get_scheduled_scans,
            commands::scheduled_scans::create_scheduled_scan,
            commands::scheduled_scans::update_scheduled_scan,
            commands::scheduled_scans::toggle_scheduled_scan,
            commands::scheduled_scans::delete_scheduled_scan,
            commands::scheduled_scans::get_next_due_scan,
            commands::scheduled_scans::run_scheduled_scan_now,
            commands::audit::get_audit_entries,
            commands::audit::verify_audit_log,
            commands::audit::repair_audit_log,
            commands::insights::get_persistence_for_file,
            commands::scan::scan_single_file,
            commands::settings::set_autostart,
            commands::settings::set_language,
            commands::settings::set_virustotal_api_key,
            commands::settings::set_malwarebazaar_api_key,
            // Network security commands
            commands::network::get_active_connections,
            commands::network::get_network_events,
            commands::network::get_network_threats,
            commands::network::set_network_monitoring,
            commands::network::get_firewall_rules,
            commands::network::add_firewall_rule,
            commands::network::remove_firewall_rule,
            commands::network::toggle_firewall_rule,
            commands::network::set_auto_block_malware,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // If Quit was clicked, allow the close to proceed naturally
                if !ALLOW_EXIT.load(Ordering::SeqCst) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        });

    app_builder
        .build(tauri::generate_context!())
        .expect("error building tauri app")
        .run(|_app, event| {
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                // Only prevent exit if Quit wasn't explicitly clicked
                if !ALLOW_EXIT.load(Ordering::SeqCst) {
                    api.prevent_exit();
                }
            }
        });
}

/// Seed initial threat data from MalwareBazaar on first launch
fn spawn_initial_threat_seed() {
    tauri::async_runtime::spawn(async move {
        let needs_seed = {
            let manager = crate::core::update_manager::UpdateManager::new();
            let stats = manager.get_stats();

            stats.blacklist_hash_count < 100
        };

        if !needs_seed {
            log::info!(
                "Threat database already populated ({} hashes), skipping initial seed",
                {
                    let m = crate::core::update_manager::UpdateManager::new();
                    m.get_stats().blacklist_hash_count
                }
            );
            return;
        }

        log::info!("First launch detected - running comprehensive threat database seed...");
        log::info!(
            "This will download ~3000+ malware hashes from MalwareBazaar (may take 1-2 minutes)"
        );

        let manager = crate::core::update_manager::UpdateManager::new();
        let results = manager.run_initial_seed().await;

        let total_added: usize = results.iter().map(|r| r.entries_added).sum();
        let success_count = results.iter().filter(|r| r.success).count();

        if success_count > 0 {
            log::info!(
                "Initial threat seed completed successfully: {} total hashes added",
                total_added
            );
        } else {
            log::warn!("Initial threat seed failed - you can manually update from the Updates tab");
        }
    });
}

/// Spawn automatic periodic threat database updates (every 6 hours)
fn spawn_automatic_threat_updates() {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(300)).await;

        let mut interval = tokio::time::interval(Duration::from_secs(6 * 3600));

        loop {
            interval.tick().await;

            log::info!("Running automatic threat database update...");

            let manager = crate::core::update_manager::UpdateManager::new();
            let results = manager.run_automatic_update().await;

            let total_added: usize = results.iter().map(|r| r.entries_added).sum();

            if total_added > 0 {
                log::info!(
                    "Automatic update completed: {} new hashes added",
                    total_added
                );
            } else {
                log::info!("Automatic update completed: no new hashes (database is up to date)");
            }
        }
    });
}

/// Spawn scheduled scan checker that runs periodically
fn spawn_scheduled_scan_checker(app_handle: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        // Wait 60 seconds after startup before checking
        tokio::time::sleep(Duration::from_secs(60)).await;

        // Check every minute for due scans
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            // Skip if a manual scan is in progress
            if crate::commands::scan::is_scanning() {
                continue;
            }

            // Check for due scans - run the sync DB.lock() call on the blocking pool
            // to avoid blocking a tokio worker thread
            let due_scan = tauri::async_runtime::spawn_blocking(|| {
                crate::commands::scheduled_scans::get_next_due_scan()
            })
            .await;

            let due_scan = match due_scan {
                Ok(result) => result,
                Err(e) => {
                    log::debug!("Scheduled scan check task error: {}", e);
                    continue;
                }
            };

            match due_scan {
                Ok(Some(scan)) => {
                    log::info!("Running scheduled scan '{}' (ID: {})", scan.name, scan.id);

                    // Start the scan
                    let scan_result = crate::commands::scan::start_scan(
                        app_handle.clone(),
                        scan.scan_type.clone(),
                        scan.custom_path.clone(),
                    )
                    .await;

                    let scan_id = scan.id;
                    let scan_name = scan.name.clone();
                    match scan_result {
                        Ok(_) => {
                            log::info!("Scheduled scan '{}' started successfully", scan_name);
                            let _ = tauri::async_runtime::spawn_blocking(move || {
                                if let Err(e) =
                                    crate::commands::scheduled_scans::mark_scan_completed(scan_id)
                                {
                                    log::warn!("Failed to mark scheduled scan as completed: {}", e);
                                }
                            })
                            .await;
                        }
                        Err(e) => {
                            log::error!("Failed to start scheduled scan '{}': {}", scan_name, e);
                            let _ = tauri::async_runtime::spawn_blocking(move || {
                                let _ =
                                    crate::commands::scheduled_scans::mark_scan_completed(scan_id);
                            })
                            .await;
                        }
                    }
                }
                Ok(None) => {
                    // No due scans
                }
                Err(e) => {
                    log::debug!("Error checking for scheduled scans: {}", e);
                }
            }
        }
    });
}

/// Generate system file whitelist on first launch
fn spawn_whitelist_generator() {
    std::thread::spawn(|| {
        // Wait 30s before starting to let the app settle -
        // whitelist generation hashes hundreds of system files and
        // competes for disk I/O with early user interactions.
        std::thread::sleep(Duration::from_secs(30));

        let whitelist_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("insecurity")
            .join("whitelists")
            .join("system_files.txt");

        let needs_generation = if whitelist_path.exists() {
            match std::fs::read_to_string(&whitelist_path) {
                Ok(content) => {
                    let count = content
                        .lines()
                        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                        .count();
                    count < 10
                }
                Err(_) => true,
            }
        } else {
            true
        };

        if !needs_generation {
            log::info!("System whitelist already populated, skipping generation");
            return;
        }

        log::info!("Generating system file whitelist from local Windows installation...");

        match crate::core::utils::generate_system_whitelist() {
            Ok(hashes) => {
                if hashes.is_empty() {
                    log::warn!("No system files could be hashed for whitelist");
                    return;
                }

                match crate::core::utils::save_whitelist(&hashes, whitelist_path.to_str().unwrap())
                {
                    Ok(_) => {
                        log::info!(
                            "System whitelist saved: {} hashes at {:?}",
                            hashes.len(),
                            whitelist_path
                        );
                        // Reload into memory so the whitelist takes effect immediately
                        // without requiring an app restart.
                        crate::core::static_scanner::initialize_whitelist();
                        log::info!(
                            "In-memory whitelist refreshed with {} new system hashes",
                            hashes.len()
                        );
                    }
                    Err(e) => {
                        log::error!("Failed to save whitelist: {}", e);
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to generate system whitelist: {}", e);
            }
        }
    });
}

/// Spawn protection heartbeat - updates status every 60 seconds
/// This allows detection of unexpected termination on next startup
fn spawn_protection_heartbeat() {
    // Use tokio timer instead of wasting an OS thread on sleep loops
    tauri::async_runtime::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            crate::core::update_heartbeat();
        }
    });
}

/// Spawn missed-events scan if protection was down
/// Scans high-risk directories (Downloads, Desktop, Temp) for threats
fn spawn_missed_events_scan(_app_handle: tauri::AppHandle) {
    use crate::core::get_missed_events_scan_paths;

    tauri::async_runtime::spawn(async move {
        // Small delay to let the app fully initialize
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let paths = get_missed_events_scan_paths();
        if paths.is_empty() {
            log::info!("No paths to scan for missed events");
            return;
        }

        log::info!(
            "Running missed-events scan on {} high-risk directories",
            paths.len()
        );
        crate::core::log_audit_event(
            crate::core::AuditEventType::ScanStarted,
            "Missed-events scan started (protection was down)",
            None,
            None,
        );

        let mut threats_found = 0;

        for path in paths {
            if !path.exists() {
                continue;
            }

            // Only scan recent files (modified in last 24 hours)
            let cutoff = chrono::Utc::now().timestamp() - (24 * 3600);

            let walker = walkdir::WalkDir::new(&path)
                .max_depth(2) // Don't go too deep
                .follow_links(false);

            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }

                // Check modification time
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                            if (duration.as_secs() as i64) < cutoff {
                                continue; // Skip old files
                            }
                        }
                    }
                }

                let file_path = entry.path().to_string_lossy().to_string();

                // Quick scan only (hash lookups, no deep analysis)
                match crate::core::DetectionPipeline::scan_file_quick(&file_path).await {
                    Ok(result) => {
                        if result.verdict != crate::core::pipeline::Verdict::Clean {
                            threats_found += 1;
                            log::warn!(
                                "Missed-events scan found threat: {} ({:?})",
                                file_path,
                                result.verdict
                            );
                        }
                    }
                    Err(e) => {
                        log::debug!("Missed-events scan error for {}: {}", file_path, e);
                    }
                }
            }
        }

        crate::core::log_audit_event(
            crate::core::AuditEventType::ScanCompleted,
            &format!(
                "Missed-events scan completed. Threats found: {}",
                threats_found
            ),
            None,
            None,
        );

        log::info!(
            "Missed-events scan completed. Threats found: {}",
            threats_found
        );
    });
}

// Global cache manager used across runtime threads - accessible via crate::CACHE_MANAGER
pub static CACHE_MANAGER: once_cell::sync::Lazy<
    std::sync::Arc<std::sync::Mutex<crate::cache::cache_manager::CacheManager>>,
> = once_cell::sync::Lazy::new(|| {
    std::sync::Arc::new(std::sync::Mutex::new(
        crate::cache::cache_manager::CacheManager::new(
            crate::cache::cache_manager::CacheConfig::default(),
        ),
    ))
});
