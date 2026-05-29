use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use sysinfo::Disks;
use tauri::AppHandle;

use crate::commands::scan;
use crate::config::Settings;
use crate::core::{log_audit_event, AuditEventType};

const EXTERNAL_MEDIA_POLL_INTERVAL: Duration = Duration::from_secs(3);

static EXTERNAL_MEDIA_MONITOR_STARTED: AtomicBool = AtomicBool::new(false);
static EXTERNAL_MEDIA_STATE: OnceLock<Mutex<ExternalMediaState>> = OnceLock::new();

#[derive(Debug, Default)]
struct ExternalMediaState {
    known_mounts: BTreeMap<String, String>,
    pending_scan: Option<(String, String)>,
}

fn external_media_state() -> &'static Mutex<ExternalMediaState> {
    EXTERNAL_MEDIA_STATE.get_or_init(|| Mutex::new(ExternalMediaState::default()))
}

fn normalize_mount_identity(path: &Path) -> String {
    let mut normalized = path.to_string_lossy().replace('/', "\\");
    while normalized.len() > 3 && normalized.ends_with('\\') {
        normalized.pop();
    }
    normalized.to_lowercase()
}

fn collect_removable_mounts() -> BTreeMap<String, String> {
    Disks::new_with_refreshed_list()
        .list()
        .iter()
        .filter(|disk| disk.is_removable())
        .filter_map(|disk| {
            let mount_point = disk.mount_point();
            let path = mount_point.to_string_lossy().to_string();
            if path.trim().is_empty() {
                None
            } else {
                Some((normalize_mount_identity(mount_point), path))
            }
        })
        .collect()
}

fn log_external_media_detected(path: &str) {
    log_audit_event(
        AuditEventType::SettingsChanged,
        &format!("External media detected: {}", path),
        None,
        None,
    );
}

fn log_external_media_scan_started(path: &str) {
    log_audit_event(
        AuditEventType::ScanStarted,
        &format!("External media scan started: {}", path),
        None,
        None,
    );
}

fn try_start_external_scan(app: &AppHandle, path: &str) {
    match scan::start_scan_internal(app.clone(), "external".to_string(), Some(path.to_string())) {
        Ok(()) => log_external_media_scan_started(path),
        Err(err) if scan::is_scan_in_progress_error(&err) => {}
        Err(err) => log::warn!("Failed to start external media scan for {}: {}", path, err),
    }
}


fn update_state(
    current_mounts: &BTreeMap<String, String>,
    protection_enabled: bool,
) -> Vec<(String, String)> {
    match external_media_state().lock() {
        Ok(mut state) => {
            let mut attached = Vec::new();

            for (identity, path) in current_mounts {
                if !state.known_mounts.contains_key(identity) {
                    attached.push((identity.clone(), path.clone()));
                }
            }

            if !protection_enabled {
                state.pending_scan = None;
            } else if let Some((identity, _)) = state.pending_scan.as_ref() {
                if !current_mounts.contains_key(identity) {
                    state.pending_scan = None;
                }
            }

            state.known_mounts = current_mounts.clone();
            attached
        }
        Err(e) => {
            log::warn!("External media state lock poisoned: {}", e);
            Vec::new()
        }
    }
}

fn queue_pending_scan(identity: String, path: String) {
    match external_media_state().lock() {
        Ok(mut state) => {
            state.pending_scan = Some((identity, path));
        }
        Err(e) => {
            log::warn!("External media state lock poisoned: {}", e);
        }
    }
}

fn take_pending_scan(current_mounts: &BTreeMap<String, String>) -> Option<String> {
    match external_media_state().lock() {
        Ok(mut state) => match state.pending_scan.take() {
            Some((identity, path)) if current_mounts.contains_key(&identity) => Some(path),
            _ => None,
        },
        Err(e) => {
            log::warn!("External media state lock poisoned: {}", e);
            None
        }
    }
}

pub fn start_external_media_monitor(app: AppHandle) -> Result<(), String> {
    if EXTERNAL_MEDIA_MONITOR_STARTED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let initial_mounts = collect_removable_mounts();
    if let Ok(mut state) = external_media_state().lock() {
        state.known_mounts = initial_mounts;
        state.pending_scan = None;
    }

    std::thread::Builder::new()
        .name("external-media-monitor".to_string())
        .spawn(move || loop {
            let settings = Settings::load();
            let protection_enabled =
                settings.real_time_protection && settings.external_media_auto_scan;
            let current_mounts = collect_removable_mounts();
            let attached = update_state(&current_mounts, protection_enabled);

            if protection_enabled && !scan::is_scanning() {
                if let Some(path) = take_pending_scan(&current_mounts) {
                    try_start_external_scan(&app, &path);
                }
            }

            if protection_enabled {
                for (identity, path) in attached {
                    log_external_media_detected(&path);

                    if scan::is_scanning() {
                        queue_pending_scan(identity, path);
                    } else {
                        try_start_external_scan(&app, &path);
                    }
                }
            }

            std::thread::sleep(EXTERNAL_MEDIA_POLL_INTERVAL);
        })
        .map(|_| ())
        .map_err(|e| format!("Failed to start external media monitor: {}", e))
}
