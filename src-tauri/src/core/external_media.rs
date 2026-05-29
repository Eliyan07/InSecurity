use std::collections::{BTreeMap, HashSet, VecDeque};
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedExternalScan {
    identity: String,
    path: String,
}

#[derive(Debug, Default)]
struct ExternalMediaState {
    known_mounts: BTreeMap<String, String>,
    queued_scans: VecDeque<QueuedExternalScan>,
    queued_identities: HashSet<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MountDelta {
    attached: Vec<(String, String)>,
    removed: Vec<String>,
}

fn external_media_state() -> &'static Mutex<ExternalMediaState> {
    EXTERNAL_MEDIA_STATE.get_or_init(|| Mutex::new(ExternalMediaState::default()))
}

fn ui_language_is_bulgarian() -> bool {
    Settings::load().language.to_lowercase().starts_with("bg")
}

fn resolve_notification_icon() -> Option<String> {
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;

    let dev_icon = exe_dir.join("../../icons/icon.png");
    if dev_icon.exists() {
        return Some(dev_icon.canonicalize().ok()?.to_string_lossy().to_string());
    }

    let candidates = [
        exe_dir.join("icons/icon.png"),
        exe_dir.join("icon.png"),
        exe_dir.join("../resources/icons/icon.png"),
    ];

    candidates
        .into_iter()
        .find(|path| path.exists())
        .and_then(|path| path.canonicalize().ok())
        .map(|path| path.to_string_lossy().to_string())
}

fn send_external_media_notification(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;

    let mut builder = app.notification().builder().title(title).body(body);
    if let Some(icon_path) = resolve_notification_icon() {
        builder = builder.icon(icon_path);
    }

    if let Err(e) = builder.show() {
        log::warn!("Failed to send external media notification: {}", e);
    }
}

fn localized_detection_notification(path: &str) -> (String, String) {
    if ui_language_is_bulgarian() {
        (
            "InSecurity - Открит е външен носител".to_string(),
            format!(
                "Свързан е сменяем носител на {}.\nЩе бъдат проверени изпълними файлове, скриптове, инсталатори и архиви.",
                path
            ),
        )
    } else {
        (
            "InSecurity - External Media Detected".to_string(),
            format!(
                "Removable media connected at {}.\nInSecurity will scan executables, scripts, installers, and archives.",
                path
            ),
        )
    }
}

fn localized_queued_notification(path: &str) -> (String, String) {
    if ui_language_is_bulgarian() {
        (
            "InSecurity - Сканирането е поставено на опашка".to_string(),
            format!(
                "Сканирането на външния носител {} е изчакано, защото в момента има друго активно сканиране.",
                path
            ),
        )
    } else {
        (
            "InSecurity - External Media Scan Queued".to_string(),
            format!(
                "The removable-media scan for {} was queued because another scan is already running.",
                path
            ),
        )
    }
}

fn localized_started_notification(path: &str) -> (String, String) {
    if ui_language_is_bulgarian() {
        (
            "InSecurity - Стартира сканиране на външен носител".to_string(),
            format!(
                "Започва проверка на {} за изпълними файлове, скриптове, инсталатори и архиви.",
                path
            ),
        )
    } else {
        (
            "InSecurity - External Media Scan Started".to_string(),
            format!(
                "Scanning {} for executables, scripts, installers, and archives.",
                path
            ),
        )
    }
}

fn normalize_mount_identity(path: &Path) -> String {
    let mut normalized = path.to_string_lossy().replace('/', "\\");
    while normalized.len() > 3 && normalized.ends_with('\\') {
        normalized.pop();
    }
    normalized.to_lowercase()
}

fn collect_removable_mounts(disks: &Disks) -> BTreeMap<String, String> {
    disks
        .list()
        .iter()
        .filter(|disk| disk.is_removable())
        .filter_map(|disk| {
            let mount_point = disk.mount_point();
            let display_path = mount_point.to_string_lossy().to_string();
            if display_path.trim().is_empty() {
                None
            } else {
                Some((normalize_mount_identity(mount_point), display_path))
            }
        })
        .collect()
}

fn diff_mounts(
    previous: &HashSet<String>,
    current: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    let mut attached: Vec<String> = current.difference(previous).cloned().collect();
    let mut removed: Vec<String> = previous.difference(current).cloned().collect();
    attached.sort();
    removed.sort();
    (attached, removed)
}

fn update_known_mounts(
    state: &mut ExternalMediaState,
    current_mounts: BTreeMap<String, String>,
) -> MountDelta {
    let previous_keys: HashSet<String> = state.known_mounts.keys().cloned().collect();
    let current_keys: HashSet<String> = current_mounts.keys().cloned().collect();
    let (attached_ids, removed_ids) = diff_mounts(&previous_keys, &current_keys);

    for removed_id in &removed_ids {
        state.remove_queued_scan(removed_id);
    }

    let attached = attached_ids
        .iter()
        .filter_map(|identity| {
            current_mounts
                .get(identity)
                .map(|path| (identity.clone(), path.clone()))
        })
        .collect();

    state.known_mounts = current_mounts;

    MountDelta {
        attached,
        removed: removed_ids,
    }
}

impl ExternalMediaState {
    fn enqueue_scan(&mut self, identity: String, path: String) -> bool {
        if self.queued_identities.contains(&identity) {
            if let Some(existing) = self
                .queued_scans
                .iter_mut()
                .find(|queued| queued.identity == identity)
            {
                existing.path = path;
            }
            return false;
        }

        self.queued_identities.insert(identity.clone());
        self.queued_scans
            .push_back(QueuedExternalScan { identity, path });
        true
    }

    fn remove_queued_scan(&mut self, identity: &str) -> bool {
        if !self.queued_identities.remove(identity) {
            return false;
        }

        self.queued_scans
            .retain(|queued| queued.identity != identity);
        true
    }

    fn clear_queue(&mut self) {
        self.queued_scans.clear();
        self.queued_identities.clear();
    }

    fn dequeue_next_scan(&mut self) -> Option<QueuedExternalScan> {
        while let Some(next) = self.queued_scans.pop_front() {
            self.queued_identities.remove(&next.identity);
            if Path::new(&next.path).exists() {
                return Some(next);
            }
        }
        None
    }
}

fn queue_external_scan(identity: String, path: String) -> bool {
    match external_media_state().lock() {
        Ok(mut state) => state.enqueue_scan(identity, path),
        Err(e) => {
            log::warn!("External media queue lock poisoned: {}", e);
            false
        }
    }
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

fn start_external_scan(app: &AppHandle, identity: String, path: String) {
    let (title, body) = localized_detection_notification(&path);
    send_external_media_notification(app, &title, &body);
    log_external_media_detected(&path);

    if scan::is_scanning() {
        if queue_external_scan(identity, path.clone()) {
            let (title, body) = localized_queued_notification(&path);
            send_external_media_notification(app, &title, &body);
        }
        return;
    }

    match scan::start_scan_internal(app.clone(), "external".to_string(), Some(path.clone())) {
        Ok(()) => {
            log_external_media_scan_started(&path);
            let (title, body) = localized_started_notification(&path);
            send_external_media_notification(app, &title, &body);
        }
        Err(err) if scan::is_scan_in_progress_error(&err) => {
            if queue_external_scan(identity, path.clone()) {
                let (title, body) = localized_queued_notification(&path);
                send_external_media_notification(app, &title, &body);
            }
        }
        Err(err) => {
            log::warn!("Failed to start external media scan for {}: {}", path, err);
        }
    }
}

fn drain_external_scan_queue(app: &AppHandle) {
    if scan::is_scanning() {
        return;
    }

    let next_scan = match external_media_state().lock() {
        Ok(mut state) => state.dequeue_next_scan(),
        Err(e) => {
            log::warn!("External media queue lock poisoned: {}", e);
            None
        }
    };

    let Some(next_scan) = next_scan else {
        return;
    };

    match scan::start_scan_internal(
        app.clone(),
        "external".to_string(),
        Some(next_scan.path.clone()),
    ) {
        Ok(()) => {
            log_external_media_scan_started(&next_scan.path);
            let (title, body) = localized_started_notification(&next_scan.path);
            send_external_media_notification(app, &title, &body);
        }
        Err(err) if scan::is_scan_in_progress_error(&err) => {
            let _ = queue_external_scan(next_scan.identity, next_scan.path);
        }
        Err(err) => {
            log::warn!(
                "Failed to start queued external media scan for {}: {}",
                next_scan.path,
                err
            );
        }
    }
}

fn refresh_external_media_state(
    current_mounts: BTreeMap<String, String>,
    protection_enabled: bool,
) -> MountDelta {
    match external_media_state().lock() {
        Ok(mut state) => {
            let delta = update_known_mounts(&mut state, current_mounts);
            if !protection_enabled {
                state.clear_queue();
            }
            delta
        }
        Err(e) => {
            log::warn!("External media state lock poisoned: {}", e);
            MountDelta::default()
        }
    }
}

pub fn start_external_media_monitor(app: AppHandle) -> Result<(), String> {
    if EXTERNAL_MEDIA_MONITOR_STARTED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let initial_mounts = collect_removable_mounts(&Disks::new_with_refreshed_list());
    if let Ok(mut state) = external_media_state().lock() {
        state.known_mounts = initial_mounts;
        state.clear_queue();
    }

    std::thread::Builder::new()
        .name("external-media-monitor".to_string())
        .spawn(move || loop {
            let current_mounts = collect_removable_mounts(&Disks::new_with_refreshed_list());
            let settings = Settings::load();
            let protection_enabled =
                settings.real_time_protection && settings.external_media_auto_scan;

            let delta = refresh_external_media_state(current_mounts, protection_enabled);

            if protection_enabled {
                for (identity, path) in delta.attached {
                    start_external_scan(&app, identity, path);
                }
                drain_external_scan_queue(&app);
            }

            std::thread::sleep(EXTERNAL_MEDIA_POLL_INTERVAL);
        })
        .map(|_| ())
        .map_err(|e| format!("Failed to start external media monitor: {}", e))
}


