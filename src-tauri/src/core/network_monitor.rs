//! Network Traffic Monitor
//! Monitors active TCP connections using the Windows IP Helper API
//! (GetExtendedTcpTable) and cross-references remote IPs against a
//! database of known malicious addresses.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use rusqlite::params;
use serde::Serialize;
use tauri::AppHandle;
use tauri::Emitter;

// ─── Global enable flag ──────────────────────────────────────────────────────

static MONITOR_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_monitor_enabled(enabled: bool) {
    MONITOR_ENABLED.store(enabled, Ordering::SeqCst);
}

pub fn is_monitor_enabled() -> bool {
    MONITOR_ENABLED.load(Ordering::SeqCst)
}

// ─── Data types ──────────────────────────────────────────────────────────────

/// One active TCP connection visible to the front-end.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveConnection {
    pub pid: u32,
    pub process_name: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub protocol: String,
    pub suspicious: bool,
    pub threat_name: Option<String>,
}

/// Emitted as a Tauri event when a suspicious connection is spotted.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkThreatEvent {
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub threat_name: String,
    pub protocol: String,
}

// ─── Win32 struct layouts ────────────────────────────────────────────────────
// windows-sys exports the function but not the table structs, so define them.

#[repr(C)]
struct MibTcpRowOwnerPid {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MibTcpTableOwnerPid {
    num_entries: u32,
    // Followed by variable-length array of MibTcpRowOwnerPid
}

// ─── Background monitor ─────────────────────────────────────────────────────

/// Start the network monitor background thread.
/// Polls `GetExtendedTcpTable` at the interval configured in settings,
/// cross-references remote IPs against malicious IP set, and emits
/// `"network_threat_detected"` events.
pub fn start_network_monitor(app: AppHandle) {
    std::thread::Builder::new()
        .name("network-monitor".into())
        .spawn(move || {
            log::info!("Network monitor thread started");

            let mut malicious_ips = load_malicious_ips();
            let mut iteration: u64 = 0;

            loop {
                if !MONITOR_ENABLED.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    continue;
                }

                // Determine poll interval from settings
                let interval_secs = {
                    let cfg = crate::config::settings::Settings::load();
                    cfg.network_monitor_interval_secs.max(1).min(30) as u64
                };

                std::thread::sleep(std::time::Duration::from_secs(interval_secs));

                // Refresh malicious IP set every 100 iterations
                iteration += 1;
                if iteration % 100 == 0 {
                    malicious_ips = load_malicious_ips();
                }

                let connections = match get_tcp_connections() {
                    Ok(c) => c,
                    Err(e) => {
                        log::debug!("GetExtendedTcpTable failed: {}", e);
                        continue;
                    }
                };

                // Build a sysinfo snapshot for PID -> process name resolution
                let mut sys = sysinfo::System::new();
                sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

                for (pid, _local_addr, _local_port, remote_addr, remote_port, state) in &connections {
                    if !malicious_ips.contains(remote_addr.as_str()) {
                        continue;
                    }

                    let (proc_name, proc_path) = process_info(&sys, *pid);
                    let threat_name = format!("Suspicious connection to {}", remote_addr);

                    let event = NetworkThreatEvent {
                        pid: *pid,
                        process_name: proc_name.clone(),
                        process_path: proc_path.clone(),
                        remote_ip: remote_addr.clone(),
                        remote_port: *remote_port,
                        threat_name: threat_name.clone(),
                        protocol: "TCP".into(),
                    };

                    if let Err(e) = app.emit("network_threat_detected", &event) {
                        log::warn!("Failed to emit network_threat_detected: {}", e);
                    }

                    // Persist to audit log
                    crate::core::tamper_protection::log_audit_event(
                        crate::core::tamper_protection::AuditEventType::ThreatDetected,
                        &format!(
                            "Network threat: {} (PID {}) -> {}:{} ({})",
                            proc_name, pid, remote_addr, remote_port, state
                        ),
                        Some(&proc_path),
                        None,
                    );

                    // Also log to DB for history
                    crate::with_db(|conn| {
                        let ts = chrono::Utc::now().timestamp();
                        let _ = conn.execute(
                            "INSERT INTO network_threats (pid, process_name, process_path, remote_ip, remote_port, threat_name, protocol, detected_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'TCP', ?7)",
                            params![pid, proc_name, proc_path, remote_addr, remote_port, threat_name, ts],
                        );
                        Some(())
                    });
                }
            }
        })
        .expect("Failed to spawn network monitor thread");
}

// ─── One-shot snapshot ──────────────────────────────────────────────────────

/// Return a snapshot of all current TCP connections with process info.
/// Intended as a Tauri command handler data source.
pub fn get_active_connections() -> Vec<ActiveConnection> {
    let rows = match get_tcp_connections() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("get_active_connections failed: {}", e);
            return Vec::new();
        }
    };

    let malicious = load_malicious_ips();

    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    rows.into_iter()
        .map(
            |(pid, local_addr, local_port, remote_addr, remote_port, state)| {
                let (name, _path) = process_info(&sys, pid);
                let suspicious = malicious.contains(remote_addr.as_str());
                let threat = if suspicious {
                    Some(format!("Known malicious IP: {}", remote_addr))
                } else {
                    None
                };

                ActiveConnection {
                    pid,
                    process_name: name,
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    state,
                    protocol: "TCP".into(),
                    suspicious,
                    threat_name: threat,
                }
            },
        )
        .collect()
}

// ─── IP Helper interop ──────────────────────────────────────────────────────

/// Call `GetExtendedTcpTable` using the two-call pattern and parse the result.
/// Returns a vec of `(pid, local_addr, local_port, remote_addr, remote_port, state_name)`.
fn get_tcp_connections() -> Result<Vec<(u32, String, u16, String, u16, String)>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable;

    const AF_INET: u32 = 2;
    const TCP_TABLE_OWNER_PID_ALL: i32 = 5;

    let mut size: u32 = 0;

    // First call: determine required buffer size
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0, // no sort
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }

    if size == 0 {
        return Err("GetExtendedTcpTable returned zero size".into());
    }

    let mut buffer: Vec<u8> = vec![0u8; size as usize];

    let ret = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if ret != 0 {
        return Err(format!("GetExtendedTcpTable failed with code {}", ret));
    }

    // Parse the table header
    let table = buffer.as_ptr() as *const MibTcpTableOwnerPid;
    let num_entries = unsafe { (*table).num_entries } as usize;

    let rows_ptr = unsafe {
        (table as *const u8).add(std::mem::size_of::<MibTcpTableOwnerPid>())
            as *const MibTcpRowOwnerPid
    };

    let mut results = Vec::with_capacity(num_entries);

    for i in 0..num_entries {
        let row = unsafe { &*rows_ptr.add(i) };

        let local_addr = u32_to_ipv4(row.local_addr);
        let remote_addr = u32_to_ipv4(row.remote_addr);
        let local_port = network_port(row.local_port);
        let remote_port = network_port(row.remote_port);
        let state = tcp_state_name(row.state);

        results.push((
            row.owning_pid,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state.to_string(),
        ));
    }

    Ok(results)
}

// ─── Conversion helpers ─────────────────────────────────────────────────────

/// Convert a u32 IPv4 address (in network byte order) to dotted-quad string.
fn u32_to_ipv4(addr: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        addr & 0xFF,
        (addr >> 8) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 24) & 0xFF,
    )
}

/// Convert a network-byte-order port stored in a u32 to a host-order u16.
fn network_port(raw: u32) -> u16 {
    (((raw >> 8) & 0xFF) | ((raw & 0xFF) << 8)) as u16
}

/// Map numeric TCP state to a human-readable name.
fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

// ─── Process resolution ─────────────────────────────────────────────────────

/// Resolve PID to (process_name, process_path) using sysinfo.
fn process_info(sys: &sysinfo::System, pid: u32) -> (String, String) {
    let sysinfo_pid = sysinfo::Pid::from_u32(pid);
    match sys.process(sysinfo_pid) {
        Some(proc) => {
            let name = proc.name().to_string_lossy().to_string();
            let path = proc
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            (name, path)
        }
        None => (format!("PID:{}", pid), String::new()),
    }
}

// ─── Malicious IP loader ────────────────────────────────────────────────────

/// Load known malicious IPs from the database into an in-memory HashSet.
fn load_malicious_ips() -> HashSet<String> {
    crate::with_db(|conn| {
        use crate::database::queries::DatabaseQueries;
        DatabaseQueries::get_malicious_ips_set(conn).ok()
    })
    .unwrap_or_default()
}

/// Seed the malicious_ips table with known C2/malware IPs.
/// Safe to call multiple times — uses INSERT OR IGNORE.
pub fn seed_default_malicious_ips() {
    use crate::database::queries::DatabaseQueries;

    // Known malicious / C2 infrastructure IPs (sinkholed, documented, or
    // historically associated with threat actors). These are public-knowledge
    // indicators used for educational/defensive purposes.
    let defaults: &[(&str, &str)] = &[
        // Cobalt Strike default teamserver IPs (commonly seen in threat intel)
        ("5.199.162.71", "Cobalt Strike C2"),
        ("23.81.246.187", "Cobalt Strike C2"),
        ("45.77.65.211", "Cobalt Strike C2"),
        ("192.210.191.186", "Cobalt Strike C2"),
        ("172.105.112.230", "Cobalt Strike C2"),
        // Emotet infrastructure (historical)
        ("45.138.98.34", "Emotet C2"),
        ("51.75.33.127", "Emotet C2"),
        ("69.16.218.101", "Emotet C2"),
        ("94.177.248.64", "Emotet C2"),
        ("185.148.169.10", "Emotet C2"),
        // TrickBot infrastructure
        ("185.56.76.94", "TrickBot C2"),
        ("195.133.145.31", "TrickBot C2"),
        ("185.142.99.7", "TrickBot C2"),
        // QakBot / Qbot
        ("140.82.49.12", "QakBot C2"),
        ("86.98.208.214", "QakBot C2"),
        ("73.151.236.31", "QakBot C2"),
        // IcedID / BokBot
        ("159.65.140.1", "IcedID C2"),
        ("188.127.237.232", "IcedID C2"),
        // AsyncRAT / njRAT common C2
        ("194.5.98.8", "AsyncRAT C2"),
        ("193.42.33.7", "njRAT C2"),
        ("141.95.11.170", "AsyncRAT C2"),
        // Redline Stealer
        ("185.215.113.75", "RedLine Stealer C2"),
        ("193.233.20.12", "RedLine Stealer C2"),
        ("77.91.68.52", "RedLine Stealer C2"),
        // Generic known-bad / sinkhole
        ("185.243.115.84", "Malware C2"),
        ("172.111.48.30", "Malware C2"),
        ("91.92.240.36", "Malware C2"),
        ("45.61.136.130", "Malware C2"),
        ("193.56.146.53", "Malware C2"),
        // Cryptomining pools (common indicators)
        ("94.130.12.27", "Cryptominer pool"),
        ("51.255.48.78", "Cryptominer pool"),
    ];

    crate::with_db(|conn| {
        for (ip, threat) in defaults {
            let _ = DatabaseQueries::insert_malicious_ip(conn, ip, Some(threat), "default");
        }
        Some(())
    });

    log::info!("Seeded {} default malicious IPs", defaults.len());
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_to_ipv4() {
        // 127.0.0.1 in network byte order = 0x0100007F
        assert_eq!(u32_to_ipv4(0x0100007F), "127.0.0.1");
        // 0.0.0.0
        assert_eq!(u32_to_ipv4(0), "0.0.0.0");
        // 192.168.1.1 in network byte order
        let addr: u32 = 192 | (168 << 8) | (1 << 16) | (1 << 24);
        assert_eq!(u32_to_ipv4(addr), "192.168.1.1");
    }

    #[test]
    fn test_tcp_state_name() {
        assert_eq!(tcp_state_name(1), "CLOSED");
        assert_eq!(tcp_state_name(2), "LISTEN");
        assert_eq!(tcp_state_name(5), "ESTABLISHED");
        assert_eq!(tcp_state_name(8), "CLOSE_WAIT");
        assert_eq!(tcp_state_name(11), "TIME_WAIT");
        assert_eq!(tcp_state_name(12), "DELETE_TCB");
        assert_eq!(tcp_state_name(99), "UNKNOWN");
    }

    #[test]
    fn test_port_conversion() {
        // Port 80 in network byte order: big-endian 0x0050 stored in u32
        // High byte = 0x00, low byte = 0x50 => raw u32 = 0x5000 (if placed as-is)
        // Actually the Win32 API stores the port as big-endian u16 in a u32 field.
        // Port 80 = 0x0050 big-endian => raw u32 low 16 bits = 0x5000
        let raw_80: u32 = 0x5000;
        assert_eq!(network_port(raw_80), 80);

        // Port 443 = 0x01BB big-endian => raw = 0xBB01
        let raw_443: u32 = 0xBB01;
        assert_eq!(network_port(raw_443), 443);

        // Port 8080 = 0x1F90 big-endian => raw = 0x901F
        let raw_8080: u32 = 0x901F;
        assert_eq!(network_port(raw_8080), 8080);

        // Port 0
        assert_eq!(network_port(0), 0);
    }

    #[test]
    fn test_monitor_enabled_toggle() {
        set_monitor_enabled(false);
        assert!(!is_monitor_enabled());
        set_monitor_enabled(true);
        assert!(is_monitor_enabled());
        set_monitor_enabled(false);
        assert!(!is_monitor_enabled());
    }
}
