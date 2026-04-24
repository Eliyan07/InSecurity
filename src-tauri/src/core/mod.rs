pub mod behavior;
pub mod feedback_store;
pub mod firewall;
/// Core detection pipeline modules
/// Updated: src-tauri/src/core/mod.rs
pub mod ingestion;
pub mod ml_bridge;
pub mod network_monitor;
pub mod pipeline;
pub mod quarantine_manager;
pub mod rate_limiter;
pub mod real_time;
pub mod reputation;
pub mod signature;
pub mod static_scanner;
pub mod tamper_protection;
pub mod threat_feed;
pub mod threat_neutralizer;
pub mod update_manager;
pub mod utils;
pub mod yara_scanner;

#[cfg(feature = "emulation")]
pub mod emulation;

pub use pipeline::DetectionPipeline;
pub use real_time::{add_watch_path, start_process_monitor, start_realtime_watcher};
pub use signature::{is_trusted_signed, verify_signature, SignatureInfo};
pub use tamper_protection::{
    compute_exclusion_signature, get_missed_events_scan_paths, log_audit_event,
    sign_all_yara_rules, sign_yara_rule, update_heartbeat, verify_exclusion_signature,
    verify_yara_rule, AuditEventType, AuditJournal, IntegrityCheckResult, IntegrityChecker,
    ProtectionStatus, SignedExclusion, SignedSettings,
};
pub use yara_scanner::{scan_with_yara, RuleSeverity, YaraMatch};

pub use firewall::auto_block_process;
pub use network_monitor::{
    get_active_connections, seed_default_malicious_ips, set_monitor_enabled, start_network_monitor,
};

#[cfg(feature = "emulation")]
pub use emulation::{EmulationConfig, EmulationResult, Emulator};
