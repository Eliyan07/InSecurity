//! Threat Neutralization Module
//! Handles active threat remediation: process killing, persistence cleaning, and child process termination

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizationResult {
    pub success: bool,
    pub processes_killed: Vec<ProcessInfo>,
    pub persistence_removed: Vec<PersistenceEntry>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl Default for NeutralizationResult {
    fn default() -> Self {
        Self {
            success: true,
            processes_killed: Vec::new(),
            persistence_removed: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub parent_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub persistence_type: PersistenceType,
    pub location: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PersistenceType {
    RegistryRunKey,
    RegistryRunOnceKey,
    ScheduledTask,
    StartupFolder,
    Service,
    WmiBehavior,
}

pub struct ThreatNeutralizer;

impl ThreatNeutralizer {
    /// Fully neutralize a threat: kill processes, clean persistence, then allow quarantine to proceed
    pub fn neutralize(file_path: &str) -> NeutralizationResult {
        let mut result = NeutralizationResult::default();

        log::info!("Starting threat neutralization for: {}", file_path);

        // Step 1: Find and kill all processes running from this path
        match Self::kill_processes_by_path(file_path) {
            Ok(killed) => {
                if !killed.is_empty() {
                    log::info!(
                        "Killed {} processes running from {}",
                        killed.len(),
                        file_path
                    );
                }
                result.processes_killed.extend(killed);
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("Failed to kill processes: {}", e));
                log::warn!("Process killing failed: {}", e);
            }
        }

        // Step 2: Clean persistence mechanisms
        match Self::clean_all_persistence(file_path) {
            Ok(removed) => {
                if !removed.is_empty() {
                    log::info!(
                        "Removed {} persistence entries for {}",
                        removed.len(),
                        file_path
                    );
                }
                result.persistence_removed.extend(removed);
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("Failed to clean some persistence: {}", e));
                log::warn!("Persistence cleaning had errors: {}", e);
            }
        }

        // Step 3: Kill any child processes that might have been spawned
        for proc in &result.processes_killed.clone() {
            if let Err(e) = Self::kill_process_tree(proc.pid) {
                result.warnings.push(format!(
                    "Failed to kill process tree for PID {}: {}",
                    proc.pid, e
                ));
            }
        }

        result.success = result.errors.is_empty();
        result
    }

    pub fn kill_processes_by_path(file_path: &str) -> Result<Vec<ProcessInfo>, String> {
        let target_path = match std::fs::canonicalize(file_path) {
            Ok(p) => p,
            Err(_) => PathBuf::from(file_path),
        };

        let mut killed = Vec::new();
        let processes = Self::enumerate_processes()?;

        for proc in processes {
            if let Some(ref exe_path) = proc.exe_path {
                let proc_path = match std::fs::canonicalize(exe_path) {
                    Ok(p) => p,
                    Err(_) => PathBuf::from(exe_path),
                };

                let paths_match = proc_path.to_string_lossy().to_lowercase()
                    == target_path.to_string_lossy().to_lowercase();

                if paths_match {
                    log::info!(
                        "Found process {} (PID {}) running from target path",
                        proc.name,
                        proc.pid
                    );

                    if Self::kill_process(proc.pid).is_ok() {
                        killed.push(proc);
                    }
                }
            }
        }

        Ok(killed)
    }

    pub fn kill_process_tree(root_pid: u32) -> Result<Vec<ProcessInfo>, String> {
        let mut killed = Vec::new();
        let mut to_kill = vec![root_pid];
        let mut visited = HashSet::new();

        let all_processes = Self::enumerate_processes()?;

        while let Some(pid) = to_kill.pop() {
            if visited.contains(&pid) {
                continue;
            }
            visited.insert(pid);

            for proc in &all_processes {
                if proc.parent_pid == Some(pid) && !visited.contains(&proc.pid) {
                    to_kill.push(proc.pid);
                }
            }
        }

        let mut pids_to_kill: Vec<u32> = visited.into_iter().collect();
        pids_to_kill.sort_by(|a, b| b.cmp(a)); // Reverse sort to try children first

        for pid in pids_to_kill {
            if let Some(proc) = all_processes.iter().find(|p| p.pid == pid) {
                if Self::kill_process(pid).is_ok() {
                    killed.push(proc.clone());
                }
            }
        }

        Ok(killed)
    }

    pub fn clean_all_persistence(file_path: &str) -> Result<Vec<PersistenceEntry>, String> {
        let mut removed = Vec::new();

        removed.extend(Self::clean_registry_run_keys(file_path)?);

        removed.extend(Self::clean_scheduled_tasks(file_path)?);

        removed.extend(Self::clean_startup_folder(file_path)?);

        if let Ok(services) = Self::clean_malicious_services(file_path) {
            removed.extend(services);
        }

        Ok(removed)
    }

    fn enumerate_processes() -> Result<Vec<ProcessInfo>, String> {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut processes = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == -1isize as HANDLE {
                return Err("Failed to create process snapshot".to_string());
            }

            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())],
                    );

                    let exe_path = Self::get_process_path(entry.th32ProcessID);

                    processes.push(ProcessInfo {
                        pid: entry.th32ProcessID,
                        name,
                        exe_path,
                        parent_pid: if entry.th32ParentProcessID > 0 {
                            Some(entry.th32ParentProcessID)
                        } else {
                            None
                        },
                    });

                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
        }

        Ok(processes)
    }

    fn get_process_path(pid: u32) -> Option<String> {
        use windows_sys::Win32::Foundation::{CloseHandle, MAX_PATH};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle == -1 {
                return None;
            }

            let mut buffer = [0u16; MAX_PATH as usize];
            let mut size = buffer.len() as u32;

            let result = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
            CloseHandle(handle);

            if result != 0 && size > 0 {
                Some(String::from_utf16_lossy(&buffer[..size as usize]))
            } else {
                None
            }
        }
    }

    fn kill_process(pid: u32) -> Result<(), String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };

        // Don't kill critical system processes
        if pid <= 4 {
            return Err("Cannot kill system process".to_string());
        }

        // Don't kill ourselves
        if pid == std::process::id() {
            return Err("Cannot kill self".to_string());
        }

        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if handle == -1 {
                return Err(format!("Failed to open process {}", pid));
            }

            let result = TerminateProcess(handle, 1);
            CloseHandle(handle);

            if result != 0 {
                log::info!("Successfully terminated process PID {}", pid);
                Ok(())
            } else {
                Err(format!("Failed to terminate process {}", pid))
            }
        }
    }

    fn clean_registry_run_keys(file_path: &str) -> Result<Vec<PersistenceEntry>, String> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut removed = Vec::new();
        let target_lower = file_path.to_lowercase();

        let locations = [
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            ),
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            ),
        ];

        for (hkey, subkey) in &locations {
            let key =
                match RegKey::predef(*hkey).open_subkey_with_flags(subkey, KEY_READ | KEY_WRITE) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

            let values: Vec<(String, String)> = key
                .enum_values()
                .filter_map(|r| r.ok())
                .map(|(name, value)| {
                    let val_str: String = value.to_string();
                    (name, val_str)
                })
                .collect();

            for (name, value) in values {
                if value.to_lowercase().contains(&target_lower) {
                    if key.delete_value(&name).is_ok() {
                        log::info!(
                            "Removed registry persistence: {}\\{} = {}",
                            subkey,
                            name,
                            value
                        );
                        removed.push(PersistenceEntry {
                            persistence_type: if subkey.contains("RunOnce") {
                                PersistenceType::RegistryRunOnceKey
                            } else {
                                PersistenceType::RegistryRunKey
                            },
                            location: format!("{}\\{}", subkey, name),
                            value,
                        });
                    }
                }
            }
        }

        Ok(removed)
    }

    fn clean_scheduled_tasks(file_path: &str) -> Result<Vec<PersistenceEntry>, String> {
        let mut removed = Vec::new();
        let target_lower = file_path.to_lowercase();

        use std::process::Command;

        let output = Command::new("schtasks")
            .args(["/Query", "/FO", "CSV", "/V"])
            .output()
            .map_err(|e| format!("Failed to query scheduled tasks: {}", e))?;

        if !output.status.success() {
            return Ok(removed);
        }

        let csv = String::from_utf8_lossy(&output.stdout);
        for line in csv.lines().skip(1) {
            // CSV format: "TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run",...
            let fields: Vec<&str> = line.split(',').map(|s| s.trim_matches('"')).collect();

            if fields.len() >= 8 {
                let task_name = fields[0];
                let task_to_run = fields[7];

                if task_to_run.to_lowercase().contains(&target_lower) {
                    // Delete this task
                    let delete_result = Command::new("schtasks")
                        .args(["/Delete", "/TN", task_name, "/F"])
                        .output();

                    if delete_result.is_ok() && delete_result.unwrap().status.success() {
                        log::info!("Removed scheduled task: {}", task_name);
                        removed.push(PersistenceEntry {
                            persistence_type: PersistenceType::ScheduledTask,
                            location: task_name.to_string(),
                            value: task_to_run.to_string(),
                        });
                    }
                }
            }
        }

        Ok(removed)
    }

    fn clean_startup_folder(file_path: &str) -> Result<Vec<PersistenceEntry>, String> {
        let mut removed = Vec::new();
        let target_lower = file_path.to_lowercase();

        let startup_paths = [
            std::env::var("APPDATA")
                .map(|p| format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", p))
                .ok(),
            Some(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup".to_string()),
        ];

        for startup_path in startup_paths.iter().flatten() {
            let dir = Path::new(startup_path);
            if !dir.exists() {
                continue;
            }

            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();

                    if path.extension().is_some_and(|e| e == "lnk") {
                        if let Ok(target) = Self::resolve_shortcut(&path) {
                            if target.to_lowercase().contains(&target_lower)
                                && std::fs::remove_file(&path).is_ok()
                            {
                                log::info!("Removed startup shortcut: {:?}", path);
                                removed.push(PersistenceEntry {
                                    persistence_type: PersistenceType::StartupFolder,
                                    location: path.to_string_lossy().to_string(),
                                    value: target,
                                });
                            }
                        }
                    }

                    // Also check .bat, .cmd, .vbs files that might reference the target
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if matches!(ext, "bat" | "cmd" | "vbs" | "ps1") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if content.to_lowercase().contains(&target_lower)
                                && std::fs::remove_file(&path).is_ok()
                            {
                                removed.push(PersistenceEntry {
                                    persistence_type: PersistenceType::StartupFolder,
                                    location: path.to_string_lossy().to_string(),
                                    value: format!("Script referencing {}", file_path),
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(removed)
    }

    fn resolve_shortcut(lnk_path: &Path) -> Result<String, String> {
        use std::process::Command;

        // Use PowerShell to resolve shortcut
        let ps_script = format!(
            "$sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut('{}').TargetPath",
            lnk_path.to_string_lossy().replace("'", "''")
        );

        let output = {
            let mut cmd = Command::new("powershell");
            crate::core::utils::configure_background_command(&mut cmd)
                .args(["-NoProfile", "-Command", &ps_script])
                .output()
        }
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err("Failed to resolve shortcut".to_string())
        }
    }

    fn clean_malicious_services(file_path: &str) -> Result<Vec<PersistenceEntry>, String> {
        use std::process::Command;

        let mut removed = Vec::new();
        let target_lower = file_path.to_lowercase();

        let output = Command::new("sc")
            .args(["query", "type=", "service", "state=", "all"])
            .output()
            .map_err(|e| format!("Failed to query services: {}", e))?;

        if !output.status.success() {
            return Ok(removed);
        }

        let services_output = String::from_utf8_lossy(&output.stdout);

        // Collect all service names first, then check each one
        let service_names: Vec<String> = services_output
            .lines()
            .filter(|line| line.starts_with("SERVICE_NAME:"))
            .filter_map(|line| line.split(':').nth(1).map(|s| s.trim().to_string()))
            .collect();

        for service_name in service_names {
            let qc_output = Command::new("sc").args(["qc", &service_name]).output();

            if let Ok(out) = qc_output {
                let config = String::from_utf8_lossy(&out.stdout);
                if config.to_lowercase().contains(&target_lower) {
                    let _ = Command::new("sc").args(["stop", &service_name]).output();
                    let delete_result = Command::new("sc").args(["delete", &service_name]).output();

                    if delete_result.is_ok() && delete_result.unwrap().status.success() {
                        removed.push(PersistenceEntry {
                            persistence_type: PersistenceType::Service,
                            location: service_name,
                            value: file_path.to_string(),
                        });
                    }
                }
            }
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_info_serialization() {
        let info = ProcessInfo {
            pid: 1234,
            name: "test.exe".to_string(),
            exe_path: Some("C:\\test\\test.exe".to_string()),
            parent_pid: Some(100),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ProcessInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.pid, 1234);
        assert_eq!(deserialized.name, "test.exe");
    }

    #[test]
    fn test_neutralization_result_default() {
        let result = NeutralizationResult::default();
        assert!(result.success);
        assert!(result.processes_killed.is_empty());
        assert!(result.persistence_removed.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_persistence_type_serialization() {
        let types = vec![
            PersistenceType::RegistryRunKey,
            PersistenceType::RegistryRunOnceKey,
            PersistenceType::ScheduledTask,
            PersistenceType::StartupFolder,
            PersistenceType::Service,
            PersistenceType::WmiBehavior,
        ];

        for pt in &types {
            let json = serde_json::to_string(pt).unwrap();
            let deserialized: PersistenceType = serde_json::from_str(&json).unwrap();
            assert_eq!(*pt, deserialized);
        }
    }

    #[test]
    fn test_persistence_entry_serialization() {
        let entry = PersistenceEntry {
            persistence_type: PersistenceType::RegistryRunKey,
            location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware".to_string(),
            value: r"C:\malware.exe".to_string(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: PersistenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.persistence_type,
            PersistenceType::RegistryRunKey
        );
        assert!(deserialized.location.contains("Run"));
    }

    #[test]
    fn test_neutralization_result_with_data() {
        let mut result = NeutralizationResult::default();
        result.processes_killed.push(ProcessInfo {
            pid: 999,
            name: "malware.exe".to_string(),
            exe_path: Some(r"C:\temp\malware.exe".to_string()),
            parent_pid: Some(1),
        });
        result.warnings.push("test warning".to_string());

        // success should still be true (no errors)
        assert!(result.success);
        assert_eq!(result.processes_killed.len(), 1);
        assert_eq!(result.warnings.len(), 1);

        // Roundtrip serialization
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: NeutralizationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.processes_killed.len(), 1);
        assert_eq!(deserialized.processes_killed[0].pid, 999);
    }

    #[test]
    fn test_process_info_without_parent() {
        let info = ProcessInfo {
            pid: 4,
            name: "System".to_string(),
            exe_path: None,
            parent_pid: None,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ProcessInfo = serde_json::from_str(&json).unwrap();
        assert!(deserialized.exe_path.is_none());
        assert!(deserialized.parent_pid.is_none());
    }
}
