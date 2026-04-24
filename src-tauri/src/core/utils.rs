//! Utility functions for the detection engine
use md5::Md5;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

pub fn configure_background_command(cmd: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    cmd
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for count in freq.iter() {
        if *count > 0 {
            let p = (*count as f64) / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

pub fn calculate_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn calculate_file_sha256(file_path: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn calculate_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn is_valid_sha256(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_valid_sha1(hash: &str) -> bool {
    hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_valid_md5(hash: &str) -> bool {
    hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Normalize a path by resolving `.` and `..` components without requiring
/// the path to exist on disk (unlike `std::fs::canonicalize`).
fn normalize_path_string(path: &str) -> String {
    let path = path.replace('/', "\\");
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('\\') {
        match component {
            "." | "" => {
                // Keep the first empty component for UNC or drive-relative paths
                if parts.is_empty() {
                    parts.push(component);
                }
            }
            ".." => {
                // Don't pop past the root (e.g. "C:" or empty for UNC)
                if parts.len() > 1 && parts.last() != Some(&"..") {
                    parts.pop();
                }
            }
            _ => parts.push(component),
        }
    }
    parts.join("\\")
}

pub fn is_system_path(file_path: &str) -> bool {
    let normalized = normalize_path_string(file_path);
    let path_lower = normalized.to_lowercase();

    let windows_system_paths = [
        "\\windows\\",
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
        "\\windows\\assembly\\",
        "\\windows\\microsoft.net\\",
        "\\windows\\servicing\\",
        "\\windows\\systemapps\\",
        "\\windows\\immersivecontrolpanel\\",
        "\\programdata\\microsoft\\",
        "\\programdata\\windows defender\\",
    ];

    for sys_path in windows_system_paths {
        if path_lower.contains(sys_path) {
            return true;
        }
    }

    // Skip our own application directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            if let Some(exe_dir_str) = exe_dir.to_str() {
                if path_lower.starts_with(&exe_dir_str.to_lowercase()) {
                    return true;
                }
            }
        }
    }

    false
}

pub fn is_scannable_file(file_path: &str) -> bool {
    let path = Path::new(file_path);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    let scannable_extensions = [
        // Windows executables
        "exe", "dll", "sys", "drv", "ocx", "scr", "cpl", "msi", "msp", "mst", // Scripts
        "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sct",
        "reg", // Java/JVM
        "jar", "class", "war", "ear", // Office macros
        "docm", "xlsm", "pptm", "dotm", "xltm", "potm", "doc", "xls",
        "ppt", // Old Office formats can contain macros
        // Archives (can contain malware)
        "zip", "rar", "7z", "cab", "iso", "img", // Other
        "lnk", "url", "pif", "com", "chm", "hlp",
    ];

    if ext.is_empty() {
        // Files without extensions are almost never malware on Windows
        // and can massively inflate scan counts (README, LICENSE, etc.)
        return false;
    }

    scannable_extensions.contains(&ext.as_str())
}

pub fn is_trusted_publisher_path(file_path: &str) -> bool {
    let normalized = normalize_path_string(file_path);
    let path_lower = normalized.to_lowercase();

    if path_lower.contains("\\program files\\") {
        return true;
    }
    if path_lower.contains("\\program files (x86)\\") {
        return true;
    }
    if path_lower.contains("\\windowsapps\\") {
        return true;
    }
    if path_lower.contains("\\programdata\\microsoft\\") {
        return true;
    }
    if path_lower.contains("\\common files\\") {
        return true;
    }

    let trusted_appdata_paths = [
        // Browsers
        "\\google\\chrome\\",
        "\\mozilla\\firefox\\",
        "\\microsoft\\edge\\",
        "\\microsoft\\onedrive\\",
        "\\bravesoftware\\",
        "\\opera software\\",
        "\\vivaldi\\",
        // Development tools
        "\\microsoft\\visualstudio\\",
        "\\jetbrains\\",
        "\\github\\",
        "\\docker\\",
        "\\vscode\\",
        "\\sublime text\\",
        // Gaming platforms
        "\\steam\\",
        "\\steamapps\\",
        "\\epic games\\",
        "\\riot games\\",
        "\\origin\\",
        "\\ubisoft\\",
        "\\gog galaxy\\",
        "\\battle.net\\",
        // Communication
        "\\discord\\",
        "\\slack\\",
        "\\zoom\\",
        "\\microsoft\\teams\\",
        "\\telegram desktop\\",
        "\\spotify\\",
        // Cloud storage
        "\\dropbox\\",
        "\\onedrive\\",
        "\\google\\drive\\",
        "\\box\\",
        // Productivity
        "\\microsoft\\office\\",
        "\\adobe\\",
        "\\autodesk\\",
        "\\notion\\",
        "\\obsidian\\",
        // Security software
        "\\malwarebytes\\",
        "\\avg\\",
        "\\avast\\",
        "\\kaspersky\\",
        "\\norton\\",
        "\\bitdefender\\",
        "\\eset\\",
        "\\mcafee\\",
        // System utilities
        "\\nvidia\\",
        "\\amd\\",
        "\\intel\\",
        "\\realtek\\",
        "\\logitech\\",
        "\\razer\\",
        "\\corsair\\",
        // Virtualization
        "\\vmware\\",
        "\\virtualbox\\",
        "\\docker\\",
        "\\wsl\\",
    ];

    for trusted_path in trusted_appdata_paths {
        if path_lower.contains(trusted_path) {
            return true;
        }
    }

    false
}

pub fn is_probable_installer_path(file_path: &str) -> bool {
    let normalized = normalize_path_string(file_path);
    let path = Path::new(&normalized);
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let installer_extensions = [
        "msi",
        "msp",
        "msix",
        "msixbundle",
        "appx",
        "appxbundle",
        "msu",
    ];
    if installer_extensions.contains(&extension.as_str()) {
        return true;
    }

    let installer_markers = [
        "setup",
        "installer",
        "install",
        "bootstrap",
        "updater",
        "update",
        "rustup-init",
    ];

    installer_markers
        .iter()
        .any(|marker| file_name.contains(marker))
}

pub fn is_self_product_installer_path(file_path: &str) -> bool {
    if !is_probable_installer_path(file_path) {
        return false;
    }

    let normalized = normalize_path_string(file_path);
    let file_name = Path::new(&normalized)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    let self_markers = ["insecurity", "antivirus-ui"];
    self_markers.iter().any(|marker| file_name.contains(marker))
}

/// Detects this application's own development/build artifacts so they do not
/// get re-flagged during local development.
pub fn is_dev_build_artifact_path(file_path: &str) -> bool {
    let normalized = normalize_path_string(file_path);
    let path_lower = normalized.to_lowercase();

    if is_self_product_installer_path(&normalized) {
        return true;
    }

    let build_output_markers = [
        "\\src-tauri\\target\\",
        "\\target\\debug\\",
        "\\target\\release\\",
        "\\target\\x86_64-pc-windows-msvc\\",
        "\\target\\i686-pc-windows-msvc\\",
        "\\target\\aarch64-pc-windows-msvc\\",
    ];

    if build_output_markers
        .iter()
        .any(|marker| path_lower.contains(marker))
    {
        return true;
    }

    let file_name = Path::new(&normalized)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    let self_build_filenames = [
        "antivirus_ui.exe",
        "antivirus-ui.exe",
        "antivirus_ui_lib.dll",
        "antivirus-ui_lib.dll",
        "bench_yara.exe",
        "nsis-output.exe",
    ];

    self_build_filenames.contains(&file_name.as_str())
}

/// Check if a file path is in a high-risk location (downloads, temp, etc.)
/// Useful for prioritizing scans or adjusting sensitivity
#[allow(dead_code)]
pub fn is_high_risk_path(file_path: &str) -> bool {
    let normalized = normalize_path_string(file_path);
    let path_lower = normalized.to_lowercase();

    let high_risk_paths = [
        // User download locations
        "\\downloads\\",
        "\\desktop\\",
        // Temporary locations
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\local\\temp\\",
        // Browser caches (downloaded files)
        "\\cache\\",
        "\\temporary internet files\\",
        // Email attachments
        "\\outlook\\",
        "\\thunderbird\\",
        // Recycle bin
        "\\$recycle.bin\\",
    ];

    for risk_path in high_risk_paths {
        if path_lower.contains(risk_path) {
            return true;
        }
    }

    if path_lower.len() > 3 {
        let chars: Vec<char> = path_lower.chars().collect();
        if chars.len() >= 3
            && chars[0].is_ascii_alphabetic()
            && chars[1] == ':'
            && chars[2] == '\\'
            && !path_lower[3..].contains('\\')
        {
            return true;
        }
    }

    false
}

fn find_existing_path(
    candidates: &[&str],
    roots: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    for root in roots {
        for candidate in candidates {
            let path = if root.as_os_str().is_empty() {
                std::path::PathBuf::from(candidate)
            } else {
                root.join(candidate)
            };
            if path.exists() {
                return Some(path);
            }
        }
    }

    None
}

pub fn find_resource_path(candidates: &[&str]) -> Option<std::path::PathBuf> {
    if let Some(path) = find_existing_path(candidates, &[std::path::PathBuf::new()]) {
        return Some(path);
    }

    let mut additional_roots: Vec<std::path::PathBuf> = Vec::new();

    if let Ok(current_dir) = std::env::current_dir() {
        additional_roots.push(current_dir);
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        additional_roots.push(std::path::PathBuf::from(manifest_dir));
    } else {
        additional_roots.push(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    }

    if let Some(path) = find_existing_path(candidates, &additional_roots) {
        return Some(path);
    }

    let mut bundle_roots: Vec<std::path::PathBuf> = Vec::new();

    if let Some(resource_dir) = crate::get_resource_dir() {
        // In bundled builds Tauri resolves resources under a bundle root
        // (for example "...\\_up_\\resources"), so search from that root too.
        if let Some(bundle_root) = resource_dir.parent() {
            bundle_roots.push(bundle_root.to_path_buf());
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            bundle_roots.push(exe_dir.to_path_buf());
            // Tauri copies bundled resources under "_up_" in dev and some
            // packaged Windows layouts; probe it before giving up.
            bundle_roots.push(exe_dir.join("_up_"));
        }
    }

    if let Some(path) = find_existing_path(candidates, &bundle_roots) {
        return Some(path);
    }

    None
}

/// Sanitize a string for safe logging — strips control characters and enforces max length
/// to prevent log injection attacks.
#[allow(dead_code)]
pub fn sanitize_for_log(s: &str, max_len: usize) -> String {
    let sanitized: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(max_len)
        .collect();

    if s.chars().count() > max_len {
        format!("{}...", sanitized)
    } else {
        sanitized
    }
}

/// Format a file size as a human-readable string (e.g. "1.50 KB", "2.00 MB").
#[allow(dead_code)]
pub fn format_file_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size >= GB {
        format!("{:.2} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{} bytes", size)
    }
}

pub fn generate_system_whitelist() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use std::collections::HashSet;

    let mut hashes = HashSet::new();

    // Directories containing trusted system executables
    let system_dirs = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Program Files\Windows Defender",
        r"C:\Program Files\Microsoft OneDrive",
        r"C:\Program Files (x86)\Microsoft\Edge\Application",
        r"C:\Program Files\Google\Chrome\Application",
        r"C:\Program Files\Mozilla Firefox",
    ];

    let extensions = ["exe", "dll"];

    for dir in system_dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if extensions.contains(&ext.to_str().unwrap_or("").to_lowercase().as_str())
                        {
                            if let Ok(hash) = calculate_file_sha256(path.to_str().unwrap_or("")) {
                                hashes.insert(hash);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(hashes.into_iter().collect())
}

pub fn save_whitelist(
    hashes: &[String],
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(file_path);

    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::create(path)?;
    writeln!(file, "# Auto-generated system whitelist")?;
    writeln!(
        file,
        "# Generated: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    )?;
    writeln!(file, "# {} entries", hashes.len())?;
    writeln!(file)?;
    for hash in hashes {
        writeln!(file, "{}", hash)?;
    }

    log::info!("Saved {} whitelist entries to {}", hashes.len(), file_path);
    Ok(())
}

pub fn load_whitelist(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut hashes = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && is_valid_sha256(trimmed) {
            hashes.push(trimmed.to_lowercase());
        }
    }

    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // All same bytes = 0 entropy
        let uniform = vec![0u8; 1000];
        assert!(calculate_entropy(&uniform) < 0.01);

        // Random-ish bytes = high entropy
        let random: Vec<u8> = (0..=255).cycle().take(1000).collect();
        assert!(calculate_entropy(&random) > 7.0);
    }

    #[test]
    fn test_is_system_path() {
        assert!(is_system_path("C:\\Windows\\System32\\kernel32.dll"));
        assert!(is_system_path("C:\\Windows\\SysWOW64\\ntdll.dll"));
        assert!(is_system_path("C:\\Windows\\WinSxS\\some_component.dll"));
        assert!(!is_system_path("C:\\Users\\test\\Downloads\\file.exe"));
        assert!(!is_system_path("C:\\Program Files\\App\\app.exe"));
    }

    #[test]
    fn test_is_scannable_file() {
        // Executable types
        assert!(is_scannable_file("test.exe"));
        assert!(is_scannable_file("library.dll"));
        assert!(is_scannable_file("script.ps1"));
        assert!(is_scannable_file("batch.bat"));
        assert!(is_scannable_file("macro.docm"));

        // Non-executable types
        assert!(!is_scannable_file("document.pdf"));
        assert!(!is_scannable_file("image.png"));
        assert!(!is_scannable_file("data.json"));
        assert!(!is_scannable_file("text.txt"));
        assert!(!is_scannable_file("video.mp4"));

        // No extension - skipped on Windows (avoids inflating scan with README, LICENSE, etc.)
        assert!(!is_scannable_file("program"));
    }

    #[test]
    fn test_is_trusted_publisher_path() {
        // Windows Program Files
        assert!(is_trusted_publisher_path(
            "C:\\Program Files\\Google\\Chrome\\chrome.exe"
        ));
        assert!(is_trusted_publisher_path(
            "C:\\Program Files (x86)\\Steam\\steam.exe"
        ));

        // Known app paths
        assert!(is_trusted_publisher_path(
            "C:\\Users\\test\\AppData\\Local\\Discord\\discord.exe"
        ));
        assert!(is_trusted_publisher_path(
            "C:\\Users\\test\\AppData\\Local\\Spotify\\spotify.exe"
        ));
        assert!(is_trusted_publisher_path(
            "D:\\SteamLibrary\\steamapps\\common\\Game\\game.exe"
        ));

        // NOT trusted
        assert!(!is_trusted_publisher_path(
            "C:\\Users\\test\\Downloads\\setup.exe"
        ));
        assert!(!is_trusted_publisher_path(
            "C:\\Users\\test\\Desktop\\unknown.exe"
        ));
        assert!(!is_trusted_publisher_path("C:\\temp\\malware.exe"));
    }

    #[test]
    fn test_is_probable_installer_path() {
        assert!(is_probable_installer_path(
            "C:\\Users\\test\\Downloads\\rustup-init.exe"
        ));
        assert!(is_probable_installer_path(
            "C:\\Users\\test\\Downloads\\InSecurity_1.0.6_x64-setup.exe"
        ));
        assert!(is_probable_installer_path(
            "C:\\Users\\test\\Downloads\\package.msi"
        ));
        assert!(!is_probable_installer_path(
            "C:\\Users\\test\\Downloads\\discord.exe"
        ));
    }

    #[test]
    fn test_is_self_product_installer_path() {
        assert!(is_self_product_installer_path(
            "C:\\Users\\test\\Downloads\\InSecurity_1.0.6_x64-setup.exe"
        ));
        assert!(is_self_product_installer_path(
            "C:\\Users\\test\\Desktop\\antivirus-ui-installer.exe"
        ));
        assert!(!is_self_product_installer_path(
            "C:\\Users\\test\\Downloads\\rustup-init.exe"
        ));
    }

    #[test]
    fn test_is_dev_build_artifact_path() {
        assert!(is_dev_build_artifact_path(
            "C:\\Users\\test\\Desktop\\project\\src-tauri\\target\\release\\antivirus_ui.exe"
        ));
        assert!(is_dev_build_artifact_path(
            "C:\\Users\\test\\Desktop\\project\\src-tauri\\target\\debug\\deps\\bench_yara.exe"
        ));
        assert!(is_dev_build_artifact_path(
            "C:\\Users\\test\\Desktop\\nsis-output.exe"
        ));
        assert!(is_dev_build_artifact_path(
            "C:\\Users\\test\\Downloads\\InSecurity_1.0.8_x64-setup.exe"
        ));
        assert!(!is_dev_build_artifact_path(
            "C:\\Users\\test\\Downloads\\random_tool.exe"
        ));
    }

    #[test]
    fn test_is_high_risk_path() {
        // High risk locations
        assert!(is_high_risk_path("C:\\Users\\test\\Downloads\\setup.exe"));
        assert!(is_high_risk_path("C:\\Users\\test\\Desktop\\file.exe"));
        assert!(is_high_risk_path("C:\\Windows\\Temp\\temp.exe"));
        assert!(is_high_risk_path(
            "C:\\Users\\test\\AppData\\Local\\Temp\\extract\\file.exe"
        ));

        // Drive root
        assert!(is_high_risk_path("E:\\malware.exe"));
        assert!(is_high_risk_path("F:\\autorun.exe"));

        // NOT high risk
        assert!(!is_high_risk_path("C:\\Program Files\\App\\app.exe"));
        assert!(!is_high_risk_path(
            "C:\\Users\\test\\AppData\\Local\\Discord\\discord.exe"
        ));
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(500), "500 bytes");
        assert_eq!(format_file_size(1024), "1.00 KB");
        assert_eq!(format_file_size(1536), "1.50 KB");
        assert_eq!(format_file_size(1048576), "1.00 MB");
        assert_eq!(format_file_size(1073741824), "1.00 GB");
    }

    #[test]
    fn test_sanitize_for_log() {
        assert_eq!(sanitize_for_log("hello", 10), "hello");
        assert_eq!(sanitize_for_log("hello world", 5), "hello...");
        assert_eq!(sanitize_for_log("test\x00null", 20), "testnull");
    }

    #[test]
    fn test_calculate_sha256() {
        let data = b"hello world";
        let hash = calculate_sha256(data);
        assert_eq!(hash.len(), 64);
        assert!(is_valid_sha256(&hash));
        // Known SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_calculate_md5() {
        let data = b"hello world";
        let hash = calculate_md5(data);
        assert_eq!(hash.len(), 32);
        assert!(is_valid_md5(&hash));
        // Known MD5 of "hello world"
        assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_is_valid_sha256() {
        assert!(is_valid_sha256(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        ));
        assert!(!is_valid_sha256("too_short"));
        assert!(!is_valid_sha256(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9X"
        )); // too long
        assert!(!is_valid_sha256(
            "ZZZZ27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )); // invalid chars
    }

    #[test]
    fn test_is_valid_sha1() {
        assert!(is_valid_sha1("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
        assert!(!is_valid_sha1("too_short"));
        assert!(!is_valid_sha1("2aae6c35c94fcfb415dbe95f408b9ce91ee846edX")); // too long
    }

    #[test]
    fn test_is_valid_md5() {
        assert!(is_valid_md5("5eb63bbbe01eeed093cb22bb8f5acdc3"));
        assert!(!is_valid_md5("too_short"));
        assert!(!is_valid_md5("5eb63bbbe01eeed093cb22bb8f5acdc3X")); // too long
    }

    // === Path traversal tests (CRITICAL security) ===

    #[test]
    fn test_is_system_path_path_traversal() {
        // Path traversal via ".." should be resolved before checking
        assert!(is_system_path(
            "C:\\Users\\test\\..\\Windows\\System32\\cmd.exe"
        ));
        assert!(is_system_path(
            "C:\\Users\\..\\Windows\\SysWOW64\\ntdll.dll"
        ));
        assert!(is_system_path(
            "D:\\temp\\..\\..\\Windows\\assembly\\test.dll"
        ));
    }

    #[test]
    fn test_is_trusted_publisher_path_traversal() {
        // Path traversal should resolve to trusted location
        assert!(is_trusted_publisher_path(
            "C:\\temp\\..\\Program Files\\Google\\Chrome\\chrome.exe"
        ));
        assert!(is_trusted_publisher_path(
            "C:\\Users\\..\\Program Files (x86)\\Steam\\steam.exe"
        ));
    }

    #[test]
    fn test_is_system_path_forward_slash_traversal() {
        assert!(is_system_path("C:/Users/../Windows/System32/kernel32.dll"));
    }

    #[test]
    fn test_is_high_risk_path_traversal() {
        // Traversal resolving to Downloads should still be high risk
        assert!(is_high_risk_path(
            "C:\\Program Files\\..\\Users\\test\\Downloads\\file.exe"
        ));
    }

    // === Normalize path string tests ===

    #[test]
    fn test_normalize_path_string_removes_dotdot() {
        assert_eq!(normalize_path_string("C:\\a\\b\\..\\c"), "C:\\a\\c");
        assert_eq!(normalize_path_string("C:\\a\\..\\b\\..\\c"), "C:\\c");
    }

    #[test]
    fn test_normalize_path_string_no_change_needed() {
        assert_eq!(
            normalize_path_string("C:\\Windows\\System32"),
            "C:\\Windows\\System32"
        );
    }

    #[test]
    fn test_normalize_path_string_forward_slashes() {
        assert_eq!(normalize_path_string("C:/Users/../Windows"), "C:\\Windows");
    }

    #[test]
    fn test_normalize_path_string_doesnt_go_past_root() {
        // Can't go above root
        let result = normalize_path_string("C:\\..\\..\\test");
        assert!(result.starts_with("C:"));
    }

    // === Entropy edge cases ===

    #[test]
    fn test_calculate_entropy_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_calculate_entropy_single_byte() {
        assert_eq!(calculate_entropy(&[42]), 0.0);
    }

    #[test]
    fn test_calculate_entropy_two_equal_values() {
        let data = vec![0u8, 1, 0, 1, 0, 1, 0, 1];
        let e = calculate_entropy(&data);
        assert!(
            (e - 1.0).abs() < 0.01,
            "Binary entropy should be ~1.0, got {}",
            e
        );
    }

    // === Whitelist file round-trip ===

    #[test]
    fn test_save_load_whitelist_roundtrip() {
        let dir = std::env::temp_dir().join("insecurity_test_whitelist_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("test_whitelist.txt");
        let path_str = file_path.to_str().unwrap();

        let hashes = vec![
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ];

        save_whitelist(&hashes, path_str).unwrap();
        let loaded = load_whitelist(path_str).unwrap();

        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&hashes[0]));
        assert!(loaded.contains(&hashes[1]));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_whitelist_skips_comments_and_blanks() {
        let dir = std::env::temp_dir().join("insecurity_test_whitelist_comments");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("test_comments.txt");

        let content = "# This is a comment\n\
            \n\
            b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9\n\
            # Another comment\n\
            not_a_valid_hash\n\
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";

        std::fs::write(&file_path, content).unwrap();
        let loaded = load_whitelist(file_path.to_str().unwrap()).unwrap();

        assert_eq!(loaded.len(), 2); // Only valid SHA256 hashes
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_whitelist_nonexistent_file() {
        assert!(load_whitelist("nonexistent_file_path_12345.txt").is_err());
    }

    // === sanitize_for_log bug fix test ===

    #[test]
    fn test_sanitize_for_log_multibyte_characters() {
        // Before fix: s.len() returned byte count, .take() used char count
        // "hello" is 5 chars + emoji is 1 char (4 bytes) = 6 chars, 9 bytes
        let input = "hello\u{1F600}"; // "hello" + grinning face emoji
        let result = sanitize_for_log(input, 6);
        // Should contain the full string since it's exactly 6 chars
        assert_eq!(result, "hello\u{1F600}");

        // Truncation: max_len=5 should cut before the emoji
        let result2 = sanitize_for_log(input, 5);
        assert_eq!(result2, "hello...");
    }

    // === format_file_size edge cases ===

    #[test]
    fn test_format_file_size_zero() {
        assert_eq!(format_file_size(0), "0 bytes");
    }

    // === is_valid_sha256 with uppercase ===

    #[test]
    fn test_is_valid_sha256_uppercase() {
        // Uppercase hex digits should be valid
        assert!(is_valid_sha256(
            "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"
        ));
    }

    // === is_scannable_file case insensitive ===

    #[test]
    fn test_is_scannable_file_case_insensitive() {
        assert!(is_scannable_file("FILE.EXE"));
        assert!(is_scannable_file("Library.DLL"));
        assert!(is_scannable_file("Script.PS1"));
    }

    // === is_high_risk_path edge cases ===

    #[test]
    fn test_is_high_risk_path_drive_root_no_subdir() {
        // "C:\" alone (just a drive root) - len is 3, code checks len > 3
        assert!(!is_high_risk_path("C:\\"));
    }

    #[test]
    fn test_is_high_risk_path_drive_root_with_file() {
        assert!(is_high_risk_path("E:\\malware.exe"));
    }

    // === find_resource_path ===

    #[test]
    fn test_find_resource_path_no_match() {
        let result = find_resource_path(&["nonexistent_path_1.txt", "nonexistent_path_2.txt"]);
        // May or may not find files relative to exe dir, so just verify no panic
        // The result depends on the exe directory contents
        let _ = result;
    }

    #[test]
    fn test_find_existing_path_handles_tauri_up_layout() {
        let dir = std::env::temp_dir().join("insecurity_test_find_resource_path_bundle");
        let bundle_root = dir.join("_up_");
        let target = bundle_root
            .join("resources")
            .join("models")
            .join("classifier");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&target).unwrap();

        let found = find_existing_path(&["resources/models/classifier"], &[bundle_root.clone()]);

        assert_eq!(found, Some(target));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // === calculate_file_sha256 ===

    #[test]
    fn test_calculate_file_sha256_real_file() {
        let dir = std::env::temp_dir().join("insecurity_test_sha256");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("test_file.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let hash = calculate_file_sha256(file_path.to_str().unwrap()).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_calculate_file_sha256_nonexistent() {
        assert!(calculate_file_sha256("nonexistent_file_xyz_123.txt").is_err());
    }
}
