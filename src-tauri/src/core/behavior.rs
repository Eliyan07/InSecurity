//! Stage 5: Behavioral Analysis
//! Behavior-based detection with API/string pattern analysis and entropy checks

use super::utils::calculate_entropy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAnalysis {
    pub suspicious_behaviors: Vec<String>,
    pub behavior_score: f64,
    pub api_indicators: Vec<String>,
    pub string_indicators: Vec<String>,
}

const SUSPICIOUS_APIS: &[(&[u8], &str, f64, bool)] = &[
    // Process manipulation - need multiple to be suspicious
    (b"CreateRemoteThread", "process_injection", 0.15, true),
    (b"VirtualAllocEx", "remote_memory_allocation", 0.10, true),
    (b"WriteProcessMemory", "process_memory_write", 0.15, true),
    (b"NtUnmapViewOfSection", "process_hollowing", 0.20, true),
    (b"SetThreadContext", "thread_hijacking", 0.15, true),
    (b"QueueUserAPC", "apc_injection", 0.15, true),
    // Privilege escalation - context dependent
    (b"AdjustTokenPrivileges", "privilege_escalation", 0.08, true),
    (b"OpenProcessToken", "token_manipulation", 0.05, true),
    (b"ImpersonateLoggedOnUser", "user_impersonation", 0.15, true),
    // Persistence - common in legitimate software too
    (b"RegSetValueEx", "registry_modification", 0.02, true),
    (b"CreateService", "service_creation", 0.05, true),
    (b"SetWindowsHookEx", "keyboard_hook", 0.08, true),
    // Anti-analysis - need multiple to be suspicious
    (b"IsDebuggerPresent", "anti_debug", 0.05, true),
    (b"CheckRemoteDebuggerPresent", "anti_debug", 0.08, true),
    (b"NtQueryInformationProcess", "anti_debug", 0.05, true),
    (b"GetTickCount", "timing_check", 0.01, true),
    (b"QueryPerformanceCounter", "timing_check", 0.01, true),
    // Network - context dependent
    (b"WSAStartup", "network_init", 0.01, true),
    (b"InternetOpenUrl", "url_download", 0.03, true),
    (b"URLDownloadToFile", "file_download", 0.10, true),
    (b"HttpSendRequest", "http_request", 0.02, true),
    // Crypto (ransomware indicators) - only suspicious with file enum
    (b"CryptEncrypt", "encryption", 0.05, true),
    (b"CryptGenKey", "key_generation", 0.03, true),
    (b"CryptAcquireContext", "crypto_context", 0.02, true),
    // Keylogging - need combination
    (b"GetAsyncKeyState", "keylogging", 0.10, true),
    (b"GetKeyState", "keylogging", 0.05, true),
    // Screenshot/clipboard - common in legitimate apps
    (b"GetClipboardData", "clipboard_access", 0.02, true),
    (b"BitBlt", "screenshot", 0.02, true),
    // File operations - very common, not suspicious alone
    (b"FindFirstFile", "file_enumeration", 0.01, true),
    (b"DeleteFile", "file_deletion", 0.01, true),
    (b"MoveFileEx", "file_manipulation", 0.01, true),
];

const SUSPICIOUS_STRINGS: &[(&[u8], &str, f64)] = &[
    // Command execution - context dependent
    (b"cmd.exe /c", "command_execution", 0.08),
    (b"powershell -enc", "encoded_powershell", 0.25),
    (b"powershell -e ", "encoded_powershell", 0.25),
    (b"-ExecutionPolicy Bypass", "policy_bypass", 0.20),
    (b"IEX(", "invoke_expression", 0.15),
    (b"Invoke-Expression", "invoke_expression", 0.15),
    (b"downloadstring", "download_execute", 0.20),
    (b"DownloadFile", "download_execute", 0.10),
    // Persistence paths - only with other indicators
    (b"\\CurrentVersion\\Run", "autorun_registry", 0.08),
    (b"\\Startup\\", "startup_folder", 0.05),
    (b"schtasks /create", "scheduled_task", 0.10),
    // Credential access - highly suspicious
    (b"mimikatz", "credential_tool", 0.50),
    (b"sekurlsa", "credential_dump", 0.40),
    (b"lsass", "lsass_access", 0.15),
    (b"SAM database", "sam_access", 0.30),
    (b"password", "password_string", 0.02),
    // Known malware tools
    (b"metasploit", "exploit_framework", 0.40),
    (b"meterpreter", "malware_payload", 0.50),
    (b"cobalt strike", "malware_c2", 0.50),
    (b"cobaltstrike", "malware_c2", 0.50),
    (b"beacon", "malware_beacon", 0.15),
    (b"empire", "malware_framework", 0.10),
    (b"powersploit", "exploit_framework", 0.40),
    // C2 indicators
    (b"pastebin.com/raw", "pastebin_c2", 0.15),
    (b"discord.com/api/webhooks", "discord_exfil", 0.20),
    (b"telegram.org/bot", "telegram_c2", 0.15),
    // Anti-AV - highly suspicious
    (b"DisableAntiSpyware", "disable_defender", 0.30),
    (b"Set-MpPreference", "defender_config", 0.15),
    (
        b"Add-MpPreference -ExclusionPath",
        "defender_exclusion",
        0.35,
    ),
    // Ransomware indicators
    (b"YOUR FILES HAVE BEEN ENCRYPTED", "ransom_note", 0.50),
    (b"YOUR FILES ARE ENCRYPTED", "ransom_note", 0.50),
    (b"send bitcoin", "ransom_demand", 0.30),
    (b"bitcoin wallet", "ransom_demand", 0.20),
    (b".onion", "tor_address", 0.10),
    // Base64 encoded PE (shellcode indicator)
    (b"TVqQAAMAAAAEAAAA", "base64_pe_header", 0.30),
    (b"TVpQAAIAAAAEAA8A", "base64_pe_header", 0.30),
];

const MALICIOUS_COMBINATIONS: &[(&[&str], &str, f64)] = &[
    // Process injection combo
    (
        &[
            "process_injection",
            "remote_memory_allocation",
            "process_memory_write",
        ],
        "process_injection_attack",
        0.40,
    ),
    // Process hollowing combo
    (
        &[
            "process_hollowing",
            "remote_memory_allocation",
            "process_memory_write",
        ],
        "process_hollowing_attack",
        0.45,
    ),
    // Keylogger combo
    (&["keylogging", "keyboard_hook"], "keylogger_behavior", 0.35),
    // Ransomware combo
    (
        &["encryption", "file_enumeration", "file_deletion"],
        "ransomware_behavior",
        0.50,
    ),
    // Dropper combo
    (
        &["file_download", "command_execution"],
        "dropper_behavior",
        0.30,
    ),
    // Credential theft combo
    (
        &["lsass_access", "privilege_escalation"],
        "credential_theft",
        0.45,
    ),
    // Anti-analysis combo
    (
        &["anti_debug", "timing_check"],
        "anti_analysis_behavior",
        0.15,
    ),
];

pub fn analyze_behavior(
    content: &[u8],
    file_type: &str,
    file_size: u64,
    existing_characteristics: &[String],
) -> Result<BehaviorAnalysis, Box<dyn std::error::Error>> {
    let mut suspicious_behaviors = Vec::new();
    let mut api_indicators = Vec::new();
    let mut string_indicators = Vec::new();
    let mut behavior_score = 0.0_f64;

    // Track categories found for combination detection
    let mut found_categories: Vec<String> = Vec::new();

    let mut api_findings: Vec<(&str, f64, bool)> = Vec::new();

    for &(pattern, category, weight, requires_combo) in SUSPICIOUS_APIS {
        if contains_pattern(content, pattern) {
            api_indicators.push(format!("{}:{}", category, String::from_utf8_lossy(pattern)));
            found_categories.push(category.to_string());
            api_findings.push((category, weight, requires_combo));
        }
    }

    for &(pattern, category, weight) in SUSPICIOUS_STRINGS {
        if contains_pattern_case_insensitive(content, pattern) {
            string_indicators.push(format!("{}:{}", category, String::from_utf8_lossy(pattern)));
            found_categories.push(category.to_string());

            behavior_score += weight;
            suspicious_behaviors.push(format!("suspicious_string:{}", category));
        }
    }

    let mut combination_bonus = 0.0_f64;
    for &(required_categories, combo_name, bonus) in MALICIOUS_COMBINATIONS {
        let matches = required_categories
            .iter()
            .filter(|&cat| found_categories.iter().any(|fc| fc == *cat))
            .count();

        if matches >= 2 {
            let ratio = matches as f64 / required_categories.len() as f64;
            let applied_bonus = bonus * ratio;
            combination_bonus += applied_bonus;
            suspicious_behaviors.push(format!("behavior_pattern:{}", combo_name));
            log::debug!(
                "Detected behavior pattern '{}' ({}/{} indicators, bonus: {:.2})",
                combo_name,
                matches,
                required_categories.len(),
                applied_bonus
            );
        }
    }

    let combination_categories: Vec<&str> = MALICIOUS_COMBINATIONS
        .iter()
        .flat_map(|(cats, _, _)| cats.iter().copied())
        .collect();

    for (category, weight, requires_combo) in api_findings {
        if !requires_combo || found_categories.iter().filter(|c| *c == category).count() >= 2 {
            behavior_score += weight;
        } else if combination_bonus > 0.0 && combination_categories.contains(&category) {
            behavior_score += weight * 0.5;
        }
    }

    behavior_score += combination_bonus;

    if file_type == "PE" && content.len() > 1024 {
        let tail_start = content.len() * 3 / 4;
        let tail_entropy = calculate_entropy(&content[tail_start..]);

        if tail_entropy > 7.9 {
            behavior_score += 0.05;
            suspicious_behaviors.push("high_entropy_tail".to_string());
        }
    }

    if file_type == "PE" && file_size < 10_000 && behavior_score > 0.1 {
        behavior_score += 0.05;
        suspicious_behaviors.push("tiny_pe_with_suspicious_apis".to_string());
    }

    for char in existing_characteristics {
        if char.contains("malicious_packer") {
            behavior_score += 0.10;
            suspicious_behaviors.push(char.clone());
        } else if char.contains("process_injection") || char.contains("hollowing") {
            behavior_score += 0.15;
            suspicious_behaviors.push(char.clone());
        } else if char.contains("ransomware") {
            behavior_score += 0.20;
            suspicious_behaviors.push(char.clone());
        }
    }

    behavior_score = behavior_score.min(1.0);

    log::debug!(
        "Behavior analysis: score={:.3}, apis={}, strings={}, behaviors={}",
        behavior_score,
        api_indicators.len(),
        string_indicators.len(),
        suspicious_behaviors.len()
    );

    Ok(BehaviorAnalysis {
        suspicious_behaviors,
        behavior_score,
        api_indicators,
        string_indicators,
    })
}

fn contains_pattern(content: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || content.len() < pattern.len() {
        return false;
    }

    if content.windows(pattern.len()).any(|w| w == pattern) {
        return true;
    }

    let wide: Vec<u8> = pattern.iter().flat_map(|&b| [b, 0u8]).collect();
    if content.len() >= wide.len() && content.windows(wide.len()).any(|w| w == wide.as_slice()) {
        return true;
    }

    false
}

fn contains_pattern_case_insensitive(content: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || content.len() < pattern.len() {
        return false;
    }

    let pattern_lower: Vec<u8> = pattern.iter().map(|b| b.to_ascii_lowercase()).collect();

    for window in content.windows(pattern.len()) {
        if window
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .eq(pattern_lower.iter().copied())
        {
            return true;
        }
    }

    let wide_pattern: Vec<u8> = pattern_lower.iter().flat_map(|&b| [b, 0u8]).collect();
    if content.len() >= wide_pattern.len() {
        for window in content.windows(wide_pattern.len()) {
            let matches = window.iter().enumerate().all(|(i, &b)| {
                if i % 2 == 0 {
                    b.to_ascii_lowercase() == wide_pattern[i]
                } else {
                    b == 0
                }
            });
            if matches {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_pattern() {
        let content = b"Hello VirtualAllocEx World";
        assert!(contains_pattern(content, b"VirtualAllocEx"));
        assert!(!contains_pattern(content, b"CreateRemoteThread"));
    }

    #[test]
    fn test_contains_pattern_wide_string() {
        // UTF-16LE encoded "VirtualAlloc"
        let wide = b"V\x00i\x00r\x00t\x00u\x00a\x00l\x00A\x00l\x00l\x00o\x00c\x00";
        assert!(contains_pattern(wide, b"VirtualAlloc"));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let content = b"Hello MIMIKATZ world";
        assert!(contains_pattern_case_insensitive(content, b"mimikatz"));
        assert!(contains_pattern_case_insensitive(content, b"MIMIKATZ"));
        assert!(contains_pattern_case_insensitive(content, b"MiMiKaTz"));
    }

    #[test]
    fn test_single_api_low_score() {
        // A single common API should not result in high score
        let content = b"kernel32.dll VirtualAlloc GetProcAddress LoadLibrary";
        let result = analyze_behavior(content, "PE", 50000, &[]).unwrap();

        assert!(
            result.behavior_score < 0.2,
            "Single common APIs should have low score, got {}",
            result.behavior_score
        );
    }

    #[test]
    fn test_injection_combo_detected() {
        // Process injection pattern should be detected
        let content = b"OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread";
        let result = analyze_behavior(content, "PE", 50000, &[]).unwrap();

        assert!(
            result.behavior_score >= 0.3,
            "Injection combo should have higher score, got {}",
            result.behavior_score
        );
        assert!(
            result
                .suspicious_behaviors
                .iter()
                .any(|b| b.contains("injection")),
            "Should detect injection pattern: {:?}",
            result.suspicious_behaviors
        );
    }

    #[test]
    fn test_known_malware_strings_high_score() {
        let content = b"mimikatz sekurlsa::logonpasswords";
        let result = analyze_behavior(content, "PE", 50000, &[]).unwrap();

        assert!(
            result.behavior_score >= 0.5,
            "Known malware strings should have high score, got {}",
            result.behavior_score
        );
    }

    #[test]
    fn test_ransomware_pattern() {
        let content = b"CryptEncrypt CryptGenKey FindFirstFile FindNextFile DeleteFile YOUR FILES HAVE BEEN ENCRYPTED";
        let result = analyze_behavior(content, "PE", 50000, &[]).unwrap();

        assert!(
            result.behavior_score >= 0.6,
            "Ransomware pattern should have high score, got {}",
            result.behavior_score
        );
        assert!(
            result
                .suspicious_behaviors
                .iter()
                .any(|b| b.contains("ransom")),
            "Should detect ransomware: {:?}",
            result.suspicious_behaviors
        );
    }

    #[test]
    fn test_legitimate_app_low_score() {
        // Simulate a typical legitimate application's API usage
        let content = b"CreateFile ReadFile WriteFile CloseHandle GetModuleHandle LoadLibrary GetProcAddress VirtualAlloc VirtualFree HeapAlloc HeapFree CreateThread WaitForSingleObject";
        let result = analyze_behavior(content, "PE", 500000, &[]).unwrap();

        assert!(
            result.behavior_score < 0.15,
            "Legitimate app pattern should have very low score, got {}",
            result.behavior_score
        );
    }

    #[test]
    fn test_encoded_powershell_flagged() {
        let content = b"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
        let result = analyze_behavior(content, "PE", 50000, &[]).unwrap();

        assert!(
            result.behavior_score >= 0.2,
            "Encoded PowerShell should be flagged, got {}",
            result.behavior_score
        );
    }

    #[test]
    fn test_existing_characteristics_factored() {
        let content = b"some content";
        let chars = vec!["malicious_packer:Themida".to_string()];
        let result = analyze_behavior(content, "PE", 50000, &chars).unwrap();

        assert!(
            result.behavior_score >= 0.1,
            "Existing malicious packer should add to score, got {}",
            result.behavior_score
        );
    }

    #[test]
    fn test_dropper_pattern() {
        let content = b"URLDownloadToFile cmd.exe /c";
        let result = analyze_behavior(content, "PE", 15000, &[]).unwrap();

        assert!(
            result
                .suspicious_behaviors
                .iter()
                .any(|b| b.contains("dropper") || b.contains("download")),
            "Should detect dropper pattern: {:?}",
            result.suspicious_behaviors
        );
    }

    #[test]
    fn test_score_capped_at_one() {
        // Even with many indicators, score should not exceed 1.0
        let content = b"mimikatz sekurlsa meterpreter cobalt strike CreateRemoteThread VirtualAllocEx WriteProcessMemory powershell -enc YOUR FILES HAVE BEEN ENCRYPTED";
        let result = analyze_behavior(
            content,
            "PE",
            5000,
            &[
                "malicious_packer:Themida".to_string(),
                "process_injection_capability".to_string(),
            ],
        )
        .unwrap();

        assert!(
            result.behavior_score <= 1.0,
            "Score should be capped at 1.0, got {}",
            result.behavior_score
        );
    }

    #[test]
    fn test_empty_content() {
        let result = analyze_behavior(b"", "PE", 0, &[]).unwrap();
        assert_eq!(result.behavior_score, 0.0);
        assert!(result.api_indicators.is_empty());
        assert!(result.string_indicators.is_empty());
        assert!(result.suspicious_behaviors.is_empty());
    }

    #[test]
    fn test_non_pe_file_type() {
        // Non-PE files should skip PE-specific checks (high entropy tail, tiny PE)
        let content = b"VirtualAllocEx CreateRemoteThread WriteProcessMemory";
        let result = analyze_behavior(content, "ELF", 50000, &[]).unwrap();
        assert!(!result
            .suspicious_behaviors
            .iter()
            .any(|b| b.contains("tiny_pe")));
        assert!(!result
            .suspicious_behaviors
            .iter()
            .any(|b| b.contains("high_entropy_tail")));
    }

    #[test]
    fn test_contains_pattern_empty_pattern() {
        assert!(!contains_pattern(b"some content", b""));
    }

    #[test]
    fn test_contains_pattern_pattern_longer_than_content() {
        assert!(!contains_pattern(b"ab", b"abcdef"));
    }

    #[test]
    fn test_case_insensitive_empty_content() {
        assert!(!contains_pattern_case_insensitive(b"", b"test"));
    }

    #[test]
    fn test_case_insensitive_empty_pattern() {
        assert!(!contains_pattern_case_insensitive(b"test", b""));
    }

    #[test]
    fn test_existing_characteristics_ransomware() {
        let content = b"some content";
        let chars = vec!["ransomware_indicator".to_string()];
        let result = analyze_behavior(content, "PE", 50000, &chars).unwrap();
        assert!(
            result.behavior_score >= 0.2,
            "Ransomware char should add 0.20: {}",
            result.behavior_score
        );
    }

    #[test]
    fn test_existing_characteristics_process_injection() {
        let content = b"some content";
        let chars = vec!["process_injection_capability".to_string()];
        let result = analyze_behavior(content, "PE", 50000, &chars).unwrap();
        assert!(
            result.behavior_score >= 0.15,
            "Process injection char should add 0.15: {}",
            result.behavior_score
        );
    }

    #[test]
    fn test_tiny_pe_with_apis() {
        // PE file < 10KB with suspicious APIs should get bonus
        let content = b"CreateRemoteThread VirtualAllocEx WriteProcessMemory";
        let result = analyze_behavior(content, "PE", 5000, &[]).unwrap();
        assert!(
            result
                .suspicious_behaviors
                .iter()
                .any(|b| b.contains("tiny_pe")),
            "Small PE with APIs should be flagged: {:?}",
            result.suspicious_behaviors
        );
    }
}
