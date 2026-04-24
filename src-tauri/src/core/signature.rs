//! Authenticode Signature Verification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    None,
    Unknown,
    Untrusted,
    PublisherAllowlist,
    PublisherMatch,
    CA,
    SelfSigned,
    Invalid,
}

// TrustLevel priority: higher = better
fn trust_rank(t: &TrustLevel) -> u8 {
    match t {
        TrustLevel::PublisherAllowlist => 7,
        TrustLevel::PublisherMatch => 6,
        TrustLevel::CA => 5,
        TrustLevel::SelfSigned => 4,
        TrustLevel::Unknown => 3,
        TrustLevel::Untrusted => 2,
        TrustLevel::Invalid => 1,
        TrustLevel::None => 0,
    }
}

fn upgrade_trust(cur: TrustLevel, candidate: TrustLevel) -> TrustLevel {
    if trust_rank(&candidate) > trust_rank(&cur) {
        candidate
    } else {
        cur
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub is_signed: bool,
    pub is_valid: bool,
    pub signer_name: Option<String>,
    pub issuer: Option<String>,
    pub timestamp: Option<String>,
    pub thumbprint: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub trust_level: TrustLevel,
    pub is_trusted_publisher: bool, // for backward compatibility
    pub raw_subject: Option<String>,
    pub raw_issuer: Option<String>,
    pub status_message: Option<String>,
}

impl Default for SignatureInfo {
    fn default() -> Self {
        SignatureInfo {
            is_signed: false,
            is_valid: false,
            signer_name: None,
            issuer: None,
            timestamp: None,
            thumbprint: None,
            not_before: None,
            not_after: None,
            trust_level: TrustLevel::None,
            is_trusted_publisher: false,
            raw_subject: None,
            raw_issuer: None,
            status_message: None,
        }
    }
}

const TRUSTED_PUBLISHERS: &[&str] = &[
    // === Operating System Vendors ===
    "microsoft corporation",
    "microsoft windows",
    "microsoft code signing pca",
    "microsoft windows publisher",
    "microsoft windows hardware compatibility publisher",
    "microsoft timestamping service",
    "apple inc",
    "apple inc.",
    // === Major Tech Companies ===
    "google llc",
    "google inc",
    "google inc.",
    "alphabet inc",
    "amazon.com services llc",
    "amazon web services",
    "meta platforms",
    "facebook",
    // === Browsers ===
    "mozilla corporation",
    "mozilla foundation",
    "brave software, inc",
    "brave software",
    "opera software",
    "vivaldi technologies",
    "the browser company",
    // === Development Tools ===
    "github, inc",
    "github, inc.",
    "git for windows",
    "python software foundation",
    "the rust foundation",
    "node.js foundation",
    "openjs foundation",
    "jetbrains s.r.o",
    "jetbrains s.r.o.",
    "sublime hq pty ltd",
    "visual studio code",
    "docker inc",
    "docker, inc",
    "hashicorp",
    "hashicorp, inc",
    "atlassian",
    "atlassian pty ltd",
    // === Security Vendors ===
    "malwarebytes inc",
    "malwarebytes corporation",
    "kaspersky lab",
    "kaspersky labs",
    "avast software",
    "avast software s.r.o",
    "avg technologies",
    "bitdefender",
    "bitdefender srl",
    "eset",
    "eset, spol",
    "symantec corporation",
    "norton",
    "nortonlifelock",
    "mcafee",
    "mcafee, llc",
    "trend micro",
    "trend micro incorporated",
    "sophos",
    "sophos limited",
    "crowdstrike",
    "crowdstrike, inc",
    "palo alto networks",
    "fortinet",
    "webroot",
    "f-secure",
    "f-secure corporation",
    "comodo",
    "comodo security solutions",
    "avira",
    "avira operations",
    // === Hardware Vendors ===
    "nvidia corporation",
    "nvidia",
    "advanced micro devices",
    "amd",
    "intel corporation",
    "intel",
    "logitech",
    "logitech inc",
    "razer inc",
    "razer usa ltd",
    "corsair",
    "corsair memory",
    "steelseries",
    "hyperx",
    "kingston technology",
    "samsung electronics",
    "seagate technology",
    "western digital",
    "realtek semiconductor",
    "realtek",
    "qualcomm",
    "broadcom",
    "marvell",
    "dell",
    "dell inc",
    "dell technologies",
    "hp inc",
    "hewlett packard",
    "hewlett-packard",
    "lenovo",
    "lenovo (beijing)",
    "asus",
    "asustek computer",
    "acer",
    "acer incorporated",
    "msi",
    "micro-star international",
    "gigabyte",
    "gigabyte technology",
    // === Common Applications ===
    "valve corp",
    "valve corporation",
    "epic games",
    "epic games, inc",
    "discord inc",
    "discord",
    "spotify ab",
    "spotify",
    "slack technologies",
    "slack technologies, inc",
    "zoom video communications",
    "zoom video communications, inc",
    "dropbox, inc",
    "dropbox",
    "adobe inc",
    "adobe systems",
    "adobe systems incorporated",
    "autodesk",
    "autodesk, inc",
    "unity technologies",
    "unreal engine",
    "blizzard entertainment",
    "activision",
    "electronic arts",
    "ea",
    "ubisoft",
    "riot games",
    "riot games, inc",
    "rockstar games",
    "take-two interactive",
    "steam",
    // === Communication & Productivity ===
    "telegram fz-llc",
    "telegram messenger",
    "signal",
    "signal messenger",
    "whatsapp",
    "whatsapp llc",
    "skype",
    "notion labs",
    "notion labs, inc",
    "evernote",
    "evernote corporation",
    "obsidian",
    "1password",
    "agilebits",
    "lastpass",
    "logmein",
    "bitwarden",
    "bitwarden inc",
    "dashlane",
    "keeper security",
    // === Virtualization & Cloud ===
    "oracle corporation",
    "oracle america",
    "vmware, inc",
    "vmware",
    "citrix",
    "citrix systems",
    "parallels",
    "parallels international",
    "virtualbox",
    "red hat",
    "red hat, inc",
    "canonical",
    "canonical ltd",
    "suse",
    "suse llc",
    // === Utilities & System Tools ===
    "7-zip",
    "igor pavlov",
    "rarlab",
    "win.rar gmbh",
    "piriform",
    "piriform software",
    "ccleaner",
    "iolo technologies",
    "glarysoft",
    "auslogics",
    "wise care 365",
    "wisecleaner",
    "iobit",
    "iobit information technology",
    // === Media & Creative ===
    "videolan",
    "vlc",
    "obs",
    "obs project",
    "audacity",
    "audacity team",
    "gimp",
    "inkscape",
    "blender foundation",
    "davinci resolve",
    "blackmagic design",
    // === Networking ===
    "cisco",
    "cisco systems",
    "netgear",
    "tp-link",
    "linksys",
    "zyxel",
    "ubiquiti",
    "ubiquiti inc",
    "openvpn",
    "openvpn inc",
    "nordvpn",
    "nord security",
    "expressvpn",
    "surfshark",
    "private internet access",
    "mullvad",
    "wireguard",
    "tailscale",
    "tailscale inc",
    "cloudflare",
    "cloudflare, inc",
    // === Database & Dev Infrastructure ===
    "mongodb",
    "mongodb, inc",
    "elastic",
    "elasticsearch",
    "redis",
    "redis ltd",
    "postgresql",
    "mariadb",
    "mariadb corporation",
    "percona",
    "cockroach labs",
    // === Financial & Business ===
    "intuit",
    "intuit inc",
    "quickbooks",
    "turbotax",
    "quicken",
    "sage",
    "sage group",
    "sap",
    "sap se",
    "salesforce",
    "salesforce.com",
    "servicenow",
    "workday",
    "docusign",
    "docusign, inc",
];

fn is_trusted_publisher_strict(signer_name: &str) -> bool {
    let lower = signer_name.trim().to_lowercase();
    for publisher in TRUSTED_PUBLISHERS {
        if lower == publisher.trim().to_lowercase() {
            return true;
        }
    }
    false
}

fn is_trusted_publisher_fuzzy(signer_name: &str) -> bool {
    let lower = signer_name.to_lowercase();
    for publisher in TRUSTED_PUBLISHERS {
        if lower.contains(publisher) {
            return true;
        }
    }
    false
}

/// Extract CN (Common Name) from a certificate subject string
fn extract_cn(subject: &str) -> Option<String> {
    for part in subject.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return Some(cn.trim().to_string());
        }
    }

    if !subject.is_empty() && !subject.contains('=') {
        return Some(subject.to_string());
    }

    None
}

fn is_trusted_certificate_authority(issuer: &str) -> bool {
    let lower = issuer.to_lowercase();

    let trusted_cas = [
        "digicert",
        "verisign",
        "comodo",
        "sectigo",
        "globalsign",
        "entrust",
        "godaddy",
        "thawte",
        "geotrust",
        "symantec",
        "microsoft",
        "apple",
        "google",
        "let's encrypt",
        "ssl.com",
        "certum",
    ];

    for ca in trusted_cas {
        if lower.contains(ca) {
            return true;
        }
    }

    false
}

pub fn verify_signature(file_path: &str) -> SignatureInfo {
    let path = Path::new(file_path);

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    if !["exe", "dll", "sys", "msi", "cab", "ocx", "drv", "scr"].contains(&ext.as_str()) {
        return SignatureInfo::default();
    }

    let ps_script = format!(
        r#"
        $ErrorActionPreference = 'SilentlyContinue'
        $sig = Get-AuthenticodeSignature -LiteralPath '{}'
        $cert = $sig.SignerCertificate
        @{{
            Status = if ($null -ne $sig.Status) {{ $sig.Status.ToString() }} else {{ 'Unknown' }}
            StatusMessage = $sig.StatusMessage
            SignerCN = if ($cert) {{ $cert.Subject }} else {{ '' }}
            Issuer = if ($cert) {{ $cert.Issuer }} else {{ '' }}
            Thumbprint = if ($cert) {{ $cert.Thumbprint }} else {{ '' }}
            NotBefore = if ($cert) {{ $cert.NotBefore.ToString('o') }} else {{ '' }}
            NotAfter = if ($cert) {{ $cert.NotAfter.ToString('o') }} else {{ '' }}
            TimeStamperCertNotBefore = if ($sig.TimeStamperCertificate) {{ $sig.TimeStamperCertificate.NotBefore.ToString('o') }} else {{ '' }}
            RawSubject = if ($cert) {{ $cert.Subject }} else {{ '' }}
            RawIssuer = if ($cert) {{ $cert.Issuer }} else {{ '' }}
        }} | ConvertTo-Json -Compress
        "#,
        file_path.replace('\'', "''") // Escape single quotes
    );

    // Use timeout to prevent individual PowerShell hangs
    let output = {
        use std::io::Read;
        const SINGLE_SIG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        let child = {
            let mut cmd = Command::new("powershell");
            crate::core::utils::configure_background_command(&mut cmd)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    &ps_script,
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
        };

        match child {
            Ok(mut child) => {
                let start = std::time::Instant::now();
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let mut stdout = Vec::new();
                            if let Some(mut out) = child.stdout.take() {
                                let _ = out.read_to_end(&mut stdout);
                            }
                            break Ok(std::process::Output {
                                status,
                                stdout,
                                stderr: Vec::new(),
                            });
                        }
                        Ok(None) => {
                            if start.elapsed() > SINGLE_SIG_TIMEOUT {
                                let _ = child.kill();
                                let _ = child.wait();
                                break Err(());
                            }
                            std::thread::sleep(std::time::Duration::from_millis(25));
                        }
                        Err(_) => {
                            let _ = child.kill();
                            break Err(());
                        }
                    }
                }
            }
            Err(e) => {
                log::debug!("PowerShell signature check failed: {}", e);
                Err(())
            }
        }
    };

    let output = match output {
        Ok(o) => o,
        Err(_) => return SignatureInfo::default(),
    };

    if !output.status.success() {
        log::debug!("PowerShell signature check returned non-zero");
        return SignatureInfo::default();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("Failed to parse signature JSON: {}", e);
            return SignatureInfo::default();
        }
    };

    let status = parsed.get("Status").and_then(|v| v.as_str()).unwrap_or("");
    let status_message = parsed
        .get("StatusMessage")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let signer_cn = parsed
        .get("SignerCN")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let issuer = parsed
        .get("Issuer")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let timestamp = parsed
        .get("TimeStamperCertNotBefore")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let thumbprint = parsed
        .get("Thumbprint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let not_before = parsed
        .get("NotBefore")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let not_after = parsed
        .get("NotAfter")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let raw_subject = parsed
        .get("RawSubject")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let raw_issuer = parsed
        .get("RawIssuer")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let is_signed = !signer_cn.is_empty();
    let is_valid = status == "Valid";
    let signer_name = extract_cn(&signer_cn);

    let mut trust_level = TrustLevel::None;
    let mut is_trusted_publisher = false;

    if is_signed && is_valid {
        if let Some(ref name) = signer_name {
            if is_trusted_publisher_strict(name) {
                trust_level = upgrade_trust(trust_level, TrustLevel::PublisherAllowlist);
                is_trusted_publisher = true;
            } else if is_trusted_publisher_fuzzy(name) {
                trust_level = upgrade_trust(trust_level, TrustLevel::PublisherMatch);
                is_trusted_publisher = true;
            }
        }
        if let Some(ref iss) = issuer {
            if is_trusted_certificate_authority(iss) {
                trust_level = upgrade_trust(trust_level, TrustLevel::CA);
            }
        }
        if let Some(ref subj) = raw_subject {
            if subj == issuer.as_deref().unwrap_or("") {
                trust_level = upgrade_trust(trust_level, TrustLevel::SelfSigned);
            }
        }
    } else if is_signed && !is_valid {
        trust_level = TrustLevel::Invalid;
    } else {
        trust_level = TrustLevel::None;
    }

    SignatureInfo {
        is_signed,
        is_valid,
        signer_name,
        issuer,
        timestamp,
        thumbprint,
        not_before,
        not_after,
        trust_level,
        is_trusted_publisher,
        raw_subject,
        raw_issuer,
        status_message,
    }
}

/// Backward compatibility: fuzzy match
pub fn is_trusted_publisher(signer_name: &str) -> bool {
    is_trusted_publisher_fuzzy(signer_name)
}

pub fn is_trusted_signed(file_path: &str) -> bool {
    let sig = verify_signature(file_path);
    sig.is_valid && sig.is_trusted_publisher
}

/// Batch-verify Authenticode signatures for multiple files in a single PowerShell invocation.
/// Returns a HashMap from file_path → SignatureInfo.
pub fn verify_signatures_batch(file_paths: &[&str]) -> HashMap<String, SignatureInfo> {
    let mut results = HashMap::new();
    if file_paths.is_empty() {
        return results;
    }

    // Filter to signable extensions only; return default for the rest
    let signable_exts = ["exe", "dll", "sys", "msi", "cab", "ocx", "drv", "scr"];
    let mut signable_paths = Vec::new();
    for &fp in file_paths {
        let ext = Path::new(fp)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();
        if signable_exts.contains(&ext.as_str()) {
            signable_paths.push(fp);
        } else {
            results.insert(fp.to_string(), SignatureInfo::default());
        }
    }

    if signable_paths.is_empty() {
        return results;
    }

    // Build a PowerShell script that checks all files and outputs one JSON object per line.
    // Each line is: filepath<TAB>json
    let mut script = String::from("$ErrorActionPreference = 'SilentlyContinue'\n$paths = @(\n");
    for path in &signable_paths {
        script.push_str(&format!("  '{}'\n", path.replace('\'', "''")));
    }
    script.push_str(
        ")\n\
         foreach ($p in $paths) {\n\
           $sig = Get-AuthenticodeSignature -LiteralPath $p\n\
           $cert = $sig.SignerCertificate\n\
           $obj = @{\n\
             Status = if ($null -ne $sig.Status) { $sig.Status.ToString() } else { 'Unknown' }\n\
             SignerCN = if ($cert) { $cert.Subject } else { '' }\n\
             Issuer = if ($cert) { $cert.Issuer } else { '' }\n\
             TimeStamperCertNotBefore = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.NotBefore.ToString('o') } else { '' }\n\
           }\n\
           $json = $obj | ConvertTo-Json -Compress\n\
           Write-Output ($p + \"`t\" + $json)\n\
         }\n",
    );

    // Use spawn + timeout to prevent PowerShell from hanging indefinitely.
    let output = {
        use std::io::Read;
        const BATCH_SIG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

        let child = {
            let mut cmd = Command::new("powershell");
            crate::core::utils::configure_background_command(&mut cmd)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    &script,
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
        };

        match child {
            Ok(mut child) => {
                let start = std::time::Instant::now();
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let mut stdout = Vec::new();
                            if let Some(mut out) = child.stdout.take() {
                                let _ = out.read_to_end(&mut stdout);
                            }
                            break Ok(std::process::Output {
                                status,
                                stdout,
                                stderr: Vec::new(),
                            });
                        }
                        Ok(None) => {
                            if start.elapsed() > BATCH_SIG_TIMEOUT {
                                log::warn!(
                                    "Batch signature verification timed out after {}s - killing PowerShell",
                                    BATCH_SIG_TIMEOUT.as_secs()
                                );
                                let _ = child.kill();
                                let _ = child.wait();
                                break Err("Timed out");
                            }
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                        Err(_) => {
                            let _ = child.kill();
                            break Err("Process error");
                        }
                    }
                }
            }
            Err(e) => Err({
                log::debug!("Batch signature check failed to launch: {}", e);
                "Launch failed"
            }),
        }
    };

    let output = match output {
        Ok(o) => o,
        Err(_reason) => {
            for path in &signable_paths {
                results.insert(path.to_string(), SignatureInfo::default());
            }
            return results;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        let Some((file_path, json_str)) = line.split_once('\t') else {
            continue;
        };

        let parsed: serde_json::Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let status = parsed.get("Status").and_then(|v| v.as_str()).unwrap_or("");
        let signer_cn = parsed
            .get("SignerCN")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let issuer = parsed
            .get("Issuer")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // (B) renamed key
        let timestamp = parsed
            .get("TimeStamperCertNotBefore")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let is_signed = !signer_cn.is_empty();
        let is_valid = status == "Valid";
        let signer_name = extract_cn(&signer_cn);

        let mut trust_level = TrustLevel::None;
        let mut is_trusted_publisher = false;

        if is_signed && is_valid {
            if let Some(ref name) = signer_name {
                if is_trusted_publisher_strict(name) {
                    trust_level = upgrade_trust(trust_level, TrustLevel::PublisherAllowlist);
                    is_trusted_publisher = true;
                } else if is_trusted_publisher_fuzzy(name) {
                    trust_level = upgrade_trust(trust_level, TrustLevel::PublisherMatch);
                    is_trusted_publisher = true;
                }
            }
            if let Some(ref iss) = issuer {
                if is_trusted_certificate_authority(iss) {
                    trust_level = upgrade_trust(trust_level, TrustLevel::CA);
                }
            }
        } else if is_signed && !is_valid {
            trust_level = TrustLevel::Invalid;
        } else {
            trust_level = TrustLevel::None;
        }

        results.insert(
            file_path.to_string(),
            SignatureInfo {
                is_signed,
                is_valid,
                signer_name,
                issuer,
                timestamp,
                thumbprint: None,
                not_before: None,
                not_after: None,
                trust_level,
                is_trusted_publisher,
                raw_subject: None,
                raw_issuer: None,
                status_message: None,
            },
        );
    }

    // Ensure all requested paths have an entry (defaults for any that failed)
    for path in &signable_paths {
        results
            .entry(path.to_string())
            .or_insert_with(SignatureInfo::default);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cn() {
        assert_eq!(
            extract_cn("CN=Microsoft Corporation, O=Microsoft Corporation"),
            Some("Microsoft Corporation".to_string())
        );
        assert_eq!(
            extract_cn("CN=Google LLC, O=Google LLC, L=Mountain View"),
            Some("Google LLC".to_string())
        );
        assert_eq!(extract_cn(""), None);
    }

    #[test]
    fn test_is_trusted_publisher() {
        // Major vendors
        assert!(is_trusted_publisher("Microsoft Corporation"));
        assert!(is_trusted_publisher("Google LLC"));
        assert!(is_trusted_publisher("Apple Inc."));
        assert!(is_trusted_publisher("NVIDIA Corporation"));
        // Development tools
        assert!(is_trusted_publisher("Python Software Foundation"));
        assert!(is_trusted_publisher("JetBrains s.r.o."));
        assert!(is_trusted_publisher("GitHub, Inc."));
        // Security vendors
        assert!(is_trusted_publisher("Malwarebytes Inc"));
        assert!(is_trusted_publisher("Kaspersky Lab"));
        assert!(is_trusted_publisher("CrowdStrike, Inc"));
        // Games
        assert!(is_trusted_publisher("Valve Corporation"));
        assert!(is_trusted_publisher("Epic Games, Inc"));
        assert!(is_trusted_publisher("Riot Games, Inc"));
        // Unknown publishers
        assert!(!is_trusted_publisher("Unknown Malware Author"));
        assert!(!is_trusted_publisher("Random Software LLC"));
        assert!(!is_trusted_publisher(""));
    }

    #[test]
    fn test_is_trusted_certificate_authority() {
        assert!(is_trusted_certificate_authority(
            "DigiCert SHA2 Assured ID Code Signing CA"
        ));
        assert!(is_trusted_certificate_authority(
            "CN=Microsoft Code Signing PCA 2011"
        ));
        assert!(is_trusted_certificate_authority(
            "VeriSign Class 3 Code Signing"
        ));
        assert!(!is_trusted_certificate_authority("Self-Signed Certificate"));
        assert!(!is_trusted_certificate_authority("Unknown CA"));
    }

    #[test]
    fn test_signature_info_default() {
        let info = SignatureInfo::default();
        assert!(!info.is_signed);
        assert!(!info.is_valid);
        assert!(!info.is_trusted_publisher);
        assert!(info.signer_name.is_none());
        assert_eq!(info.trust_level, TrustLevel::None);
    }

    #[test]
    fn test_extract_cn_no_cn() {
        // Subject without CN= should return None if it has = signs
        assert_eq!(extract_cn("O=Some Org, L=City"), None);
    }

    #[test]
    fn test_extract_cn_plain_name() {
        // Subject without any = should return the whole string
        assert_eq!(
            extract_cn("Microsoft Corporation"),
            Some("Microsoft Corporation".to_string())
        );
    }

    #[test]
    fn test_trust_rank_ordering() {
        assert!(
            trust_rank(&TrustLevel::PublisherAllowlist) > trust_rank(&TrustLevel::PublisherMatch)
        );
        assert!(trust_rank(&TrustLevel::PublisherMatch) > trust_rank(&TrustLevel::CA));
        assert!(trust_rank(&TrustLevel::CA) > trust_rank(&TrustLevel::SelfSigned));
        assert!(trust_rank(&TrustLevel::SelfSigned) > trust_rank(&TrustLevel::Unknown));
        assert!(trust_rank(&TrustLevel::Unknown) > trust_rank(&TrustLevel::Untrusted));
        assert!(trust_rank(&TrustLevel::Untrusted) > trust_rank(&TrustLevel::Invalid));
        assert!(trust_rank(&TrustLevel::Invalid) > trust_rank(&TrustLevel::None));
    }

    #[test]
    fn test_upgrade_trust_prefers_higher() {
        let result = upgrade_trust(TrustLevel::None, TrustLevel::CA);
        assert_eq!(result, TrustLevel::CA);

        // Should NOT downgrade
        let result = upgrade_trust(TrustLevel::PublisherAllowlist, TrustLevel::CA);
        assert_eq!(result, TrustLevel::PublisherAllowlist);
    }

    #[test]
    fn test_is_trusted_publisher_case_insensitive() {
        assert!(is_trusted_publisher("MICROSOFT CORPORATION"));
        assert!(is_trusted_publisher("microsoft corporation"));
        assert!(is_trusted_publisher("Microsoft Corporation"));
    }

    #[test]
    fn test_is_trusted_publisher_strict_exact_match() {
        assert!(is_trusted_publisher_strict("Microsoft Corporation"));
        assert!(is_trusted_publisher_strict("Google LLC"));
        assert!(!is_trusted_publisher_strict("Microsoft")); // partial doesn't work for strict
        assert!(!is_trusted_publisher_strict(
            "Some Microsoft Corporation Software"
        )); // extra text
    }

    #[test]
    fn test_verify_signature_non_signable_extension() {
        // .txt files should return default (unsigned) SignatureInfo
        let info = verify_signature("C:\\test\\document.txt");
        assert!(!info.is_signed);
        assert!(!info.is_valid);
        assert_eq!(info.trust_level, TrustLevel::None);
    }
}
