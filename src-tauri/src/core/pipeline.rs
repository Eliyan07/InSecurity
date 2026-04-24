//! Detection Pipeline Orchestrator

#[cfg(feature = "emulation")]
use crate::core::emulation::{EmulationConfig, Emulator};
use crate::core::{
    behavior, ingestion, ml_bridge, reputation,
    signature::{verify_signature, SignatureInfo},
    static_scanner,
    utils::{
        is_dev_build_artifact_path, is_probable_installer_path, is_scannable_file,
        is_self_product_installer_path, is_system_path, is_trusted_publisher_path,
    },
    yara_scanner,
};
use crate::ml::{EmberExtractor, NoveltyExtractor};
use crate::{NOVELTY_MODEL, ONNX_CLASSIFIER};
use serde::{Deserialize, Serialize};
#[cfg(feature = "emulation")]
use std::time::Duration;

/// Maximum file size for scanning (100MB)
pub const MAX_SCAN_SIZE: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malware,
    Unknown,
}

#[must_use = "scan results should be checked for threats"]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    pub file_hash: String,
    pub verdict: Verdict,
    pub confidence: f64,
    pub threat_level: String,
    pub threat_name: Option<String>,
    pub scan_time_ms: u64,
    pub detailed_results: DetailedResults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedResults {
    pub static_analysis: Option<static_scanner::StaticAnalysisResult>,
    pub ml_prediction: Option<ml_bridge::MLPrediction>,
    pub reputation_score: Option<reputation::ReputationScore>,
    pub novelty_score: Option<ml_bridge::NoveltyPrediction>,
    pub behavior_analysis: Option<behavior::BehaviorAnalysis>,
    pub emulation_result: Option<EmulationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_info: Option<SignatureInfoSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfoSummary {
    pub is_signed: bool,
    pub is_valid: bool,
    pub signer_name: Option<String>,
    pub issuer: Option<String>,
    pub timestamp: Option<String>,
    pub thumbprint: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub trust_level: crate::core::signature::TrustLevel,
    pub is_trusted_publisher: bool,
    pub raw_subject: Option<String>,
    pub raw_issuer: Option<String>,
    pub status_message: Option<String>,
}

impl From<SignatureInfo> for SignatureInfoSummary {
    fn from(info: SignatureInfo) -> Self {
        SignatureInfoSummary {
            is_signed: info.is_signed,
            is_valid: info.is_valid,
            signer_name: info.signer_name,
            issuer: info.issuer,
            timestamp: info.timestamp,
            thumbprint: info.thumbprint,
            not_before: info.not_before,
            not_after: info.not_after,
            trust_level: info.trust_level,
            is_trusted_publisher: info.is_trusted_publisher,
            raw_subject: info.raw_subject,
            raw_issuer: info.raw_issuer,
            status_message: info.status_message,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationSummary {
    pub instructions_executed: u64,
    pub detected_oep: Option<u64>,
    pub api_call_count: usize,
    pub suspicious_behaviors: Vec<String>,
    pub unpacking_detected: bool,
}

pub struct DetectionPipeline;

impl DetectionPipeline {
    #[must_use]
    pub fn is_excluded(file_path: &str) -> bool {
        if let Some(db_mutex) = crate::get_database() {
            if let Ok(guard) = db_mutex.lock() {
                if let Some(ref conn) = *guard {
                    if let Ok(excluded) =
                        crate::database::queries::DatabaseQueries::is_path_excluded(conn, file_path)
                    {
                        return excluded;
                    }
                }
            }
        }
        false
    }

    /// Async version of is_excluded that runs DB access on a blocking thread
    /// Use this in scan_file_internal to avoid blocking the tokio runtime
    async fn is_excluded_async(file_path: &str) -> bool {
        let path = file_path.to_string();
        crate::with_db_async(move |conn| {
            Ok(
                crate::database::queries::DatabaseQueries::is_path_excluded(conn, &path)
                    .unwrap_or(false),
            )
        })
        .await
        .unwrap_or(false)
    }

    /// Run complete detection pipeline on a file
    pub async fn scan_file(file_path: &str) -> Result<ScanResult, Box<dyn std::error::Error>> {
        Self::scan_file_internal(file_path, false, false).await
    }

    /// Run complete detection pipeline on a file, optionally bypassing cache
    /// Use bypass_cache=true for manual scans (Quick/Full scan) to force fresh analysis
    pub async fn scan_file_with_options(
        file_path: &str,
        bypass_cache: bool,
    ) -> Result<ScanResult, Box<dyn std::error::Error>> {
        Self::scan_file_internal(file_path, bypass_cache, false).await
    }

    /// Ultra-fast quick scan mode - hash lookups only
    /// 1. Compute file hash
    /// 2. Check against known malware database (blacklist)
    /// 3. Check against known good database (whitelist)
    /// 4. Only run full pipeline on unknown/suspicious files
    pub async fn scan_file_quick(
        file_path: &str,
    ) -> Result<ScanResult, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();

        // Skip non-scannable files immediately
        if !is_scannable_file(file_path) {
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: String::new(),
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Non-executable".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        if is_dev_build_artifact_path(file_path) {
            log::debug!("Skipping developer/build artifact path: {}", file_path);
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: String::new(),
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Developer Build Artifact".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        // Skip system paths
        if is_system_path(file_path) {
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: String::new(),
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("System Path".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        // Compute hash on a blocking thread to avoid starving the tokio runtime
        // File I/O is synchronous and would block the async executor otherwise
        let file_path_owned = file_path.to_string();
        let file_hash = tokio::task::spawn_blocking(move || {
            ingestion::compute_file_hash(&file_path_owned).unwrap_or_default()
        })
        .await
        .unwrap_or_default();

        if file_hash.is_empty() {
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: String::new(),
                verdict: Verdict::Unknown,
                confidence: 0.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Could not read file".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        // Check blacklist (known malware) - instant
        if static_scanner::is_blacklisted(&file_hash) {
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash,
                verdict: Verdict::Malware,
                confidence: 0.95,
                threat_level: "HIGH".to_string(),
                threat_name: Some("Known Malware (Blacklisted Hash)".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        // Check whitelist (known good) - instant
        if static_scanner::is_whitelisted(&file_hash) {
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash,
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Whitelisted".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        // For unknown files in high-risk locations (Downloads, Desktop,
        // Temp, drive root, etc.), run the full detection pipeline. The file
        // already passed is_scannable_file() above, so it has a risky
        // extension. This fulfills the docstring promise: "Only run full
        // pipeline on unknown/suspicious files".
        if crate::core::utils::is_high_risk_path(file_path) {
            log::info!(
                "Quick scan: unknown file in high-risk path, running full pipeline: {}",
                file_path
            );
            return Self::scan_file_with_options(file_path, true).await;
        }

        // Low-risk unknowns (trusted locations, non-download paths):
        // return clean with lower confidence
        Ok(ScanResult {
            file_path: file_path.to_string(),
            file_hash,
            verdict: Verdict::Clean,
            confidence: 0.4,
            threat_level: "LOW".to_string(),
            threat_name: Some("Quick Scan - Not in database".to_string()),
            scan_time_ms: start.elapsed().as_millis() as u64,
            detailed_results: DetailedResults {
                static_analysis: None,
                ml_prediction: None,
                reputation_score: None,
                novelty_score: None,
                behavior_analysis: None,
                emulation_result: None,
                signature_info: None,
            },
        })
    }

    /// Internal scan implementation (full pipeline)
    async fn scan_file_internal(
        file_path: &str,
        bypass_cache: bool,
        _quick_mode: bool,
    ) -> Result<ScanResult, Box<dyn std::error::Error>> {
        use crate::core::rate_limiter::SCAN_RATE_LIMITER;

        let start = std::time::Instant::now();

        // Rate limit only real-time scans, not manual scans (Quick/Full/Custom).
        // Manual scans already have their own concurrency control via buffer_unordered.
        // `is_scanning()` reads the IS_SCANNING AtomicBool - true during manual scans.
        if !bypass_cache && !crate::commands::scan::is_scanning() {
            if let Some(wait_seconds) = SCAN_RATE_LIMITER.acquire() {
                log::warn!("Scan rate limited, please wait {} seconds", wait_seconds);
                return Err(format!(
                    "Rate limited: too many scans, wait {} seconds",
                    wait_seconds
                )
                .into());
            }
        }

        // Stage 0: Check exclusions first (fastest check) - async to avoid blocking tokio
        if Self::is_excluded_async(file_path).await {
            log::debug!("File excluded from scanning: {}", file_path);
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: String::new(),
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Excluded".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        // Stage 0.1: Skip app's own directory, build artifacts, and system paths
        if is_dev_build_artifact_path(file_path) {
            log::debug!("Skipping developer/build artifact path: {}", file_path);
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: String::new(),
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Developer Build Artifact".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        if is_system_path(file_path) {
            log::debug!("Skipping system/app path: {}", file_path);
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: String::new(),
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("System Path".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        // Stage 0.2: Skip non-executable file types (data files that can't contain malware)
        if !is_scannable_file(file_path) {
            log::debug!("Skipping non-scannable file type: {}", file_path);
            let fp = file_path.to_string();
            let file_hash = tokio::task::spawn_blocking(move || {
                ingestion::compute_file_hash(&fp).unwrap_or_default()
            })
            .await
            .unwrap_or_default();
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash,
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Non-executable".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: None,
                },
            });
        }

        //  Stage 0.3: Check digital signature EARLY for trusted signed files
        //  Only meaningful for PE executables - scripts, archives, etc. don't have
        //  Authenticode signatures and the WinVerifyTrust call wastes ~50-200ms each.
        let is_pe_extension = {
            let ext = std::path::Path::new(file_path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            matches!(
                ext.as_str(),
                "exe" | "dll" | "sys" | "drv" | "ocx" | "scr" | "cpl" | "msi"
            )
        };
        let signature_info = if is_pe_extension {
            let fp = file_path.to_string();
            tokio::task::spawn_blocking(move || verify_signature(&fp))
                .await
                .unwrap_or_else(|_| SignatureInfo::default())
        } else {
            SignatureInfo::default()
        };

        if signature_info.is_valid
            && signature_info.is_trusted_publisher
            && is_probable_installer_path(file_path)
        {
            log::info!(
                "Trusted signed installer detected - skipping deep analysis: {} (signer: {})",
                file_path,
                signature_info.signer_name.as_deref().unwrap_or("unknown")
            );
            let fp = file_path.to_string();
            let quick_hash = tokio::task::spawn_blocking(move || {
                ingestion::compute_file_hash(&fp).unwrap_or_default()
            })
            .await
            .unwrap_or_default();

            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: quick_hash,
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Trusted Installer".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: Some(signature_info.clone().into()),
                },
            });
        }

        if signature_info.is_valid && signature_info.is_trusted_publisher {
            // Double-trust: valid signature from a known publisher AND in a trusted install location.
            // Early-exit as Clean to avoid false positives from YARA/behavior matching legitimate
            // OS/vendor functionality (e.g. OneDrive using crypto APIs, file enumeration, etc.).
            if is_trusted_publisher_path(file_path) {
                log::info!(
                    "Trusted signed + trusted path - skipping analysis: {} (signer: {})",
                    file_path,
                    signature_info.signer_name.as_deref().unwrap_or("unknown")
                );
                let fp = file_path.to_string();
                let quick_hash = tokio::task::spawn_blocking(move || {
                    ingestion::compute_file_hash(&fp).unwrap_or_default()
                })
                .await
                .unwrap_or_default();

                return Ok(ScanResult {
                    file_path: file_path.to_string(),
                    file_hash: quick_hash,
                    verdict: Verdict::Clean,
                    confidence: 1.0,
                    threat_level: "LOW".to_string(),
                    threat_name: Some("Trusted Publisher".to_string()),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    detailed_results: DetailedResults {
                        static_analysis: None,
                        ml_prediction: None,
                        reputation_score: None,
                        novelty_score: None,
                        behavior_analysis: None,
                        emulation_result: None,
                        signature_info: Some(signature_info.into()),
                    },
                });
            }

            log::info!(
                "Trusted signed executable (not in trusted path) - continuing analysis: {} (signer: {})",
                file_path,
                signature_info.signer_name.as_deref().unwrap_or("unknown")
            );
        }

        // Stage 0.5: Quick hash check - compute hash and check cache before full scan
        let fp = file_path.to_string();
        let quick_hash = tokio::task::spawn_blocking(move || {
            ingestion::compute_file_hash(&fp).unwrap_or_default()
        })
        .await
        .unwrap_or_default();

        // Blacklist check before whitelist - blacklist always wins
        if !quick_hash.is_empty() && static_scanner::is_blacklisted(&quick_hash) {
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: quick_hash,
                verdict: Verdict::Malware,
                confidence: 0.95,
                threat_level: "HIGH".to_string(),
                threat_name: Some("Known Malware (Blacklisted Hash)".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: Some(signature_info.into()),
                },
            });
        }

        if !quick_hash.is_empty() && static_scanner::is_whitelisted(&quick_hash) {
            log::debug!("File hash is whitelisted: {}", file_path);
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: quick_hash,
                verdict: Verdict::Clean,
                confidence: 1.0,
                threat_level: "LOW".to_string(),
                threat_name: Some("Whitelisted".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: Some(signature_info.into()),
                },
            });
        }

        // Check cache only if not bypassing (real-time uses cache, manual scans bypass it)
        // Two-phase lookup: check in-memory cache first (short lock), then fall back to DB
        // (separate lock) to avoid holding cache lock during DB I/O.
        if !bypass_cache && !quick_hash.is_empty() {
            // Phase 1: Check in-memory cache (quick)
            let cached_result = {
                if let Ok(mut cache_guard) = crate::CACHE_MANAGER.lock() {
                    cache_guard.get_cache_mut().get(&quick_hash)
                } else {
                    None
                }
            };
            // Phase 2: If not in cache, try DB (without holding cache lock)
            let cached_result = cached_result.or_else(|| {
                let db_result = crate::with_db(|conn| {
                    crate::database::queries::DatabaseQueries::get_verdict_by_hash(
                        conn,
                        &quick_hash,
                    )
                    .ok()
                    .flatten()
                });
                if let Some(row) = db_result {
                    let cached = crate::cache::hash_cache::CachedVerdict {
                        verdict: row.verdict.clone(),
                        confidence: row.confidence,
                        timestamp: row.scanned_at as u64,
                        ttl_seconds: 86400,
                        last_accessed: row.scanned_at as u64,
                        threat_name: row.threat_name.clone(),
                    };
                    // Insert into cache (re-acquire lock briefly)
                    if let Ok(mut cache_guard) = crate::CACHE_MANAGER.lock() {
                        cache_guard
                            .get_cache_mut()
                            .set(quick_hash.clone(), cached.clone());
                    }
                    Some(cached)
                } else {
                    None
                }
            });
            if let Some(cached) = cached_result {
                log::debug!("Cache hit for {}: verdict={}", file_path, cached.verdict);
                let verdict = match cached.verdict.to_lowercase().as_str() {
                    "clean" => Verdict::Clean,
                    "suspicious" | "pup" => Verdict::Suspicious,
                    "malware" => Verdict::Malware,
                    _ => Verdict::Unknown,
                };
                let threat_level = match verdict {
                    Verdict::Malware => "HIGH",
                    Verdict::Suspicious => "MEDIUM",
                    _ => "LOW",
                }
                .to_string();

                return Ok(ScanResult {
                    file_path: file_path.to_string(),
                    file_hash: quick_hash,
                    verdict,
                    confidence: cached.confidence,
                    threat_level,
                    threat_name: cached.threat_name.clone(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    detailed_results: DetailedResults {
                        static_analysis: None,
                        ml_prediction: None,
                        reputation_score: None,
                        novelty_score: None,
                        behavior_analysis: None,
                        emulation_result: None,
                        signature_info: Some(signature_info.into()),
                    },
                });
            }
        }

        let fp = file_path.to_string();
        let file_size =
            tokio::task::spawn_blocking(move || std::fs::metadata(&fp).map(|m| m.len()))
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!("Spawn blocking failed: {}", e).into()
                })?
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        if file_size > MAX_SCAN_SIZE {
            log::warn!(
                "File too large for scanning ({} bytes): {}",
                file_size,
                file_path
            );
            let fp = file_path.to_string();
            let file_hash = tokio::task::spawn_blocking(move || {
                ingestion::compute_file_hash(&fp).unwrap_or_default()
            })
            .await
            .unwrap_or_default();
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash,
                verdict: Verdict::Unknown,
                confidence: 0.0,
                threat_level: "LOW".to_string(),
                threat_name: Some(format!(
                    "File too large ({}MB limit)",
                    MAX_SCAN_SIZE / 1024 / 1024
                )),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: None,
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: Some(signature_info.into()),
                },
            });
        }

        // Stage 1: Ingestion + Stage 2: Static Analysis
        // Run on blocking thread - file I/O, hashing, YARA rules are all CPU/IO heavy
        // Pass the precomputed SHA256 from Stage 0.5 to avoid hashing the file a second time.
        let fp = file_path.to_string();
        let precomputed_hash = quick_hash.clone();
        let (metadata, file_content, static_result) = tokio::task::spawn_blocking(move || {
            let precomputed = if precomputed_hash.is_empty() {
                None
            } else {
                Some(precomputed_hash.as_str())
            };
            let ingestion_result = ingestion::ingest_file_with_hash(&fp, precomputed)
                .map_err(|e| format!("Ingestion failed: {}", e))?;
            let metadata = ingestion_result.metadata;
            let file_content = ingestion_result.content;

            let static_result = static_scanner::perform_static_analysis(
                &metadata.sha256_hash,
                &file_content,
                &metadata.file_type,
                &metadata.packer_flags,
                &metadata.embedded_objects,
            )
            .map_err(|e| format!("Static analysis failed: {}", e))?;

            Ok::<_, String>((metadata, file_content, static_result))
        })
        .await
        .map_err(|e| -> Box<dyn std::error::Error> {
            format!("Spawn blocking failed: {}", e).into()
        })?
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

        if static_result.is_blacklisted {
            // Blacklist always wins. Never treat as FP due to signature.
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: metadata.sha256_hash,
                verdict: Verdict::Malware,
                confidence: 0.95,
                threat_level: "HIGH".to_string(),
                threat_name: Some("Known Malware (Blacklisted Hash)".to_string()),
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: Some(static_result),
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: Some(signature_info.into()),
                },
            });
        }

        if static_result.is_whitelisted {
            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: metadata.sha256_hash,
                verdict: Verdict::Clean,
                confidence: 0.99,
                threat_level: "LOW".to_string(),
                threat_name: None,
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: Some(static_result),
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: None,
                    emulation_result: None,
                    signature_info: Some(signature_info.into()),
                },
            });
        }

        let is_from_trusted_location = is_trusted_publisher_path(file_path);
        let has_valid_signature = signature_info.is_valid;

        let is_low_risk = static_result.yara_matches.is_empty()
            && static_result.entropy_score < 7.5
            && static_result.suspicious_characteristics.len() < 2
            && (metadata.file_type != "PE" || has_valid_signature || is_from_trusted_location);

        if is_low_risk {
            log::debug!("Low-risk file detected, using fast path: {}", file_path);

            let fc = file_content.clone();
            let ft = metadata.file_type.clone();
            let fs = metadata.file_size;
            let sc = static_result.suspicious_characteristics.clone();
            let behavior_result = tokio::task::spawn_blocking(move || {
                behavior::analyze_behavior(&fc, &ft, fs, &sc).ok()
            })
            .await
            .unwrap_or(None);

            // Signature-aware behavior threshold: trusted-signed binaries (Microsoft, Google, etc.)
            // legitimately use crypto, file enumeration, and network APIs - don't flag them
            // unless behavior is extreme. Unsigned files keep the stricter threshold.
            let behavior_threshold =
                if signature_info.is_valid && signature_info.is_trusted_publisher {
                    0.90
                } else if signature_info.is_valid {
                    0.80
                } else {
                    0.60
                };

            let (verdict, confidence) = if let Some(ref beh) = behavior_result {
                if beh.behavior_score > behavior_threshold {
                    (Verdict::Suspicious, beh.behavior_score)
                } else {
                    (Verdict::Clean, 1.0 - beh.behavior_score)
                }
            } else {
                (Verdict::Clean, 0.90)
            };

            return Ok(ScanResult {
                file_path: file_path.to_string(),
                file_hash: metadata.sha256_hash,
                verdict,
                confidence,
                threat_level: "LOW".to_string(),
                threat_name: None,
                scan_time_ms: start.elapsed().as_millis() as u64,
                detailed_results: DetailedResults {
                    static_analysis: Some(static_result),
                    ml_prediction: None,
                    reputation_score: None,
                    novelty_score: None,
                    behavior_analysis: behavior_result,
                    emulation_result: None,
                    signature_info: Some(signature_info.into()),
                },
            });
        }

        // Full scan path for higher-risk files
        // Run ML, reputation, novelty, and behavior analysis concurrently.
        // ML uses ONNX Runtime (Rust-native), so it no longer shares the Python GIL.
        // All four tasks run truly in parallel.

        let file_content_for_ml = file_content.clone();
        let ml_file_size = metadata.file_size;
        // Clone the Arc so the spawn_blocking closure can own it.
        let onnx_clf = ONNX_CLASSIFIER.get().and_then(|opt| opt.clone());
        let ml_task = tokio::task::spawn_blocking(move || {
            // Skip for large files: EMBER extraction over 20MB is slow and
            // the ML signal on huge NSIS installers is low anyway.
            if ml_file_size > 20 * 1024 * 1024 {
                return None;
            }
            let features: Vec<f64> = EmberExtractor::new().extract_from_bytes(&file_content_for_ml);
            let ml_bridge = match onnx_clf {
                Some(clf) => ml_bridge::MLBridge::with_onnx("1.0.0", clf),
                None => {
                    log::warn!("ONNX classifier not available; skipping ML prediction");
                    return None;
                }
            };
            match ml_bridge.predict_onnx(features) {
                Ok(pred) => Some(pred),
                Err(e) => {
                    log::warn!("ML prediction failed: {}", e);
                    None
                }
            }
        });

        let hash_for_rep = metadata.sha256_hash.clone();
        let rep_task = reputation::query_reputation(&hash_for_rep);

        let fc = file_content.clone();
        let ft = metadata.file_type.clone();
        let fs = metadata.file_size;
        let sc = static_result.suspicious_characteristics.clone();
        let behavior_task = tokio::task::spawn_blocking(move || {
            // Skip for large files: byte-pattern scanning over 50 MB+
            // iterates gigabytes of data and takes minutes to complete.
            if fs > 20 * 1024 * 1024 {
                return None;
            }
            behavior::analyze_behavior(&fc, &ft, fs, &sc).ok()
        });

        let file_content_for_novelty = file_content.clone();
        let novelty_model = NOVELTY_MODEL.get().and_then(|opt| opt.clone());
        let novelty_task = tokio::task::spawn_blocking(move || {
            let model = novelty_model?;
            let features = NoveltyExtractor::new().extract_from_bytes(&file_content_for_novelty);
            match model.predict(&features) {
                Ok(pred) => Some(pred),
                Err(e) => {
                    log::warn!("Novelty prediction failed: {}", e);
                    None
                }
            }
        });

        let (ml_result, reputation, novelty, behavior_result) = tokio::join!(
            async { ml_task.await.unwrap_or(None) },
            async { rep_task.await.ok() },
            async { novelty_task.await.unwrap_or(None) },
            async { behavior_task.await.unwrap_or(None) },
        );

        // Stage 7: CPU/Memory Emulation (for packed PE files)
        #[cfg(feature = "emulation")]
        let emulation_summary = Self::run_emulation_if_needed(
            &file_content,
            &metadata.file_type,
            &metadata.packer_flags,
        );
        #[cfg(not(feature = "emulation"))]
        let emulation_summary: Option<EmulationSummary> = None;

        let (verdict, confidence, threat_level) = Self::determine_verdict(
            file_path,
            &signature_info,
            &static_result,
            &ml_result,
            &reputation,
            &behavior_result,
            &emulation_summary,
            &novelty,
        );

        // Derive threat_name from available analysis data
        let threat_name = Self::derive_threat_name(
            &verdict,
            confidence,
            &static_result,
            &ml_result,
            &reputation,
        );

        Ok(ScanResult {
            file_path: file_path.to_string(),
            file_hash: metadata.sha256_hash,
            verdict,
            confidence,
            threat_level,
            threat_name,
            scan_time_ms: start.elapsed().as_millis() as u64,
            detailed_results: DetailedResults {
                static_analysis: Some(static_result),
                ml_prediction: ml_result,
                reputation_score: reputation,
                novelty_score: novelty.clone(),
                behavior_analysis: behavior_result,
                emulation_result: emulation_summary,
                signature_info: Some(signature_info.into()),
            },
        })
    }

    /// Derive a human-readable threat name from available analysis data
    fn derive_threat_name(
        verdict: &Verdict,
        confidence: f64,
        static_result: &static_scanner::StaticAnalysisResult,
        ml_result: &Option<ml_bridge::MLPrediction>,
        reputation: &Option<reputation::ReputationScore>,
    ) -> Option<String> {
        // Only derive threat names for threats, not clean files
        if *verdict == Verdict::Clean {
            return None;
        }

        // Low-confidence suspicious detections should not surface a highly specific
        // malware family name in the main UI. Those details remain available in the
        // expanded analysis panels (YARA, ML, reputation), but the headline should
        // stay appropriately cautious.
        if *verdict == Verdict::Suspicious && confidence < 0.70 {
            return Some("Suspicious.Activity".to_string());
        }

        // Priority 1: YARA rule matches (most specific and reliable)
        if !static_result.yara_matches.is_empty() {
            // Find the highest severity match
            let best_match = static_result
                .yara_matches
                .iter()
                .max_by_key(|m| match m.severity {
                    yara_scanner::RuleSeverity::Critical => 5,
                    yara_scanner::RuleSeverity::High => 4,
                    yara_scanner::RuleSeverity::Medium => 3,
                    yara_scanner::RuleSeverity::Low => 2,
                    yara_scanner::RuleSeverity::Info => 1,
                });

            if let Some(m) = best_match {
                // Format as "Category.RuleName" if category is available
                let name = if !m.category.is_empty() && m.category != "unknown" {
                    format!("{}.{}", Self::capitalize_first(&m.category), m.rule_name)
                } else {
                    m.rule_name.clone()
                };
                return Some(name);
            }
        }

        // Priority 2: Reputation/VirusTotal suggested names
        if let Some(rep) = reputation {
            if !rep.suggested_names.is_empty() {
                return Some(rep.suggested_names[0].clone());
            }
            // If we have threat detections, construct a name from detection count
            if rep.threat_count > 0 {
                let detection_rate = if !rep.detections.is_empty() {
                    format!("{}/{} engines", rep.threat_count, rep.detections.len())
                } else {
                    format!("{} engines", rep.threat_count)
                };
                return Some(format!("Detected by {}", detection_rate));
            }
        }

        // Priority 3: ML predicted malware family
        if let Some(ml) = ml_result {
            if ml.model_available && ml.is_malware {
                if let Some(ref family) = ml.malware_family {
                    return Some(format!("ML:{}", family));
                }
                // Generic ML detection
                let confidence_pct = (ml.confidence * 100.0) as u32;
                return Some(format!("ML.Generic ({}% confidence)", confidence_pct));
            }
        }

        // Priority 4: Generic verdict-based name
        match verdict {
            Verdict::Malware => Some("Malware.Generic".to_string()),
            Verdict::Suspicious => Some("Suspicious.Activity".to_string()),
            _ => None,
        }
    }

    fn capitalize_first(s: &str) -> String {
        let mut chars = s.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().chain(chars).collect(),
        }
    }

    #[cfg(feature = "emulation")]
    fn run_emulation_if_needed(
        file_content: &[u8],
        file_type: &str,
        packer_flags: &[String],
    ) -> Option<EmulationSummary> {
        // Only emulate PE files that appear packed
        let is_pe =
            file_type.contains("PE") || file_type.contains("exe") || file_type.contains("dll");
        let is_packed = !packer_flags.is_empty();

        if !is_pe || !is_packed {
            log::debug!(
                "Skipping emulation: is_pe={}, is_packed={}",
                is_pe,
                is_packed
            );
            return None;
        }

        log::info!(
            "Running CPU emulation for packed PE file (packers: {:?})",
            packer_flags
        );

        let config = EmulationConfig {
            max_instructions: 500_000,
            timeout: Duration::from_secs(10),
            trace_instructions: false,
            trace_memory: false,
            detect_oep: true,
            max_memory_bytes: 128 * 1024 * 1024,
            max_stack_size: 2 * 1024 * 1024,
            max_heap_size: 32 * 1024 * 1024,
        };

        let emulator = Emulator::new(config);

        match emulator.emulate_bytes(file_content) {
            Ok(result) => {
                log::info!(
                    "Emulation completed: {} instructions, OEP={:?}, {} API calls",
                    result.instructions_executed,
                    result.detected_oep,
                    result.api_calls.len()
                );

                Some(EmulationSummary {
                    instructions_executed: result.instructions_executed,
                    detected_oep: result.detected_oep,
                    api_call_count: result.api_calls.len(),
                    suspicious_behaviors: result.suspicious_behaviors,
                    unpacking_detected: result.detected_oep.is_some(),
                })
            }
            Err(e) => {
                log::warn!("Emulation failed: {}", e);
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn determine_verdict(
        file_path: &str,
        signature_info: &SignatureInfo,
        static_result: &static_scanner::StaticAnalysisResult,
        ml_result: &Option<ml_bridge::MLPrediction>,
        reputation: &Option<reputation::ReputationScore>,
        behavior: &Option<behavior::BehaviorAnalysis>,
        emulation: &Option<EmulationSummary>,
        novelty: &Option<ml_bridge::NoveltyPrediction>,
    ) -> (Verdict, f64, String) {
        use crate::core::yara_scanner::RuleSeverity;

        // Defense-in-depth: handle blacklisted/whitelisted files even though
        // the scan pipeline also checks these before calling determine_verdict.
        if static_result.is_blacklisted {
            return (Verdict::Malware, 0.95, "HIGH".to_string());
        }
        if static_result.is_whitelisted {
            return (Verdict::Clean, 0.0, "LOW".to_string());
        }

        let has_strong_yara = static_result
            .yara_matches
            .iter()
            .any(|m| matches!(m.severity, RuleSeverity::Critical | RuleSeverity::High));

        let mut malware_score = 0.0_f64;
        let mut confidence_factors: Vec<(&str, f64)> = Vec::new();

        // TRUST FACTORS (reduce malware score for legitimate software)
        // Factor 1: Digital signature from trusted publisher (STRONG trust signal)
        if signature_info.is_valid && signature_info.is_trusted_publisher {
            malware_score -= 0.5;
            confidence_factors.push(("trusted_signature", -0.5));
            log::debug!("Trusted signature: reducing score by 0.5");
        } else if signature_info.is_valid {
            malware_score -= 0.2;
            confidence_factors.push(("valid_signature", -0.2));
            log::debug!("Valid signature (unknown publisher): reducing score by 0.2");
        }

        // Factor 2: File is from a trusted installation location
        if is_trusted_publisher_path(file_path) {
            malware_score -= 0.15;
            confidence_factors.push(("trusted_path", -0.15));
            log::debug!("Trusted path: reducing score by 0.15");
        }

        if is_probable_installer_path(file_path) && !has_strong_yara {
            let installer_reduction =
                if signature_info.is_valid && signature_info.is_trusted_publisher {
                    -0.20
                } else if is_self_product_installer_path(file_path) {
                    -0.18
                } else if signature_info.is_valid {
                    -0.12
                } else {
                    -0.05
                };
            malware_score += installer_reduction;
            confidence_factors.push(("installer_context", installer_reduction));
            log::debug!(
                "Installer context detected: reducing score by {:.2}",
                -installer_reduction
            );
        }

        // THREAT FACTORS (increase malware score for suspicious indicators)
        // Factor 1: YARA signature matches (most reliable detection)
        if !static_result.yara_matches.is_empty() {
            let mut yara_score = 0.0_f64;
            let mut has_critical = false;
            let mut has_high = false;

            // Files in trusted installation paths (Program Files, etc.) get reduced
            // YARA weights even if signature verification failed, since legitimate
            // software in these paths commonly contains strings that trigger generic rules.
            let is_trusted_path_file = is_trusted_publisher_path(file_path);

            for yara_match in &static_result.yara_matches {
                match yara_match.severity {
                    RuleSeverity::Critical => {
                        if signature_info.is_valid && signature_info.is_trusted_publisher {
                            yara_score += 0.2;
                            log::warn!(
                                "Critical YARA match on trusted signed file - possible FP: {}",
                                yara_match.rule_name
                            );
                        } else if is_trusted_path_file {
                            yara_score += 0.25;
                            log::warn!("Critical YARA match on file in trusted path (sig unverified) - possible FP: {}", yara_match.rule_name);
                        } else {
                            yara_score += 0.5;
                            has_critical = true;
                        }
                    }
                    RuleSeverity::High => {
                        if signature_info.is_valid {
                            yara_score += 0.15;
                        } else if is_trusted_path_file {
                            yara_score += 0.18;
                        } else {
                            yara_score += 0.30;
                            has_high = true;
                        }
                    }
                    RuleSeverity::Medium => {
                        yara_score += 0.15;
                    }
                    RuleSeverity::Low => {
                        yara_score += 0.08;
                    }
                    RuleSeverity::Info => {
                        yara_score += 0.03;
                    }
                }
            }

            let capped_yara = yara_score.min(0.7);
            malware_score += capped_yara;
            confidence_factors.push(("yara_matches", capped_yara));

            // Only instant-malware for critical/high YARA on files that are BOTH unsigned
            // AND not in a trusted installation path. Files in Program Files, etc. with
            // common strings (e.g. "(admin)", pipe names) can trigger FPs on rules like
            // CobaltStrike that match generic patterns found in legitimate software.
            let in_trusted_path = is_trusted_publisher_path(file_path);

            if has_critical && !signature_info.is_valid && !in_trusted_path {
                log::info!("Critical YARA match on unsigned file outside trusted path - immediate malware verdict");
                return (Verdict::Malware, 0.95, "HIGH".to_string());
            }

            if has_high && malware_score >= 0.6 && !signature_info.is_valid && !in_trusted_path {
                log::info!("High YARA match with supporting evidence outside trusted path - malware verdict");
                return (
                    Verdict::Malware,
                    malware_score.min(0.95),
                    "HIGH".to_string(),
                );
            }
        }

        // Factor 2: High entropy (packed/encrypted) - REDUCED weight
        if static_result.entropy_score > 7.8 {
            let entropy_weight = if signature_info.is_valid { 0.05 } else { 0.10 };
            malware_score += entropy_weight;
            confidence_factors.push(("high_entropy", entropy_weight));
        } else if static_result.entropy_score > 7.5 {
            let entropy_weight = if signature_info.is_valid { 0.02 } else { 0.05 };
            malware_score += entropy_weight;
            confidence_factors.push(("elevated_entropy", entropy_weight));
        }

        // Factor 3: Suspicious characteristics - REDUCED weight and threshold
        let susp_count = static_result.suspicious_characteristics.len();
        if susp_count >= 5 && !signature_info.is_valid {
            malware_score += 0.15;
            confidence_factors.push(("many_suspicious_chars", 0.15));
        } else if susp_count >= 3 && !signature_info.is_valid {
            malware_score += 0.08;
            confidence_factors.push(("some_suspicious_chars", 0.08));
        }

        // Factor 4: ML prediction - REDUCED weight, only for unsigned files
        if let Some(ml) = ml_result {
            if ml.model_available && ml.is_malware {
                let ml_weight = if signature_info.is_valid {
                    ml.confidence * 0.1
                } else if is_trusted_publisher_path(file_path) {
                    ml.confidence * 0.15
                } else {
                    ml.confidence * 0.25
                };
                malware_score += ml_weight;
                confidence_factors.push(("ml_prediction", ml_weight));
            }
        }

        // Factor 5: Reputation score (from VirusTotal, etc.)
        if let Some(rep) = reputation {
            if rep.threat_count > 0 {
                let rep_weight = if rep.threat_count >= 10 && !signature_info.is_valid {
                    rep.overall_score * 0.2
                } else if rep.threat_count >= 5 {
                    rep.overall_score * 0.1
                } else {
                    rep.overall_score * 0.05
                };
                malware_score += rep_weight;
                confidence_factors.push(("reputation", rep_weight));
            }
        }

        // Factor 6: Behavior analysis - REDUCED weight
        if let Some(beh) = behavior {
            let beh_weight = if signature_info.is_valid {
                beh.behavior_score * 0.05
            } else {
                beh.behavior_score * 0.10
            };
            malware_score += beh_weight;
            confidence_factors.push(("behavior", beh_weight));
        }

        // Factor 7: Novelty detection - very low weight (high FP rate)
        if let Some(nov) = novelty {
            if nov.is_novel && !signature_info.is_valid {
                let novelty_weight = nov.confidence * 0.05; // Reduced from 0.2
                malware_score += novelty_weight;
                confidence_factors.push(("novelty", novelty_weight));
            }
        }

        // Factor 8: Emulation results
        if let Some(emu) = emulation {
            if emu.unpacking_detected && !signature_info.is_valid {
                malware_score += 0.08;
                confidence_factors.push(("unpacking_detected", 0.08));
            }
            if !emu.suspicious_behaviors.is_empty() && !signature_info.is_valid {
                let emu_weight = 0.05 * (emu.suspicious_behaviors.len() as f64).min(2.0);
                malware_score += emu_weight;
                confidence_factors.push(("emu_suspicious", emu_weight));
            }
        }

        // FINAL VERDICT DETERMINATION

        malware_score = malware_score.clamp(0.0, 1.0);

        log::debug!(
            "Verdict scoring for {}: final_score={:.3}, factors={:?}",
            file_path,
            malware_score,
            confidence_factors
        );

        let verdict = if malware_score >= 0.70 {
            Verdict::Malware
        } else if malware_score >= 0.45 {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        };

        let threat_level = if malware_score >= 0.70 {
            "HIGH"
        } else if malware_score >= 0.45 {
            "MEDIUM"
        } else {
            "LOW"
        };

        (verdict, malware_score, threat_level.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::yara_scanner::{RuleSeverity, YaraMatch};

    fn make_signature_info(
        is_valid: bool,
        is_trusted: bool,
        signer: Option<&str>,
    ) -> SignatureInfo {
        SignatureInfo {
            is_signed: is_valid,
            is_valid,
            signer_name: signer.map(|s| s.to_string()),
            issuer: None,
            timestamp: None,
            thumbprint: None,
            not_before: None,
            not_after: None,
            trust_level: crate::core::signature::TrustLevel::None,
            is_trusted_publisher: is_trusted,
            raw_subject: None,
            raw_issuer: None,
            status_message: None,
        }
    }

    #[test]
    fn test_verdict_trusted_signed_file_with_suspicious_chars() {
        // A signed Microsoft file with some "suspicious" APIs should still be clean
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![],
            entropy_score: 6.5,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![
                "suspicious_injection_apis".to_string(),
                "suspicious_api_combo".to_string(),
            ],
        };

        let signature = make_signature_info(true, true, Some("Microsoft Corporation"));

        let (verdict, confidence, _) = DetectionPipeline::determine_verdict(
            "C:\\Windows\\System32\\test.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        assert_eq!(
            verdict,
            Verdict::Clean,
            "Trusted signed file should be clean"
        );
        assert!(
            confidence < 0.45,
            "Confidence should be low, got {}",
            confidence
        );
    }

    #[test]
    fn test_verdict_unsigned_file_with_critical_yara() {
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![YaraMatch {
                rule_name: "Ransomware_WannaCry".to_string(),
                severity: RuleSeverity::Critical,
                description: "WannaCry Ransomware".to_string(),
                category: "ransomware".to_string(),
                offset: Some(0),
            }],
            entropy_score: 7.5,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![],
        };

        let signature = make_signature_info(false, false, None);

        let (verdict, confidence, threat_level) = DetectionPipeline::determine_verdict(
            "C:\\Users\\test\\malware.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        assert_eq!(verdict, Verdict::Malware);
        assert!(confidence >= 0.95);
        assert_eq!(threat_level, "HIGH");
    }

    #[test]
    fn test_verdict_signed_file_with_high_entropy() {
        // Signed file with high entropy (like a packed installer) should be clean
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![],
            entropy_score: 7.9,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec!["packed_indicator:UPX".to_string()],
        };

        let signature = make_signature_info(true, true, Some("Google LLC"));

        let (verdict, confidence, _) = DetectionPipeline::determine_verdict(
            "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        assert_eq!(verdict, Verdict::Clean);
        assert!(confidence < 0.45);
    }

    #[test]
    fn test_self_installer_gets_false_positive_reduction() {
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![],
            entropy_score: 7.9,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![
                "suspicious_api_combo".to_string(),
                "anti_debug".to_string(),
                "process_hollowing".to_string(),
                "code_injection".to_string(),
                "packed_indicator".to_string(),
            ],
        };

        let signature = make_signature_info(false, false, None);

        let (verdict, confidence, _) = DetectionPipeline::determine_verdict(
            "C:\\Users\\test\\Downloads\\InSecurity_1.0.6_x64-setup.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        assert_eq!(verdict, Verdict::Clean);
        assert!(
            confidence < 0.45,
            "Installer score should stay below suspicious threshold"
        );
    }

    #[test]
    fn test_verdict_unsigned_suspicious_file() {
        // High YARA (+0.30) + entropy >7.8 (+0.10) + 3 suspicious chars (+0.08)
        // + behavior 0.8*0.10 (+0.08) = 0.56 -> Suspicious
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![YaraMatch {
                rule_name: "Suspicious_Packer".to_string(),
                severity: RuleSeverity::High,
                description: "Known packer".to_string(),
                category: "packer".to_string(),
                offset: Some(0),
            }],
            entropy_score: 7.9,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![
                "suspicious_injection_apis".to_string(),
                "suspicious_api_combo".to_string(),
                "anti_debug".to_string(),
            ],
        };

        let signature = make_signature_info(false, false, None);

        let behavior = Some(behavior::BehaviorAnalysis {
            behavior_score: 0.8,
            suspicious_behaviors: vec!["keylogger_api".to_string()],
            api_indicators: vec![],
            string_indicators: vec![],
        });

        let (verdict, confidence, _) = DetectionPipeline::determine_verdict(
            "C:\\Users\\test\\download.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &behavior,
            &None,
            &None,
        );

        // Should be at least suspicious
        assert!(verdict == Verdict::Suspicious || verdict == Verdict::Malware);
        assert!(confidence >= 0.45);
    }

    #[test]
    fn test_trusted_path_reduces_score() {
        // Need enough positive signals so the -0.15 trusted path reduction is visible.
        // 5 suspicious chars on unsigned file = +0.15; entropy > 7.8 unsigned = +0.10
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![],
            entropy_score: 7.9,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![
                "suspicious_api_combo".to_string(),
                "suspicious_injection_apis".to_string(),
                "anti_debug".to_string(),
                "process_hollowing".to_string(),
                "code_injection".to_string(),
            ],
        };

        let signature = make_signature_info(false, false, None);

        // File from Program Files (trusted path -> -0.15)
        let (verdict1, score1, _) = DetectionPipeline::determine_verdict(
            "C:\\Program Files\\SomeApp\\app.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        // Same file from Downloads (no path reduction)
        let (_verdict2, score2, _) = DetectionPipeline::determine_verdict(
            "C:\\Users\\test\\Downloads\\app.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        assert!(
            score1 < score2,
            "Trusted path should have lower score: {} vs {}",
            score1,
            score2
        );
        assert_eq!(verdict1, Verdict::Clean);
    }

    #[test]
    fn test_verdict_all_clean_no_signals() {
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![],
            entropy_score: 4.0,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![],
        };
        let signature = make_signature_info(false, false, None);

        let (verdict, confidence, _) = DetectionPipeline::determine_verdict(
            "C:\\test\\benign.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        assert_eq!(verdict, Verdict::Clean);
        assert!(confidence < 0.45, "Score should be low: {}", confidence);
    }

    #[test]
    fn test_verdict_ml_alone_insufficient_for_detection() {
        // ML detection alone should not cause malware verdict (by design)
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![],
            entropy_score: 5.0,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![],
        };
        let signature = make_signature_info(false, false, None);
        let ml = Some(crate::core::ml_bridge::MLPrediction {
            is_malware: true,
            confidence: 0.99,
            malware_family: Some("Trojan.Generic".to_string()),
            model_version: "test".to_string(),
            model_available: true,
            verdict: crate::core::ml_bridge::MLVerdict::Malware,
            raw_score: 0.99,
        });

        let (verdict, confidence, _) = DetectionPipeline::determine_verdict(
            "C:\\test\\file.exe",
            &signature,
            &static_result,
            &ml,
            &None,
            &None,
            &None,
            &None,
        );

        // ML alone has weight 0.25, so 0.99 * 0.25 = 0.2475 -> Clean
        assert_eq!(
            verdict,
            Verdict::Clean,
            "ML alone should not trigger detection, score={}",
            confidence
        );
    }

    #[test]
    fn test_verdict_combined_signals_reach_malware() {
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![YaraMatch {
                rule_name: "Suspicious_Code".to_string(),
                severity: RuleSeverity::Medium,
                description: "Suspicious code pattern".to_string(),
                category: "trojan".to_string(),
                offset: Some(0),
            }],
            entropy_score: 7.5,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![
                "suspicious_injection_apis".to_string(),
                "suspicious_api_combo".to_string(),
                "anti_debug".to_string(),
            ],
        };
        let signature = make_signature_info(false, false, None);
        let ml = Some(crate::core::ml_bridge::MLPrediction {
            is_malware: true,
            confidence: 0.95,
            malware_family: Some("Trojan.GenericKD".to_string()),
            model_version: "test".to_string(),
            model_available: true,
            verdict: crate::core::ml_bridge::MLVerdict::Malware,
            raw_score: 0.95,
        });
        let behavior = Some(behavior::BehaviorAnalysis {
            behavior_score: 0.8,
            suspicious_behaviors: vec!["process_injection".to_string()],
            api_indicators: vec![],
            string_indicators: vec![],
        });

        let (verdict, confidence, _) = DetectionPipeline::determine_verdict(
            "C:\\Users\\test\\Downloads\\payload.exe",
            &signature,
            &static_result,
            &ml,
            &None,
            &behavior,
            &None,
            &None,
        );

        assert!(
            verdict == Verdict::Malware || verdict == Verdict::Suspicious,
            "Combined signals should detect: verdict={:?}, score={}",
            verdict,
            confidence
        );
        assert!(
            confidence >= 0.45,
            "Score should be elevated: {}",
            confidence
        );
    }

    #[test]
    fn test_blacklisted_file_is_malware() {
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![],
            entropy_score: 4.0,
            is_whitelisted: false,
            is_blacklisted: true,
            suspicious_characteristics: vec![],
        };
        let signature = make_signature_info(false, false, None);

        let (verdict, confidence, _) = DetectionPipeline::determine_verdict(
            "C:\\test\\known_malware.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        assert_eq!(
            verdict,
            Verdict::Malware,
            "Blacklisted file should be Malware"
        );
        assert!(
            confidence >= 0.95,
            "Blacklisted should have high confidence: {}",
            confidence
        );
    }

    #[test]
    fn test_whitelisted_file_is_clean() {
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![],
            entropy_score: 7.5,
            is_whitelisted: true,
            is_blacklisted: false,
            suspicious_characteristics: vec!["suspicious_api_combo".to_string()],
        };
        let signature = make_signature_info(false, false, None);

        let (verdict, _, _) = DetectionPipeline::determine_verdict(
            "C:\\test\\whitelisted.exe",
            &signature,
            &static_result,
            &None,
            &None,
            &None,
            &None,
            &None,
        );

        assert_eq!(verdict, Verdict::Clean, "Whitelisted file should be Clean");
    }

    #[test]
    fn test_low_confidence_suspicious_threat_name_stays_generic() {
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![YaraMatch {
                rule_name: "RAT_CobaltStrike_Beacon".to_string(),
                severity: RuleSeverity::Critical,
                description: "Cobalt Strike Beacon".to_string(),
                category: "rat".to_string(),
                offset: Some(0),
            }],
            entropy_score: 6.0,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![],
        };

        let threat_name = DetectionPipeline::derive_threat_name(
            &Verdict::Suspicious,
            0.57,
            &static_result,
            &None,
            &None,
        );

        assert_eq!(threat_name, Some("Suspicious.Activity".to_string()));
    }

    #[test]
    fn test_high_confidence_malware_keeps_specific_yara_name() {
        let static_result = static_scanner::StaticAnalysisResult {
            yara_matches: vec![YaraMatch {
                rule_name: "RAT_CobaltStrike_Beacon".to_string(),
                severity: RuleSeverity::Critical,
                description: "Cobalt Strike Beacon".to_string(),
                category: "rat".to_string(),
                offset: Some(0),
            }],
            entropy_score: 7.8,
            is_whitelisted: false,
            is_blacklisted: false,
            suspicious_characteristics: vec![],
        };

        let threat_name = DetectionPipeline::derive_threat_name(
            &Verdict::Malware,
            0.95,
            &static_result,
            &None,
            &None,
        );

        assert_eq!(threat_name, Some("Rat.RAT_CobaltStrike_Beacon".to_string()));
    }

    #[test]
    fn test_capitalize_first_empty() {
        assert_eq!(DetectionPipeline::capitalize_first(""), "");
    }

    #[test]
    fn test_capitalize_first_single_char() {
        assert_eq!(DetectionPipeline::capitalize_first("a"), "A");
    }

    #[test]
    fn test_capitalize_first_normal() {
        assert_eq!(DetectionPipeline::capitalize_first("trojan"), "Trojan");
    }

    #[test]
    fn test_capitalize_first_already_upper() {
        assert_eq!(DetectionPipeline::capitalize_first("Malware"), "Malware");
    }

    #[test]
    fn test_verdict_enum_serialization() {
        // Verify serde serialization matches expected format
        let clean_json = serde_json::to_string(&Verdict::Clean).unwrap();
        let malware_json = serde_json::to_string(&Verdict::Malware).unwrap();
        assert!(clean_json.contains("Clean") || clean_json.contains("clean"));
        assert!(malware_json.contains("Malware") || malware_json.contains("malware"));
    }

    #[test]
    fn test_verdict_enum_equality() {
        assert_eq!(Verdict::Clean, Verdict::Clean);
        assert_ne!(Verdict::Clean, Verdict::Malware);
        assert_ne!(Verdict::Suspicious, Verdict::Unknown);
    }
}
