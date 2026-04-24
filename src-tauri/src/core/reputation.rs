//! Stage 3: Reputation Scoring
//! VirusTotal API integration, threat intelligence aggregation
use crate::database::queries::DatabaseQueries;
use crate::with_db;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::rate_limiter::VT_RATE_LIMITER;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub overall_score: f64,
    pub threat_count: u32,
    pub last_analysis_date: i64,
    pub sources: Vec<String>,
    pub detections: Vec<VtDetection>,
    pub suggested_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtDetection {
    pub engine_name: String,
    pub category: String,       // "malicious", "suspicious", "undetected"
    pub result: Option<String>, // Threat name if detected
}

fn parse_vt_response(body: &str) -> (f64, u32, Vec<VtDetection>, Vec<String>) {
    let mut overall_score = 0.0_f64;
    let mut threat_count = 0u32;
    let mut detections = Vec::new();
    let mut suggested_names: Vec<String> = Vec::new();
    let mut parsed_vt_structure = false;

    if let Ok(val) = serde_json::from_str::<JsonValue>(body) {
        // VT API v3 structure: data.attributes.last_analysis_results
        if let Some(data) = val.get("data") {
            if let Some(attrs) = data.get("attributes") {
                parsed_vt_structure = true;
                if let Some(stats) = attrs.get("last_analysis_stats") {
                    let malicious =
                        stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let suspicious = stats
                        .get("suspicious")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let total = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0)
                        + stats
                            .get("suspicious")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                        + stats
                            .get("undetected")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                        + stats.get("harmless").and_then(|v| v.as_u64()).unwrap_or(0);

                    threat_count = malicious + suspicious;

                    if total > 0 {
                        overall_score =
                            (malicious as f64 * 1.0 + suspicious as f64 * 0.5) / total as f64;
                    }
                }

                // Parse individual engine results
                if let Some(results) = attrs.get("last_analysis_results") {
                    if let Some(obj) = results.as_object() {
                        for (engine, result) in obj {
                            let category = result
                                .get("category")
                                .and_then(|v| v.as_str())
                                .unwrap_or("undetected")
                                .to_string();
                            let detection_name = result
                                .get("result")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());

                            if category == "malicious" || category == "suspicious" {
                                if let Some(ref name) = detection_name {
                                    if !name.is_empty() {
                                        suggested_names.push(name.clone());
                                    }
                                }
                            }

                            detections.push(VtDetection {
                                engine_name: engine.clone(),
                                category,
                                result: detection_name,
                            });
                        }
                    }
                }

                // Also check popular_threat_classification for better naming
                if let Some(classification) = attrs.get("popular_threat_classification") {
                    if let Some(labels) = classification.get("suggested_threat_label") {
                        if let Some(label) = labels.as_str() {
                            suggested_names.insert(0, label.to_string());
                        }
                    }
                }
            }
        }

        // Fallback heuristic: only if we couldn't parse the expected VT API structure
        // (e.g., non-standard response format). Do NOT apply this when we successfully
        // parsed data.attributes but detections were empty - that means the file is clean.
        if !parsed_vt_structure && detections.is_empty() {
            let s = val.to_string().to_lowercase();
            if s.contains("malic") || s.contains("positiv") || s.contains("threat") {
                overall_score = 0.85;
                threat_count = 1;
            }
        }
    }

    suggested_names.sort();
    suggested_names.dedup();

    (overall_score, threat_count, detections, suggested_names)
}

async fn fetch_and_persist_remote(
    hash: &str,
) -> Result<ReputationScore, Box<dyn std::error::Error>> {
    let vt_key = crate::config::settings::get_api_key("virustotal_api_key")
        .or_else(|| std::env::var("VIRUSTOTAL_API_KEY").ok());

    if vt_key.is_none() {
        VT_RATE_LIMITER.warn_once("VIRUSTOTAL_API_KEY not set - VirusTotal lookups disabled. Get a free key at https://www.virustotal.com/gui/join-us");
        return Ok(ReputationScore {
            overall_score: 0.0,
            threat_count: 0,
            last_analysis_date: Utc::now().timestamp(),
            sources: vec!["virustotal:no_api_key".to_string()],
            detections: Vec::new(),
            suggested_names: Vec::new(),
        });
    }

    if let Some(wait_seconds) = VT_RATE_LIMITER.check() {
        log::warn!("VirusTotal rate limit reached (4 req/min free tier). Need to wait {} seconds. Skipping lookup for hash: {}", wait_seconds, &hash[..8.min(hash.len())]);
        return Ok(ReputationScore {
            overall_score: 0.0,
            threat_count: 0,
            last_analysis_date: Utc::now().timestamp(),
            sources: vec!["virustotal:rate_limited".to_string()],
            detections: Vec::new(),
            suggested_names: Vec::new(),
        });
    }
    VT_RATE_LIMITER.record();

    let api_key = vt_key.expect("API key was already validated as present");
    let vt_url = format!("https://www.virustotal.com/api/v3/files/{}", hash);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = client
        .get(&vt_url)
        .header("x-apikey", &api_key)
        .send()
        .await?;

    let status = resp.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        log::warn!("VirusTotal API returned 429 Too Many Requests - rate limit exceeded");
        return Err("VirusTotal rate limit exceeded. Free tier allows 4 requests/minute.".into());
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        log::error!("VirusTotal API key is invalid or expired");
        return Err("VirusTotal API key is invalid. Check your VIRUSTOTAL_API_KEY.".into());
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        log::debug!(
            "Hash {} not found in VirusTotal database",
            &hash[..8.min(hash.len())]
        );
        return Ok(ReputationScore {
            overall_score: 0.0,
            threat_count: 0,
            last_analysis_date: Utc::now().timestamp(),
            sources: vec!["virustotal:not_found".to_string()],
            detections: Vec::new(),
            suggested_names: Vec::new(),
        });
    }

    let body = resp.text().await?;

    with_db(|conn| {
        let ts = Utc::now().timestamp();
        if let Err(e) = DatabaseQueries::insert_external_report(conn, "virustotal", hash, &body, ts)
        {
            log::warn!("Failed to persist external report: {}", e);
        }
        Some(())
    });

    let (overall_score, threat_count, detections, suggested_names) = parse_vt_response(&body);

    Ok(ReputationScore {
        overall_score,
        threat_count,
        last_analysis_date: Utc::now().timestamp(),
        sources: vec!["virustotal".to_string()],
        detections,
        suggested_names,
    })
}

/// Query reputation information for a file hash.
/// First consult the local DB cache (external_reports). If a recent result exists return it.
/// Otherwise fetch an external report, persist, and return the derived reputation.
pub async fn query_reputation(
    file_hash: &str,
) -> Result<ReputationScore, Box<dyn std::error::Error>> {
    let cached_result: Option<ReputationScore> = with_db(|conn| {
        if let Ok(Some(report)) =
            DatabaseQueries::get_external_report(conn, "virustotal", file_hash)
        {
            let age_secs = Utc::now().timestamp() - report.fetched_at;
            if age_secs <= 7 * 24 * 60 * 60 {
                let (overall_score, threat_count, detections, suggested_names) =
                    parse_vt_response(&report.data_json);

                return Some(ReputationScore {
                    overall_score,
                    threat_count,
                    last_analysis_date: report.fetched_at,
                    sources: vec![format!("cached:{}", report.fetched_at)],
                    detections,
                    suggested_names,
                });
            }
        }
        None
    });

    if let Some(score) = cached_result {
        return Ok(score);
    }

    fetch_and_persist_remote(file_hash).await
}

pub fn calculate_reputation_score(vt_score: f64, other_sources: Vec<f64>) -> ReputationScore {
    let mut total_score = vt_score;
    for score in &other_sources {
        total_score += score;
    }

    let overall_score = total_score / (other_sources.len() as f64 + 1.0);

    ReputationScore {
        overall_score,
        threat_count: 0,
        last_analysis_date: chrono::Utc::now().timestamp(),
        sources: vec!["virustotal".to_string()],
        detections: Vec::new(),
        suggested_names: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vt_response_empty_string() {
        let (score, count, dets, names) = parse_vt_response("");
        assert_eq!(score, 0.0);
        assert_eq!(count, 0);
        assert!(dets.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn test_parse_vt_response_invalid_json() {
        let (score, count, dets, names) = parse_vt_response("not json at all");
        assert_eq!(score, 0.0);
        assert_eq!(count, 0);
        assert!(dets.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn test_parse_vt_response_empty_json_object() {
        let (score, count, dets, names) = parse_vt_response("{}");
        assert_eq!(score, 0.0);
        assert_eq!(count, 0);
        assert!(dets.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn test_parse_vt_response_clean_file() {
        let body = r#"{
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 60,
                        "harmless": 10
                    },
                    "last_analysis_results": {}
                }
            }
        }"#;
        let (score, count, dets, names) = parse_vt_response(body);
        assert_eq!(score, 0.0);
        assert_eq!(count, 0);
        assert!(dets.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn test_parse_vt_response_malicious_file() {
        let body = r#"{
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 40,
                        "suspicious": 5,
                        "undetected": 20,
                        "harmless": 5
                    },
                    "last_analysis_results": {
                        "Kaspersky": {
                            "category": "malicious",
                            "result": "Trojan.Win32.Agent"
                        },
                        "Avast": {
                            "category": "malicious",
                            "result": "Win32:Malware-gen"
                        },
                        "ClamAV": {
                            "category": "undetected",
                            "result": null
                        }
                    }
                }
            }
        }"#;
        let (score, count, dets, names) = parse_vt_response(body);
        assert!(score > 0.5, "Score should be high for 40/70 malicious");
        assert_eq!(count, 45); // 40 malicious + 5 suspicious
        assert_eq!(dets.len(), 3);
        assert!(names.contains(&"Trojan.Win32.Agent".to_string()));
        assert!(names.contains(&"Win32:Malware-gen".to_string()));
    }

    #[test]
    fn test_parse_vt_response_with_threat_classification() {
        let body = r#"{
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 30,
                        "suspicious": 0,
                        "undetected": 40,
                        "harmless": 0
                    },
                    "last_analysis_results": {
                        "Engine1": {
                            "category": "malicious",
                            "result": "Ransom.WannaCry"
                        }
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "ransomware.wannacry"
                    }
                }
            }
        }"#;
        let (_score, _count, _dets, names) = parse_vt_response(body);
        // suggested_threat_label is inserted first but names get sorted,
        // so check it exists rather than assuming position
        assert!(names.contains(&"ransomware.wannacry".to_string()));
        assert!(names.contains(&"Ransom.WannaCry".to_string()));
    }

    #[test]
    fn test_parse_vt_response_not_found() {
        // VT returns 404 body - typically {"error": {"code": "NotFoundError"}}
        let body = r#"{"error": {"code": "NotFoundError"}}"#;
        let (score, count, dets, _names) = parse_vt_response(body);
        assert_eq!(score, 0.0);
        assert_eq!(count, 0);
        assert!(dets.is_empty());
    }

    #[test]
    fn test_parse_vt_response_deduplicates_names() {
        let body = r#"{
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 0,
                        "undetected": 0,
                        "harmless": 0
                    },
                    "last_analysis_results": {
                        "Engine1": { "category": "malicious", "result": "Trojan.Generic" },
                        "Engine2": { "category": "malicious", "result": "Trojan.Generic" }
                    }
                }
            }
        }"#;
        let (_score, _count, _dets, names) = parse_vt_response(body);
        // Should be deduplicated
        let count = names.iter().filter(|n| *n == "Trojan.Generic").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_calculate_reputation_score_vt_only() {
        let score = calculate_reputation_score(0.8, vec![]);
        assert!((score.overall_score - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_calculate_reputation_score_averaged() {
        let score = calculate_reputation_score(0.6, vec![0.4, 0.8]);
        // (0.6 + 0.4 + 0.8) / 3 = 0.6
        assert!((score.overall_score - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_calculate_reputation_score_zero() {
        let score = calculate_reputation_score(0.0, vec![0.0, 0.0]);
        assert_eq!(score.overall_score, 0.0);
    }

    #[test]
    fn test_reputation_score_serialization_roundtrip() {
        let score = ReputationScore {
            overall_score: 0.75,
            threat_count: 5,
            last_analysis_date: 1700000000,
            sources: vec!["virustotal".to_string()],
            detections: vec![VtDetection {
                engine_name: "TestEngine".to_string(),
                category: "malicious".to_string(),
                result: Some("Trojan.Test".to_string()),
            }],
            suggested_names: vec!["Trojan.Test".to_string()],
        };
        let json = serde_json::to_string(&score).unwrap();
        let deser: ReputationScore = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.overall_score, 0.75);
        assert_eq!(deser.threat_count, 5);
        assert_eq!(deser.detections.len(), 1);
        assert_eq!(deser.detections[0].engine_name, "TestEngine");
    }
}
