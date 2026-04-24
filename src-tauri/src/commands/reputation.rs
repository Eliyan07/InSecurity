use crate::database::queries::DatabaseQueries;
/// Reputation commands
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationData {
    pub file_hash: String,
    pub overall_score: f64,
    pub threat_count: u32,
    pub sources: Vec<String>,
}

/// Update file reputation from VirusTotal
#[tauri::command]
pub async fn update_reputation(hash: String) -> Result<ReputationData, String> {
    match crate::core::reputation::query_reputation(&hash).await {
        Ok(score) => Ok(ReputationData {
            file_hash: hash,
            overall_score: score.overall_score,
            threat_count: score.threat_count,
            sources: score.sources,
        }),
        Err(e) => Err(format!("Failed to update reputation: {}", e)),
    }
}

/// Get file reputation
#[tauri::command]
pub async fn get_file_reputation(hash: String) -> Result<ReputationData, String> {
    crate::with_db_async(move |conn| {
        let mut sources = vec![];
        let mut overall_score = 0.0_f64;
        let mut threat_count = 0u32;

        if let Ok(Some(report)) = DatabaseQueries::get_external_report(conn, "remote", &hash) {
            sources.push(format!("persisted:{}", report.fetched_at));
            // Best-effort parsing
            if report.data_json.to_lowercase().contains("malic")
                || report.data_json.to_lowercase().contains("positiv")
            {
                overall_score = 0.9;
                threat_count = 1;
            }
        }

        Ok(ReputationData {
            file_hash: hash,
            overall_score,
            threat_count,
            sources,
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_data_serialize() {
        let data = ReputationData {
            file_hash: "abc123def456".to_string(),
            overall_score: 0.85,
            threat_count: 3,
            sources: vec!["VirusTotal".to_string(), "MalwareBazaar".to_string()],
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"file_hash\":\"abc123def456\""));
        assert!(json.contains("\"overall_score\":0.85"));
        assert!(json.contains("\"threat_count\":3"));
        assert!(json.contains("VirusTotal"));
    }

    #[test]
    fn test_reputation_data_deserialize() {
        let json = r#"{"file_hash":"test","overall_score":0.0,"threat_count":0,"sources":[]}"#;
        let data: ReputationData = serde_json::from_str(json).unwrap();
        assert_eq!(data.file_hash, "test");
        assert_eq!(data.overall_score, 0.0);
        assert_eq!(data.threat_count, 0);
        assert!(data.sources.is_empty());
    }

    #[test]
    fn test_reputation_data_clone() {
        let data = ReputationData {
            file_hash: "hash1".to_string(),
            overall_score: 0.5,
            threat_count: 1,
            sources: vec!["source1".to_string()],
        };
        let cloned = data.clone();
        assert_eq!(cloned.file_hash, data.file_hash);
        assert_eq!(cloned.overall_score, data.overall_score);
        assert_eq!(cloned.sources.len(), 1);
    }

    #[test]
    fn test_reputation_data_roundtrip() {
        let original = ReputationData {
            file_hash: "abc".to_string(),
            overall_score: 0.99,
            threat_count: 42,
            sources: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: ReputationData = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.file_hash, original.file_hash);
        assert_eq!(restored.threat_count, original.threat_count);
        assert_eq!(restored.sources.len(), 3);
    }
}
