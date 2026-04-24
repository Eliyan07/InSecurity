//! Tauri commands for ML feedback and adaptive learning

use crate::core::feedback_store::FeedbackStore;
pub use crate::core::feedback_store::{FeedbackStats, ThresholdRecommendation};
use serde::{Deserialize, Serialize};
use tauri::command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackResult {
    pub success: bool,
    pub message: String,
}

#[command]
pub async fn report_false_positive(
    file_hash: String,
    original_verdict: String,
    confidence: f64,
    features_json: Option<String>,
) -> Result<FeedbackResult, String> {
    log::info!(
        "False positive reported: {} (was: {}, confidence: {:.2})",
        &file_hash[..16.min(file_hash.len())],
        original_verdict,
        confidence
    );

    tokio::task::spawn_blocking(move || {
        let store = FeedbackStore::new()?;
        match store.report_false_positive(
            &file_hash,
            &original_verdict,
            confidence,
            features_json.as_deref(),
        ) {
            Ok(true) => Ok(FeedbackResult {
                success: true,
                message: "False positive reported successfully".to_string(),
            }),
            Ok(false) => Ok(FeedbackResult {
                success: false,
                message: "Failed to record feedback".to_string(),
            }),
            Err(e) => Err(format!("Error reporting false positive: {}", e)),
        }
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[command]
pub async fn report_false_negative(
    file_hash: String,
    original_verdict: String,
    confidence: f64,
    actual_threat: String,
    features_json: Option<String>,
) -> Result<FeedbackResult, String> {
    log::info!(
        "False negative reported: {} (was: {}, actual: {})",
        &file_hash[..16.min(file_hash.len())],
        original_verdict,
        actual_threat
    );

    tokio::task::spawn_blocking(move || {
        let store = FeedbackStore::new()?;
        match store.report_false_negative(
            &file_hash,
            &original_verdict,
            confidence,
            &actual_threat,
            features_json.as_deref(),
        ) {
            Ok(true) => Ok(FeedbackResult {
                success: true,
                message: "False negative reported successfully".to_string(),
            }),
            Ok(false) => Ok(FeedbackResult {
                success: false,
                message: "Failed to record feedback".to_string(),
            }),
            Err(e) => Err(format!("Error reporting false negative: {}", e)),
        }
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[command]
pub async fn get_ml_feedback_stats() -> Result<FeedbackStats, String> {
    tokio::task::spawn_blocking(|| FeedbackStore::new()?.get_feedback_stats())
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

/// Check if significant feedback has accumulated (for analytics display).
#[command]
pub async fn check_ml_retrain_status() -> Result<bool, String> {
    tokio::task::spawn_blocking(|| FeedbackStore::new()?.should_retrain())
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[command]
pub async fn get_threshold_adjustment() -> Result<ThresholdRecommendation, String> {
    tokio::task::spawn_blocking(|| FeedbackStore::new()?.get_threshold_recommendation())
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feedback_result_serialize_success() {
        let result = FeedbackResult {
            success: true,
            message: "False positive reported successfully".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("False positive reported"));
    }

    #[test]
    fn test_feedback_result_deserialize() {
        let json = r#"{"success":false,"message":"Failed"}"#;
        let result: FeedbackResult = serde_json::from_str(json).unwrap();
        assert!(!result.success);
        assert_eq!(result.message, "Failed");
    }

    #[test]
    fn test_feedback_stats_serialize() {
        let mut by_type = std::collections::HashMap::new();
        by_type.insert("false_positive".to_string(), 5);
        by_type.insert("false_negative".to_string(), 2);

        let stats = FeedbackStats {
            by_type,
            by_source: std::collections::HashMap::new(),
            last_7_days: std::collections::HashMap::new(),
            unprocessed: 3,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"unprocessed\":3"));
        assert!(json.contains("false_positive"));
    }

    #[test]
    fn test_threshold_recommendation_serialize() {
        let rec = ThresholdRecommendation {
            adjustment: -0.05,
            reason: "Too many false positives".to_string(),
            fp_count: Some(10),
            fn_count: Some(1),
            fp_ratio: Some(0.15),
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"adjustment\":-0.05"));
        assert!(json.contains("\"fp_count\":10"));
    }

    #[test]
    fn test_threshold_recommendation_optional_fields() {
        let rec = ThresholdRecommendation {
            adjustment: 0.0,
            reason: "No adjustment needed".to_string(),
            fp_count: None,
            fn_count: None,
            fp_ratio: None,
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: ThresholdRecommendation = serde_json::from_str(&json).unwrap();
        assert!(back.fp_count.is_none());
        assert!(back.fn_count.is_none());
        assert!(back.fp_ratio.is_none());
    }

    #[test]
    fn test_feedback_result_clone() {
        let result = FeedbackResult {
            success: true,
            message: "Success".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.success, result.success);
        assert_eq!(cloned.message, result.message);
    }
}
