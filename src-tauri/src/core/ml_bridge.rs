//! ML Model Bridge
//!
//! Classifier inference is done via ONNX Runtime (Rust-native).
use crate::ml::OnnxClassifier;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum MLVerdict {
    Malware,
    Suspicious,
    Clean,
    #[default]
    Unknown,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLPrediction {
    pub is_malware: bool,
    pub confidence: f64,
    pub malware_family: Option<String>,
    pub model_version: String,
    /// Whether the ML model was actually available for prediction
    /// If false, the prediction is a placeholder and should not be trusted
    #[serde(default)]
    pub model_available: bool,
    #[serde(default)]
    pub verdict: MLVerdict,
    #[serde(default)]
    pub raw_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoveltyPrediction {
    pub is_novel: bool,
    pub anomaly_score: f64,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub model_available: bool,
}

pub struct MLBridge {
    pub model_version: String,
    pub onnx_classifier: Option<Arc<OnnxClassifier>>,
}

impl MLBridge {
    pub fn new(model_version: &str) -> Self {
        MLBridge {
            model_version: model_version.to_string(),
            onnx_classifier: None,
        }
    }

    pub fn with_onnx(model_version: &str, clf: Arc<OnnxClassifier>) -> Self {
        MLBridge {
            model_version: model_version.to_string(),
            onnx_classifier: Some(clf),
        }
    }

    /// Classify a file using the ONNX-based LightGBM model.
    ///
    /// This replaces `predict_with_py3`, which crashed with STATUS_ACCESS_VIOLATION
    /// because LightGBM's OpenMP thread pool cannot initialize inside the embedded
    /// Python runtime on Windows.  ONNX Runtime runs entirely in Rust — no Python,
    /// no OpenMP, no crash.
    pub fn predict_onnx(&self, features: Vec<f64>) -> Result<MLPrediction, String> {
        let clf = self
            .onnx_classifier
            .as_ref()
            .ok_or("ONNX classifier not initialized")?;

        let (confidence, verdict_str) = clf.predict(&features)?;
        let confidence = confidence as f64;

        let (is_malware, verdict) = match verdict_str {
            "malware" => (true, MLVerdict::Malware),
            "suspicious" => (true, MLVerdict::Suspicious),
            _ => (false, MLVerdict::Clean),
        };

        let malware_family = if confidence > 0.95 {
            Some("Generic.Malware".to_string())
        } else if confidence > 0.85 {
            Some("Trojan.Generic".to_string())
        } else if confidence > 0.70 {
            Some("Suspicious.Behavior".to_string())
        } else if confidence > 0.50 {
            Some("Suspicious.Generic".to_string())
        } else {
            None
        };

        Ok(MLPrediction {
            is_malware,
            confidence,
            malware_family,
            model_version: self.model_version.clone(),
            model_available: true,
            verdict,
            raw_score: confidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_verdict_default_is_unknown() {
        assert_eq!(MLVerdict::default(), MLVerdict::Unknown);
    }

    #[test]
    fn test_ml_verdict_serde_roundtrip() {
        let verdicts = vec![
            MLVerdict::Malware,
            MLVerdict::Suspicious,
            MLVerdict::Clean,
            MLVerdict::Unknown,
            MLVerdict::Error,
        ];
        for v in verdicts {
            let json = serde_json::to_string(&v).unwrap();
            let back: MLVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn test_ml_verdict_rename_all_lowercase() {
        assert_eq!(
            serde_json::to_string(&MLVerdict::Malware).unwrap(),
            "\"malware\""
        );
        assert_eq!(
            serde_json::to_string(&MLVerdict::Suspicious).unwrap(),
            "\"suspicious\""
        );
        assert_eq!(
            serde_json::to_string(&MLVerdict::Clean).unwrap(),
            "\"clean\""
        );
        assert_eq!(
            serde_json::to_string(&MLVerdict::Unknown).unwrap(),
            "\"unknown\""
        );
        assert_eq!(
            serde_json::to_string(&MLVerdict::Error).unwrap(),
            "\"error\""
        );
    }

    #[test]
    fn test_ml_prediction_serde_roundtrip() {
        let pred = MLPrediction {
            is_malware: true,
            confidence: 0.95,
            malware_family: Some("Trojan.GenericKD".to_string()),
            model_version: "1.0".to_string(),
            model_available: true,
            verdict: MLVerdict::Malware,
            raw_score: 0.95,
        };
        let json = serde_json::to_string(&pred).unwrap();
        let back: MLPrediction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.is_malware, true);
        assert_eq!(back.confidence, 0.95);
        assert_eq!(back.malware_family, Some("Trojan.GenericKD".to_string()));
        assert_eq!(back.model_available, true);
        assert_eq!(back.verdict, MLVerdict::Malware);
    }

    #[test]
    fn test_ml_prediction_defaults_from_partial_json() {
        let json =
            r#"{"is_malware":false,"confidence":0.1,"malware_family":null,"model_version":"2.0"}"#;
        let pred: MLPrediction = serde_json::from_str(json).unwrap();
        assert_eq!(pred.model_available, false); // default
        assert_eq!(pred.verdict, MLVerdict::Unknown); // default
        assert_eq!(pred.raw_score, 0.0); // default
    }

    #[test]
    fn test_novelty_prediction_serde_roundtrip() {
        let pred = NoveltyPrediction {
            is_novel: true,
            anomaly_score: -0.5,
            confidence: 0.8,
            model_available: true,
        };
        let json = serde_json::to_string(&pred).unwrap();
        let back: NoveltyPrediction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.is_novel, true);
        assert_eq!(back.anomaly_score, -0.5);
        assert_eq!(back.confidence, 0.8);
        assert_eq!(back.model_available, true);
    }

    #[test]
    fn test_novelty_prediction_defaults_from_partial_json() {
        let json = r#"{"is_novel":false,"anomaly_score":0.0}"#;
        let pred: NoveltyPrediction = serde_json::from_str(json).unwrap();
        assert_eq!(pred.confidence, 0.0); // default
        assert_eq!(pred.model_available, false); // default
    }

    #[test]
    fn test_ml_bridge_new() {
        let bridge = MLBridge::new("v1.0");
        assert_eq!(bridge.model_version, "v1.0");
    }

    #[test]
    fn test_ml_bridge_new_empty_version() {
        let bridge = MLBridge::new("");
        assert_eq!(bridge.model_version, "");
    }

    #[test]
    fn test_ml_prediction_clone() {
        let pred = MLPrediction {
            is_malware: true,
            confidence: 0.9,
            malware_family: None,
            model_version: "1.0".to_string(),
            model_available: true,
            verdict: MLVerdict::Malware,
            raw_score: 0.9,
        };
        let cloned = pred.clone();
        assert_eq!(cloned.confidence, pred.confidence);
        assert_eq!(cloned.verdict, pred.verdict);
    }
}
