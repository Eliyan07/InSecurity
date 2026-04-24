//! ONNX-based novelty detector (IsolationForest).
//!
//! The model is a sklearn Pipeline (StandardScaler + IsolationForest) exported to
//! ONNX via `scripts/convert_novelty_to_onnx.py`.
//!
//! skl2onnx emits two outputs for IsolationForest:
//!   - `"label"`  — int64 label: 1 = normal, -1 = anomaly
//!   - `"scores"` — float32 raw anomaly score (negative = more anomalous)
//!
//! Anomaly threshold: -0.5 (from `resources/models/novelty/threshold.json`).
//! Confidence formula (mirrors `model.py _score_to_confidence`):
//!   confidence = clamp((THRESHOLD - score) / |THRESHOLD|, 0.0, 1.0)
//!
//! `ort::Session` is Send + Sync, so `Arc<OnnxNoveltyDetector>` can be shared
//! across Tokio spawn_blocking tasks without any additional locking.

use std::sync::Mutex;

use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;

use crate::core::ml_bridge::NoveltyPrediction;

/// Number of behavioral features expected by the novelty model.
const NOVELTY_FEATURES: usize = 42;

/// Anomaly threshold — scores below this are flagged as anomalous.
/// Matches `THRESHOLD = -0.5` in `python/ml_models/novelty/model.py`.
const ANOMALY_THRESHOLD: f32 = -0.5;

/// Thread-safe ONNX novelty detector.
///
/// `Session::run()` requires `&mut Session`, so we wrap it in a `Mutex`.
pub struct OnnxNoveltyDetector {
    session: Mutex<Session>,
}

impl OnnxNoveltyDetector {
    /// Load an ONNX model from `model_path`.
    pub fn load(model_path: &str) -> Result<Self, String> {
        let session = Session::builder()
            .map_err(|e| e.to_string())?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| e.to_string())?
            .with_intra_threads(1)
            .map_err(|e| e.to_string())?
            .commit_from_file(model_path)
            .map_err(|e| e.to_string())?;

        log::info!(
            "ONNX novelty detector loaded: {} input(s), {} output(s)",
            session.inputs().len(),
            session.outputs().len()
        );

        Ok(Self {
            session: Mutex::new(session),
        })
    }

    /// Predict novelty for a single feature vector.
    ///
    /// Returns a [`NoveltyPrediction`] with:
    /// - `is_novel`     — true when `label == -1` (anomaly)
    /// - `anomaly_score` — raw IsolationForest score (negative = more anomalous)
    /// - `confidence`   — normalised to `[0, 1]` via threshold formula
    /// - `model_available` — always `true` when this method succeeds
    pub fn predict(&self, features: &[f64]) -> Result<NoveltyPrediction, String> {
        // Pad or truncate to the expected feature count.
        let mut padded: Vec<f32> = features
            .iter()
            .take(NOVELTY_FEATURES)
            .map(|&x| x as f32)
            .collect();
        padded.resize(NOVELTY_FEATURES, 0.0_f32);

        let shape = [1_usize, NOVELTY_FEATURES];
        let tensor_val =
            ort::value::Tensor::<f32>::from_array((shape, padded)).map_err(|e| e.to_string())?;

        let (label, anomaly_score): (i64, f32) = {
            let mut session = self
                .session
                .lock()
                .map_err(|_| "ONNX novelty session lock poisoned")?;

            let outputs = session
                .run(ort::inputs!["input" => tensor_val])
                .map_err(|e| e.to_string())?;

            // Primary: label output ("label") — int64, shape [1]
            let label_val: i64 = {
                let (_, label_slice) = outputs["label"]
                    .try_extract_tensor::<i64>()
                    .map_err(|e| e.to_string())?;
                *label_slice.first().ok_or("label tensor is empty")?
            };

            // Secondary: anomaly score ("scores") — float32, shape [1, 1] or [1]
            let score_val: f32 = {
                let (_, score_slice) = outputs["scores"]
                    .try_extract_tensor::<f32>()
                    .map_err(|e| e.to_string())?;
                *score_slice.first().ok_or("scores tensor is empty")?
            };

            (label_val, score_val)
            // outputs and session guard drop here
        };

        // label == -1  →  anomaly (novel);  label == 1  →  normal
        let is_novel = label == -1;

        // Confidence: how far the score is below the threshold, normalised.
        // score in (-∞, THRESHOLD]  →  confidence in [0, 1]:
        //   score == THRESHOLD  →  confidence 0.0  (just barely anomalous)
        //   score << THRESHOLD  →  confidence → 1.0
        let confidence = if is_novel {
            let raw = (ANOMALY_THRESHOLD - anomaly_score) / ANOMALY_THRESHOLD.abs();
            raw.clamp(0.0, 1.0) as f64
        } else {
            0.0
        };

        Ok(NoveltyPrediction {
            is_novel,
            anomaly_score: anomaly_score as f64,
            confidence,
            model_available: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_path() -> String {
        let candidates = [
            "../resources/models/novelty/model.onnx",
            "resources/models/novelty/model.onnx",
        ];
        for p in &candidates {
            if std::path::Path::new(p).exists() {
                return p.to_string();
            }
        }
        panic!("novelty model.onnx not found — run: python scripts/convert_novelty_to_onnx.py");
    }

    #[test]
    fn novelty_detector_loads_and_predicts() {
        let det = OnnxNoveltyDetector::load(&model_path())
            .expect("ONNX novelty detector should load successfully");

        let features = vec![0.0f64; NOVELTY_FEATURES];
        let pred = det
            .predict(&features)
            .expect("prediction on zero features should succeed");

        assert!(
            (0.0..=1.0).contains(&pred.confidence),
            "confidence {} out of range",
            pred.confidence
        );
        assert!(pred.model_available, "model_available should be true");
        println!(
            "Smoke test: is_novel={}, score={:.4}, confidence={:.4}",
            pred.is_novel, pred.anomaly_score, pred.confidence
        );
    }

    #[test]
    fn novelty_detector_handles_short_feature_vec() {
        let det = OnnxNoveltyDetector::load(&model_path()).expect("load");
        let features = vec![0.5f64; 10];
        assert!(
            det.predict(&features).is_ok(),
            "short feature vec should be padded and not crash"
        );
    }

    #[test]
    fn novelty_detector_handles_long_feature_vec() {
        let det = OnnxNoveltyDetector::load(&model_path()).expect("load");
        let features = vec![0.5f64; NOVELTY_FEATURES + 100];
        assert!(
            det.predict(&features).is_ok(),
            "long feature vec should be truncated and not crash"
        );
    }
}
