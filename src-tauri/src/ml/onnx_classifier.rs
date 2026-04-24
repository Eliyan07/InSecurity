//! ONNX-based malware classifier.
//!
//!
//! The model is a LightGBM binary classifier exported to ONNX via
//! `scripts/convert_to_onnx.py`. With `zipmap=False`, the `probabilities`
//! output is a plain float32 tensor of shape [batch, 2]:
//!   - index 0 → P(clean)
//!   - index 1 → P(malware)
//!
//! `ort::Session` is Send + Sync, so `Arc<OnnxClassifier>` can be shared
//! across Tokio spawn_blocking tasks without any locking.

use std::sync::Mutex;

use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;

/// EMBER feature count expected by the classifier model.
const EMBER_FEATURES: usize = 2381;

/// Thresholds matching the Python classifier defaults.
const THRESHOLD_MALWARE: f32 = 0.90;
const THRESHOLD_SUSPICIOUS: f32 = 0.35;

/// Thread-safe ONNX classifier.
///
/// `Session::run()` requires `&mut Session`, so we wrap it in a `Mutex`.
/// `Arc<OnnxClassifier>` can be freely shared across spawn_blocking tasks;
/// each task acquires the lock only for the duration of a single inference call.
pub struct OnnxClassifier {
    session: Mutex<Session>,
}

impl OnnxClassifier {
    /// Load an ONNX model from `model_path`.
    ///
    /// Uses a single intra-op thread so ONNX Runtime never spawns worker
    /// threads that could interfere with the embedded Python runtime or Tokio.
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
            "ONNX classifier loaded: {} input(s), {} output(s)",
            session.inputs().len(),
            session.outputs().len()
        );

        Ok(Self {
            session: Mutex::new(session),
        })
    }

    /// Predict malware probability for a single EMBER feature vector.
    ///
    /// Returns `(confidence, verdict)` where:
    /// - `confidence` is the raw malware probability in `[0.0, 1.0]`
    /// - `verdict` is `"malware"`, `"suspicious"`, or `"clean"`
    pub fn predict(&self, features: &[f64]) -> Result<(f32, &'static str), String> {
        // Pad or truncate to the expected feature count.
        let mut padded: Vec<f32> = features
            .iter()
            .take(EMBER_FEATURES)
            .map(|&x| x as f32)
            .collect();
        padded.resize(EMBER_FEATURES, 0.0_f32);

        // Build a tensor via the (shape, Vec<T>) tuple API — no ndarray version
        // dependency needed. OwnedTensorArrayData is implemented for (D: ToShape, Vec<T>).
        let shape = [1_usize, EMBER_FEATURES];
        let tensor_val =
            ort::value::Tensor::<f32>::from_array((shape, padded)).map_err(|e| e.to_string())?;

        // Session::run() requires &mut Session. Lock for the duration of inference
        // and extract the scalar we need before releasing the lock.
        let malware_prob: f32 = {
            let mut session = self
                .session
                .lock()
                .map_err(|_| "ONNX session lock poisoned")?;

            // inputs! returns Vec directly in ort 2.0.0-rc.12 (no Result wrapper).
            let outputs = session
                .run(ort::inputs!["input" => tensor_val])
                .map_err(|e| e.to_string())?;

            // try_extract_tensor::<T>() returns (&Shape, &[T]) in ort 2.0.0-rc.12.
            // Shape is [1, 2]: [p(clean), p(malware)] for batch size 1.
            let (_, probs_slice) = outputs["probabilities"]
                .try_extract_tensor::<f32>()
                .map_err(|e| e.to_string())?;

            *probs_slice
                .get(1)
                .ok_or("probabilities tensor has fewer than 2 elements")?
            // outputs and session guard drop here, releasing the lock.
        };

        let confidence = malware_prob.clamp(0.0, 1.0);
        let verdict = if confidence >= THRESHOLD_MALWARE {
            "malware"
        } else if confidence >= THRESHOLD_SUSPICIOUS {
            "suspicious"
        } else {
            "clean"
        };

        Ok((confidence, verdict))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_path() -> String {
        // `cargo test` runs with CWD = src-tauri/
        let candidates = [
            "../resources/models/classifier/model.onnx",
            "resources/models/classifier/model.onnx",
        ];
        for p in &candidates {
            if std::path::Path::new(p).exists() {
                return p.to_string();
            }
        }
        panic!("model.onnx not found — run: python scripts/convert_to_onnx.py");
    }

    #[test]
    fn onnx_classifier_loads_and_predicts() {
        let clf =
            OnnxClassifier::load(&model_path()).expect("ONNX classifier should load successfully");

        // All-zeros features (empty file-like input) → expect a valid low-confidence result
        let features = vec![0.0f64; EMBER_FEATURES];
        let (confidence, verdict) = clf
            .predict(&features)
            .expect("prediction on zero features should succeed");

        assert!(
            (0.0..=1.0).contains(&confidence),
            "confidence {confidence} is outside [0, 1]"
        );
        assert!(
            ["malware", "suspicious", "clean"].contains(&verdict),
            "unexpected verdict: {verdict}"
        );
        println!("Smoke test result: confidence={confidence:.4}, verdict={verdict}");
    }

    #[test]
    fn onnx_classifier_handles_short_feature_vec() {
        let clf = OnnxClassifier::load(&model_path()).expect("load");
        // Fewer features than EMBER_FEATURES — should pad with zeros and not crash
        let features = vec![0.5f64; 100];
        assert!(
            clf.predict(&features).is_ok(),
            "short feature vec should be padded gracefully"
        );
    }

    #[test]
    fn onnx_classifier_handles_long_feature_vec() {
        let clf = OnnxClassifier::load(&model_path()).expect("load");
        // More features than EMBER_FEATURES — should truncate and not crash
        let features = vec![0.5f64; EMBER_FEATURES + 500];
        assert!(
            clf.predict(&features).is_ok(),
            "long feature vec should be truncated gracefully"
        );
    }
}
