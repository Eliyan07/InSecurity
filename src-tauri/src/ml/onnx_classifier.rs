use std::sync::Mutex;

use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;

const EMBER_FEATURES: usize = 2381;

const THRESHOLD_MALWARE: f32 = 0.90;
const THRESHOLD_SUSPICIOUS: f32 = 0.35;

pub struct OnnxClassifier {
    session: Mutex<Session>,
}

impl OnnxClassifier {
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

    pub fn predict(&self, features: &[f64]) -> Result<(f32, &'static str), String> {
        let mut padded: Vec<f32> = features
            .iter()
            .take(EMBER_FEATURES)
            .map(|&x| x as f32)
            .collect();
        padded.resize(EMBER_FEATURES, 0.0_f32);

        let shape = [1_usize, EMBER_FEATURES];
        let tensor_val =
            ort::value::Tensor::<f32>::from_array((shape, padded)).map_err(|e| e.to_string())?;

        let malware_prob: f32 = {
            let mut session = self
                .session
                .lock()
                .map_err(|_| "ONNX session lock poisoned")?;

            let outputs = session
                .run(ort::inputs!["input" => tensor_val])
                .map_err(|e| e.to_string())?;

            let (_, probs_slice) = outputs["probabilities"]
                .try_extract_tensor::<f32>()
                .map_err(|e| e.to_string())?;

            *probs_slice
                .get(1)
                .ok_or("probabilities tensor has fewer than 2 elements")?
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
        let features = vec![0.5f64; 100];
        assert!(
            clf.predict(&features).is_ok(),
            "short feature vec should be padded gracefully"
        );
    }

    #[test]
    fn onnx_classifier_handles_long_feature_vec() {
        let clf = OnnxClassifier::load(&model_path()).expect("load");
        let features = vec![0.5f64; EMBER_FEATURES + 500];
        assert!(
            clf.predict(&features).is_ok(),
            "long feature vec should be truncated gracefully"
        );
    }
}
