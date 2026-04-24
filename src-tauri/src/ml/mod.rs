pub mod onnx_classifier;
pub mod onnx_novelty;

mod ember_extractor;
mod novelty_extractor;

pub use ember_extractor::{EmberExtractor, EMBER_FEATURE_COUNT, EMBER_SCHEMA_VERSION};
pub use novelty_extractor::NoveltyExtractor;
pub use onnx_classifier::OnnxClassifier;
pub use onnx_novelty::OnnxNoveltyDetector;

pub const FEATURE_COUNT: usize = EMBER_FEATURE_COUNT;
pub const SCHEMA_VERSION: &str = EMBER_SCHEMA_VERSION;
