"""
Isolation Forest Novelty Detector
=================================
Detects anomalous/novel samples that differ from known benign patterns.
Uses 42 behavioral features extracted by NoveltyFeatureExtractor.

Model files (in resources/models/novelty/):
- model.joblib: Trained Isolation Forest
- scaler.pkl: StandardScaler for feature normalization
- threshold.json: Decision threshold
- features.json: Feature names and count
"""

import json
import numpy as np
from typing import List, Dict, Optional
import logging
from pathlib import Path

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..model_security import secure_load_pickle, ModelSecurityError
from .features import NoveltyFeatureExtractor

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path(__file__).parent.parent.parent.parent / "resources" / "models" / "novelty"

_feature_extractor: Optional[NoveltyFeatureExtractor] = None


def get_feature_extractor() -> NoveltyFeatureExtractor:
    """Get or create the global feature extractor."""
    global _feature_extractor
    if _feature_extractor is None:
        _feature_extractor = NoveltyFeatureExtractor()
    return _feature_extractor


class NoveltyDetector:
    """
    Isolation Forest-based novelty detector.
    
    Trained on benign samples to detect anomalous patterns.
    Uses 42 behavioral features (section entropy, imports, packer indicators, etc.)
    """

    def __init__(self, model_path: Optional[str] = None, model_dir: Optional[Path] = None):
        """
        Initialize the detector.
        
        Args:
            model_path: Direct path to model file
            model_dir: Directory containing model files (uses default if None)
        """
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.model_version = "2.0.0"
        self.contamination = 0.005
        self.threshold = -0.5
        self.feature_names: Optional[List[str]] = None
        self.num_features = 42
        self.model_dir = model_dir or DEFAULT_MODEL_DIR
        self.model_available = False
        self.training_stats: Optional[Dict] = None

        if model_path:
            self.load_model(model_path)
        else:
            self._auto_load_model()

    def _auto_load_model(self) -> None:
        """Auto-load model from default directory.

        The desktop app uses the exported ONNX model at runtime, so this legacy
        Python path keeps model auto-loading disabled by default.
        """
        return  # keep self.model = None (set in __init__)

    def _initialize_default_model(self) -> None:
        """Initialize untrained default model."""
        try:
            # n_jobs=1: joblib's 'loky' backend forks child processes, which
            # crashes on Windows when called from a non-main thread.
            self.model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
                n_jobs=1,
            )
            self.model_available = False
        except Exception as e:
            logger.error(f"Failed to initialize model: {e}")

    def load_model(self, model_path: str) -> None:
        """Load a trained model."""
        try:
            path = Path(model_path)
            if path.suffix == '.joblib' and HAS_JOBLIB:
                self.model = joblib.load(model_path)
            else:
                self.model = secure_load_pickle(model_path)
            self.model_available = True
        except ModelSecurityError as e:
            logger.error(f"Security verification failed: {e}")
            self._initialize_default_model()
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self._initialize_default_model()

    def _scale_features(self, features: np.ndarray) -> np.ndarray:
        """Scale features using loaded scaler."""
        if self.scaler is not None:
            return self.scaler.transform(features)
        return features

    def detect_anomaly(self, features: List[float]) -> Dict:
        """
        Detect if sample is anomalous.

        Args:
            features: 42 behavioral features

        Returns:
            Dict with is_novel, anomaly_score, confidence, model_available
        """
        try:
            if self.model is None:
                return {
                    "is_novel": None,
                    "anomaly_score": 0.0,
                    "confidence": 0.0,
                    "model_available": False
                }

            X = np.array([features], dtype=np.float32)
            X_scaled = self._scale_features(X)

            anomaly_score = float(self.model.decision_function(X_scaled)[0])
            is_novel = anomaly_score < self.threshold
            confidence = self._score_to_confidence(anomaly_score)

            return {
                "is_novel": bool(is_novel),
                "anomaly_score": anomaly_score,
                "confidence": confidence,
                "threshold": self.threshold,
                "model_available": True
            }

        except Exception as e:
            logger.error(f"Detection failed: {e}")
            return {
                "is_novel": None,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "model_available": False,
                "error": str(e)
            }

    def _score_to_confidence(self, score: float) -> float:
        """Convert anomaly score to confidence (0-1)."""
        try:
            if score < self.threshold:
                distance = abs(score - self.threshold)
                confidence = min(0.5 + distance * 2, 1.0)
            else:
                distance = score - self.threshold
                confidence = max(0.5 - distance * 2, 0.0)
            return float(np.clip(confidence, 0.0, 1.0))
        except Exception:
            return 0.5

    def get_model_info(self) -> Dict:
        """Get model information."""
        return {
            "model_available": self.model_available,
            "model_version": self.model_version,
            "num_features": self.num_features,
            "threshold": self.threshold,
            "contamination": self.contamination,
            "has_scaler": self.scaler is not None,
            "training_samples": self.training_stats.get('n_samples') if self.training_stats else None,
            "trained_at": self.training_stats.get('trained_at') if self.training_stats else None,
        }


_detector: Optional[NoveltyDetector] = None


def get_detector() -> NoveltyDetector:
    """Get or create the global detector instance."""
    global _detector
    if _detector is None:
        _detector = NoveltyDetector()
    return _detector


def detect_anomaly(features: List[float]) -> Dict:
    """Detect anomaly from pre-extracted features."""
    return get_detector().detect_anomaly(features)


def detect_anomaly_from_file(file_path: str) -> Dict:
    """
    Detect anomaly directly from file path.
    
    Extracts 42 features and runs Isolation Forest detection.
    """
    extractor = get_feature_extractor()
    detector = get_detector()
    
    try:
        features = extractor.extract(file_path)
        
        if features is None:
            return {
                "is_novel": None,
                "anomaly_score": 0.0,
                "model_available": detector.model_available,
                "features_extracted": False,
            }
        
        result = detector.detect_anomaly(features.tolist())
        result["features_extracted"] = True
        return result
        
    except Exception as e:
        logger.error(f"Error in detect_anomaly_from_file: {e}")
        return {
            "is_novel": None,
            "anomaly_score": 0.0,
            "model_available": detector.model_available,
            "features_extracted": False,
            "error": str(e),
        }


def load_model(model_path: str) -> None:
    """Load a new model."""
    global _detector
    _detector = NoveltyDetector(model_path)


def get_model_info() -> Dict:
    """Get model information."""
    return get_detector().get_model_info()
