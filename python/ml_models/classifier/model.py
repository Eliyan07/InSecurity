"""
LightGBM Malware Classifier
===========================
Binary classification model trained on EMBER dataset features.
Uses 2381 features extracted by the Rust EMBER extractor.

Model files (in resources/models/classifier/):
- model.bin or model.txt: LightGBM model
- calibrator.pkl: Probability calibration (Platt scaling)
- manifest.json: Model metadata and version
"""

import numpy as np
from typing import List, Dict, Optional
import logging
import json
from pathlib import Path
import lightgbm as lgb

from ..model_security import secure_load_pickle, ModelSecurityError

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path(__file__).parent.parent.parent.parent / "resources" / "models" / "classifier"

DEFAULT_THRESHOLDS = {
    "malware": 0.90,
    "suspicious": 0.35,
    "clean": 0.35
}


class MalwareClassifier:
    """
    LightGBM-based malware classifier.
    
    Expects 2381 EMBER features extracted by the Rust feature extractor.
    Returns calibrated probability scores with verdict classification.
    """
    
    def __init__(self, model_path: Optional[str] = None, model_dir: Optional[Path] = None):
        """
        Initialize the classifier.
        
        Args:
            model_path: Direct path to model file
            model_dir: Directory containing model files (uses default if None)
        """
        self.model: Optional[lgb.Booster] = None
        self.model_version = "1.0.0"
        self.calibrator = None
        self.feature_names = None
        self.feature_importance = None
        self.thresholds = DEFAULT_THRESHOLDS.copy()
        self.model_dir = model_dir or DEFAULT_MODEL_DIR
        
        if model_path:
            self.load_model(model_path)
        else:
            self._auto_load_model()
    
    def _auto_load_model(self) -> None:
        """Auto-load model from default directory."""
        if not self.model_dir.exists():
            logger.warning(f"Model directory not found: {self.model_dir}")
            return

        for model_file in [self.model_dir / "model.bin", self.model_dir / "model.txt"]:
            if model_file.exists():
                try:
                    self.load_model(str(model_file))
                    break
                except Exception as e:
                    logger.warning(f"Failed to load {model_file}: {e}")

        # calibrator.pkl loading is intentionally skipped in the legacy Python
        # runtime path. The desktop app uses ONNX inference directly, so raw
        # LightGBM probabilities are used here only for offline tooling.
        # calibrator_path = self.model_dir / "calibrator.pkl"
        
        thresholds_path = self.model_dir / "ml_thresholds.json"
        if thresholds_path.exists():
            try:
                with open(thresholds_path) as f:
                    config = json.load(f)
                    if "thresholds" in config:
                        self.thresholds.update(config["thresholds"])
            except Exception as e:
                logger.warning(f"Failed to load thresholds: {e}")
        
        manifest_path = self.model_dir / "manifest.json"
        if manifest_path.exists():
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
                    self.model_version = manifest.get("model_version", "1.0.0")
            except Exception as e:
                logger.warning(f"Failed to load manifest: {e}")
    
    def load_model(self, model_path: str) -> None:
        """Load a trained LightGBM model."""
        try:
            path = Path(model_path)
            
            # num_threads=1 is passed to predict() below, not here: LightGBM
            # ignores the params argument when loading from a model file and
            # uses the file's stored parameters instead (hence the UserWarning).
            if path.suffix in ['.bin', '.txt']:
                self.model = lgb.Booster(model_file=model_path)
            elif path.suffix == '.pkl':
                self.model = secure_load_pickle(model_path)
                if self.model is not None and hasattr(self.model, 'set_params'):
                    self.model.set_params(num_threads=1)
            else:
                try:
                    self.model = lgb.Booster(model_file=model_path)
                except Exception:
                    self.model = secure_load_pickle(model_path)
                    if self.model is not None and hasattr(self.model, 'set_params'):
                        self.model.set_params(num_threads=1)
            
            if self.model:
                self.feature_names = self.model.feature_name()
                self.feature_importance = self.model.feature_importance()
                logger.info(f"Model loaded: {self.model.num_feature()} features")
        
        except ModelSecurityError as e:
            logger.error(f"Model security verification failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def load_calibrator(self, calibrator_path: str) -> None:
        """Load probability calibrator."""
        try:
            self.calibrator = secure_load_pickle(calibrator_path)
            logger.info(f"Calibrator loaded from {calibrator_path}")
        except Exception as e:
            logger.error(f"Failed to load calibrator: {e}")
    
    def predict(self, features: List[float]) -> Dict:
        """
        Predict malware probability.
        
        Args:
            features: 2381 EMBER features
            
        Returns:
            Dict with is_malware, confidence, verdict, etc.
        """
        try:
            if self.model is None:
                return {
                    "is_malware": None,
                    "confidence": 0.0,
                    "malware_family": None,
                    "raw_score": 0.0,
                    "model_available": False,
                    "verdict": "unknown"
                }
            
            X = np.array([features], dtype=np.float32)
            
            expected = self.model.num_feature()
            if X.shape[1] != expected:
                if X.shape[1] < expected:
                    X = np.pad(X, ((0, 0), (0, expected - X.shape[1])))
                else:
                    X = X[:, :expected]
            
            # num_threads=1: the Booster constructor's params={"num_threads":1}
            # is silently ignored when loading from a model file (see LightGBM
            # UserWarning: "Ignoring params argument").  The model file's stored
            # num_threads is used instead.  Passing num_threads here bypasses
            # that and calls omp_set_num_threads(1) at the C level, preventing
            # OpenMP from spawning worker threads (which crashes the embedded
            # Python runtime with STATUS_ACCESS_VIOLATION on Windows).
            raw_prediction = self.model.predict(
                X, num_iteration=self.model.best_iteration, num_threads=1
            )[0]
            
            if self.calibrator:
                try:
                    calibrated = self.calibrator.predict_proba([[raw_prediction]])[0][1]
                except Exception:
                    calibrated = raw_prediction
            else:
                calibrated = raw_prediction
            
            confidence = float(np.clip(calibrated, 0.0, 1.0))
            
            if confidence >= self.thresholds["malware"]:
                verdict = "malware"
                is_malware = True
            elif confidence >= self.thresholds["suspicious"]:
                verdict = "suspicious"
                is_malware = True
            else:
                verdict = "clean"
                is_malware = False
            
            return {
                "is_malware": is_malware,
                "confidence": confidence,
                "malware_family": self._get_malware_family(confidence),
                "raw_score": float(raw_prediction),
                "model_available": True,
                "verdict": verdict
            }
        
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {
                "is_malware": False,
                "confidence": 0.0,
                "malware_family": None,
                "raw_score": 0.0,
                "model_available": False,
                "verdict": "error"
            }
    
    def _get_malware_family(self, confidence: float) -> Optional[str]:
        """Determine malware family based on confidence."""
        if confidence > 0.95:
            return "Generic.Malware"
        elif confidence > 0.85:
            return "Trojan.Generic"
        elif confidence > 0.70:
            return "Suspicious.Behavior"
        elif confidence > 0.50:
            return "Suspicious.Generic"
        return None


_classifier = MalwareClassifier()


def predict(features: List[float]) -> Dict:
    """Predict malware probability from EMBER features."""
    return _classifier.predict(features)


def load_model(model_path: str) -> None:
    """Load a new model."""
    global _classifier
    _classifier = MalwareClassifier(model_path)
