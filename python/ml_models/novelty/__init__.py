"""
Novelty Detection Module
Isolation Forest-based anomaly detection for unknown malware
"""

from .model import (
    NoveltyDetector,
    detect_anomaly,
    detect_anomaly_from_file,
    load_model,
    get_model_info,
    get_detector,
)
from .features import (
    NoveltyFeatureExtractor,
    batch_extract,
    calculate_entropy,
)

__all__ = [
    "NoveltyDetector",
    "detect_anomaly",
    "detect_anomaly_from_file",
    "load_model",
    "get_model_info",
    "get_detector",
    "NoveltyFeatureExtractor",
    "batch_extract",
    "calculate_entropy",
]
