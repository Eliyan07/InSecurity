"""
Classifier Module
LightGBM-based malware classification using EMBER features
"""

from .model import (
    MalwareClassifier,
    predict,
    load_model,
)

__all__ = [
    "MalwareClassifier",
    "predict",
    "load_model",
]
