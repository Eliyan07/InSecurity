"""
Novelty Detector Training Script
Trains an Isolation Forest model for detecting novel/zero-day malware samples

Usage:
    python -m training.train_novelty --benign_dir ./training_data/features/benign --output ./resources/models/novelty/model.pkl

The model is trained on BENIGN samples only. At inference time, malware samples
should appear as anomalies (novel) since they differ from the learned benign distribution.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml_models.model_security import secure_save_pickle
from ml_models.novelty import NoveltyDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_features_from_json(json_path: str) -> np.ndarray:
    """Load feature vectors from a JSON file"""
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    if isinstance(data, list):
        return np.array(data)
    elif isinstance(data, dict) and 'features' in data:
        return np.array(data['features'])
    else:
        raise ValueError(f"Unexpected JSON format in {json_path}")


def load_features_from_directory(data_dir: str) -> Tuple[np.ndarray, List[str]]:
    """
    Load all feature vectors from a directory of JSON files
    
    Args:
        data_dir: Directory containing JSON files with EMBER feature vectors
        
    Returns:
        Tuple of (features array, list of file names)
    """
    data_path = Path(data_dir)
    if not data_path.exists():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")
    
    features_list = []
    file_names = []
    
    for json_file in data_path.glob("*.json"):
        try:
            features = load_features_from_json(str(json_file))
            if features.ndim == 1:
                features_list.append(features)
                file_names.append(json_file.name)
            else:
                for i, feat in enumerate(features):
                    features_list.append(feat)
                    file_names.append(f"{json_file.name}_{i}")
        except Exception as e:
            logger.warning(f"Failed to load {json_file}: {e}")
            continue
    
    if not features_list:
        raise ValueError(f"No valid feature files found in {data_dir}")
    
    return np.array(features_list), file_names


def train_novelty_detector(
    features: np.ndarray,
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42
) -> IsolationForest:
    """
    Train an Isolation Forest model
    
    Args:
        features: Training feature matrix (benign samples only)
        contamination: Expected proportion of outliers in training data
        n_estimators: Number of trees in the forest
        random_state: Random seed for reproducibility
        
    Returns:
        Trained IsolationForest model
    """
    logger.info(f"Training Isolation Forest with {len(features)} samples...")
    logger.info(f"  - n_estimators: {n_estimators}")
    logger.info(f"  - contamination: {contamination}")
    logger.info(f"  - feature dimensions: {features.shape[1]}")
    
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
        verbose=1
    )
    
    model.fit(features)
    logger.info("Training complete!")
    
    return model


def evaluate_model(model: IsolationForest, benign_features: np.ndarray, malware_features: np.ndarray = None):
    """
    Evaluate the trained model
    
    Args:
        model: Trained IsolationForest
        benign_features: Benign test samples (should be classified as normal)
        malware_features: Optional malware test samples (should be classified as anomalies)
    """
    benign_scores = model.decision_function(benign_features)
    benign_preds = model.predict(benign_features)
    
    benign_normal = np.sum(benign_preds == 1)
    benign_anomaly = np.sum(benign_preds == -1)
    
    logger.info("=== Evaluation Results ===")
    logger.info(f"Benign samples: {len(benign_features)}")
    logger.info(f"  - Classified as normal: {benign_normal} ({100*benign_normal/len(benign_features):.1f}%)")
    logger.info(f"  - Classified as anomaly: {benign_anomaly} ({100*benign_anomaly/len(benign_features):.1f}%)")
    logger.info(f"  - Average score: {benign_scores.mean():.4f}")
    
    if malware_features is not None and len(malware_features) > 0:
        malware_scores = model.decision_function(malware_features)
        malware_preds = model.predict(malware_features)
        
        malware_normal = np.sum(malware_preds == 1)
        malware_anomaly = np.sum(malware_preds == -1)
        
        logger.info(f"Malware samples: {len(malware_features)}")
        logger.info(f"  - Classified as normal: {malware_normal} ({100*malware_normal/len(malware_features):.1f}%)")
        logger.info(f"  - Classified as anomaly (DETECTED): {malware_anomaly} ({100*malware_anomaly/len(malware_features):.1f}%)")
        logger.info(f"  - Average score: {malware_scores.mean():.4f}")


def main():
    parser = argparse.ArgumentParser(description="Train Novelty Detection Model")
    parser.add_argument("--benign_dir", required=True, help="Directory with benign sample features (JSON)")
    parser.add_argument("--malware_dir", default=None, help="Optional: Directory with malware features for evaluation")
    parser.add_argument("--output", required=True, help="Output path for trained model (.pkl)")
    parser.add_argument("--contamination", type=float, default=0.05, help="Expected contamination ratio")
    parser.add_argument("--n_estimators", type=int, default=100, help="Number of trees")
    parser.add_argument("--test_split", type=float, default=0.2, help="Test split ratio for evaluation")
    
    args = parser.parse_args()
    
    logger.info(f"Loading benign features from {args.benign_dir}...")
    benign_features, benign_names = load_features_from_directory(args.benign_dir)
    logger.info(f"Loaded {len(benign_features)} benign samples")
    
    train_features, test_features = train_test_split(
        benign_features, 
        test_size=args.test_split, 
        random_state=42
    )
    
    model = train_novelty_detector(
        train_features,
        contamination=args.contamination,
        n_estimators=args.n_estimators
    )
    
    malware_features = None
    if args.malware_dir:
        logger.info(f"Loading malware features from {args.malware_dir}...")
        malware_features, _ = load_features_from_directory(args.malware_dir)
        logger.info(f"Loaded {len(malware_features)} malware samples")
    
    evaluate_model(model, test_features, malware_features)
    
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    detector = NoveltyDetector()
    detector.model = model
    detector.model_version = "1.0.0"
    detector.contamination = args.contamination
    
    secure_save_pickle(model, str(output_path))
    logger.info(f"Model saved to {output_path}")
    logger.info(f"Signature saved to {output_path}.sig")


if __name__ == "__main__":
    main()
