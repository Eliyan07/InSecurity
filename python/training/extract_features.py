"""
Feature Extraction Script
Extracts EMBER features from PE files for training the novelty detector

Usage:
    python -m ml_models.training.extract_features --input_dir ./samples/benign --output_dir ./training_data/benign

Requires:
    - ember (pip install ember)
    - lief (pip install lief)
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional, List, Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    import ember
    EMBER_AVAILABLE = True
except ImportError:
    EMBER_AVAILABLE = False
    logger.warning("ember not installed. Run: pip install ember")


def extract_features_from_file(file_path: str) -> Optional[List[float]]:
    """
    Extract EMBER features from a single PE file
    
    Args:
        file_path: Path to PE file
        
    Returns:
        Feature vector as list of floats, or None if extraction failed
    """
    if not EMBER_AVAILABLE:
        raise RuntimeError("ember package not installed")
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        features = ember.features.PEFeatureExtractor(2).feature_vector(file_data)
        return features.tolist()
    except PermissionError:
        logger.debug(f"Permission denied (file locked): {file_path}")
        return None
    except Exception as e:
        logger.debug(f"Failed to extract features from {file_path}: {e}")
        return None


def process_file(args: tuple) -> tuple:
    """Process a single file (for parallel processing)"""
    file_path, output_dir = args
    
    try:
        features = extract_features_from_file(file_path)
        if features is None:
            return (file_path, False, "Feature extraction failed")
        
        file_name = Path(file_path).stem
        output_path = Path(output_dir) / f"{file_name}.json"
        
        with open(output_path, 'w') as f:
            json.dump({
                "source_file": str(file_path),
                "features": features,
                "feature_count": len(features)
            }, f)
        
        return (file_path, True, str(output_path))
    except Exception as e:
        return (file_path, False, str(e))


def extract_features_batch(
    input_dir: str,
    output_dir: str,
    extensions: List[str] = ['.exe', '.dll', '.sys'],
    max_workers: int = 4
) -> Dict[str, int]:
    """
    Extract features from all PE files in a directory
    
    Args:
        input_dir: Directory containing PE files
        output_dir: Directory to save feature JSON files
        extensions: File extensions to process
        max_workers: Number of parallel workers
        
    Returns:
        Dict with success/failure counts
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    files = []
    for ext in extensions:
        files.extend(input_path.glob(f"**/*{ext}"))
        files.extend(input_path.glob(f"**/*{ext.upper()}"))
    
    logger.info(f"Found {len(files)} PE files to process")
    
    results = {"success": 0, "failed": 0, "errors": []}
    
    tasks = [(str(f), str(output_path)) for f in files]
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_file, task): task for task in tasks}
        
        for i, future in enumerate(as_completed(futures)):
            file_path, success, message = future.result()
            
            if success:
                results["success"] += 1
            else:
                results["failed"] += 1
                results["errors"].append(f"{file_path}: {message}")
            
            if (i + 1) % 100 == 0:
                logger.info(f"Processed {i + 1}/{len(files)} files...")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Extract EMBER features from PE files")
    parser.add_argument("--input_dir", required=True, help="Directory containing PE files")
    parser.add_argument("--output_dir", required=True, help="Directory to save feature JSON files")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers")
    parser.add_argument("--extensions", nargs="+", default=[".exe", ".dll", ".sys"], help="File extensions to process")
    
    args = parser.parse_args()
    
    if not EMBER_AVAILABLE:
        logger.error("ember package not installed. Run: pip install ember")
        sys.exit(1)
    
    logger.info(f"Extracting features from {args.input_dir}")
    logger.info(f"Output directory: {args.output_dir}")
    
    results = extract_features_batch(
        args.input_dir,
        args.output_dir,
        args.extensions,
        args.workers
    )
    
    logger.info("=== Extraction Complete ===")
    logger.info(f"Success: {results['success']}")
    logger.info(f"Failed: {results['failed']}")
    
    if results["errors"]:
        logger.info("First 10 errors:")
        for err in results["errors"][:10]:
            logger.info(f"  {err}")


if __name__ == "__main__":
    main()
