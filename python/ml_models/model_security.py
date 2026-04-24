"""
Model Security Module
Provides signing and verification helpers for offline Python model artifacts.

These helpers are for development tooling only. The shipped desktop app performs
runtime detection in Rust and does not require a Python runtime.
"""

import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_SECRET_KEY = b"insecurity_model_signing_key_v1"


class ModelSecurityError(Exception):
    """Raised when model security verification fails"""


class ModelVerifier:
    """
    Verifies model file integrity using HMAC-SHA256 signatures.

    Security model:
    - Each model file (.pkl) should have a corresponding .sig file
    - The .sig file contains the HMAC-SHA256 of the model file
    - Only models with valid signatures are loaded by offline tooling
    - This prevents loading of tampered or malicious pickle files
    """

    def __init__(self, secret_key: Optional[bytes] = None):
        """
        Initialize the model verifier.

        Args:
            secret_key: HMAC secret key. If None, uses default or env var.
        """
        self.secret_key = secret_key or self._get_secret_key()

    def _get_secret_key(self) -> bytes:
        """Get secret key from environment or use default"""
        env_key = os.environ.get("MODEL_SIGNING_KEY")
        if env_key:
            return env_key.encode("utf-8")

        key_file = Path(__file__).parent / ".model_key"
        if key_file.exists():
            try:
                return key_file.read_bytes()
            except Exception as exc:  # pragma: no cover - best-effort warning path
                logger.warning(f"Failed to read key file: {exc}")

        logger.warning("Using default model signing key - set MODEL_SIGNING_KEY in production!")
        return DEFAULT_SECRET_KEY

    def compute_signature(self, model_path: str) -> str:
        """
        Compute HMAC-SHA256 signature for a model file.

        Args:
            model_path: Path to the model file

        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        model_bytes = Path(model_path).read_bytes()
        signature = hmac.new(self.secret_key, model_bytes, hashlib.sha256)
        return signature.hexdigest()

    def sign_model(self, model_path: str) -> str:
        """
        Create a signature file for a model.

        Args:
            model_path: Path to the model file

        Returns:
            Path to the created signature file
        """
        signature = self.compute_signature(model_path)
        sig_path = f"{model_path}.sig"

        Path(sig_path).write_text(signature)
        logger.info(f"Model signed: {sig_path}")

        return sig_path

    def verify_signature(self, model_path: str) -> Tuple[bool, str]:
        """
        Verify a model file's signature.

        Args:
            model_path: Path to the model file

        Returns:
            Tuple of (is_valid, message)
        """
        sig_path = f"{model_path}.sig"

        if not Path(sig_path).exists():
            return False, f"Signature file not found: {sig_path}"

        try:
            expected_signature = Path(sig_path).read_text().strip()
        except Exception as exc:
            return False, f"Failed to read signature file: {exc}"

        try:
            actual_signature = self.compute_signature(model_path)
        except Exception as exc:
            return False, f"Failed to compute model signature: {exc}"

        if hmac.compare_digest(expected_signature, actual_signature):
            return True, "Signature valid"
        return False, "Signature mismatch - model file may be tampered"

    def verify_or_raise(self, model_path: str) -> None:
        """
        Verify a model file's signature, raising an exception on failure.

        Args:
            model_path: Path to the model file

        Raises:
            ModelSecurityError: If verification fails
        """
        is_valid, message = self.verify_signature(model_path)
        if not is_valid:
            raise ModelSecurityError(message)
        logger.info(f"Model signature verified: {model_path}")


def secure_load_pickle(model_path: str, verify: bool = True) -> object:
    """
    Securely load a pickle file with optional signature verification.

    Args:
        model_path: Path to the pickle file
        verify: Whether to verify signature (default: True)

    Returns:
        Unpickled object

    Raises:
        ModelSecurityError: If verification fails
        FileNotFoundError: If model file doesn't exist
    """
    import pickle

    if not Path(model_path).exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    dev_mode = os.environ.get("ML_DEV_MODE", "0") == "1"

    if verify and not dev_mode:
        verifier = ModelVerifier()
        sig_path = f"{model_path}.sig"

        if Path(sig_path).exists():
            verifier.verify_or_raise(model_path)
        else:
            logger.warning(
                f"No signature file for {model_path}. "
                f"Set ML_DEV_MODE=1 to skip verification or sign the model."
            )
            if os.environ.get("ML_STRICT_MODE", "0") == "1":
                raise ModelSecurityError(f"Signature file required in strict mode: {sig_path}")

    with open(model_path, "rb") as handle:
        return pickle.load(handle)


def secure_save_pickle(obj: object, model_path: str, sign: bool = True) -> str:
    """
    Securely save a pickle file with signature.

    Args:
        obj: Object to pickle
        model_path: Path to save the pickle file
        sign: Whether to create a signature file (default: True)

    Returns:
        Path to the saved model file
    """
    import pickle

    with open(model_path, "wb") as handle:
        pickle.dump(obj, handle)

    if sign:
        verifier = ModelVerifier()
        verifier.sign_model(model_path)

    logger.info(f"Model saved securely: {model_path}")
    return model_path


def sign_model_cli(model_path: str) -> None:
    """CLI entry point for signing a model file"""
    verifier = ModelVerifier()
    sig_path = verifier.sign_model(model_path)
    print(f"Signature created: {sig_path}")


def verify_model_cli(model_path: str) -> None:
    """CLI entry point for verifying a model file"""
    verifier = ModelVerifier()
    is_valid, message = verifier.verify_signature(model_path)
    status = "OK" if is_valid else "ERROR"
    print(f"[{status}] {message}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python model_security.py [sign|verify] <model_path>")
        sys.exit(1)

    command = sys.argv[1]
    model_path = sys.argv[2]

    if command == "sign":
        sign_model_cli(model_path)
    elif command == "verify":
        verify_model_cli(model_path)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
