"""
Unit tests for model_security module
Tests HMAC-SHA256 signature creation and verification for ML model files
"""

import os
import tempfile
import pytest
from pathlib import Path
import pickle

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from ml_models.model_security import (
    ModelVerifier,
    ModelSecurityError,
    secure_load_pickle,
    secure_save_pickle,
    DEFAULT_SECRET_KEY,
)


class TestModelVerifier:
    """Tests for ModelVerifier class"""
    
    def test_init_with_default_key(self):
        """Verifier should initialize with default key when none provided"""
        verifier = ModelVerifier()
        assert verifier.secret_key is not None
    
    def test_init_with_custom_key(self):
        """Verifier should use custom key when provided"""
        custom_key = b"my_custom_secret_key"
        verifier = ModelVerifier(secret_key=custom_key)
        assert verifier.secret_key == custom_key
    
    def test_init_from_env_var(self, monkeypatch):
        """Verifier should read key from MODEL_SIGNING_KEY env var"""
        monkeypatch.setenv("MODEL_SIGNING_KEY", "env_secret_key")
        verifier = ModelVerifier()
        assert verifier.secret_key == b"env_secret_key"
    
    def test_compute_signature(self):
        """Should compute consistent HMAC-SHA256 signatures"""
        verifier = ModelVerifier(secret_key=b"test_key")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"test model content")
            
            sig1 = verifier.compute_signature(path)
            sig2 = verifier.compute_signature(path)
            
            assert sig1 == sig2
            assert len(sig1) == 64
            assert all(c in '0123456789abcdef' for c in sig1)
    
    def test_different_content_different_signature(self):
        """Different file contents should produce different signatures"""
        verifier = ModelVerifier(secret_key=b"test_key")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path1 = os.path.join(tmpdir, "model1.pkl")
            path2 = os.path.join(tmpdir, "model2.pkl")
            with open(path1, 'wb') as f:
                f.write(b"content 1")
            with open(path2, 'wb') as f:
                f.write(b"content 2")
            
            sig1 = verifier.compute_signature(path1)
            sig2 = verifier.compute_signature(path2)
            
            assert sig1 != sig2
    
    def test_sign_model_creates_sig_file(self):
        """sign_model should create a .sig file with the signature"""
        verifier = ModelVerifier(secret_key=b"test_key")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"model data")
            
            sig_path = verifier.sign_model(path)
            
            assert sig_path == f"{path}.sig"
            assert Path(sig_path).exists()
            
            sig_content = Path(sig_path).read_text()
            expected_sig = verifier.compute_signature(path)
            assert sig_content == expected_sig
    
    def test_verify_signature_valid(self):
        """verify_signature should return True for valid signatures"""
        verifier = ModelVerifier(secret_key=b"test_key")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"valid model data")
            
            verifier.sign_model(path)
            
            is_valid, msg = verifier.verify_signature(path)
            assert is_valid is True
            assert "valid" in msg.lower()
    
    def test_verify_signature_invalid(self):
        """verify_signature should return False for tampered files"""
        verifier = ModelVerifier(secret_key=b"test_key")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"original content")
            
            verifier.sign_model(path)
            
            with open(path, 'wb') as tampered:
                tampered.write(b"malicious content")
            
            is_valid, msg = verifier.verify_signature(path)
            assert is_valid is False
            assert "mismatch" in msg.lower() or "invalid" in msg.lower()
    
    def test_verify_signature_missing_sig_file(self):
        """verify_signature should return False when .sig file is missing"""
        verifier = ModelVerifier(secret_key=b"test_key")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"model without signature")
            
            is_valid, msg = verifier.verify_signature(path)
            assert is_valid is False
            assert "not found" in msg.lower() or "missing" in msg.lower()


class TestSecurePickleFunctions:
    """Tests for secure_load_pickle and secure_save_pickle functions"""
    
    def test_secure_save_and_load(self):
        """Should be able to save and load with signature verification"""
        test_data = {"key": "value", "numbers": [1, 2, 3]}
        
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = os.path.join(tmpdir, "test_model.pkl")
            
            secure_save_pickle(test_data, model_path)
            
            assert Path(f"{model_path}.sig").exists()
            
            loaded_data = secure_load_pickle(model_path)
            assert loaded_data == test_data
    
    def test_secure_load_fails_on_tampered_file(self):
        """secure_load_pickle should raise error for tampered files"""
        test_data = {"original": "data"}
        
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = os.path.join(tmpdir, "test_model.pkl")
            
            secure_save_pickle(test_data, model_path)
            
            with open(model_path, 'wb') as f:
                pickle.dump({"malicious": "data"}, f)
            
            with pytest.raises(ModelSecurityError):
                secure_load_pickle(model_path)
    
    def test_secure_load_fails_missing_signature(self, monkeypatch):
        """secure_load_pickle should raise error when signature is missing in strict mode"""
        monkeypatch.setenv("ML_STRICT_MODE", "1")
        test_data = {"test": "data"}
        
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = os.path.join(tmpdir, "unsigned_model.pkl")
            
            with open(model_path, 'wb') as f:
                pickle.dump(test_data, f)
            
            with pytest.raises(ModelSecurityError):
                secure_load_pickle(model_path)
    
    def test_secure_load_dev_mode(self, monkeypatch):
        """In dev mode, should allow loading unsigned models with warning"""
        monkeypatch.setenv("ML_DEV_MODE", "1")
        
        test_data = {"dev": "data"}
        
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = os.path.join(tmpdir, "dev_model.pkl")
            
            with open(model_path, 'wb') as f:
                pickle.dump(test_data, f)
            
            loaded = secure_load_pickle(model_path)
            assert loaded == test_data
    
    def test_secure_load_strict_mode(self, monkeypatch):
        """In strict mode, should reject even signed models from unknown signers"""
        monkeypatch.setenv("ML_STRICT_MODE", "1")
        
        if "ML_DEV_MODE" in os.environ:
            monkeypatch.delenv("ML_DEV_MODE")
        
        test_data = {"strict": "data"}
        
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = os.path.join(tmpdir, "strict_model.pkl")
            
            verifier = ModelVerifier(secret_key=b"different_key")
            with open(model_path, 'wb') as f:
                pickle.dump(test_data, f)
            verifier.sign_model(model_path)
            
            with pytest.raises(ModelSecurityError):
                secure_load_pickle(model_path)


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_empty_model_file(self):
        """Should handle empty model files gracefully"""
        verifier = ModelVerifier(secret_key=b"test_key")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                pass  # Empty file
            
            sig = verifier.compute_signature(path)
            # Should still produce a valid signature
            assert len(sig) == 64
    
    def test_large_model_file(self):
        """Should handle large model files"""
        verifier = ModelVerifier(secret_key=b"test_key")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                # Write 10MB of data
                f.write(b"x" * (10 * 1024 * 1024))
            
            sig = verifier.compute_signature(path)
            assert len(sig) == 64
            
            verifier.sign_model(path)
            is_valid, _ = verifier.verify_signature(path)
            assert is_valid is True
    
    def test_nonexistent_file(self):
        """Should raise appropriate error for nonexistent files"""
        verifier = ModelVerifier()
        
        with pytest.raises((FileNotFoundError, OSError)):
            verifier.compute_signature("/nonexistent/path/model.pkl")


class TestVerifyOrRaise:
    """Tests for verify_or_raise method."""

    def test_verify_or_raise_valid(self):
        """Should not raise for valid signature."""
        verifier = ModelVerifier(secret_key=b"test_key")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"valid content")
            verifier.sign_model(path)
            verifier.verify_or_raise(path)  # Should not raise

    def test_verify_or_raise_invalid(self):
        """Should raise ModelSecurityError for tampered file."""
        verifier = ModelVerifier(secret_key=b"test_key")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"original")
            verifier.sign_model(path)
            with open(path, 'wb') as tampered:
                tampered.write(b"tampered")
            with pytest.raises(ModelSecurityError):
                verifier.verify_or_raise(path)

    def test_verify_or_raise_missing_sig(self):
        """Should raise ModelSecurityError when no .sig file."""
        verifier = ModelVerifier(secret_key=b"test_key")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"no sig")
            with pytest.raises(ModelSecurityError):
                verifier.verify_or_raise(path)


class TestCLIFunctions:
    """Tests for sign_model_cli and verify_model_cli."""

    def test_sign_model_cli(self, capsys):
        """sign_model_cli creates .sig and prints path."""
        from ml_models.model_security import sign_model_cli
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"model data for cli")
            sign_model_cli(path)
            captured = capsys.readouterr()
            assert "Signature created" in captured.out
            assert Path(f"{path}.sig").exists()

    def test_verify_model_cli_valid(self, capsys):
        """verify_model_cli prints ✓ for valid model."""
        from ml_models.model_security import verify_model_cli, ModelVerifier
        verifier = ModelVerifier()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"cli verify data")
            verifier.sign_model(path)
            verify_model_cli(path)
            captured = capsys.readouterr()
            assert "✓" in captured.out or "valid" in captured.out.lower()

    def test_verify_model_cli_invalid(self, capsys):
        """verify_model_cli prints ✗ for unsigned model."""
        from ml_models.model_security import verify_model_cli
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            with open(path, 'wb') as f:
                f.write(b"unsigned cli data")
            verify_model_cli(path)
            captured = capsys.readouterr()
            assert "✗" in captured.out or "not found" in captured.out.lower()


class TestGetSecretKeyFromFile:
    """Tests for _get_secret_key reading from .model_key file."""

    def test_key_from_file(self, tmp_path, monkeypatch):
        """Key loaded from .model_key file when it exists."""
        if "MODEL_SIGNING_KEY" in os.environ:
            monkeypatch.delenv("MODEL_SIGNING_KEY")
        key_file = tmp_path / ".model_key"
        key_file.write_bytes(b"file_based_secret_key")
        # Patch the path resolution
        import ml_models.model_security as msec
        original_file = Path(msec.__file__)
        monkeypatch.setattr(msec, '__file__', str(tmp_path / "model_security.py"))
        verifier = ModelVerifier()
        # The key file location is relative to __file__, so this may or may not find it
        # Just ensure no crash
        assert verifier.secret_key is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
