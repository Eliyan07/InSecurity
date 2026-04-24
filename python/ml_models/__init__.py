"""
ML Models Package
=================

This package contains standalone Python tooling used for model preparation,
conversion, and signing. The production desktop app performs runtime detection
in Rust and does not ship these modules.

Use this package only for offline development tasks such as:
- training or inspecting experimental models
- signing pickle/joblib artifacts
- running Python-side tooling tests

If you are only building or running the desktop app, you can ignore this folder.
"""

import os

# Keep numerical libraries single-threaded in offline tooling scripts.
# The shipped app does not use this Python path for runtime inference.
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

__version__ = "2.2.0"

__all__ = []


def _load_optional_exports() -> None:
    # These imports are optional so lightweight tasks can still work even when
    # ML dependencies are not installed in the current Python environment.
    optional_groups = (
        (".classifier", ("predict", "MalwareClassifier")),
        (
            ".novelty",
            ("detect_anomaly", "detect_anomaly_from_file", "NoveltyDetector", "NoveltyFeatureExtractor"),
        ),
        (
            ".model_security",
            ("ModelVerifier", "ModelSecurityError", "secure_load_pickle", "secure_save_pickle"),
        ),
    )

    for module_name, names in optional_groups:
        try:
            module = __import__(f"{__name__}{module_name}", fromlist=list(names))
        except Exception:
            continue

        for name in names:
            globals()[name] = getattr(module, name)
            __all__.append(name)


_load_optional_exports()
