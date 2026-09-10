"""Supervised machine learning detection modules."""

from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.random_forest_detector import RandomForestMLDetector
from sentinel_detection.ml.trainer import (
    CANONICAL_ML_FEATURES,
    create_deterministic_baseline_model,
    save_model_artifacts,
)

__all__ = [
    "MLModelMetadata",
    "RandomForestMLDetector",
    "CANONICAL_ML_FEATURES",
    "create_deterministic_baseline_model",
    "save_model_artifacts",
]
