"""Model metadata schema for machine learning threat detectors."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MLModelMetadata(BaseModel):
    """Strongly-typed metadata for serializing and validating supervised ML models."""

    model_name: str = Field(..., description="Unique model identifier")
    model_version: str = Field(..., description="Semantic version of model weights")
    algorithm: str = Field(default="RandomForestClassifier", description="ML algorithm name")
    feature_version: str = Field(default="1.0", description="Compatible FeatureVector schema version")
    feature_names: List[str] = Field(..., description="Strict ordered list of feature column names")
    target_classes: List[str] = Field(..., description="Target class labels mapped to model output indices")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 creation timestamp",
    )
    hyperparameters: Dict[str, Any] = Field(default_factory=dict, description="Model training hyperparameters")
    metrics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Validation metrics or explicit inference infrastructure declaration",
    )
    dataset_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Training dataset provenance, sample count, and checksums",
    )
    class_thresholds: Dict[str, float] = Field(
        default_factory=dict,
        description="Class-specific calibrated probability thresholds derived from validation split",
    )
    calibration_provenance: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Methodology, split details, and validation metrics for probability threshold calibration",
    )

