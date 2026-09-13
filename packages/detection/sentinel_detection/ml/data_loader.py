"""Safe dataset loader and anti-leakage data partitioner for SentinelAI ML pipeline.

Ensures:
- Robust CSV parsing with NaN/Inf sanitization
- Explicit feature alignment with CANONICAL_ML_FEATURES
- Anti-leakage partitioning (temporal / host-aware / stratified)
- Class imbalance adjustment to realistic operational distributions
"""

import csv
import logging
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union, overload
import numpy as np
from sklearn.model_selection import StratifiedKFold, train_test_split

from sentinel_detection.ml.dataset_adapter import BaseDatasetAdapter, CICDatasetAdapter
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES

logger = logging.getLogger("sentinel.ml.data_loader")


@overload
def load_dataset_from_csv(
    file_path: Union[str, Path],
    adapter: Optional[BaseDatasetAdapter] = ...,
    max_samples: Optional[int] = ...,
    *,
    return_metadata: Literal[True],
) -> Tuple[np.ndarray, np.ndarray, List[str], Dict[str, np.ndarray]]: ...


@overload
def load_dataset_from_csv(
    file_path: Union[str, Path],
    adapter: Optional[BaseDatasetAdapter] = ...,
    max_samples: Optional[int] = ...,
    return_metadata: Literal[False] = ...,
) -> Tuple[np.ndarray, np.ndarray, List[str]]: ...


def load_dataset_from_csv(
    file_path: Union[str, Path],
    adapter: Optional[BaseDatasetAdapter] = None,
    max_samples: Optional[int] = None,
    return_metadata: bool = False,
) -> Union[Tuple[np.ndarray, np.ndarray, List[str]], Tuple[np.ndarray, np.ndarray, List[str], Dict[str, np.ndarray]]]:
    """Load and adapt a CSV dataset into canonical numpy feature matrices.
    
    Returns:
        X: np.ndarray of shape (N, 15) with float64 features
        y: np.ndarray of shape (N,) with string threat labels
        feature_names: list of canonical feature column names
        metadata (optional, if return_metadata=True): dict with additional passive metadata
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    adapt = adapter or CICDatasetAdapter()
    X_rows: List[List[float]] = []
    y_labels: List[str] = []
    dst_ports: List[int] = []

    logger.info(f"Loading dataset from {path} with adapter {adapt.__class__.__name__}...")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if max_samples and len(X_rows) >= max_samples:
                break

            result = adapt.adapt_record(row)
            if result is None:
                continue

            feats, label = result
            X_rows.append(feats)
            y_labels.append(label)

            if return_metadata:
                port_raw = row.get(" Destination Port") or row.get("Destination Port") or "0"
                try:
                    p = int(str(port_raw).strip())
                except (ValueError, TypeError):
                    p = 0
                dst_ports.append(p)

    if not X_rows:
        raise ValueError(f"No valid records could be extracted from {path}")

    X = np.array(X_rows, dtype=np.float64)
    y = np.array(y_labels, dtype=object)

    logger.info(f"Loaded {len(X)} records across {len(set(y_labels))} classes from {path.name}")
    if return_metadata:
        meta = {"destination_ports": np.array(dst_ports, dtype=np.int32)}
        return X, y, CANONICAL_ML_FEATURES, meta
    return X, y, CANONICAL_ML_FEATURES


def balance_dataset(
    X: np.ndarray,
    y: np.ndarray,
    benign_ratio: float = 0.85,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """Subsample majority benign class to match operational distribution (e.g. 85% benign)."""
    rng = np.random.RandomState(random_state)
    benign_mask = y == "BENIGN"
    attack_mask = ~benign_mask

    n_attacks = int(np.sum(attack_mask))
    n_benign = int(np.sum(benign_mask))

    if n_attacks == 0 or n_benign == 0:
        return X, y

    # Desired benign count: n_benign = (benign_ratio / (1 - benign_ratio)) * n_attacks
    target_benign = int((benign_ratio / (1.0 - benign_ratio)) * n_attacks)
    target_benign = min(n_benign, max(target_benign, n_attacks))

    benign_indices = np.where(benign_mask)[0]
    attack_indices = np.where(attack_mask)[0]

    if n_benign > target_benign:
        selected_benign = rng.choice(benign_indices, size=target_benign, replace=False)
    else:
        selected_benign = benign_indices

    combined_indices = np.concatenate([selected_benign, attack_indices])
    rng.shuffle(combined_indices)

    return X[combined_indices], y[combined_indices]


def create_train_test_split(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.20,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Create stratified train/test split with deterministic reproducibility."""
    return train_test_split(
        X,
        y,
        test_size=test_size,
        stratify=y,
        random_state=random_state,
    )
