"""Numerically stable statistical utilities for passive feature engineering."""

import collections
import math
from typing import Sequence, Tuple, Union


def safe_div(
    numerator: Union[int, float],
    denominator: Union[int, float],
    default: float = 0.0,
) -> float:
    """Safely divide numerator by denominator, returning default on zero/invalid denominator."""
    if denominator == 0 or math.isnan(denominator) or math.isnan(numerator):
        return default
    try:
        res = float(numerator) / float(denominator)
        if math.isinf(res) or math.isnan(res):
            return default
        return res
    except (ZeroDivisionError, OverflowError):
        return default


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy in bits/symbol for a string.
    
    H(S) = - sum(p(x) * log2(p(x)))
    Returns:
        float: Entropy value >= 0.0 (0.0 for empty string or identical characters).
    """
    if not s:
        return 0.0

    length = len(s)
    counts = collections.Counter(s)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return max(0.0, round(entropy, 6))


def summary_statistics(values: Sequence[Union[int, float]]) -> Tuple[float, float, float, float]:
    """Calculate (min, max, mean, standard_deviation) for a sequence of numeric values.
    
    Returns:
        Tuple[float, float, float, float]: (min_val, max_val, mean_val, std_val)
        Returns (0.0, 0.0, 0.0, 0.0) if sequence is empty.
    """
    if not values:
        return 0.0, 0.0, 0.0, 0.0

    n = len(values)
    min_val = float(min(values))
    max_val = float(max(values))
    mean_val = float(sum(values)) / n

    if n <= 1:
        return min_val, max_val, mean_val, 0.0

    # Welford / sample population variance
    variance = sum((x - mean_val) ** 2 for x in values) / n
    std_val = math.sqrt(max(0.0, variance))

    return min_val, max_val, round(mean_val, 4), round(std_val, 4)


def rate(count: Union[int, float], duration: Union[int, float]) -> float:
    """Calculate events per unit time safely."""
    return safe_div(count, duration, default=0.0)


def ratio(a: Union[int, float], b: Union[int, float]) -> float:
    """Calculate ratio a / b safely."""
    return safe_div(a, b, default=0.0)
