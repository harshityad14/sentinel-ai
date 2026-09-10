"""Passive feature engineering and statistical extraction module for SentinelAI."""

from sentinel_features.base import BaseFeatureExtractor
from sentinel_features.dns import DNSFeatureExtractor
from sentinel_features.extractor import UnifiedFeatureExtractor
from sentinel_features.network import NetworkFeatureExtractor
from sentinel_features.registry import FeatureDefinition, FeatureRegistry, default_registry
from sentinel_features.statistical import (
    rate,
    ratio,
    safe_div,
    shannon_entropy,
    summary_statistics,
)
from sentinel_features.tcp import TCPFeatureExtractor
from sentinel_features.tls import TLSFeatureExtractor
from sentinel_features.timing import TimingFeatureExtractor

__all__ = [
    "BaseFeatureExtractor",
    "DNSFeatureExtractor",
    "FeatureDefinition",
    "FeatureRegistry",
    "NetworkFeatureExtractor",
    "TCPFeatureExtractor",
    "TLSFeatureExtractor",
    "TimingFeatureExtractor",
    "UnifiedFeatureExtractor",
    "default_registry",
    "rate",
    "ratio",
    "safe_div",
    "shannon_entropy",
    "summary_statistics",
]
