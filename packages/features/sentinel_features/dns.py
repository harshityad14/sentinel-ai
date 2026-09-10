"""Passive DNS metadata feature extraction."""

from typing import Optional
from sentinel_features.statistical import safe_div, shannon_entropy
from sentinel_models.events import DNSMetadata
from sentinel_models.features import DNSFeatures


class DNSFeatureExtractor:
    """Extracts lexical, structural, and information entropy features from passive DNS telemetry."""

    @staticmethod
    def extract(dns: Optional[DNSMetadata]) -> Optional[DNSFeatures]:
        """Derive DNSFeatures from DNSMetadata without inspecting application payloads.
        
        Returns None if no DNS metadata is present.
        """
        if dns is None or not dns.query_name:
            return None

        qname = dns.query_name.strip()
        qlen = len(qname)

        if qlen == 0:
            return None

        labels = [part for part in qname.split(".") if part]
        label_cnt = len(labels)
        subdomain_dpth = max(0, label_cnt - 2)

        digits = sum(1 for c in qname if c.isdigit())
        alphas = sum(1 for c in qname if c.isalpha())
        unique_chars = len(set(qname))

        entropy_val = shannon_entropy(qname)
        d_ratio = round(safe_div(digits, qlen), 4)
        a_ratio = round(safe_div(alphas, qlen), 4)
        u_ratio = round(safe_div(unique_chars, qlen), 4)

        is_nx = bool(dns.response_code and "NXDOMAIN" in dns.response_code.upper())

        return DNSFeatures(
            query_length=qlen,
            subdomain_depth=subdomain_dpth,
            shannon_entropy=entropy_val,
            digit_ratio=d_ratio,
            alphabetic_ratio=a_ratio,
            unique_char_ratio=u_ratio,
            label_count=label_cnt,
            is_nxdomain=is_nx,
        )
