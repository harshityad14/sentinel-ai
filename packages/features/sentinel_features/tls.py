"""Passive TLS metadata feature extraction."""

from typing import Optional
from sentinel_models.events import TLSMetadata
from sentinel_models.features import TLSFeatures


class TLSFeatureExtractor:
    """Extracts passive TLS handshake characteristics without payload decryption."""

    @staticmethod
    def extract(tls: Optional[TLSMetadata]) -> Optional[TLSFeatures]:
        """Derive TLSFeatures from TLSMetadata.
        
        Returns None if no TLS metadata is present.
        """
        if tls is None:
            return None

        has_sni = bool(tls.sni and tls.sni.strip())
        cipher_cnt = len(tls.cipher_suites) if tls.cipher_suites else 0
        has_ja3 = bool(tls.ja3 and tls.ja3.strip())
        has_ja4 = bool(tls.ja4 and tls.ja4.strip())

        return TLSFeatures(
            tls_version=tls.version,
            sni_present=has_sni,
            cipher_suite_count=cipher_cnt,
            ja3_present=has_ja3,
            ja3_hash=tls.ja3 if has_ja3 else None,
            ja4_present=has_ja4,
            ja4_hash=tls.ja4 if has_ja4 else None,
        )
