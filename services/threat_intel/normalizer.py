"""CyberSentinel AI — Threat Intelligence Indicator Normalization & Validation (Sprint 13)"""

import ipaddress
import re
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA1 = "hash_sha1"
    HASH_MD5 = "hash_md5"
    EMAIL = "email"
    CERTIFICATE_SHA256 = "certificate_sha256"


# Validation regexes
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
HASH_SHA256_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
HASH_SHA1_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")
HASH_MD5_REGEX = re.compile(r"^[0-9a-fA-F]{32}$")
EMAIL_REGEX = re.compile(
    r"^[^@\s<>]+@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class NormalizedIndicator(BaseModel):
    """Result of indicator normalization and syntactic validation."""

    indicator_type: str = Field(..., description="Canonical indicator type")
    value: str = Field(..., description="Canonical normalized representation")
    raw_value: str = Field(..., description="Source representation as supplied")
    is_valid: bool = Field(..., description="Whether syntax is valid for the specified type")
    error_code: Optional[str] = Field(default=None, description="Diagnostic code if invalid")
    error_message: Optional[str] = Field(default=None, description="Human-readable reason if invalid")


def normalize_indicator(indicator_type: str, raw_value: str) -> NormalizedIndicator:
    """Validate and normalize indicator values using type-specific rules.

    Does not perform external DNS lookups or fetch URLs (fail closed and offline-safe).
    """
    raw_clean = raw_value.strip()
    itype = indicator_type.strip().lower()

    if not raw_clean:
        return NormalizedIndicator(
            indicator_type=itype,
            value="",
            raw_value=raw_value,
            is_valid=False,
            error_code="EMPTY_VALUE",
            error_message="Indicator value cannot be empty",
        )

    # 1. IPv4
    if itype in ("ipv4", "ip", "ipv4-addr"):
        try:
            ip = ipaddress.IPv4Address(raw_clean)
            return NormalizedIndicator(
                indicator_type=IndicatorType.IPV4.value,
                value=str(ip),
                raw_value=raw_value,
                is_valid=True,
            )
        except ValueError as err:
            return NormalizedIndicator(
                indicator_type=IndicatorType.IPV4.value,
                value=raw_clean,
                raw_value=raw_value,
                is_valid=False,
                error_code="INVALID_IPV4_FORMAT",
                error_message=f"Invalid IPv4 syntax: {err}",
            )

    # 2. IPv6
    if itype in ("ipv6", "ipv6-addr"):
        try:
            ip6 = ipaddress.IPv6Address(raw_clean)
            return NormalizedIndicator(
                indicator_type=IndicatorType.IPV6.value,
                value=ip6.compressed,
                raw_value=raw_value,
                is_valid=True,
            )
        except ValueError as err:
            return NormalizedIndicator(
                indicator_type=IndicatorType.IPV6.value,
                value=raw_clean,
                raw_value=raw_value,
                is_valid=False,
                error_code="INVALID_IPV6_FORMAT",
                error_message=f"Invalid IPv6 syntax: {err}",
            )

    # 3. Domain
    if itype in ("domain", "domain-name", "hostname", "fqdn"):
        domain_norm = raw_clean.lower().rstrip(".")
        if len(domain_norm) > 253 or not DOMAIN_REGEX.match(domain_norm):
            return NormalizedIndicator(
                indicator_type=IndicatorType.DOMAIN.value,
                value=domain_norm,
                raw_value=raw_value,
                is_valid=False,
                error_code="INVALID_DOMAIN_FORMAT",
                error_message="Invalid domain name syntax according to RFC 1035/1123",
            )
        return NormalizedIndicator(
            indicator_type=IndicatorType.DOMAIN.value,
            value=domain_norm,
            raw_value=raw_value,
            is_valid=True,
        )

    # 4. URL
    if itype == "url":
        try:
            parsed = urlparse(raw_clean)
            if parsed.scheme.lower() not in ("http", "https"):
                return NormalizedIndicator(
                    indicator_type=IndicatorType.URL.value,
                    value=raw_clean,
                    raw_value=raw_value,
                    is_valid=False,
                    error_code="UNSUPPORTED_URL_SCHEME",
                    error_message=f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed.",
                )
            if not parsed.netloc:
                return NormalizedIndicator(
                    indicator_type=IndicatorType.URL.value,
                    value=raw_clean,
                    raw_value=raw_value,
                    is_valid=False,
                    error_code="MISSING_URL_NETLOC",
                    error_message="URL missing host / network location",
                )
            # Normalized canonical URL representation: lowercase scheme and netloc, preserved path/query
            normalized_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
            if parsed.query:
                normalized_url += f"?{parsed.query}"
            return NormalizedIndicator(
                indicator_type=IndicatorType.URL.value,
                value=normalized_url,
                raw_value=raw_value,
                is_valid=True,
            )
        except Exception as err:
            return NormalizedIndicator(
                indicator_type=IndicatorType.URL.value,
                value=raw_clean,
                raw_value=raw_value,
                is_valid=False,
                error_code="MALFORMED_URL",
                error_message=f"Malformed URL string: {err}",
            )

    # 5. Email addresses
    if itype in ("email", "email-addr", "email_address"):
        normalized_email = raw_clean.lower()
        if len(normalized_email) > 320 or not EMAIL_REGEX.match(normalized_email):
            return NormalizedIndicator(
                indicator_type=IndicatorType.EMAIL.value,
                value=normalized_email,
                raw_value=raw_value,
                is_valid=False,
                error_code="INVALID_EMAIL_FORMAT",
                error_message="Invalid email address syntax",
            )
        return NormalizedIndicator(
            indicator_type=IndicatorType.EMAIL.value,
            value=normalized_email,
            raw_value=raw_value,
            is_valid=True,
        )

    # 6. Hashes and certificate fingerprints
    if itype in (
        "certificate_sha256",
        "cert_sha256",
        "x509_sha256",
        "x509-certificate:hashes.sha-256",
        "x509-certificate:hashes.sha256",
    ):
        val_lower = raw_clean.lower()
        if not HASH_SHA256_REGEX.match(val_lower):
            return NormalizedIndicator(
                indicator_type=IndicatorType.CERTIFICATE_SHA256.value,
                value=val_lower,
                raw_value=raw_value,
                is_valid=False,
                error_code="INVALID_CERTIFICATE_SHA256_FORMAT",
                error_message="Certificate SHA-256 fingerprint must be exactly 64 hexadecimal characters",
            )
        return NormalizedIndicator(
            indicator_type=IndicatorType.CERTIFICATE_SHA256.value,
            value=val_lower,
            raw_value=raw_value,
            is_valid=True,
        )

    # 7. File hashes
    if itype in ("hash_sha256", "sha256", "file:hashes.sha-256", "file:hashes.sha256"):
        val_lower = raw_clean.lower()
        if not HASH_SHA256_REGEX.match(val_lower):
            return NormalizedIndicator(
                indicator_type=IndicatorType.HASH_SHA256.value,
                value=val_lower,
                raw_value=raw_value,
                is_valid=False,
                error_code="INVALID_SHA256_FORMAT",
                error_message="SHA-256 hash must be exactly 64 hexadecimal characters",
            )
        return NormalizedIndicator(
            indicator_type=IndicatorType.HASH_SHA256.value,
            value=val_lower,
            raw_value=raw_value,
            is_valid=True,
        )

    if itype in ("hash_sha1", "sha1", "file:hashes.sha-1", "file:hashes.sha1"):
        val_lower = raw_clean.lower()
        if not HASH_SHA1_REGEX.match(val_lower):
            return NormalizedIndicator(
                indicator_type=IndicatorType.HASH_SHA1.value,
                value=val_lower,
                raw_value=raw_value,
                is_valid=False,
                error_code="INVALID_SHA1_FORMAT",
                error_message="SHA-1 hash must be exactly 40 hexadecimal characters",
            )
        return NormalizedIndicator(
            indicator_type=IndicatorType.HASH_SHA1.value,
            value=val_lower,
            raw_value=raw_value,
            is_valid=True,
        )

    if itype in ("hash_md5", "md5", "file:hashes.md5"):
        val_lower = raw_clean.lower()
        if not HASH_MD5_REGEX.match(val_lower):
            return NormalizedIndicator(
                indicator_type=IndicatorType.HASH_MD5.value,
                value=val_lower,
                raw_value=raw_value,
                is_valid=False,
                error_code="INVALID_MD5_FORMAT",
                error_message="MD5 hash must be exactly 32 hexadecimal characters",
            )
        return NormalizedIndicator(
            indicator_type=IndicatorType.HASH_MD5.value,
            value=val_lower,
            raw_value=raw_value,
            is_valid=True,
        )

    # Unsupported indicator type
    return NormalizedIndicator(
        indicator_type=itype,
        value=raw_clean,
        raw_value=raw_value,
        is_valid=False,
        error_code="UNSUPPORTED_INDICATOR_TYPE",
        error_message=f"Unsupported indicator type: '{indicator_type}'",
    )


__all__ = [
    "IndicatorType",
    "NormalizedIndicator",
    "normalize_indicator",
]
