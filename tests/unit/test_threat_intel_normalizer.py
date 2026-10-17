"""CyberSentinel AI — Unit Tests: Threat Intelligence Normalization (Sprint 13)"""


from services.threat_intel.normalizer import (
    IndicatorType,
    normalize_indicator,
)


def test_ipv4_normalization():
    """Verify valid IPv4 address parsing and trimming."""
    norm = normalize_indicator("ipv4", "  198.51.100.42  ")
    assert norm.is_valid is True
    assert norm.indicator_type == IndicatorType.IPV4.value
    assert norm.value == "198.51.100.42"
    assert norm.raw_value == "  198.51.100.42  "


def test_ipv4_rejection_of_invalid_syntax():
    """Verify rejection of malformed IPv4 strings."""
    invalid_ips = ["999.1.1.1", "198.51.100", "198.51.100.abc", "198.51.100.1.1"]
    for bad_ip in invalid_ips:
        norm = normalize_indicator("ipv4", bad_ip)
        assert norm.is_valid is False
        assert norm.error_code == "INVALID_IPV4_FORMAT"


def test_ipv6_normalization():
    """Verify IPv6 address normalization and compression."""
    norm = normalize_indicator("ipv6", "2001:0db8:0000:0000:0000:0000:0000:0001")
    assert norm.is_valid is True
    assert norm.indicator_type == IndicatorType.IPV6.value
    assert norm.value == "2001:db8::1"


def test_domain_normalization():
    """Verify domain normalization: lowercasing, stripping trailing dot."""
    norm = normalize_indicator("domain", "  MALICIOUS-C2.Example.COM. ")
    assert norm.is_valid is True
    assert norm.indicator_type == IndicatorType.DOMAIN.value
    assert norm.value == "malicious-c2.example.com"


def test_domain_rejection_of_invalid_characters():
    """Verify rejection of illegal domain characters or oversized strings."""
    bad_domains = ["not a domain", "-leading-dash.com", "trailing-.com", "domain..com", "a" * 260 + ".com"]
    for bad in bad_domains:
        norm = normalize_indicator("domain", bad)
        assert norm.is_valid is False
        assert norm.error_code == "INVALID_DOMAIN_FORMAT"


def test_url_normalization_without_fetching():
    """Verify URL normalization: canonical scheme and host lowercasing without network execution."""
    norm = normalize_indicator("url", "HTTP://Evil.Org:8080/path/payload.exe?token=123")
    assert norm.is_valid is True
    assert norm.indicator_type == IndicatorType.URL.value
    assert norm.value == "http://evil.org:8080/path/payload.exe?token=123"


def test_url_rejection_of_unsupported_schemes():
    """Verify that file://, gopher://, javascript:, ftp:// are rejected."""
    unsupported = ["file:///etc/passwd", "javascript:alert(1)", "ftp://evil.com/drop", "gopher://bad"]
    for url in unsupported:
        norm = normalize_indicator("url", url)
        assert norm.is_valid is False
        assert norm.error_code == "UNSUPPORTED_URL_SCHEME"


def test_hash_normalization_sha256_sha1_md5():
    """Verify hex validation and lowercasing of hashes."""
    sha256_val = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
    norm256 = normalize_indicator("hash_sha256", sha256_val)
    assert norm256.is_valid is True
    assert norm256.value == sha256_val.lower()

    sha1_val = "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"
    norm1 = normalize_indicator("hash_sha1", sha1_val)
    assert norm1.is_valid is True
    assert norm1.value == sha1_val.lower()

    md5_val = "C4CA4238A0B923820DCC509A6F75849B"
    norm_md5 = normalize_indicator("hash_md5", md5_val)
    assert norm_md5.is_valid is True
    assert norm_md5.value == md5_val.lower()


def test_hash_rejection_of_invalid_lengths_or_characters():
    """Verify rejection of corrupted hash representations."""
    bad_hashes = ["too_short", "275a021b", "275a021b" + "g" * 56]
    for bad in bad_hashes:
        norm = normalize_indicator("hash_sha256", bad)
        assert norm.is_valid is False
        assert norm.error_code == "INVALID_SHA256_FORMAT"


def test_email_normalization_and_validation():
    norm = normalize_indicator("email-addr", " Analyst@Example.COM ")
    assert norm.is_valid is True
    assert norm.indicator_type == IndicatorType.EMAIL.value
    assert norm.value == "analyst@example.com"

    invalid = normalize_indicator("email", "not-an-email")
    assert invalid.is_valid is False
    assert invalid.error_code == "INVALID_EMAIL_FORMAT"


def test_certificate_sha256_normalization():
    fingerprint = "AB" * 32
    norm = normalize_indicator("x509_sha256", fingerprint)
    assert norm.is_valid is True
    assert norm.indicator_type == IndicatorType.CERTIFICATE_SHA256.value
    assert norm.value == fingerprint.lower()
