"""Tests for the offline repository security gate."""

from scripts.security_gate import check_tls_configuration, find_secrets


def test_secret_scanner_ignores_documented_placeholders(tmp_path):
    source = tmp_path / ".env.example"
    source.write_text(
        "SECRET_KEY=local_insecure_development_secret_key_minimum_32_chars_long\n",
        encoding="utf-8",
    )

    assert find_secrets(tmp_path) == []


def test_secret_scanner_detects_private_keys(tmp_path):
    source = tmp_path / "settings.py"
    source.write_text(
        "KEY = '-----BEGIN PRIVATE KEY-----'\n",
        encoding="utf-8",
    )

    assert find_secrets(tmp_path) == [str(source) + ":1"]


def test_tls_configuration_requires_secure_profile(tmp_path):
    tls_dir = tmp_path / "apps" / "web"
    tls_dir.mkdir(parents=True)
    (tls_dir / "nginx.tls.conf").write_text(
        "listen 443 ssl;\n"
        "ssl_certificate /etc/nginx/tls/tls.crt;\n"
        "ssl_certificate_key /etc/nginx/tls/tls.key;\n"
        "ssl_protocols TLSv1.2 TLSv1.3;\n",
        encoding="utf-8",
    )
    (tmp_path / "compose.tls.yaml").write_text(
        'profiles: ["tls"]\nvolumes:\n  - ./tls:/etc/nginx/tls:ro\n',
        encoding="utf-8",
    )

    status, message = check_tls_configuration(tmp_path)

    assert status == "PASS"
    assert "verified" in message


def test_tls_configuration_rejects_missing_profile(tmp_path):
    status, message = check_tls_configuration(tmp_path)
    assert status == "FAIL"
    assert "incomplete" in message
