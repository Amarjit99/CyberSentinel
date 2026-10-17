"""Tests for the offline repository security gate."""

from scripts.security_gate import find_secrets


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
