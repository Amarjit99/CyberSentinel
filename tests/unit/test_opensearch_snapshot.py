import pytest

from scripts.opensearch_snapshot import restore_snapshot


def test_snapshot_restore_requires_explicit_destructive_consent():
    with pytest.raises(ValueError, match="allow-destructive-restore"):
        restore_snapshot(
            "http://127.0.0.1:9200",
            "cybersentinel",
            "daily",
            allow_destructive_restore=False,
        )
