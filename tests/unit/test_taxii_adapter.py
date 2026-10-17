"""Safety and contract tests for the TAXII 2.1 adapter."""

from unittest.mock import Mock

import httpx
import pytest

from services.threat_intel.adapters.taxii21 import (
    TaxiiAdapter,
    TaxiiAdapterConfig,
    TaxiiAdapterError,
    TaxiiRateLimitError,
    TaxiiTimeoutError,
)


def _response(payload, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status.side_effect = (
        httpx.HTTPStatusError("error", request=Mock(), response=response)
        if status_code >= 400
        else None
    )
    return response


def test_taxii_adapter_parses_collection_objects():
    client = Mock()
    client.get.return_value = _response(
        {
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "pattern": "[ipv4-addr:value = '198.51.100.10']",
                }
            ]
        }
    )
    adapter = TaxiiAdapter(
        TaxiiAdapterConfig("https://intel.example/collections/1/objects"),
        client=client,
    )

    records = adapter.fetch_records()

    assert records[0].indicator_value == "198.51.100.10"
    assert client.get.call_args.kwargs["headers"]["Accept"] == TaxiiAdapter.ACCEPT


def test_taxii_adapter_rejects_provider_failure():
    client = Mock()
    client.get.side_effect = httpx.TimeoutException("timeout")
    adapter = TaxiiAdapter(TaxiiAdapterConfig("https://intel.example/feed"), client=client)

    with pytest.raises(TaxiiTimeoutError):
        adapter.fetch_records()


def test_taxii_adapter_does_not_return_empty_success_for_invalid_payload():
    client = Mock()
    client.get.return_value = _response({"unexpected": []})
    adapter = TaxiiAdapter(TaxiiAdapterConfig("https://intel.example/feed"), client=client)

    with pytest.raises(TaxiiAdapterError):
        adapter.fetch_records()


def test_taxii_adapter_enforces_local_rate_limit():
    client = Mock()
    client.get.return_value = _response({"objects": []})
    adapter = TaxiiAdapter(
        TaxiiAdapterConfig("https://intel.example/feed", requests_per_minute=1),
        client=client,
        clock=lambda: 100.0,
    )

    adapter.fetch_records()
    with pytest.raises(TaxiiRateLimitError):
        adapter.fetch_records()
