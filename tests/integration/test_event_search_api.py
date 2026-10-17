"""Phase 6 event exploration API contract and safety tests."""

from fastapi.testclient import TestClient

from apps.api.main import app


def test_event_search_requires_bounded_query_and_returns_contract():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/events/search",
            params={"q": "ab", "limit": 1},
            headers={"X-Operator-Role": "SOC_ANALYST"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 1
    assert "filters_applied" in body
    assert isinstance(body["events"], list)
    assert all("raw_event" not in event for event in body["events"])


def test_event_search_rejects_reversed_time_window():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/events/search",
            params={
                "start_time": "2026-10-17T12:00:00Z",
                "end_time": "2026-10-17T11:00:00Z",
            },
            headers={"X-Operator-Role": "SOC_ANALYST"},
        )
    assert response.status_code == 422


def test_event_search_rejects_unbounded_limit():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/events/search",
            params={"limit": 101},
            headers={"X-Operator-Role": "SOC_ANALYST"},
        )
    assert response.status_code == 422
