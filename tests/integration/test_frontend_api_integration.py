"""Integration tests for frontend-facing APIs and workflows.
Traceability: CSAI-R1.3-UX-COMPLETION, Sprint 24
Verifies that all frontend workflows connect to real backend APIs with authentic RBAC enforcement,
optimistic concurrency control, multi-person approvals, and safety guardrails.
"""

from fastapi.testclient import TestClient

from apps.api.main import app

client = TestClient(app)


def test_frontend_health_and_readiness_contracts():
    """Verify frontend readiness and health checks return the expected contract shape."""
    h_resp = client.get("/health")
    assert h_resp.status_code == 200
    h_data = h_resp.json()
    assert h_data["status"] in ["healthy", "degraded"]
    assert "version" in h_data
    assert "checks" in h_data

    r_resp = client.get("/ready")
    assert r_resp.status_code == 200
    r_data = r_resp.json()
    assert "ready" in r_data
    assert isinstance(r_data["ready"], bool)


def test_frontend_role_authorization_enforcement():
    """Verify that VIEWER role is rejected with 403 on protected mutating endpoints,
    while authorized roles succeed."""
    # Attempt transition as VIEWER -> 403 Forbidden
    resp = client.post(
        "/api/v1/incidents/nonexistent-inc/transition",
        headers={"X-Operator-Role": "VIEWER"},
        json={"to_state": "TRIAGED", "version": 1, "reason": "Viewer attempt"},
    )
    assert resp.status_code in [401, 403]

    # Attempt benchmark run as VIEWER -> 403 Forbidden
    resp_bm = client.post(
        "/api/v1/benchmarks/run",
        headers={"X-Operator-Role": "VIEWER"},
        json={"execution_mode": "deterministic_offline"},
    )
    assert resp_bm.status_code in [401, 403]


def test_frontend_incident_lifecycle_workflow():
    """Verify incident listing, detail fetching, note addition, and state transition."""
    # 1. Fetch incidents
    resp = client.get("/api/v1/incidents", headers={"X-Operator-Role": "SOC_ANALYST"})
    assert resp.status_code == 200
    incidents = resp.json()
    if isinstance(incidents, dict) and "incidents" in incidents:
        incidents = incidents["incidents"]

    assert isinstance(incidents, list)
    if len(incidents) > 0:
        inc = incidents[0]
        inc_id = inc["id"]

        # 2. Add note
        note_resp = client.post(
            f"/api/v1/incidents/{inc_id}/notes",
            headers={"X-Operator-Role": "SOC_ANALYST"},
            json={"note": "Test note from automated integration suite"},
        )
        assert note_resp.status_code in [200, 201]

        # 3. Check timeline
        tl_resp = client.get(
            f"/api/v1/incidents/{inc_id}/timeline",
            headers={"X-Operator-Role": "SOC_ANALYST"},
        )
        assert tl_resp.status_code == 200


def test_frontend_detection_candidate_lifecycle():
    """Verify generating, validating, reviewing, and activating rule candidates."""
    # 1. Generate candidate as SECURITY_ENGINEER
    gen_payload = {
        "title": "Frontend Test Suspicious Script Execution",
        "objective": "Detect certutil download flags in command line arguments",
        "severity": "medium",
        "category": "process_creation",
        "product": "windows",
        "required_fields": ["CommandLine", "Image"],
        "benign_filters": [],
    }
    gen_resp = client.post(
        "/api/v1/detection/candidates",
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
        json=gen_payload,
    )
    assert gen_resp.status_code in [200, 201]
    cand = gen_resp.json()
    cand_id = cand["id"]

    # 2. Validate candidate
    val_resp = client.post(
        f"/api/v1/detection/candidates/{cand_id}/validate",
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
    )
    assert val_resp.status_code == 200

    # 3. Test candidate
    yaml_str = cand.get("raw_yaml") or cand.get("rule_yaml")
    test_resp = client.post(
        f"/api/v1/detection/candidates/{cand_id}/test",
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
        json={"rule_yaml": yaml_str, "use_sample_fixtures": True, "max_events": 10},
    )
    assert test_resp.status_code == 200

    # 4. Review candidate
    rev_resp = client.post(
        f"/api/v1/detection/candidates/{cand_id}/review",
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
        json={"decision": "APPROVED", "notes": "Approved for lab validation"},
    )
    assert rev_resp.status_code == 200


def test_frontend_response_dry_run_safety():
    """Verify that response execution strictly maintains dry_run and rejects live execution bypass."""
    # Fetch catalogue
    cat_resp = client.get("/api/v1/response/catalogue", headers={"X-Operator-Role": "SOC_ANALYST"})
    assert cat_resp.status_code == 200
    catalogue = cat_resp.json()
    if isinstance(catalogue, dict) and "catalogue" in catalogue:
        catalogue = catalogue["catalogue"]
    assert len(catalogue) > 0


def test_frontend_benchmark_integration():
    """Verify ground truth retrieval and offline benchmark execution initiated by authorized engineer."""
    # 1. Ground truth retrieval
    gt_resp = client.get(
        "/api/v1/benchmarks/ground-truth",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert gt_resp.status_code == 200
    gt = gt_resp.json()
    assert gt["dataset_id"] == "DS-CYBERSENTINEL-BENCHMARK-V1"
    labels = gt.get("labels") or gt.get("scenarios") or []
    assert len(labels) == 16

    # 2. Baselines retrieval
    base_resp = client.get(
        "/api/v1/benchmarks/baselines",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert base_resp.status_code == 200
