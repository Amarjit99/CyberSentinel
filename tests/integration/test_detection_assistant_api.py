"""CyberSentinel AI — Detection Engineering Assistant API Integration Tests (Sprint 19)
Tests REST API endpoints and ToolExecutionService dispatch for detection engineering tools.
"""

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from packages.auth import Principal, RBACRoleEnum
from services.agents.executor import default_tool_executor
from services.agents.tool_schemas import ToolExecutionRequest


@pytest.fixture
def client():
    from services.persistence.database import init_db
    init_db()
    return TestClient(app)


@pytest.fixture
def detection_engineer_headers():
    return {
        "X-Operator-Role": "DETECTION_ENGINEER",
        "X-Operator-Id": "det-eng-01",
        "X-Operator-Name": "Detection Engineer",
    }


@pytest.fixture
def admin_headers():
    return {
        "X-Operator-Role": "ADMIN",
        "X-Operator-Id": "admin-01",
        "X-Operator-Name": "Administrator",
    }


def test_api_generate_and_get_candidate(client: TestClient, detection_engineer_headers: dict):
    """Test generating a candidate rule via REST API and fetching candidate details."""
    payload = {
        "title": "API Test PowerShell Detection",
        "objective": "Detect PowerShell execution with encoded command or web download",
        "target_technique": "T1059.001",
        "category": "process_creation",
        "product": "windows",
        "severity": "high",
    }

    create_resp = client.post("/api/v1/detection/candidates", json=payload, headers=detection_engineer_headers)
    assert create_resp.status_code == 201
    cand_data = create_resp.json()
    assert cand_data["id"].startswith("drc-")
    assert cand_data["title"] == "API Test PowerShell Detection"
    assert cand_data["status"] == "VALIDATED"
    candidate_id = cand_data["id"]

    # Fetch candidate details
    get_resp = client.get(f"/api/v1/detection/candidates/{candidate_id}", headers=detection_engineer_headers)
    assert get_resp.status_code == 200
    fetched = get_resp.json()
    assert fetched["id"] == candidate_id
    assert fetched["validation_report"]["is_valid"] is True


def test_api_list_candidates(client: TestClient, detection_engineer_headers: dict):
    """Test listing candidates with optional status filter."""
    list_resp = client.get("/api/v1/detection/candidates", headers=detection_engineer_headers)
    assert list_resp.status_code == 200
    candidates = list_resp.json()
    assert isinstance(candidates, list)


def test_api_candidate_review_and_activation_lifecycle(
    client: TestClient, detection_engineer_headers: dict, admin_headers: dict
):
    """Test end-to-end review lifecycle: generate -> review -> activate -> deactivate."""
    # 1. Generate candidate
    gen_payload = {
        "title": "Lifecycle Test Rule",
        "objective": "Detect credential access using Mimikatz or sekurlsa",
        "target_technique": "T1003.001",
    }
    gen_resp = client.post("/api/v1/detection/candidates", json=gen_payload, headers=detection_engineer_headers)
    assert gen_resp.status_code == 201
    cand_id = gen_resp.json()["id"]

    # 2. Activation without approval must fail with 422
    act_fail_resp = client.post(f"/api/v1/detection/candidates/{cand_id}/activate", headers=admin_headers)
    assert act_fail_resp.status_code == 422

    # 3. Human review: approve candidate
    review_payload = {
        "decision": "APPROVED",
        "notes": "Peer review completed. Logic verified against memory forensics telemetry.",
    }
    review_resp = client.post(
        f"/api/v1/detection/candidates/{cand_id}/review",
        json=review_payload,
        headers=detection_engineer_headers,
    )
    assert review_resp.status_code == 200
    assert review_resp.json()["status"] == "APPROVED"

    # 4. Now activate candidate -> must succeed
    act_resp = client.post(f"/api/v1/detection/candidates/{cand_id}/activate", headers=admin_headers)
    assert act_resp.status_code == 200
    assert act_resp.json()["status"] == "ACTIVE"

    # 5. Deactivate candidate
    deact_resp = client.post(f"/api/v1/detection/candidates/{cand_id}/deactivate", headers=admin_headers)
    assert deact_resp.status_code == 200
    assert deact_resp.json()["status"] == "DEPRECATED"


def test_api_adhoc_validation_and_explain(client: TestClient, detection_engineer_headers: dict):
    """Test ad-hoc validate and explain endpoints."""
    sample_yaml = """
title: AdHoc API Validation Test
id: 33333333-4444-5555-6666-777777777777
status: experimental
description: Test rule for adhoc endpoints
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: certutil.exe
        command_line|contains: -urlcache
    condition: selection
falsepositives:
    - Legitimate PKI certificate maintenance
level: medium
"""

    # Validate
    val_resp = client.post(
        "/api/v1/detection/validate",
        json={"rule_yaml": sample_yaml},
        headers=detection_engineer_headers,
    )
    assert val_resp.status_code == 200
    val_data = val_resp.json()
    assert val_data["is_valid"] is True

    # Explain
    exp_resp = client.post(
        "/api/v1/detection/explain",
        json={"rule_yaml": sample_yaml},
        headers=detection_engineer_headers,
    )
    assert exp_resp.status_code == 200
    exp_data = exp_resp.json()
    assert exp_data["title"] == "AdHoc API Validation Test"
    assert len(exp_data["false_positive_risks"]) > 0


def test_api_adhoc_safe_testing(client: TestClient, detection_engineer_headers: dict):
    """Test ad-hoc rule testing endpoint against synthetic fixtures."""
    sample_yaml = """
title: PowerShell WebClient Test
id: 44444444-5555-6666-7777-888888888888
status: experimental
description: Safe test execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: powershell.exe
        command_line|contains: Net.WebClient
    condition: selection
level: high
"""
    test_resp = client.post(
        "/api/v1/detection/test",
        json={
            "rule_yaml": sample_yaml,
            "use_sample_fixtures": True,
            "max_events": 20,
        },
        headers=detection_engineer_headers,
    )
    assert test_resp.status_code == 200
    res = test_resp.json()
    assert res["total_events_evaluated"] > 0
    assert res["passed_positive_fixtures"] is True


def test_tool_executor_sprint19_tools():
    """Verify tool execution via central ToolExecutionService."""
    from services.persistence.database import SessionLocal, init_db

    init_db()
    session = SessionLocal()
    try:
        principal = Principal(
            id="det-agent",
            name="Detection Assistant Agent",
            roles=[RBACRoleEnum.DETECTION_ENGINEER, RBACRoleEnum.SECURITY_ENGINEER],
        )

        # 1. Test generate_candidate_rule tool
        gen_call = ToolExecutionRequest(
            tool_name="generate_candidate_rule",
            arguments={
                "title": "Detect PowerShell Downloads",
                "objective": "Detect suspicious PowerShell downloads with WebClient",
                "target_technique": "T1059.001",
            },
        )
        res_gen = default_tool_executor.execute_tool(gen_call, principal=principal, db_session=session)
        assert res_gen.status == "SUCCESS"
        assert "candidate_id" in res_gen.data
        raw_yaml = res_gen.data["raw_yaml"]

        # 2. Test validate_sigma_rule tool
        val_call = ToolExecutionRequest(
            tool_name="validate_sigma_rule",
            arguments={"rule_yaml": raw_yaml},
        )
        res_val = default_tool_executor.execute_tool(val_call, principal=principal, db_session=session)
        assert res_val.status == "SUCCESS"
        assert res_val.data["is_valid"] is True

        # 3. Test explain_detection_rule tool
        exp_call = ToolExecutionRequest(
            tool_name="explain_detection_rule",
            arguments={"rule_yaml": raw_yaml},
        )
        res_exp = default_tool_executor.execute_tool(exp_call, principal=principal, db_session=session)
        assert res_exp.status == "SUCCESS"
        assert "title" in res_exp.data
        assert len(res_exp.data["false_positive_risks"]) > 0

        # 4. Test test_candidate_rule tool
        test_call = ToolExecutionRequest(
            tool_name="test_candidate_rule",
            arguments={"rule_yaml": raw_yaml, "use_sample_fixtures": True},
        )
        res_test = default_tool_executor.execute_tool(test_call, principal=principal, db_session=session)
        assert res_test.status == "SUCCESS"
        assert res_test.data["total_events_evaluated"] > 0
    finally:
        session.close()
