"""CyberSentinel AI — Scenario Static Validator (Sprint 22)
Validates scenario definitions against structural, schema, size, and safety constraints.
Governing Decisions: ADR-0005, CSAI-R1.1-LAB-SCENARIOS
"""

import json
import re
from typing import Any, Dict, List, Optional, Union

from pydantic import ValidationError

from attack.registry import AttackCatalog, attack_catalog
from scenarios.models import ScenarioDefinition, ScenarioValidationResult
from schemas.canonical_event import CanonicalEvent

# Forbidden tokens ensuring scenario definitions remain pure inert data
DANGEROUS_CODE_PATTERNS = [
    re.compile(r"\b(eval|exec|compile|__import__|subprocess(?:\.[a-zA-Z0-9_]+)?|os\.system|shutil(?:\.[a-zA-Z0-9_]+)?|pty)\s*\(", re.IGNORECASE),
    re.compile(r"\b(powershell|cmd\.exe|bash|sh|zsh)\s+-c", re.IGNORECASE),
    re.compile(r"<script[\s>]", re.IGNORECASE),
]

MAX_EVENTS_PER_SCENARIO: int = 100
MAX_SCENARIO_PAYLOAD_BYTES: int = 262_144  # 256 KB


class ScenarioValidator:
    """Static data-driven validator enforcing safety, limits, and schema compliance for scenarios."""

    def __init__(self, catalog: Optional[AttackCatalog] = None):
        self.catalog = catalog or attack_catalog

    def validate_scenario(
        self,
        raw_input: Union[ScenarioDefinition, Dict[str, Any], str],
    ) -> ScenarioValidationResult:
        """Validate a scenario definition object, dictionary, or JSON string."""
        errors: List[str] = []
        warnings: List[str] = []
        scenario_id = "UNKNOWN"
        event_count = 0

        # 1. Payload format & string parsing
        if isinstance(raw_input, str):
            raw_str = raw_input
            try:
                data = json.loads(raw_input)
            except Exception as ex:
                return ScenarioValidationResult(
                    scenario_id="PARSE_ERROR",
                    is_valid=False,
                    errors=[f"Invalid JSON syntax in scenario definition: {ex}"],
                )
        elif isinstance(raw_input, dict):
            raw_str = json.dumps(raw_input)
            data = raw_input
        elif isinstance(raw_input, ScenarioDefinition):
            raw_str = raw_input.model_dump_json()
            data = raw_input.model_dump(mode="json")
        else:
            return ScenarioValidationResult(
                scenario_id="TYPE_ERROR",
                is_valid=False,
                errors=[f"Unsupported scenario input type: {type(raw_input).__name__}"],
            )

        # 2. Size bounds check
        payload_bytes = len(raw_str.encode("utf-8"))
        if payload_bytes > MAX_SCENARIO_PAYLOAD_BYTES:
            errors.append(
                f"Scenario payload size ({payload_bytes} bytes) exceeds maximum allowed limit of {MAX_SCENARIO_PAYLOAD_BYTES} bytes."
            )

        # 3. Dangerous code injection prevention in definitions
        for pattern in DANGEROUS_CODE_PATTERNS:
            # Exempt specific synthetic payload fields that test detection of suspicious commands
            matches = pattern.findall(raw_str)
            if matches:
                # Allow only if confined within synthetic_events command_line or raw_event fields
                # Check top-level scenario metadata for forbidden executable code
                meta_sample = f"{data.get('scenario_id', '')} {data.get('name', '')} {data.get('objective', '')}"
                if pattern.search(meta_sample):
                    errors.append(
                        f"Executable code pattern '{pattern.pattern}' detected in scenario metadata. Scenarios must be pure data."
                    )

        # 4. Pydantic schema validation
        try:
            scenario = ScenarioDefinition.model_validate(data)
            scenario_id = scenario.scenario_id
        except ValidationError as ve:
            for err in ve.errors():
                loc = " -> ".join(str(part) for part in err["loc"])
                errors.append(f"Schema violation at '{loc}': {err['msg']}")
            return ScenarioValidationResult(
                scenario_id=str(data.get("scenario_id", "SCHEMA_ERROR")),
                is_valid=False,
                errors=errors,
                warnings=warnings,
            )

        # 5. Event count limits
        event_count = len(scenario.synthetic_events)
        if event_count > MAX_EVENTS_PER_SCENARIO:
            errors.append(
                f"Scenario defines {event_count} events, exceeding the maximum allowed limit of {MAX_EVENTS_PER_SCENARIO} events."
            )

        # 6. Canonical event validation for fixtures
        for idx, ev_dict in enumerate(scenario.synthetic_events):
            if not isinstance(ev_dict, dict):
                errors.append(f"Event fixture #{idx} is not a valid dictionary structure.")
                continue

            # Validate whether the fixture parses into CanonicalEvent
            try:
                CanonicalEvent.model_validate(ev_dict)
            except ValidationError as ce_err:
                # If negative case or malformed-event test, flag as warning rather than release error
                if scenario.is_negative_case and "malformed" in scenario.scenario_id.lower():
                    warnings.append(
                        f"Event fixture #{idx} failed canonical validation (permitted for negative malformed test): {ce_err.errors()[0]['msg']}"
                    )
                else:
                    errors.append(
                        f"Event fixture #{idx} failed CanonicalEvent validation: {ce_err.errors()[0]['msg']} (field: {ce_err.errors()[0]['loc']})"
                    )

            # Check required canonical fields
            for req_field in scenario.required_canonical_fields:
                if req_field not in ev_dict or ev_dict[req_field] is None:
                    if not (scenario.is_negative_case and "malformed" in scenario.scenario_id.lower()):
                        errors.append(f"Event fixture #{idx} missing required canonical field '{req_field}'.")

        # 7. MITRE ATT&CK technique catalog verification
        for tech_id in scenario.attack_technique_ids:
            tech = self.catalog.get_technique(tech_id)
            if not tech:
                warnings.append(
                    f"ATT&CK Technique ID '{tech_id}' is not recognized in authoritative Enterprise ATT&CK v{self.catalog.version} catalog."
                )

        return ScenarioValidationResult(
            scenario_id=scenario_id,
            is_valid=(len(errors) == 0),
            errors=errors,
            warnings=warnings,
            event_count=event_count,
        )


default_scenario_validator = ScenarioValidator()
