"""CyberSentinel AI — Scenario Catalogue & Discovery Service (Sprint 22)
Loads, parses, and provides access to authoritative defensive lab scenarios.
Governing Decisions: ADR-0005, CSAI-R1.1-LAB-SCENARIOS
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from scenarios.models import ScenarioDefinition, ScenarioValidationResult
from scenarios.validator import ScenarioValidator, default_scenario_validator

logger = logging.getLogger("cybersentinel.scenarios.catalogue")

DEFAULT_FIXTURES_DIR = Path(__file__).parent / "fixtures"


class ScenarioCatalogue:
    """In-memory registry and repository of validated scenario definitions."""

    def __init__(
        self,
        fixtures_dir: Optional[Path] = None,
        validator: Optional[ScenarioValidator] = None,
    ):
        self.fixtures_dir = fixtures_dir or DEFAULT_FIXTURES_DIR
        self.validator = validator or default_scenario_validator
        self._scenarios: Dict[str, ScenarioDefinition] = {}
        self._validation_results: Dict[str, ScenarioValidationResult] = {}
        self.reload()

    def reload(self) -> int:
        """Scan fixtures directory, validate definitions, and load valid scenarios."""
        self._scenarios.clear()
        self._validation_results.clear()

        if not self.fixtures_dir.is_dir():
            logger.warning("Scenario fixtures directory not found: %s", self.fixtures_dir)
            return 0

        fixture_files = sorted(list(self.fixtures_dir.glob("*.json")))
        for fpath in fixture_files:
            try:
                raw_text = fpath.read_text(encoding="utf-8")
                val_result = self.validator.validate_scenario(raw_text)
                self._validation_results[val_result.scenario_id] = val_result

                if val_result.is_valid:
                    data = json.loads(raw_text)
                    scenario = ScenarioDefinition.model_validate(data)
                    self._scenarios[scenario.scenario_id] = scenario
                else:
                    logger.warning(
                        "Scenario '%s' in file '%s' failed validation: %s",
                        val_result.scenario_id,
                        fpath.name,
                        "; ".join(val_result.errors),
                    )
            except Exception as ex:
                logger.error("Failed to load scenario fixture '%s': %s", fpath.name, ex)

        logger.info(
            "Scenario catalogue loaded %d valid scenarios (%d total files evaluated).",
            len(self._scenarios),
            len(fixture_files),
        )
        return len(self._scenarios)

    @property
    def scenario_count(self) -> int:
        return len(self._scenarios)

    def get_scenario(self, scenario_id: str) -> Optional[ScenarioDefinition]:
        """Fetch scenario definition by its stable identifier."""
        return self._scenarios.get(scenario_id)

    def list_scenarios(self, category: Optional[str] = None) -> List[ScenarioDefinition]:
        """List all loaded scenarios, optionally filtered by category."""
        scenarios = list(self._scenarios.values())
        if category:
            scenarios = [s for s in scenarios if s.category.value == category]
        return scenarios

    def get_validation_report(self) -> Dict[str, ScenarioValidationResult]:
        """Get all validation diagnostic reports for the loaded fixtures."""
        return dict(self._validation_results)


default_scenario_catalogue = ScenarioCatalogue()
