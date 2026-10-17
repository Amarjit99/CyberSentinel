"""CyberSentinel AI — Ground Truth Repository & Dataset Manager (Sprint 23)
Manages independently labelled scenario ground truths with provenance,
schema validation, and version control.

Governing Decisions: ADR-0002, Phase 23 Specification, docs/26-BENCHMARK-DESIGN.md
Traceability: CSAI-R1.2-BENCHMARK §3
"""

import json
import logging
from pathlib import Path
from typing import List, Optional, Union

from pydantic import ValidationError

from services.benchmark.models import BenchmarkDataset, GroundTruthLabel

logger = logging.getLogger("cybersentinel.benchmark.ground_truth")

DEFAULT_GROUND_TRUTH_PATH = (
    Path(__file__).parent.parent.parent / "benchmarks" / "ground_truth" / "ground_truth_v1.json"
)


class GroundTruthError(Exception):
    """Raised when ground truth validation fails or labels are malformed."""

    pass


class GroundTruthRepository:
    """Manages ground-truth labels for benchmark scenarios.

    Non-negotiable invariants:
    1. Ground-truth labels are independently authored and immutable during a benchmark run.
    2. Unknown scenario IDs raise explicit errors rather than defaulting to empty guesses.
    3. Missing or ambiguous labels are explicitly marked NOT_EVALUABLE.
    """

    def __init__(
        self,
        dataset_path: Optional[Union[str, Path]] = None,
        file_path: Optional[Union[str, Path]] = None,
    ) -> None:
        target_path = file_path or dataset_path or DEFAULT_GROUND_TRUTH_PATH
        self.path = Path(target_path)
        self._explicit_path = bool(dataset_path or file_path)
        self._dataset: Optional[BenchmarkDataset] = None
        self._load()

    def _load(self) -> None:
        """Load and strictly validate the ground truth dataset JSON."""
        if not self.path.is_file():
            if self._explicit_path:
                raise FileNotFoundError(f"Ground truth dataset not found at '{self.path}'")
            logger.warning("Ground truth file not found at '%s'", self.path)
            self._dataset = BenchmarkDataset(
                dataset_id="DS-EMPTY",
                version="0.0.0",
                name="Empty Dataset",
                description="Uninitialized fallback dataset",
            )
            return

        try:
            raw_text = self.path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            self._dataset = BenchmarkDataset.model_validate(data)
            logger.info(
                "Loaded ground truth dataset '%s' v%s with %d scenario labels",
                self._dataset.dataset_id,
                self._dataset.version,
                len(self._dataset.labels),
            )
        except ValidationError:
            raise
        except Exception as ex:
            raise GroundTruthError(f"Failed to parse ground truth file at '{self.path}': {ex}") from ex

    def get_dataset(self) -> BenchmarkDataset:
        """Return the validated benchmark dataset."""
        return self.dataset

    @property
    def dataset(self) -> BenchmarkDataset:
        """Get the validated benchmark dataset."""
        if self._dataset is None:
            self._load()
        assert self._dataset is not None
        return self._dataset

    @property
    def dataset_id(self) -> str:
        return self.dataset.dataset_id

    @property
    def version(self) -> str:
        return self.dataset.version

    def get_label(self, scenario_id: str) -> Optional[GroundTruthLabel]:
        """Fetch ground truth label for a given scenario ID."""
        return self.dataset.labels.get(scenario_id)

    def require_label(self, scenario_id: str) -> GroundTruthLabel:
        """Fetch ground truth label or raise GroundTruthError if unknown."""
        lbl = self.get_label(scenario_id)
        if not lbl:
            raise GroundTruthError(
                f"Unknown scenario ID '{scenario_id}' in ground truth dataset '{self.dataset_id}'"
            )
        return lbl

    def list_scenario_ids(self) -> List[str]:
        """List all labelled scenario IDs in the dataset."""
        return list(self.dataset.labels.keys())

    def list_evaluable_ids(self) -> List[str]:
        """List scenario IDs marked evaluable."""
        return [sid for sid, lbl in self.dataset.labels.items() if lbl.evaluable]

    def reload(self) -> None:
        """Force reload from disk."""
        self._load()


default_ground_truth_repo = GroundTruthRepository()
